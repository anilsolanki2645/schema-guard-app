"""
Schema Guard – Production Concurrency & Load Testing Harness
Benchmarks system throughput, API latency percentiles (p50, p90, p95, p99),
and error rates under high concurrent traffic.
"""
import os
import sys
import time
import json
import statistics
import concurrent.futures
from typing import List, Dict, Any

# Ensure Django environment is initialized
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")
import django
django.setup()

from django.test import Client
from core.models import Organization, User, Pipeline, ApiKey
from core.security import encrypt_secret, generate_api_key


class BenchmarkResult:
    def __init__(self, endpoint_name: str, latencies: List[float], status_codes: List[int], total_time: float):
        self.endpoint_name = endpoint_name
        self.latencies = latencies
        self.status_codes = status_codes
        self.total_time = total_time
        self.total_requests = len(latencies)
        self.success_count = sum(1 for c in status_codes if 200 <= c < 300)
        self.error_count = self.total_requests - self.success_count

    def print_summary(self):
        rps = self.total_requests / self.total_time if self.total_time > 0 else 0
        sorted_lat = sorted(self.latencies)
        p50 = sorted_lat[int(len(sorted_lat) * 0.50)] if sorted_lat else 0
        p90 = sorted_lat[int(len(sorted_lat) * 0.90)] if sorted_lat else 0
        p95 = sorted_lat[int(len(sorted_lat) * 0.95)] if sorted_lat else 0
        p99 = sorted_lat[int(len(sorted_lat) * 0.99)] if sorted_lat else 0
        avg_lat = statistics.mean(self.latencies) if self.latencies else 0
        min_lat = min(self.latencies) if self.latencies else 0
        max_lat = max(self.latencies) if self.latencies else 0

        print(f"\n=======================================================")
        print(f"  LOAD TEST RESULTS: {self.endpoint_name}")
        print(f"=======================================================")
        print(f"  Total Requests:       {self.total_requests}")
        print(f"  Successful (2xx):     {self.success_count} ({self.success_count / self.total_requests * 100:.1f}%)")
        print(f"  Failed (4xx/5xx):     {self.error_count}")
        print(f"  Duration:             {self.total_time:.2f} seconds")
        print(f"  Throughput:           {rps:.2f} requests/sec")
        print(f"-------------------------------------------------------")
        print(f"  Min Latency:          {min_lat * 1000:.2f} ms")
        print(f"  Avg Latency:          {avg_lat * 1000:.2f} ms")
        print(f"  Median (p50):         {p50 * 1000:.2f} ms")
        print(f"  p90 Latency:          {p90 * 1000:.2f} ms")
        print(f"  p95 Latency:          {p95 * 1000:.2f} ms")
        print(f"  p99 Latency:          {p99 * 1000:.2f} ms")
        print(f"  Max Latency:          {max_lat * 1000:.2f} ms")
        print(f"=======================================================\n")


def setup_load_test_data():
    """Create test organization, user, API key, and pipeline for benchmarking."""
    from django.core.management import call_command
    from django.db import connection
    call_command('migrate', verbosity=0)
    with connection.cursor() as cursor:
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA busy_timeout=60000;")
    org, _ = Organization.objects.get_or_create(name="Benchmark Org", defaults={"plan": "enterprise", "max_pipelines": 1000})
    user, _ = User.objects.get_or_create(
        username="bench_user",
        defaults={
            "email": "bench@loadtest.local",
            "password_hash": "hash",
            "role": "subadmin",
            "organization": org,
            "is_verified": True
        }
    )
    raw_key, kid, khash = generate_api_key()
    api_key_obj, _ = ApiKey.objects.get_or_create(
        key_id=kid,
        defaults={
            "key_hash": khash,
            "name": "Benchmark Key",
            "organization": org,
            "created_by": "bench_user",
            "is_active": True
        }
    )
    pipeline, _ = Pipeline.objects.get_or_create(
        id="bench_pipe_orders",
        defaults={
            "name": "Benchmark Orders Pipeline",
            "db_type": "sqlite",
            "conn_str": encrypt_secret("sqlite:///bench.db"),
            "schema": "main",
            "table": "orders",
            "organization": org,
            "contract_yaml": "source:\n  type: sqlite\n  connection: sqlite:///bench.db\n  schema: main\n  table: orders\ncolumns:\n  - name: id\n    type: INTEGER\n    nullable: false\n  - name: amount\n    type: NUMERIC\n    nullable: true\n",
            "lock_signature": "bench_lock_signature_sha256"
        }
    )
    return org, user, raw_key, pipeline


def benchmark_endpoint(
    name: str,
    make_request_fn,
    total_requests: int = 100,
    concurrency: int = 10
) -> BenchmarkResult:
    latencies = []
    status_codes = []

    def safe_worker():
        from django.db import connection
        try:
            return make_request_fn()
        finally:
            connection.close()

    start_time = time.perf_counter()

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(safe_worker) for _ in range(total_requests)]
        for f in concurrent.futures.as_completed(futures):
            try:
                status, elapsed = f.result()
                status_codes.append(status)
                latencies.append(elapsed)
            except Exception as e:
                status_codes.append(500)
                latencies.append(0.0)

    total_time = time.perf_counter() - start_time
    return BenchmarkResult(name, latencies, status_codes, total_time)


def run_full_load_test(total_requests_per_test=100, concurrency=10):
    print("-------------------------------------------------------")
    print("Initializing Schema Guard Load Test Suite...")
    print(f"Configuration: {total_requests_per_test} requests per test, {concurrency} concurrent threads")
    print("-------------------------------------------------------")

    org, user, raw_api_key, pipeline = setup_load_test_data()

    # 1. Health Check Endpoint
    def req_health():
        client = Client()
        t0 = time.perf_counter()
        res = client.get("/api/health")
        t1 = time.perf_counter()
        return res.status_code, (t1 - t0)

    health_res = benchmark_endpoint("Health Check API (/api/health)", req_health, total_requests_per_test, concurrency)
    health_res.print_summary()

    # 2. CI/CD Gate Validation Endpoint (API Key Authentication + Schema Comparison)
    gate_payload = json.dumps({
        "commit_sha": "git_commit_sha_bench",
        "branch": "feature/analytics",
        "schema": {
            "columns": [
                {"name": "id", "type": "INTEGER", "nullable": False},
                {"name": "amount", "type": "NUMERIC", "nullable": True}
            ]
        }
    })

    def req_gate():
        client = Client()
        t0 = time.perf_counter()
        res = client.post(
            f"/api/pipelines/{pipeline.id}/validate-gate",
            data=gate_payload,
            content_type="application/json",
            HTTP_X_SCHEMA_GUARD_TOKEN=raw_api_key
        )
        t1 = time.perf_counter()
        return res.status_code, (t1 - t0)

    gate_res = benchmark_endpoint("CI/CD Gate Validation (/api/pipelines/<id>/validate-gate)", req_gate, total_requests_per_test, concurrency)
    gate_res.print_summary()

    # 3. Authenticated Pipelines Listing Endpoint (Session Auth + Masking)
    def req_pipelines_list():
        client = Client()
        session = client.session
        session['user'] = {
            "username": user.username,
            "role": user.role,
            "organization_id": org.id,
            "permissions": {"see": True, "create": True, "edit": True, "delete": True},
            "is_verified": True
        }
        session.save()
        t0 = time.perf_counter()
        res = client.get("/api/pipelines")
        t1 = time.perf_counter()
        return res.status_code, (t1 - t0)

    list_res = benchmark_endpoint("Pipelines Catalog List (/api/pipelines)", req_pipelines_list, total_requests_per_test, concurrency)
    list_res.print_summary()

    # 4. Public Pricing & Marketing Showcase Page (/pricing)
    def req_pricing_page():
        client = Client()
        t0 = time.perf_counter()
        res = client.get("/pricing")
        t1 = time.perf_counter()
        return res.status_code, (t1 - t0)

    pricing_res = benchmark_endpoint("Public Pricing Showcase (/pricing)", req_pricing_page, total_requests_per_test, concurrency)
    pricing_res.print_summary()

    # 5. Stripe Checkout Session Initiation (/api/billing/checkout)
    checkout_payload = json.dumps({"plan": "pro"})
    def req_checkout_api():
        client = Client()
        session = client.session
        session['user'] = {
            "username": user.username,
            "role": user.role,
            "organization_id": org.id,
            "permissions": {"see": True, "create": True, "edit": True, "delete": True},
            "is_verified": True
        }
        session.save()
        t0 = time.perf_counter()
        res = client.post(
            "/api/billing/checkout",
            data=checkout_payload,
            content_type="application/json"
        )
        t1 = time.perf_counter()
        return res.status_code, (t1 - t0)

    checkout_res = benchmark_endpoint("Stripe Checkout Initiation (/api/billing/checkout)", req_checkout_api, total_requests_per_test, concurrency)
    checkout_res.print_summary()

    # 6. Stripe Webhook Event Ingestion (/api/billing/webhook)
    webhook_payload = json.dumps({
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "customer": "cus_loadtest",
                "subscription": "sub_loadtest",
                "metadata": {
                    "org_id": str(org.id),
                    "plan": "pro"
                }
            }
        }
    })
    def req_webhook_api():
        client = Client()
        t0 = time.perf_counter()
        res = client.post(
            "/api/billing/webhook",
            data=webhook_payload,
            content_type="application/json"
        )
        t1 = time.perf_counter()
        return res.status_code, (t1 - t0)

    webhook_res = benchmark_endpoint("Stripe Webhook Ingestion (/api/billing/webhook)", req_webhook_api, total_requests_per_test, concurrency)
    webhook_res.print_summary()

    print("\n=======================================================")
    print("  ALL 6 LOAD BENCHMARKS COMPLETED SUCCESSFULLY")
    print("=======================================================\n")


if __name__ == "__main__":
    reqs = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    conc = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    run_full_load_test(reqs, conc)
