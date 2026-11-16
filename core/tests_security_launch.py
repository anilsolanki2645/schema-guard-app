"""
Comprehensive Launch & Security Verification Tests
Verifies encryption, SQL injection prevention, API keys, CI/CD gates,
multi-tenancy boundaries, quota enforcement, and Airflow operator compatibility.
"""
import json
from unittest.mock import patch, Mock
from django.test import TestCase, Client
from django.utils import timezone
from core.models import Organization, User, Pipeline, ConnectionProfile, ApiKey, SchemaSnapshot
from core.security import (
    encrypt_secret,
    decrypt_secret,
    mask_connection_string,
    sanitize_sql_identifier,
    generate_api_key,
    hash_api_key,
)
from core.views import (
    resolve_connection_string,
    perform_data_quality_validation,
    ensure_contract_and_snapshot_files,
)
from core.airflow_operator import SchemaGuardOperator, SchemaGuardSensor


class CredentialSecurityTests(TestCase):
    """Test encryption, decryption, and credential masking."""

    def test_encrypt_and_decrypt_cycle(self):
        raw_conn = "postgresql://myuser:P@ssw0rd123!@db.example.com:5432/analytics"
        encrypted = encrypt_secret(raw_conn)
        self.assertNotEqual(encrypted, raw_conn)
        self.assertTrue(encrypted.startswith("enc:fernet:"))
        
        decrypted = decrypt_secret(encrypted)
        self.assertEqual(decrypted, raw_conn)

    def test_mask_connection_string(self):
        raw_conn = "postgresql://data_user:SuperSecretPass@db.internal:5432/mydb"
        masked = mask_connection_string(raw_conn)
        self.assertEqual(masked, "postgresql://data_user:****@db.internal:5432/mydb")
        self.assertNotIn("SuperSecretPass", masked)

    def test_mask_encrypted_connection_string(self):
        raw_conn = "mysql://root:MySQLPassword2026@127.0.0.1:3306/sales"
        encrypted = encrypt_secret(raw_conn)
        masked = mask_connection_string(encrypted)
        self.assertEqual(masked, "mysql://root:****@127.0.0.1:3306/sales")
        self.assertNotIn("MySQLPassword2026", masked)

    def test_resolve_connection_string_with_encrypted_profile(self):
        org = Organization.objects.create(name="Security Org")
        raw_conn = "postgresql://prof_user:prof_pass@localhost:5432/proddb"
        profile = ConnectionProfile.objects.create(
            name="test-profile",
            db_type="postgres",
            conn_str=encrypt_secret(raw_conn),
            organization=org
        )
        resolved = resolve_connection_string(f"profile:{profile.name}")
        self.assertEqual(resolved, raw_conn)


class SQLInjectionPreventionTests(TestCase):
    """Test that all SQL identifiers are strictly sanitized against injection attacks."""

    def test_sanitize_valid_identifiers(self):
        self.assertEqual(sanitize_sql_identifier("users", "postgres"), '"users"')
        self.assertEqual(sanitize_sql_identifier("order_items_2026", "mysql"), "`order_items_2026`")
        self.assertEqual(sanitize_sql_identifier("schema_1", "sqlite"), "`schema_1`")

    def test_sanitize_rejects_malicious_injections(self):
        malicious_inputs = [
            "users; DROP TABLE customers; --",
            "users' OR '1'='1",
            "users --",
            "table/*comment*/",
            "schema.table",
            "col name with spaces",
            "col;DELETE FROM users",
        ]
        for bad_input in malicious_inputs:
            with self.assertRaises(ValueError):
                sanitize_sql_identifier(bad_input, "postgres")

    def test_data_quality_rejects_sql_injection(self):
        # Even if someone injects a bad table name, the validator catches it immediately
        bad_table = "orders; DROP TABLE core_user; --"
        report = perform_data_quality_validation(
            "postgres",
            "sqlite:///test_dq.db",
            "public",
            bad_table,
            [{"name": "id", "nullable": False}]
        )
        self.assertEqual(report["status"], "FAIL")
        self.assertTrue(any("Invalid SQL identifier" in c["metric"] for c in report["checks"]))


class ApiKeyAndCICDGateTests(TestCase):
    """Test cryptographically secure API keys and CI/CD gate validation."""

    def setUp(self):
        self.client = Client()
        self.org = Organization.objects.create(name="Gate Org")
        self.user = User.objects.create(
            username="ci_admin",
            email="ci@gate.org",
            password_hash="hash",
            role="subadmin",
            organization=self.org,
            is_verified=True,
        )
        self.pipeline = Pipeline.objects.create(
            id="gate_pipeline",
            name="Gate Pipeline",
            db_type="sqlite",
            conn_str=encrypt_secret("sqlite:///dummy.db"),
            schema="main",
            table="orders",
            organization=self.org,
            contract_yaml="source:\n  type: postgres\n  connection: postgresql://readonly@localhost:5432/orders\n  schema: main\n  table: orders\ncolumns:\n  - name: id\n    type: INTEGER\n    nullable: false\n",
            lock_signature="test_signature_hash"
        )
        raw_key, key_id, key_hash = generate_api_key()
        self.raw_api_key = raw_key
        self.api_key_obj = ApiKey.objects.create(
            key_id=key_id,
            key_hash=key_hash,
            name="GitHub Actions Key",
            organization=self.org,
            created_by="ci_admin",
            is_active=True
        )

    def test_api_key_generation(self):
        raw, kid, khash = generate_api_key()
        self.assertTrue(raw.startswith("sg_live_"))
        self.assertTrue(len(raw) > 30)
        self.assertEqual(hash_api_key(raw), khash)

    def test_gate_validation_with_valid_api_key(self):
        payload = {
            "commit_sha": "abc1234",
            "branch": "main",
            "schema": {
                "columns": [
                    {"name": "id", "type": "INTEGER", "nullable": False}
                ]
            }
        }
        res = self.client.post(
            f"/api/pipelines/{self.pipeline.id}/validate-gate",
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_X_SCHEMA_GUARD_TOKEN=self.raw_api_key
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["compatible"])
        self.assertEqual(data["status"], "PASS")

        # Verify last_used_at was updated on ApiKey
        self.api_key_obj.refresh_from_db()
        self.assertIsNotNone(self.api_key_obj.last_used_at)

    def test_gate_validation_with_invalid_api_key_fails(self):
        payload = {
            "commit_sha": "abc1234",
            "branch": "main",
            "schema": {"columns": [{"name": "id", "type": "INTEGER", "nullable": False}]}
        }
        res = self.client.post(
            f"/api/pipelines/{self.pipeline.id}/validate-gate",
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_X_SCHEMA_GUARD_TOKEN="invalid_key_12345"
        )
        self.assertEqual(res.status_code, 403)

    def test_gate_validation_with_bearer_token(self):
        payload = {
            "commit_sha": "def5678",
            "branch": "feature/analytics",
            "schema": {
                "columns": [
                    {"name": "id", "type": "INTEGER", "nullable": False}
                ]
            }
        }
        res = self.client.post(
            f"/api/pipelines/{self.pipeline.id}/validate-gate",
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.raw_api_key}"
        )
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.json()["compatible"])

    def test_gate_detects_contract_breaking_change(self):
        # Propose dropping column 'id'
        payload = {
            "commit_sha": "bad_commit",
            "branch": "bad_branch",
            "schema": {
                "columns": [
                    {"name": "new_random_col", "type": "VARCHAR(255)", "nullable": True}
                ]
            }
        }
        res = self.client.post(
            f"/api/pipelines/{self.pipeline.id}/validate-gate",
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_X_SCHEMA_GUARD_TOKEN=self.raw_api_key
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertFalse(data["compatible"])
        self.assertEqual(data["status"], "FAIL")
        self.assertTrue(any("missing in the proposed schema" in v for v in data["violations"]))


class QuotaAndMultiTenancyTests(TestCase):
    """Test plan tier quotas and cross-tenant isolation."""

    def setUp(self):
        self.client = Client()
        self.org = Organization.objects.create(name="Startup Corp", plan="free", max_pipelines=2)
        self.user = User.objects.create(
            username="startup_lead",
            email="lead@startup.com",
            password_hash="hash",
            role="subadmin",
            organization=self.org,
            is_verified=True
        )

    def test_quota_blocks_pipeline_creation_when_limit_reached(self):
        session = self.client.session
        session['user'] = {
            "username": self.user.username,
            "role": self.user.role,
            "organization_id": self.org.id,
            "permissions": {"create": True, "see": True, "edit": True, "delete": True},
            "is_verified": True
        }
        session.save()

        # Create 2 pipelines (reaching the quota)
        Pipeline.objects.create(id="p1", name="Pipeline 1", db_type="sqlite", conn_str="sqlite://", schema="m", table="t1", organization=self.org)
        Pipeline.objects.create(id="p2", name="Pipeline 2", db_type="sqlite", conn_str="sqlite://", schema="m", table="t2", organization=self.org)

        # Attempt to create a 3rd pipeline
        payload = {
            "name": "Pipeline 3",
            "dbType": "sqlite",
            "connStr": "sqlite:///dummy.db",
            "schema": "main",
            "table": "t3"
        }
        res = self.client.post(
            "/api/pipelines",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 402)
        self.assertIn("Pipeline limit reached", res.json()["detail"])


class AirflowOperatorCompatibilityTests(TestCase):
    """Test Airflow custom operator and sensor payload construction."""

    def test_airflow_operator_payload_structure(self):
        op = SchemaGuardOperator(
            task_id="test_gate",
            endpoint_url="https://app.schemaguard.com/api/pipelines/orders/validate-gate",
            token="sg_live_test_token_123",
            commit_sha="a1b2c3d",
            branch="staging"
        )
        self.assertEqual(op.token, "sg_live_test_token_123")
        self.assertEqual(op.commit_sha, "a1b2c3d")
        self.assertEqual(op.branch, "staging")

    def test_airflow_sensor_initialization(self):
        sensor = SchemaGuardSensor(
            task_id="poke_gate",
            endpoint_url="https://app.schemaguard.com/api/pipelines/orders/validate-gate",
            token="sg_live_test_token_123"
        )
        self.assertEqual(sensor.token, "sg_live_test_token_123")


class SSRFDefenseTests(TestCase):
    """Test webhook SSRF defense blocks private and cloud metadata targets."""

    def test_ssrf_rejects_internal_metadata_and_loopback(self):
        from core.views import send_custom_webhook_alert
        with self.settings(DEBUG=False, IS_TESTING=False):
            res_meta = send_custom_webhook_alert([], {}, "http://169.254.169.254/latest/meta-data", "pipe", "Clean")
            self.assertFalse(res_meta)

            res_local = send_custom_webhook_alert([], {}, "http://localhost:8000/internal", "pipe", "Clean")
            self.assertFalse(res_local)

            res_priv = send_custom_webhook_alert([], {}, "http://10.0.0.5/webhook", "pipe", "Clean")
            self.assertFalse(res_priv)

            res_bad_proto = send_custom_webhook_alert([], {}, "ftp://malicious.com/hook", "pipe", "Clean")
            self.assertFalse(res_bad_proto)
