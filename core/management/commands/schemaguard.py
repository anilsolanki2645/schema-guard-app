"""
Schema Guard Enterprise Autonomous CLI (schemaguard)
Provides an enterprise command-line interface for:
  - check: Run contract drift checks on pipelines or contracts
  - lock: Generate and verify cryptographic SHA256 contract lock signatures
  - diff: Output structural differences between contract baseline and live catalogs
  - impact: Analyze DDL statement table lock severity and zero-downtime migration recipes
  - gate: CI/CD deployment blocker exiting with code 0 (clean) or code 1 (breaking drift)
"""

import sys
import json
from django.core.management.base import BaseCommand
from core.models import Pipeline
from core.views import analyze_ddl_lock_impact


class Command(BaseCommand):
    help = "Schema Guard Autonomous CLI - Gatekeeper, Lock Verifier, and DDL Risk Engine"

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(dest="subcommand", help="Schema Guard Action")

        # 1. check
        check_p = subparsers.add_parser("check", help="Verify pipeline contract drift against live database")
        check_p.add_argument("--pipeline", "-p", help="Pipeline ID to verify", required=True)
        check_p.add_argument("--json", action="store_true", help="Output results in JSON format")

        # 2. lock
        lock_p = subparsers.add_parser("lock", help="Compute cryptographic lock signature for contract baseline")
        lock_p.add_argument("--pipeline", "-p", help="Pipeline ID to lock", required=True)
        lock_p.add_argument("--json", action="store_true", help="Output results in JSON format")

        # 3. diff
        diff_p = subparsers.add_parser("diff", help="Display structural column differences")
        diff_p.add_argument("--pipeline", "-p", help="Pipeline ID to inspect", required=True)
        diff_p.add_argument("--json", action="store_true", help="Output results in JSON format")

        # 4. impact
        impact_p = subparsers.add_parser("impact", help="Assess DDL table lock duration, rewrites, and safe recipes")
        impact_p.add_argument("--ddl", help="DDL statements separated by semicolons")
        impact_p.add_argument("--dialect", default="postgres", help="Database dialect (postgres, mysql, snowflake, sqlite)")
        impact_p.add_argument("--rows", type=int, default=100000, help="Estimated target table row count")
        impact_p.add_argument("--json", action="store_true", help="Output results in JSON format")

        # 5. gate
        gate_p = subparsers.add_parser("gate", help="CI/CD blocking gate (exits with 1 on breaking drift)")
        gate_p.add_argument("--pipeline", "-p", help="Pipeline ID to gate check", required=True)
        gate_p.add_argument("--strict", action="store_true", help="Treat any drift or warnings as breaking")
        gate_p.add_argument("--json", action="store_true", help="Output results in JSON format")

    def handle(self, *args, **options):
        subcmd = options.get("subcommand")
        if not subcmd:
            self.stdout.write(self.style.ERROR("Error: Subcommand required. Choose from: check, lock, diff, impact, gate."))
            sys.exit(1)

        is_json = options.get("json", False)

        if subcmd == "check":
            self.handle_check(options, is_json)
        elif subcmd == "lock":
            self.handle_lock(options, is_json)
        elif subcmd == "diff":
            self.handle_diff(options, is_json)
        elif subcmd == "impact":
            self.handle_impact(options, is_json)
        elif subcmd == "gate":
            self.handle_gate(options, is_json)

    def handle_check(self, options, is_json):
        pipe_id = options.get("pipeline")
        p = Pipeline.objects.filter(id=pipe_id).first()
        if not p:
            self.stdout.write(self.style.ERROR(f"Pipeline '{pipe_id}' not found."))
            sys.exit(1)

        from core.views import perform_pipeline_check
        result = perform_pipeline_check(p.id)
        if is_json:
            self.stdout.write(json.dumps(result, indent=2))
        else:
            status = result.get("status", "Unknown")
            violations = result.get("violations", [])
            color = self.style.SUCCESS if status == "Clean" else self.style.WARNING
            self.stdout.write(color(f"Pipeline {pipe_id} Check Result: {status}"))
            self.stdout.write(f"Violations Detected: {len(violations)}")
            for v in violations:
                if isinstance(v, dict):
                    msg = v.get('message') or v.get('description') or str(v)
                    v_type = v.get('type', 'DRIFT')
                    col = v.get('column', '-')
                    self.stdout.write(f"  - [{v_type}] {col}: {msg}")
                else:
                    self.stdout.write(f"  - {v}")

    def handle_lock(self, options, is_json):
        pipe_id = options.get("pipeline")
        p = Pipeline.objects.filter(id=pipe_id).first()
        if not p:
            self.stdout.write(self.style.ERROR(f"Pipeline '{pipe_id}' not found."))
            sys.exit(1)

        import hashlib
        content = p.contract_yaml or json.dumps(p.schema_map)
        sig = f"sha256:{hashlib.sha256(content.encode('utf-8')).hexdigest()}"
        p.lock_signature = sig
        p.save(update_fields=['lock_signature'])

        res = {"pipeline_id": pipe_id, "lock_signature": sig, "status": "LOCKED"}
        if is_json:
            self.stdout.write(json.dumps(res, indent=2))
        else:
            self.stdout.write(self.style.SUCCESS(f"Successfully locked contract for '{pipe_id}'."))
            self.stdout.write(f"Signature: {sig}")

    def handle_diff(self, options, is_json):
        pipe_id = options.get("pipeline")
        p = Pipeline.objects.filter(id=pipe_id).first()
        if not p:
            self.stdout.write(self.style.ERROR(f"Pipeline '{pipe_id}' not found."))
            sys.exit(1)

        schema_map = p.schema_map or {}
        left_cols = schema_map.get("left", [])
        right_cols = schema_map.get("right", [])

        res = {
            "pipeline_id": pipe_id,
            "target_table": p.table,
            "baseline_columns_count": len(left_cols),
            "live_columns_count": len(right_cols),
            "schema_map": schema_map
        }
        if is_json:
            self.stdout.write(json.dumps(res, indent=2))
        else:
            self.stdout.write(self.style.MIGRATE_HEADING(f"Schema Structure for '{pipe_id}' ({p.table}):"))
            self.stdout.write(f"  Baseline Columns: {len(left_cols)} | Live Columns: {len(right_cols)}")
            for col in right_cols:
                name = col.get("name", "-")
                c_type = col.get("type", "-")
                status = col.get("status", "clean")
                pk = " [PK]" if col.get("pk") else ""
                null = "NULL" if col.get("nullable", True) else "NOT NULL"
                tag = f"[{status.upper()}]" if status != "clean" else "[OK]"
                self.stdout.write(f"  {tag:8} {name:20} {c_type:15} {null:10}{pk}")

    def handle_impact(self, options, is_json):
        ddl = options.get("ddl") or "ALTER TABLE users ADD COLUMN age integer;"
        dialect = options.get("dialect", "postgres")
        rows = options.get("rows", 100000)

        statements = [s.strip() for s in ddl.split(";") if s.strip()]
        impact = analyze_ddl_lock_impact(statements, dialect, row_count=rows)

        if is_json:
            self.stdout.write(json.dumps(impact, indent=2))
        else:
            self.stdout.write(self.style.MIGRATE_HEADING(f"DDL Lock Risk & Table Rewrite Assessment ({dialect.upper()}):"))
            self.stdout.write(f"  Overall Risk: {impact['overall_risk']}")
            self.stdout.write(f"  Safe Window: {impact['safe_deployment_window']}")
            self.stdout.write(f"  Table Rewrite Required: {impact['table_rewrite_required']}")
            self.stdout.write(f"  Max Lock Duration: {impact['max_lock_duration']}")
            for st in impact["analyzed_statements"]:
                self.stdout.write(f"\n  Statement: {st['statement']}")
                self.stdout.write(f"    Lock Level: {st['lock_level']} | Duration: {st['estimated_lock_duration']}")
                self.stdout.write(f"    Recommended Recipe: {st['recommended_recipe']}")

    def handle_gate(self, options, is_json):
        pipe_id = options.get("pipeline")
        strict = options.get("strict", False)
        p = Pipeline.objects.filter(id=pipe_id).first()
        if not p:
            self.stdout.write(self.style.ERROR(f"Pipeline '{pipe_id}' not found."))
            sys.exit(1)

        from core.views import perform_pipeline_check
        result = perform_pipeline_check(p.id)
        status = result.get("status", "Unknown")
        violations = result.get("violations", [])
        dq_report = result.get("dataQuality", {})

        has_breaking = False
        breaking_count = 0
        for v in violations:
            v_str = json.dumps(v).upper() if isinstance(v, dict) else str(v).upper()
            if any(kw in v_str for kw in ["DROPPED", "MISSING", "BREAKING", "INCOMPATIBLE", "TYPE CHANGED", "NOT NULL"]):
                has_breaking = True
                breaking_count += 1

        if dq_report.get("status") == "FAIL":
            has_breaking = True
            breaking_count += 1

        if status in ("Failed", "Error"):
            has_breaking = True

        passed = (status == "Clean") if strict else (not has_breaking)

        output = {
            "pipeline_id": pipe_id,
            "gate_passed": passed,
            "strict_mode": strict,
            "status": status,
            "breaking_drift_count": breaking_count,
            "total_violations": len(violations)
        }

        if is_json:
            self.stdout.write(json.dumps(output, indent=2))
        else:
            if passed:
                self.stdout.write(self.style.SUCCESS(f"CI/CD GATE PASSED: Pipeline '{pipe_id}' has no breaking drift."))
            else:
                self.stdout.write(self.style.ERROR(f"CI/CD GATE BLOCKED: Breaking schema drift detected in '{pipe_id}'! ({breaking_count} breaking issues)"))

        if not passed:
            sys.exit(1)
