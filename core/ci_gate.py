"""
Schema Guard CI/CD Pipeline Gate Engine.
Provides automated schema contract gate verification for GitHub Actions,
GitLab CI, and CI/CD pipelines, including PR markdown comment generation
and ready-to-run workflow templates.
"""

from typing import Dict, List, Any, Tuple


def normalize_type_str(t: str) -> str:
    if not t:
        return ""
    return str(t).lower().replace(" ", "").replace("character varying", "varchar")


def evaluate_proposed_schema_against_contract(
    contract_cols: List[Dict[str, Any]],
    proposed_cols: List[Dict[str, Any]],
    policy: Dict[str, Any] = None
) -> Tuple[List[str], List[str]]:
    """
    Evaluates proposed columns against locked contract specification.
    Returns (violations, warnings).
    """
    policy = policy or {}
    allow_nullable_expansion = policy.get("allow_nullable_expansion", False)
    allow_type_widening = policy.get("allow_type_widening", False)

    violations = []
    warnings = []

    contract_map = {c["name"].lower(): c for c in contract_cols if isinstance(c, dict) and "name" in c}
    proposed_map = {c["name"].lower(): c for c in proposed_cols if isinstance(c, dict) and "name" in c}

    # 1. Missing columns: Defined in contract but omitted in proposed schema -> Critical violation
    for name, c_col in contract_map.items():
        if name not in proposed_map:
            violations.append(f"Missing column '{c_col['name']}': Defined in contract baseline as {c_col.get('type', 'ANY')}, but absent in proposed changes.")
            continue

        p_col = proposed_map[name]

        # 2. Nullability mismatch
        c_null = c_col.get("nullable", True)
        p_null = p_col.get("nullable", True)

        if c_null and not p_null:
            # Contract allowed NULL, proposed makes it NOT NULL
            violations.append(f"Breaking constraint on '{c_col['name']}': Contract allows NULL, but proposed schema enforces NOT NULL without guaranteed backfill.")
        elif not c_null and p_null:
            if not allow_nullable_expansion:
                warnings.append(f"Nullable expansion on '{c_col['name']}': Contract expects NOT NULL, proposed schema allows NULL.")

        # 3. Type compatibility
        c_type = normalize_type_str(c_col.get("type", ""))
        p_type = normalize_type_str(p_col.get("type", ""))

        if c_type and p_type and c_type != p_type:
            allowed = False
            for drift in c_col.get("allowed_drift", []):
                if normalize_type_str(drift.get("from")) == c_type and normalize_type_str(drift.get("to")) == p_type:
                    allowed = True
                    break

            if not allowed:
                # Type mismatch
                violations.append(f"Type mismatch on '{c_col['name']}': Contract baseline expects '{c_col.get('type')}', but proposed schema has '{p_col.get('type')}'.")

    # 4. Extra uncontracted columns
    for name, p_col in proposed_map.items():
        if name not in contract_map:
            p_null = p_col.get("nullable", True)
            if not p_null:
                warnings.append(f"New column '{p_col['name']}' ({p_col.get('type')}) is NOT NULL. Ensure a default value is provided so ingestion does not fail.")
            else:
                warnings.append(f"New column '{p_col['name']}' ({p_col.get('type')}) added (not in contract baseline).")

    return violations, warnings


def build_github_markdown_report(
    pipeline_name: str,
    table: str,
    schema: str,
    environment: str,
    status: str,
    violations: List[str],
    warnings: List[str],
    commit_sha: str = None,
    branch: str = None
) -> str:
    """
    Builds a formatted GitHub PR comment markdown table.
    """
    is_passed = (status == "PASSED")
    status_badge = "🟢 **PASSED**" if is_passed else "🔴 **BLOCKED**"
    headline = "All schema changes are backward-compatible with verified data contracts." if is_passed else f"Found {len(violations)} breaking schema contract violation(s)."

    md = f"## 🛡️ Schema Guard Gate Report\n\n"
    md += f"| Status | Pipeline | Table | Environment |\n"
    md += f"| :---: | :--- | :--- | :---: |\n"
    md += f"| {status_badge} | **{pipeline_name}** | `{schema}.{table}` | `{environment.upper()}` |\n\n"

    if commit_sha or branch:
        meta_parts = []
        if branch:
            meta_parts.append(f"**Branch**: `{branch}`")
        if commit_sha:
            meta_parts.append(f"**Commit**: `{commit_sha[:8]}`")
        md += " • ".join(meta_parts) + "\n\n"

    md += f"> {headline}\n\n"

    if violations:
        md += "### ❌ Breaking Violations (Deployment Blocked)\n\n"
        md += "| Severity | Column / Rule | Description |\n"
        md += "| :---: | :--- | :--- |\n"
        for v in violations:
            md += f"| 🔴 CRITICAL | Contract Compliance | {v} |\n"
        md += "\n"

    if warnings:
        md += "### ⚠️ Warnings & Advisories (Non-blocking)\n\n"
        md += "| Severity | Advisory | Description |\n"
        md += "| :---: | :--- | :--- |\n"
        for w in warnings:
            md += f"| 🟡 WARNING | Schema Drift | {w} |\n"
        md += "\n"

    md += "---\n"
    if not is_passed:
        md += "*Action Required*: Either adjust your migration DDL to prevent breaking contract consumers, or promote an updated data contract in the **Schema Guard Dashboard** before merging.\n"
    else:
        md += "*Gate Approval*: Safe to merge into target branch.\n"

    return md


def generate_ci_workflow_template(
    platform: str,
    base_url: str,
    pipeline_id: str,
    table_name: str
) -> Dict[str, str]:
    """
    Generates ready-to-commit CI workflow configuration files.
    """
    platform = (platform or "github").lower()
    base_url = (base_url or "https://schemaguard.onrender.com").rstrip("/")

    if platform == "github":
        filename = ".github/workflows/schema-guard.yml"
        content = f"""name: Schema Guard Contract Gate

on:
  pull_request:
    branches: [ main, master ]
  push:
    branches: [ main, master ]

jobs:
  schema-contract-check:
    name: Verify Data Contract Compliance
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run Schema Guard Gate Check
        id: schema_guard
        run: |
          echo "🔍 Querying Schema Guard Gate for table '{table_name}'..."
          
          RESPONSE=$(curl -s -X POST "{base_url}/api/ci/gate" \\
            -H "Content-Type: application/json" \\
            -H "X-Schema-Guard-Token: ${{{{ secrets.SCHEMA_GUARD_API_KEY }}}}" \\
            -d '{{
              "pipeline_id": "{pipeline_id}",
              "commit_sha": "${{{{ github.event.pull_request.head.sha || github.sha }}}}",
              "branch": "${{{{ github.head_ref || github.ref_name }}}}"
            }}')
          
          echo "$RESPONSE" > gate_response.json
          cat gate_response.json
          
          STATUS=$(jq -r '.status // "ERROR"' gate_response.json)
          EXIT_CODE=$(jq -r '.exit_code // 1' gate_response.json)
          
          echo "gate_status=$STATUS" >> $GITHUB_OUTPUT
          echo "exit_code=$EXIT_CODE" >> $GITHUB_OUTPUT

      - name: Post PR Comment
        if: github.event_name == 'pull_request' && always()
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            try {{
              const data = JSON.parse(fs.readFileSync('gate_response.json', 'utf8'));
              if (data.github_markdown) {{
                await github.rest.issues.createComment({{
                  issue_number: context.issue.number,
                  owner: context.repo.owner,
                  repo: context.repo.repo,
                  body: data.github_markdown
                }});
              }}
            }} catch (e) {{
              console.log("Could not post PR comment:", e);
            }}

      - name: Enforce Gate Result
        run: |
          EXIT_CODE=${{{{ steps.schema_guard.outputs.exit_code }}}}
          if [ "$EXIT_CODE" -ne "0" ]; then
            echo "❌ Schema Guard contract validation failed. Merging is blocked."
            exit 1
          fi
          echo "✅ Schema Guard contract gate passed successfully!"
"""

    elif platform == "gitlab":
        filename = ".gitlab-ci.yml"
        content = f"""# GitLab CI Schema Guard Gate
stages:
  - test

schema-contract-gate:
  stage: test
  image: curlimages/curl:latest
  only:
    - merge_requests
    - main
  script:
    - |
      RESPONSE=$(curl -s -X POST "{base_url}/api/ci/gate" \\
        -H "Content-Type: application/json" \\
        -H "X-Schema-Guard-Token: $SCHEMA_GUARD_API_KEY" \\
        -d '{{"pipeline_id": "{pipeline_id}", "commit_sha": "$CI_COMMIT_SHA", "branch": "$CI_COMMIT_REF_NAME"}}')
      echo "$RESPONSE"
      EXIT_CODE=$(echo "$RESPONSE" | grep -o '"exit_code":[0-9]*' | cut -d':' -f2)
      if [ "$EXIT_CODE" != "0" ]; then
        echo "❌ Schema Guard Gate failed: Breaking contract changes detected."
        exit 1
      fi
      echo "✅ Schema Guard Gate passed."
"""

    else:  # Bash / cURL
        filename = "schema_guard_gate.sh"
        content = f"""#!/usr/bin/env bash
# Schema Guard CI/CD Gate Verification Script
set -e

SCHEMA_GUARD_TOKEN="${{SCHEMA_GUARD_API_KEY:-$1}}"
if [ -z "$SCHEMA_GUARD_TOKEN" ]; then
  echo "Error: SCHEMA_GUARD_API_KEY environment variable or argument required."
  exit 1
fi

echo "Verifying schema contract for '{table_name}' on {base_url}..."
RESPONSE=$(curl -s -X POST "{base_url}/api/ci/gate" \\
  -H "Content-Type: application/json" \\
  -H "X-Schema-Guard-Token: $SCHEMA_GUARD_TOKEN" \\
  -d '{{"pipeline_id": "{pipeline_id}"}}')

echo "$RESPONSE"
EXIT_CODE=$(echo "$RESPONSE" | grep -o '"exit_code":[0-9]*' | cut -d':' -f2)

if [ "$EXIT_CODE" != "0" ]; then
  echo "❌ Schema Guard: Breaking changes detected. Gate BLOCKED."
  exit 1
else
  echo "✅ Schema Guard: All contract requirements PASSED."
  exit 0
fi
"""

    return {
        "platform": platform,
        "filename": filename,
        "content": content
    }
