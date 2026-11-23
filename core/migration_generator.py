"""
Schema Guard Automated Schema Migration Generator.
Generates forward (UP) and rollback (DOWN) migration scripts across:
- Native SQL (PostgreSQL, MySQL, Snowflake, SQLite, BigQuery)
- Flyway Versioned Migrations (V & U files)
- Liquibase Changelogs (YAML and XML)
- Python Alembic (upgrade and downgrade functions)
"""

import datetime
import re
from typing import Dict, List, Any, Tuple


def normalize_sql_type(raw_type: str) -> str:
    """Normalize SQL type string for comparison."""
    if not raw_type:
        return ""
    t = str(raw_type).strip().lower()
    # Normalize synonyms
    t = re.sub(r'\s+', ' ', t)
    if t in ['int4', 'integer', 'int']:
        return 'integer'
    if t in ['int8', 'bigint']:
        return 'bigint'
    if t in ['int2', 'smallint']:
        return 'smallint'
    if t in ['bool', 'boolean']:
        return 'boolean'
    if t.startswith('varchar') or t.startswith('character varying'):
        return 'varchar' if '(' not in t else t
    if t in ['text', 'string']:
        return 'text'
    if t in ['float8', 'double precision', 'double']:
        return 'double precision'
    if t in ['float4', 'real', 'float']:
        return 'real'
    if t in ['decimal', 'numeric']:
        return 'numeric'
    if t.startswith('timestamp'):
        return 'timestamp'
    return t


def parse_contract_columns(contract_yaml: str) -> List[Dict[str, Any]]:
    """Extract list of column specs from contract YAML or string."""
    if not contract_yaml:
        return []
    import yaml
    try:
        data = yaml.safe_load(contract_yaml)
        if isinstance(data, dict):
            cols = data.get("columns", [])
            result = []
            for c in cols:
                if isinstance(c, dict) and "name" in c:
                    result.append({
                        "name": str(c["name"]).strip(),
                        "type": str(c.get("type", "varchar(255)")).strip(),
                        "nullable": bool(c.get("nullable", True)),
                        "pk": bool(c.get("pk", c.get("primary_key", False)))
                    })
            return result
    except Exception:
        pass
    return []


def extract_diffs_from_pipeline(pipeline) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Extract differences between expected contract and live database columns.
    Returns (diffs_list, meta_dict).
    """
    # 1. Try to read contract columns
    contract_cols = parse_contract_columns(getattr(pipeline, 'contract_yaml', ''))
    
    # 2. Try to read live columns from schema_map
    live_cols = []
    schema_map = getattr(pipeline, 'schema_map', {}) or {}
    if isinstance(schema_map, dict):
        if "right" in schema_map and isinstance(schema_map["right"], list):
            for c in schema_map["right"]:
                if isinstance(c, dict) and "name" in c:
                    live_cols.append({
                        "name": str(c["name"]).strip(),
                        "type": str(c.get("type", "varchar(255)")).strip(),
                        "nullable": bool(c.get("nullable", True)),
                        "pk": bool(c.get("pk", c.get("primary_key", False))),
                        "status": c.get("status", "clean")
                    })
        elif "left" in schema_map and isinstance(schema_map["left"], list):
            # Fallback if contract_yaml was empty
            if not contract_cols:
                for c in schema_map["left"]:
                    if isinstance(c, dict) and "name" in c:
                        contract_cols.append({
                            "name": str(c["name"]).strip(),
                            "type": str(c.get("type", "varchar(255)")).strip(),
                            "nullable": bool(c.get("nullable", True)),
                            "pk": bool(c.get("pk", c.get("primary_key", False)))
                        })

    contract_col_map = {c["name"].lower(): c for c in contract_cols}
    live_col_map = {c["name"].lower(): c for c in live_cols}

    diffs = []
    
    # Columns in contract but missing in live DB -> Need ADD COLUMN
    for key, c_col in contract_col_map.items():
        if key not in live_col_map:
            risk = "SAFE" if c_col.get("nullable", True) else "WARNING"
            diffs.append({
                "action": "add_column",
                "column": c_col["name"],
                "contract_type": c_col["type"],
                "live_type": None,
                "contract_nullable": c_col.get("nullable", True),
                "live_nullable": None,
                "risk": risk,
                "reason": f"Column '{c_col['name']}' defined in contract baseline is missing in live database.",
                "risk_description": "Adding nullable column is non-blocking." if risk == "SAFE" else "Adding NOT NULL column requires a default value or backfill."
            })
        else:
            l_col = live_col_map[key]
            # Check type mismatch
            c_norm = normalize_sql_type(c_col["type"])
            l_norm = normalize_sql_type(l_col["type"])
            if c_norm and l_norm and c_norm != l_norm:
                diffs.append({
                    "action": "alter_type",
                    "column": c_col["name"],
                    "contract_type": c_col["type"],
                    "live_type": l_col["type"],
                    "contract_nullable": c_col.get("nullable", True),
                    "live_nullable": l_col.get("nullable", True),
                    "risk": "WARNING",
                    "reason": f"Type mismatch: live database has '{l_col['type']}', but contract expects '{c_col['type']}'.",
                    "risk_description": "Type casting required. Validate potential truncation or casting exceptions."
                })
            # Check nullability mismatch
            if c_col.get("nullable") is not None and l_col.get("nullable") is not None:
                if c_col["nullable"] != l_col["nullable"]:
                    risk = "SAFE" if c_col["nullable"] else "BREAKING"
                    diffs.append({
                        "action": "alter_null",
                        "column": c_col["name"],
                        "contract_type": c_col["type"],
                        "live_type": l_col["type"],
                        "contract_nullable": c_col["nullable"],
                        "live_nullable": l_col["nullable"],
                        "risk": risk,
                        "reason": f"Nullability mismatch: live is {'NULLABLE' if l_col['nullable'] else 'NOT NULL'}, contract expects {'NULLABLE' if c_col['nullable'] else 'NOT NULL'}.",
                        "risk_description": "Relaxing constraint is safe." if risk == "SAFE" else "Setting NOT NULL on live table will fail if existing rows have NULLs."
                    })

    # Columns in live DB but not in contract -> Uncontracted / Extra column
    for key, l_col in live_col_map.items():
        if key not in contract_col_map:
            diffs.append({
                "action": "drop_column",
                "column": l_col["name"],
                "contract_type": None,
                "live_type": l_col["type"],
                "contract_nullable": None,
                "live_nullable": l_col.get("nullable", True),
                "risk": "BREAKING",
                "reason": f"Uncontracted column '{l_col['name']}' ({l_col['type']}) found in live database.",
                "risk_description": "Dropping a live column permanently deletes all data contained within it."
            })

    meta = {
        "pipeline_id": getattr(pipeline, 'id', ''),
        "pipeline_name": getattr(pipeline, 'name', ''),
        "schema": getattr(pipeline, 'schema', 'public') or 'public',
        "table": getattr(pipeline, 'table', 'table') or 'table',
        "db_type": (getattr(pipeline, 'db_type', 'postgres') or 'postgres').lower(),
        "contract_columns_count": len(contract_cols),
        "live_columns_count": len(live_cols)
    }

    return diffs, meta


def generate_sql_dialect_statements(diffs: List[Dict[str, Any]], db_type: str, schema: str, table: str) -> Tuple[List[str], List[str], List[str]]:
    """
    Generate UP and DOWN SQL statements for the specified database engine.
    Returns (up_statements, down_statements, warnings).
    """
    db_type = (db_type or "postgres").lower()
    tbl = f"{schema}.{table}" if schema and schema.lower() not in ['none', '', 'public'] and db_type in ['postgres', 'snowflake'] else table
    if db_type == "mysql":
        tbl = f"`{table}`"

    up_stmts = []
    down_stmts = []
    warnings = []

    for d in diffs:
        action = d["action"]
        col = d["column"]
        c_type = d.get("contract_type") or "VARCHAR(255)"
        l_type = d.get("live_type") or "VARCHAR(255)"
        c_null = d.get("contract_nullable", True)
        l_null = d.get("live_nullable", True)

        if action == "add_column":
            null_clause = "" if c_null else " NOT NULL DEFAULT ''"
            if not c_null:
                warnings.append(f"Column '{col}' is NOT NULL. A default value or backfill is advised before locking constraints.")

            if db_type == "postgres":
                up_stmts.append(f"ALTER TABLE {tbl} ADD COLUMN IF NOT EXISTS {col} {c_type}{null_clause};")
                down_stmts.append(f"ALTER TABLE {tbl} DROP COLUMN IF EXISTS {col};")
            elif db_type == "mysql":
                null_kw = "NULL" if c_null else "NOT NULL DEFAULT ''"
                up_stmts.append(f"ALTER TABLE {tbl} ADD COLUMN `{col}` {c_type} {null_kw};")
                down_stmts.append(f"ALTER TABLE {tbl} DROP COLUMN `{col}`;")
            elif db_type == "snowflake":
                up_stmts.append(f"ALTER TABLE {tbl} ADD COLUMN {col} {c_type};")
                down_stmts.append(f"ALTER TABLE {tbl} DROP COLUMN {col};")
            elif db_type == "bigquery":
                up_stmts.append(f"ALTER TABLE {tbl} ADD COLUMN {col} {c_type};")
                down_stmts.append(f"ALTER TABLE {tbl} DROP COLUMN {col};")
            else:  # sqlite
                up_stmts.append(f"ALTER TABLE {tbl} ADD COLUMN {col} {c_type};")
                down_stmts.append(f"-- SQLite DROP COLUMN: ALTER TABLE {tbl} DROP COLUMN {col}; (requires SQLite 3.35.0+)")

        elif action == "drop_column":
            warnings.append(f"DATA LOSS ALERT: Dropping column '{col}' will irreversibly delete existing data.")
            if db_type == "postgres":
                up_stmts.append(f"ALTER TABLE {tbl} DROP COLUMN IF EXISTS {col};")
                down_stmts.append(f"ALTER TABLE {tbl} ADD COLUMN IF NOT EXISTS {col} {l_type};")
            elif db_type == "mysql":
                up_stmts.append(f"ALTER TABLE {tbl} DROP COLUMN `{col}`;")
                down_stmts.append(f"ALTER TABLE {tbl} ADD COLUMN `{col}` {l_type};")
            elif db_type in ["snowflake", "bigquery"]:
                up_stmts.append(f"ALTER TABLE {tbl} DROP COLUMN {col};")
                down_stmts.append(f"ALTER TABLE {tbl} ADD COLUMN {col} {l_type};")
            else:  # sqlite
                up_stmts.append(f"ALTER TABLE {tbl} DROP COLUMN {col};")
                down_stmts.append(f"ALTER TABLE {tbl} ADD COLUMN {col} {l_type};")

        elif action == "alter_type":
            warnings.append(f"Type conversion on '{col}' from '{l_type}' to '{c_type}'. Validate value compatibility.")
            if db_type == "postgres":
                up_stmts.append(f"ALTER TABLE {tbl} ALTER COLUMN {col} TYPE {c_type} USING {col}::{c_type};")
                down_stmts.append(f"ALTER TABLE {tbl} ALTER COLUMN {col} TYPE {l_type} USING {col}::{l_type};")
            elif db_type == "mysql":
                null_kw = "NULL" if c_null else "NOT NULL"
                up_stmts.append(f"ALTER TABLE {tbl} MODIFY COLUMN `{col}` {c_type} {null_kw};")
                down_stmts.append(f"ALTER TABLE {tbl} MODIFY COLUMN `{col}` {l_type} {null_kw};")
            elif db_type == "snowflake":
                up_stmts.append(f"ALTER TABLE {tbl} ALTER COLUMN {col} SET DATA TYPE {c_type};")
                down_stmts.append(f"ALTER TABLE {tbl} ALTER COLUMN {col} SET DATA TYPE {l_type};")
            elif db_type == "bigquery":
                up_stmts.append(f"-- BigQuery does not support direct ALTER COLUMN TYPE. Recreate column or table.")
                down_stmts.append(f"-- Rollback requires recreation.")
            else:  # sqlite
                up_stmts.append(f"-- SQLite dynamic typing: column '{col}' accommodates '{c_type}'.")
                down_stmts.append(f"-- SQLite type revert for '{col}'.")

        elif action == "alter_null":
            if db_type == "postgres":
                clause_up = "DROP NOT NULL" if c_null else "SET NOT NULL"
                clause_down = "SET NOT NULL" if c_null else "DROP NOT NULL"
                up_stmts.append(f"ALTER TABLE {tbl} ALTER COLUMN {col} {clause_up};")
                down_stmts.append(f"ALTER TABLE {tbl} ALTER COLUMN {col} {clause_down};")
            elif db_type == "mysql":
                up_null = "NULL" if c_null else "NOT NULL"
                down_null = "NOT NULL" if c_null else "NULL"
                up_stmts.append(f"ALTER TABLE {tbl} MODIFY COLUMN `{col}` {c_type} {up_null};")
                down_stmts.append(f"ALTER TABLE {tbl} MODIFY COLUMN `{col}` {c_type} {down_null};")
            elif db_type == "snowflake":
                clause_up = "DROP NOT NULL" if c_null else "SET NOT NULL"
                clause_down = "SET NOT NULL" if c_null else "DROP NOT NULL"
                up_stmts.append(f"ALTER TABLE {tbl} ALTER COLUMN {col} {clause_up};")
                down_stmts.append(f"ALTER TABLE {tbl} ALTER COLUMN {col} {clause_down};")
            else:
                up_stmts.append(f"-- {db_type.upper()} nullability change for '{col}' to {'NULL' if c_null else 'NOT NULL'}.")
                down_stmts.append(f"-- Revert nullability for '{col}'.")

    return up_stmts, down_stmts, warnings


def generate_flyway_migrations(up_stmts: List[str], down_stmts: List[str], table: str) -> Tuple[str, str, str, str]:
    """Generates Flyway V and U files."""
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S")
    clean_table = re.sub(r'[^a-zA-Z0-9_]', '_', table)
    
    v_filename = f"V{ts}__{clean_table}_schema_alignment.sql"
    u_filename = f"U{ts}__{clean_table}_schema_alignment.sql"

    v_content = f"-- Flyway Versioned Migration: {v_filename}\n"
    v_content += f"-- Generated by Schema Guard on {datetime.datetime.now(datetime.timezone.utc).isoformat()}\n"
    v_content += "-- Target Table: " + table + "\n\n"
    v_content += "\n".join(up_stmts) if up_stmts else "-- No schema changes detected.\n"
    v_content += "\n"

    u_content = f"-- Flyway Undo Migration: {u_filename}\n"
    u_content += f"-- Generated by Schema Guard on {datetime.datetime.now(datetime.timezone.utc).isoformat()}\n"
    u_content += "-- Reverses: " + v_filename + "\n\n"
    u_content += "\n".join(down_stmts) if down_stmts else "-- No rollback changes required.\n"
    u_content += "\n"

    return v_filename, v_content, u_filename, u_content


def generate_liquibase_yaml(diffs: List[Dict[str, Any]], table: str) -> str:
    """Generates a Liquibase YAML changelog."""
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    clean_table = re.sub(r'[^a-zA-Z0-9_]', '_', table)

    yaml_out = "databaseChangeLog:\n"
    yaml_out += f"  - changeSet:\n"
    yaml_out += f"      id: align-{clean_table}-{ts}\n"
    yaml_out += f"      author: schema-guard\n"
    yaml_out += f"      comment: \"Auto-generated schema alignment for {table}\"\n"
    yaml_out += "      changes:\n"

    if not diffs:
        yaml_out += "        - empty: {}\n"
        return yaml_out

    rollback_lines = []

    for d in diffs:
        action = d["action"]
        col = d["column"]
        c_type = d.get("contract_type") or "varchar(255)"
        l_type = d.get("live_type") or "varchar(255)"

        if action == "add_column":
            yaml_out += f"        - addColumn:\n"
            yaml_out += f"            tableName: {table}\n"
            yaml_out += f"            columns:\n"
            yaml_out += f"              - column:\n"
            yaml_out += f"                  name: {col}\n"
            yaml_out += f"                  type: {c_type}\n"
            rollback_lines.append(f"        - dropColumn:\n            tableName: {table}\n            columnName: {col}")

        elif action == "drop_column":
            yaml_out += f"        - dropColumn:\n"
            yaml_out += f"            tableName: {table}\n"
            yaml_out += f"            columnName: {col}\n"
            rollback_lines.append(f"        - addColumn:\n            tableName: {table}\n            columns:\n              - column:\n                  name: {col}\n                  type: {l_type}")

        elif action == "alter_type":
            yaml_out += f"        - modifyDataType:\n"
            yaml_out += f"            tableName: {table}\n"
            yaml_out += f"            columnName: {col}\n"
            yaml_out += f"            newDataType: {c_type}\n"
            rollback_lines.append(f"        - modifyDataType:\n            tableName: {table}\n            columnName: {col}\n            newDataType: {l_type}")

    if rollback_lines:
        yaml_out += "      rollback:\n"
        for r in rollback_lines:
            yaml_out += f"{r}\n"

    return yaml_out


def generate_alembic_python(diffs: List[Dict[str, Any]], table: str) -> str:
    """Generates Python Alembic upgrade and downgrade functions."""
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y_%m_%d_%H%M")
    clean_table = re.sub(r'[^a-zA-Z0-9_]', '_', table)

    code = f'"""align_{clean_table}_{ts}\n\n'
    code += 'Revision ID: ' + ts + '\n'
    code += 'Revises: \n'
    code += 'Create Date: ' + datetime.datetime.now(datetime.timezone.utc).isoformat() + '\n'
    code += '"""\n'
    code += 'from alembic import op\n'
    code += 'import sqlalchemy as sa\n\n'
    code += '# revision identifiers, used by Alembic.\n'
    code += f'revision = "{ts}"\n'
    code += 'down_revision = None\n'
    code += 'branch_labels = None\n'
    code += 'depends_on = None\n\n\n'

    code += 'def upgrade() -> None:\n'
    if not diffs:
        code += '    pass\n\n'
    else:
        for d in diffs:
            action = d["action"]
            col = d["column"]
            raw_c_type = d.get("contract_type") or "VARCHAR(255)"
            c_null = d.get("contract_nullable", True)

            sa_type = "sa.Text()"
            if "int" in raw_c_type.lower():
                sa_type = "sa.Integer()"
            elif "numeric" in raw_c_type.lower() or "decimal" in raw_c_type.lower():
                sa_type = "sa.Numeric()"
            elif "bool" in raw_c_type.lower():
                sa_type = "sa.Boolean()"
            elif "timestamp" in raw_c_type.lower():
                sa_type = "sa.DateTime()"
            elif "varchar" in raw_c_type.lower():
                m = re.search(r'\d+', raw_c_type)
                length = m.group(0) if m else "255"
                sa_type = f"sa.String({length})"

            if action == "add_column":
                code += f"    op.add_column('{table}', sa.Column('{col}', {sa_type}, nullable={c_null}))\n"
            elif action == "drop_column":
                code += f"    op.drop_column('{table}', '{col}')\n"
            elif action == "alter_type":
                code += f"    op.alter_column('{table}', '{col}', type_={sa_type})\n"
            elif action == "alter_null":
                code += f"    op.alter_column('{table}', '{col}', nullable={c_null})\n"
        code += '\n\n'

    code += 'def downgrade() -> None:\n'
    if not diffs:
        code += '    pass\n'
    else:
        for d in diffs:
            action = d["action"]
            col = d["column"]
            raw_l_type = d.get("live_type") or "VARCHAR(255)"
            l_null = d.get("live_nullable", True)

            sa_type = "sa.Text()"
            if "int" in raw_l_type.lower():
                sa_type = "sa.Integer()"
            elif "numeric" in raw_l_type.lower() or "decimal" in raw_l_type.lower():
                sa_type = "sa.Numeric()"
            elif "bool" in raw_l_type.lower():
                sa_type = "sa.Boolean()"
            elif "timestamp" in raw_l_type.lower():
                sa_type = "sa.DateTime()"
            elif "varchar" in raw_l_type.lower():
                m = re.search(r'\d+', raw_l_type)
                length = m.group(0) if m else "255"
                sa_type = f"sa.String({length})"

            if action == "add_column":
                code += f"    op.drop_column('{table}', '{col}')\n"
            elif action == "drop_column":
                code += f"    op.add_column('{table}', sa.Column('{col}', {sa_type}, nullable={l_null}))\n"
            elif action == "alter_type":
                code += f"    op.alter_column('{table}', '{col}', type_={sa_type})\n"
            elif action == "alter_null":
                code += f"    op.alter_column('{table}', '{col}', nullable={l_null})\n"

    return code


def generate_migration_bundle(pipeline, target_engine: str = None) -> Dict[str, Any]:
    """
    High-level entry point: builds a comprehensive multi-dialect migration package
    for a given pipeline.
    """
    diffs, meta = extract_diffs_from_pipeline(pipeline)
    db_type = (target_engine or meta["db_type"] or "postgres").lower()
    schema = meta["schema"]
    table = meta["table"]

    # Calculate risk counts
    safe_count = sum(1 for d in diffs if d.get("risk") == "SAFE")
    warning_count = sum(1 for d in diffs if d.get("risk") == "WARNING")
    breaking_count = sum(1 for d in diffs if d.get("risk") == "BREAKING")

    up_stmts, down_stmts, warnings = generate_sql_dialect_statements(diffs, db_type, schema, table)
    
    sql_up = "\n".join(up_stmts) if up_stmts else "-- No schema changes needed. Database is fully aligned with contract."
    sql_down = "\n".join(down_stmts) if down_stmts else "-- No rollback changes needed."

    v_fn, v_content, u_fn, u_content = generate_flyway_migrations(up_stmts, down_stmts, table)
    liquibase_yaml = generate_liquibase_yaml(diffs, table)
    alembic_code = generate_alembic_python(diffs, table)

    return {
        "success": True,
        "pipeline_id": meta["pipeline_id"],
        "pipeline_name": meta["pipeline_name"],
        "schema": schema,
        "table": table,
        "db_type": db_type,
        "diff_count": len(diffs),
        "diffs": diffs,
        "risk_summary": {
            "safe": safe_count,
            "warning": warning_count,
            "breaking": breaking_count,
            "total": len(diffs)
        },
        "warnings": warnings,
        "sql": {
            "up": sql_up,
            "down": sql_down,
            "filename_up": f"{table}_align_up.sql",
            "filename_down": f"{table}_align_down.sql"
        },
        "flyway": {
            "versioned_filename": v_fn,
            "versioned_sql": v_content,
            "undo_filename": u_fn,
            "undo_sql": u_content
        },
        "liquibase": {
            "yaml": liquibase_yaml,
            "filename": f"db.changelog_{table}.yaml"
        },
        "alembic": {
            "python": alembic_code,
            "filename": f"alembic_migration_{table}.py"
        }
    }
