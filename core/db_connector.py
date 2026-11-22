"""
Universal Multi-Database Engine Connector Service
Supports:
  1. PostgreSQL (psycopg & psycopg2-binary)
  2. MySQL / MariaDB (pymysql)
  3. Snowflake (snowflake-sqlalchemy)
  4. Microsoft SQL Server (pymssql)
  5. Oracle Database (oracledb)
  6. Databricks Lakehouse (databricks-sqlalchemy & databricks-sql-connector)
"""

import logging
import re
from typing import List, Dict, Any, Tuple
from urllib.parse import urlparse, quote_plus
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine

logger = logging.getLogger(__name__)

# Try importing drivers to determine active capabilities
HAS_PSYCOPG = False
try:
    import psycopg
    HAS_PSYCOPG = True
except ImportError:
    pass

HAS_PSYCOPG2 = False
try:
    import psycopg2
    HAS_PSYCOPG2 = True
except ImportError:
    pass


def normalize_connection_url(db_type: str, conn_str: str) -> str:
    """
    Normalizes and canonicalizes database connection URLs with the correct driver dialect prefix.
    """
    if not isinstance(conn_str, str):
        return conn_str

    conn = conn_str.strip()
    db_clean = (db_type or "").lower().strip()

    # 1. PostgreSQL Normalization
    if db_clean in ("postgres", "postgresql") or conn.startswith(("postgres://", "postgresql://", "postgresql+")):
        if conn.startswith("postgres://"):
            conn = "postgresql://" + conn[len("postgres://"):]

        # Ensure correct driver is attached
        if conn.startswith("postgresql://"):
            if HAS_PSYCOPG:
                conn = "postgresql+psycopg://" + conn[len("postgresql://"):]
            elif HAS_PSYCOPG2:
                conn = "postgresql+psycopg2://" + conn[len("postgresql://"):]

    # 2. MySQL / MariaDB Normalization
    elif db_clean in ("mysql", "mariadb") or conn.startswith("mysql://"):
        if conn.startswith("mysql://"):
            conn = "mysql+pymysql://" + conn[len("mysql://"):]
        elif not conn.startswith("mysql+"):
            conn = "mysql+pymysql://" + conn

    # 3. Microsoft SQL Server Normalization
    elif db_clean in ("sqlserver", "mssql", "sql_server") or conn.startswith(("mssql://", "sqlserver://")):
        if conn.startswith("sqlserver://"):
            conn = "mssql+pymssql://" + conn[len("sqlserver://"):]
        elif conn.startswith("mssql://"):
            conn = "mssql+pymssql://" + conn[len("mssql://"):]
        elif not conn.startswith("mssql+"):
            conn = "mssql+pymssql://" + conn

    # 4. Oracle Database Normalization
    elif db_clean in ("oracle", "oracledb") or conn.startswith("oracle://"):
        if conn.startswith("oracle://"):
            conn = "oracle+oracledb://" + conn[len("oracle://"):]
        elif not conn.startswith("oracle+"):
            conn = "oracle+oracledb://" + conn

    # 5. Databricks Lakehouse Normalization
    elif db_clean in ("databricks", "lakehouse"):
        if not conn.startswith("databricks://"):
            conn = "databricks://" + conn

    return conn


def create_db_engine(db_type: str, conn_str: str, timeout: int = 8) -> Tuple[Engine, dict]:
    """
    Creates a configured SQLAlchemy Engine for the target database.
    """
    normalized_url = normalize_connection_url(db_type, conn_str)
    connect_args = {}

    db_clean = (db_type or "").lower().strip()

    # Apply database-specific connect_args
    if "postgres" in normalized_url or db_clean in ("postgres", "postgresql"):
        connect_args["connect_timeout"] = timeout
        # Special handling for Neon pooler DNS lookup on Windows
        try:
            from urllib.parse import urlparse
            import socket
            parsed_u = urlparse(normalized_url)
            h = parsed_u.hostname
            if h and ("neon.tech" in h or "aws" in h or "pooler" in h):
                resolved_ip = socket.gethostbyname(h)
                if resolved_ip:
                    connect_args["hostaddr"] = resolved_ip
        except Exception:
            pass

    elif "mysql" in normalized_url or db_clean in ("mysql", "mariadb"):
        connect_args["connect_timeout"] = timeout

    elif "mssql" in normalized_url or db_clean in ("sqlserver", "mssql"):
        connect_args["timeout"] = timeout
        connect_args["login_timeout"] = timeout

    elif "oracle" in normalized_url or db_clean in ("oracle", "oracledb"):
        connect_args["tcp_connect_timeout"] = float(timeout)

    engine = create_engine(
        normalized_url,
        connect_args=connect_args,
        pool_pre_ping=True,
        pool_recycle=300
    )
    return engine, connect_args


def test_db_connection(db_type: str, conn_str: str, timeout: int = 8) -> Tuple[bool, str]:
    """
    Executes a ping query to verify database connectivity and credentials.
    Returns (True, message) on success, (False, error_details) on failure.
    """
    engine = None
    try:
        engine, _ = create_db_engine(db_type, conn_str, timeout=timeout)
        
        db_clean = (db_type or "").lower().strip()
        ping_sql = "SELECT 1 FROM DUAL" if db_clean in ("oracle", "oracledb") else "SELECT 1"

        with engine.connect() as connection:
            res = connection.execute(text(ping_sql)).scalar()
            
        return True, f"Connection test succeeded. Server responded: {res}"
    except Exception as exc:
        logger.error(f"Database connection test failed for {db_type}: {exc}", exc_info=True)
        return False, str(exc)
    finally:
        if engine:
            try:
                engine.dispose()
            except Exception:
                pass


def get_db_schemas(db_type: str, conn_str: str) -> List[str]:
    """
    Retrieves all available schema names for the database.
    """
    engine = None
    try:
        engine, _ = create_db_engine(db_type, conn_str)
        inspector = inspect(engine)
        schemas = inspector.get_schema_names()
        return sorted([s for s in schemas if s])
    finally:
        if engine:
            try:
                engine.dispose()
            except Exception:
                pass


def get_db_tables(db_type: str, conn_str: str, schema_name: str = None) -> List[str]:
    """
    Retrieves all table and view names in the target schema.
    """
    engine = None
    try:
        engine, _ = create_db_engine(db_type, conn_str)
        inspector = inspect(engine)
        
        # Determine appropriate default schema if not provided
        effective_schema = schema_name
        if not effective_schema:
            db_clean = (db_type or "").lower().strip()
            if db_clean in ("postgres", "postgresql"):
                effective_schema = "public"
            elif db_clean in ("sqlserver", "mssql"):
                effective_schema = "dbo"

        tables = inspector.get_table_names(schema=effective_schema)
        try:
            views = inspector.get_view_names(schema=effective_schema)
            tables = list(set(tables + views))
        except Exception:
            pass

        return sorted(tables)
    finally:
        if engine:
            try:
                engine.dispose()
            except Exception:
                pass


def get_db_columns(db_type: str, conn_str: str, schema_name: str, table_name: str) -> Dict[str, Any]:
    """
    Retrieves column metadata for the table (name, type, nullable, primary_key).
    """
    engine = None
    try:
        engine, _ = create_db_engine(db_type, conn_str)
        inspector = inspect(engine)
        
        effective_schema = schema_name
        if not effective_schema:
            db_clean = (db_type or "").lower().strip()
            if db_clean in ("postgres", "postgresql"):
                effective_schema = "public"
            elif db_clean in ("sqlserver", "mssql"):
                effective_schema = "dbo"

        columns = inspector.get_columns(table_name, schema=effective_schema)
        
        pk_columns = []
        try:
            pk_info = inspector.get_pk_constraint(table_name, schema=effective_schema)
            pk_columns = pk_info.get("constrained_columns", [])
        except Exception:
            pass

        schema_res = {
            "table": f"{effective_schema}.{table_name}" if effective_schema else table_name,
            "columns": []
        }
        for col in columns:
            schema_res["columns"].append({
                "name": col["name"],
                "type": str(col["type"]),
                "nullable": col.get("nullable", True),
                "primary_key": col["name"] in pk_columns
            })

        return schema_res
    finally:
        if engine:
            try:
                engine.dispose()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Augment BaseExtractor to ensure get_tables, get_schemas, and normalized URLs
# ---------------------------------------------------------------------------
try:
    from schema_guard.extractors.base import BaseExtractor

    def _extractor_get_tables(self, connection_details, schema_name=None):
        db_type = self.__class__.__name__.lower().replace("extractor", "")
        return get_db_tables(db_type, connection_details, schema_name)

    def _extractor_get_schemas(self, connection_details):
        db_type = self.__class__.__name__.lower().replace("extractor", "")
        return get_db_schemas(db_type, connection_details)

    BaseExtractor.get_tables = _extractor_get_tables
    BaseExtractor.get_schemas = _extractor_get_schemas
except Exception as _patch_err:
    logger.warning(f"Could not monkey-patch schema_guard BaseExtractor: {_patch_err}")
