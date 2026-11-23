"""
Schema Guard – Comprehensive Test Suite
Tests for models, views, API endpoints, authentication, and permission boundaries.
"""
import json
from django.test import TestCase, Client
from django.urls import reverse
from core.models import Organization, User, Pipeline, AuditLog, SchemaSnapshot, ContractVersion, ApiKey
from core.views import hash_password, verify_password, generate_code
from core.security import hash_api_key
from unittest.mock import patch, Mock, MagicMock


class PasswordHashingTests(TestCase):
    """Test password hashing and verification utilities."""

    def test_hash_password_returns_hash(self):
        hashed = hash_password("test_password")
        self.assertIsInstance(hashed, str)
        self.assertNotEqual(hashed, "test_password")
        self.assertTrue(len(hashed) > 20)

    def test_verify_password_correct(self):
        hashed = hash_password("secure123")
        self.assertTrue(verify_password("secure123", hashed))

    def test_verify_password_incorrect(self):
        hashed = hash_password("secure123")
        self.assertFalse(verify_password("wrong_password", hashed))

    def test_verify_password_with_invalid_hash(self):
        self.assertFalse(verify_password("test", "invalid_hash_string"))

    def test_generate_code_length(self):
        code = generate_code()
        self.assertEqual(len(code), 6)
        self.assertTrue(code.isdigit())


class OrganizationModelTests(TestCase):
    """Test Organization model."""

    def test_create_organization(self):
        org = Organization.objects.create(name="Test Corp")
        self.assertEqual(str(org), "Test Corp")
        self.assertIsNotNone(org.created_at)

    def test_unique_organization_name(self):
        Organization.objects.create(name="Unique Corp")
        with self.assertRaises(Exception):
            Organization.objects.create(name="Unique Corp")


class UserModelTests(TestCase):
    """Test User model."""

    def setUp(self):
        self.org = Organization.objects.create(name="Test Org")

    def test_create_user(self):
        user = User.objects.create(
            username="testuser",
            email="test@example.com",
            password_hash=hash_password("password123"),
            role="operator",
            permissions={"see": True, "create": False, "edit": False, "delete": False},
            organization=self.org,
        )
        self.assertEqual(str(user), "testuser")
        self.assertFalse(user.is_verified)

    def test_unique_username(self):
        User.objects.create(
            username="unique_user",
            email="a@test.com",
            password_hash=hash_password("pass"),
        )
        with self.assertRaises(Exception):
            User.objects.create(
                username="unique_user",
                email="b@test.com",
                password_hash=hash_password("pass"),
            )

    def test_unique_email(self):
        User.objects.create(
            username="user1",
            email="same@test.com",
            password_hash=hash_password("pass"),
        )
        with self.assertRaises(Exception):
            User.objects.create(
                username="user2",
                email="same@test.com",
                password_hash=hash_password("pass"),
            )


class PipelineModelTests(TestCase):
    """Test Pipeline model."""

    def setUp(self):
        self.org = Organization.objects.create(name="Pipeline Org")

    def test_create_pipeline(self):
        pipe = Pipeline.objects.create(
            id="test_pipeline",
            name="Test Pipeline",
            db_type="postgres",
            conn_str="postgresql://user:pass@localhost/db",
            schema="public",
            table="orders",
            organization=self.org,
        )
        self.assertEqual(str(pipe), "Test Pipeline")
        self.assertEqual(pipe.status, "Clean")
        self.assertEqual(pipe.cron, "0 0 * * *")


class AuditLogModelTests(TestCase):
    """Test AuditLog model."""

    def test_create_audit_log(self):
        log = AuditLog.objects.create(
            action="user.login",
            actor="admin",
            target_type="user",
            target_id="admin",
            details={"method": "password"},
        )
        self.assertIn("admin", str(log))
        self.assertIsNotNone(log.timestamp)

    def test_audit_log_ordering(self):
        AuditLog.objects.create(action="user.login", actor="user1")
        AuditLog.objects.create(action="user.logout", actor="user2")
        logs = AuditLog.objects.all()
        self.assertEqual(logs[0].actor, "user2")  # Most recent first


class AuthFlowTests(TestCase):
    """Test authentication views and flows."""

    def setUp(self):
        self.client = Client()
        self.org = Organization.objects.create(name="Auth Test Org")
        self.user = User.objects.create(
            username="authuser",
            email="auth@test.com",
            password_hash=hash_password("AuthPass123!"),
            role="subadmin",
            permissions={"see": True, "create": True, "edit": True, "delete": True},
            organization=self.org,
            is_verified=True,
        )

    def test_login_page_renders(self):
        response = self.client.get(reverse('login_page'))
        self.assertEqual(response.status_code, 200)

    def test_login_with_correct_credentials(self):
        response = self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'authuser',
            'password': 'AuthPass123!',
        })
        self.assertEqual(response.status_code, 302)  # Redirect to dashboard
        self.assertIn('user', self.client.session)

    def test_login_with_wrong_password(self):
        response = self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'authuser',
            'password': 'WrongPassword',
        })
        self.assertEqual(response.status_code, 200)  # Renders login with error
        self.assertNotIn('user', self.client.session)

    def test_login_redirects_authenticated_user(self):
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'authuser',
            'password': 'AuthPass123!',
        })
        response = self.client.get(reverse('login_page'))
        self.assertEqual(response.status_code, 302)  # Redirects to dashboard

    def test_logout_clears_session(self):
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'authuser',
            'password': 'AuthPass123!',
        })
        response = self.client.get(reverse('logout'))
        self.assertEqual(response.status_code, 302)
        self.assertNotIn('user', self.client.session)

    def test_register_with_missing_fields(self):
        response = self.client.post(reverse('login_or_register'), {
            'action': 'register',
            'username': '',
            'password': 'SomePass',
        })
        self.assertEqual(response.status_code, 200)

    def test_register_duplicate_username(self):
        response = self.client.post(reverse('login_or_register'), {
            'action': 'register',
            'username': 'authuser',
            'password': 'SomePass',
            'email': 'new@test.com',
        })
        self.assertEqual(response.status_code, 200)  # Re-renders with error


class ProtectedViewTests(TestCase):
    """Test that protected views require authentication."""

    def setUp(self):
        self.client = Client()

    def test_dashboard_requires_login(self):
        response = self.client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 302)  # Redirect to login

    def test_builder_requires_login(self):
        response = self.client.get(reverse('builder'))
        self.assertEqual(response.status_code, 302)

    def test_admin_requires_login(self):
        response = self.client.get(reverse('admin_panel'))
        self.assertEqual(response.status_code, 302)

    def test_troubleshooting_requires_login(self):
        response = self.client.get(reverse('troubleshooting'))
        self.assertEqual(response.status_code, 302)


class HealthCheckTests(TestCase):
    """Test health check endpoint."""

    def test_health_check_returns_200(self):
        response = self.client.get(reverse('health_check'))
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data['status'], 'healthy')
        self.assertIn('database', data)
        self.assertIn('version', data)
        self.assertIn('timestamp', data)


class PipelineAPIPermissionTests(TestCase):
    """Test pipeline API permission boundaries."""

    def setUp(self):
        self.client = Client()
        self.org = Organization.objects.create(name="API Test Org")
        
        # Create verified subadmin
        self.admin_user = User.objects.create(
            username="apiadmin",
            email="apiadmin@test.com",
            password_hash=hash_password("Admin123!"),
            role="subadmin",
            permissions={"see": True, "create": True, "edit": True, "delete": True},
            organization=self.org,
            is_verified=True,
        )
        
        # Create viewer with limited permissions
        self.viewer_user = User.objects.create(
            username="apiviewer",
            email="apiviewer@test.com",
            password_hash=hash_password("Viewer123!"),
            role="viewer",
            permissions={"see": True, "create": False, "edit": False, "delete": False},
            organization=self.org,
            is_verified=True,
        )

    def _login_as(self, username, password):
        """Helper to login as a specific user."""
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': username,
            'password': password,
        })

    def test_pipelines_api_requires_login(self):
        response = self.client.get(reverse('pipelines_api'))
        self.assertEqual(response.status_code, 302)

    def test_pipelines_api_returns_data_for_authenticated_user(self):
        self._login_as('apiadmin', 'Admin123!')
        response = self.client.get(reverse('pipelines_api'))
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIsInstance(data, list)

    def test_users_api_requires_admin_role(self):
        self._login_as('apiviewer', 'Viewer123!')
        response = self.client.get(reverse('get_users_api'))
        self.assertEqual(response.status_code, 403)  # Forbidden for viewers

    def test_users_api_allowed_for_subadmin(self):
        self._login_as('apiadmin', 'Admin123!')
        response = self.client.get(reverse('get_users_api'))
        self.assertEqual(response.status_code, 200)


class AuditTrailIntegrationTests(TestCase):
    """Test that audit trail entries are created for key actions."""

    def setUp(self):
        self.client = Client()
        self.org = Organization.objects.create(name="Audit Test Org")
        self.user = User.objects.create(
            username="audituser",
            email="audit@test.com",
            password_hash=hash_password("AuditPass123!"),
            role="subadmin",
            permissions={"see": True, "create": True, "edit": True, "delete": True},
            organization=self.org,
            is_verified=True,
        )

    def test_login_creates_audit_entry(self):
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'audituser',
            'password': 'AuditPass123!',
        })
        logs = AuditLog.objects.filter(action='user.login', actor='audituser')
        self.assertEqual(logs.count(), 1)

    def test_logout_creates_audit_entry(self):
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'audituser',
            'password': 'AuditPass123!',
        })
        self.client.get(reverse('logout'))
        logs = AuditLog.objects.filter(action='user.logout', actor='audituser')
        self.assertEqual(logs.count(), 1)


class PipelineGateTests(TestCase):
    """Test the Proactive CI/CD Schema Validation Gate."""
    
    def setUp(self):
        import os
        import yaml
        from core.views import CONTRACTS_DIR
        
        self.client = Client()
        self.org = Organization.objects.create(name="Gate Org")
        self.user = User.objects.create(
            username="gateuser",
            email="gate@test.com",
            password_hash=hash_password("Pass123!"),
            role="subadmin",
            permissions={"see": True, "create": True, "edit": True, "delete": True},
            organization=self.org,
            is_verified=True,
        )
        
        self.pipeline = Pipeline.objects.create(
            id="gate_pipeline",
            name="Gate Pipeline",
            db_type="postgres",
            conn_str="postgresql://user:pass@localhost/db",
            schema="public",
            table="gate_table",
            lock_signature="test_signature_abc123",
            organization=self.org
        )
        
        # Create a mock contract configuration on disk
        self.contract_dir = CONTRACTS_DIR
        os.makedirs(self.contract_dir, exist_ok=True)
        self.contract_path = os.path.join(self.contract_dir, "gate_table.yaml")
        
        self.contract_data = {
            "source": {
                "name": "gate_pipeline_contract",
                "type": "postgres",
                "connection": "postgresql://user:pass@localhost/db",
                "schema": "public",
                "table": "gate_table"
            },
            "columns": [
                {"name": "id", "type": "integer", "nullable": False},
                {"name": "name", "type": "varchar(255)", "nullable": True}
            ]
        }
        
        with open(self.contract_path, "w") as f:
            yaml.dump(self.contract_data, f)
            
    def tearDown(self):
        import os
        if os.path.exists(self.contract_path):
            try:
                os.remove(self.contract_path)
            except OSError:
                pass

    def test_validate_gate_unauthorized(self):
        url = reverse('validate_pipeline_gate_api', args=[self.pipeline.id])
        payload = {
            "commit_sha": "a1b2c3d4",
            "branch": "feature/test",
            "schema": {"columns": [{"name": "id", "type": "integer", "nullable": False}]}
        }
        response = self.client.post(url, json.dumps(payload), content_type="application/json")
        self.assertEqual(response.status_code, 403)

    def test_validate_gate_authorized_via_token_success(self):
        url = reverse('validate_pipeline_gate_api', args=[self.pipeline.id])
        payload = {
            "commit_sha": "a1b2c3d4",
            "branch": "feature/test",
            "schema": {
                "columns": [
                    {"name": "id", "type": "integer", "nullable": False},
                    {"name": "name", "type": "varchar(255)", "nullable": True}
                ]
            }
        }
        headers = {"HTTP_X_SCHEMA_GUARD_TOKEN": self.pipeline.lock_signature}
        response = self.client.post(url, json.dumps(payload), content_type="application/json", **headers)
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertTrue(data["compatible"])
        self.assertEqual(data["status"], "PASS")
        self.assertEqual(len(data["violations"]), 0)

    def test_validate_gate_mismatch_type(self):
        url = reverse('validate_pipeline_gate_api', args=[self.pipeline.id])
        payload = {
            "commit_sha": "a1b2c3d4",
            "branch": "feature/test",
            "schema": {
                "columns": [
                    {"name": "id", "type": "varchar(50)", "nullable": False}, # Changed type from integer
                    {"name": "name", "type": "varchar(255)", "nullable": True}
                ]
            }
        }
        headers = {"HTTP_X_SCHEMA_GUARD_TOKEN": self.pipeline.lock_signature}
        response = self.client.post(url, json.dumps(payload), content_type="application/json", **headers)
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertFalse(data["compatible"])
        self.assertEqual(data["status"], "FAIL")
        self.assertTrue(len(data["violations"]) > 0)
        self.assertIn("type mismatch", data["violations"][0])

    def test_validate_gate_missing_column(self):
        url = reverse('validate_pipeline_gate_api', args=[self.pipeline.id])
        payload = {
            "commit_sha": "a1b2c3d4",
            "branch": "feature/test",
            "schema": {
                "columns": [
                    {"name": "name", "type": "varchar(255)", "nullable": True} # Missing 'id'
                ]
            }
        }
        headers = {"HTTP_X_SCHEMA_GUARD_TOKEN": self.pipeline.lock_signature}
        response = self.client.post(url, json.dumps(payload), content_type="application/json", **headers)
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertFalse(data["compatible"])
        self.assertEqual(data["status"], "FAIL")
        self.assertTrue(len(data["violations"]) > 0)
        self.assertIn("missing", data["violations"][0])

    def test_validate_gate_added_column_warning(self):
        url = reverse('validate_pipeline_gate_api', args=[self.pipeline.id])
        payload = {
            "commit_sha": "a1b2c3d4",
            "branch": "feature/test",
            "schema": {
                "columns": [
                    {"name": "id", "type": "integer", "nullable": False},
                    {"name": "name", "type": "varchar(255)", "nullable": True},
                    {"name": "created_at", "type": "timestamp", "nullable": True} # Added nullable column
                ]
            }
        }
        headers = {"HTTP_X_SCHEMA_GUARD_TOKEN": self.pipeline.lock_signature}
        response = self.client.post(url, json.dumps(payload), content_type="application/json", **headers)
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertTrue(data["compatible"])
        self.assertEqual(data["status"], "PASS")
        self.assertEqual(len(data["violations"]), 0)
        self.assertTrue(len(data["warnings"]) > 0)
        self.assertIn("added", data["warnings"][0])

    def test_get_gate_logs_endpoint(self):
        # Authenticate session
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'gateuser',
            'password': 'Pass123!',
        })
        
        # Insert a gate log in DB
        from core.models import GateValidationLog
        GateValidationLog.objects.create(
            pipeline=self.pipeline,
            commit_sha="a1b2c3d4e5f6",
            branch="main",
            status="PASS",
            violations_count=0
        )
        
        url = reverse('get_gate_logs_api', args=[self.pipeline.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["commit_sha"], "a1b2c3d4e5f6")
        self.assertEqual(data[0]["status"], "PASS")


class PipelineSandboxTests(TestCase):
    """Test the DDL Blast Radius Simulation Sandbox features."""
    
    def setUp(self):
        import os
        import yaml
        from core.views import CONTRACTS_DIR
        
        self.client = Client()
        self.org = Organization.objects.create(name="Sandbox Org")
        
        self.user = User.objects.create(
            username="sandboxuser",
            email="sandbox@test.com",
            password_hash=hash_password("Pass123!"),
            role="operator",
            permissions={"see": True, "create": True, "edit": True, "delete": True},
            organization=self.org,
            is_verified=True,
        )
        
        self.pipeline = Pipeline.objects.create(
            id="sandbox_pipeline",
            name="Sandbox Pipeline",
            db_type="postgres",
            conn_str="postgresql://user:pass@localhost/db",
            schema="public",
            table="sandbox_table",
            lock_signature="signature_xyz_789",
            organization=self.org
        )
        
        # Create mock baseline contract yaml file
        self.contract_dir = CONTRACTS_DIR
        os.makedirs(self.contract_dir, exist_ok=True)
        self.contract_path = os.path.join(self.contract_dir, "sandbox_table.yaml")
        
        self.contract_data = {
            "source": {
                "name": "sandbox_contract",
                "type": "postgres",
                "connection": "postgresql://user:pass@localhost/db",
                "schema": "public",
                "table": "sandbox_table"
            },
            "columns": [
                {"name": "id", "type": "integer", "nullable": False},
                {"name": "name", "type": "varchar(255)", "nullable": True}
            ]
        }
        
        with open(self.contract_path, "w") as f:
            yaml.dump(self.contract_data, f)
            
        # Log in user session
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'sandboxuser',
            'password': 'Pass123!',
        })

    def tearDown(self):
        import os
        if os.path.exists(self.contract_path):
            try:
                os.remove(self.contract_path)
            except OSError:
                pass

    def test_sandbox_page_renders(self):
        response = self.client.get(reverse('sandbox_page'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "DDL Blast Radius Simulation Sandbox")

    def test_simulate_add_column_safe(self):
        url = reverse('simulate_ddl_api')
        payload = {
            "pipeline_id": self.pipeline.id,
            "ddl_sql": "ALTER TABLE sandbox_table ADD COLUMN email varchar(100);"
        }
        response = self.client.post(url, json.dumps(payload), content_type="application/json")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        
        self.assertEqual(data["status"], "success")
        self.assertTrue(data["compatible"])
        self.assertEqual(data["compliance_rating"], "Safe (Compatible)")
        self.assertEqual(len(data["violations"]), 0)
        self.assertTrue(len(data["warnings"]) > 0)
        self.assertIn("added", data["warnings"][0])
        self.assertIn("email", data["yaml_preview"])

    def test_simulate_drop_column_breaking(self):
        url = reverse('simulate_ddl_api')
        payload = {
            "pipeline_id": self.pipeline.id,
            "ddl_sql": "ALTER TABLE sandbox_table DROP COLUMN name;"
        }
        response = self.client.post(url, json.dumps(payload), content_type="application/json")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        
        self.assertEqual(data["status"], "success")
        self.assertFalse(data["compatible"])
        self.assertEqual(data["compliance_rating"], "High Risk (Breaking)")
        self.assertTrue(len(data["violations"]) > 0)
        self.assertIn("dropped", data["violations"][0])
        self.assertNotIn("- name: name", data["yaml_preview"])
        self.assertIn("Expand-and-Contract", data["recipe"])

    def test_simulate_rename_column_breaking(self):
        url = reverse('simulate_ddl_api')
        payload = {
            "pipeline_id": self.pipeline.id,
            "ddl_sql": "ALTER TABLE sandbox_table RENAME COLUMN name TO first_name;"
        }
        response = self.client.post(url, json.dumps(payload), content_type="application/json")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        
        self.assertEqual(data["status"], "success")
        self.assertFalse(data["compatible"])
        self.assertTrue(len(data["violations"]) > 0)
        self.assertIn("first_name", data["yaml_preview"])
        self.assertIn("trigger_sync_sandbox_table", data["recipe"])

    def test_simulate_alter_type(self):
        url = reverse('simulate_ddl_api')
        payload = {
            "pipeline_id": self.pipeline.id,
            "ddl_sql": "ALTER TABLE sandbox_table ALTER COLUMN name TYPE varchar(500);"
        }
        response = self.client.post(url, json.dumps(payload), content_type="application/json")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        
        self.assertEqual(data["status"], "success")
        self.assertFalse(data["compatible"])
        self.assertTrue(len(data["violations"]) > 0)
        self.assertIn("type mismatch", data["violations"][0])

    def test_simulate_invalid_sql(self):
        url = reverse('simulate_ddl_api')
        payload = {
            "pipeline_id": self.pipeline.id,
            "ddl_sql": "CREATE TABLE random_table (id int);"
        }
        response = self.client.post(url, json.dumps(payload), content_type="application/json")
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertEqual(data["status"], "failed")
        self.assertIn("Unsupported DDL query", data["message"])

    def test_simulate_add_column_scd2(self):
        url = reverse('simulate_ddl_api')
        payload = {
            "pipeline_id": self.pipeline.id,
            "ddl_sql": "ALTER TABLE sandbox_table ADD COLUMN phone varchar(20);",
            "target_type": "scd2"
        }
        response = self.client.post(url, json.dumps(payload), content_type="application/json")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data["status"], "success")
        self.assertTrue(data["compatible"])
        self.assertIn("SCD TYPE 2 SAFE ADD COLUMN", data["recipe"])
        self.assertNotIn("SET NOT NULL", data["recipe"])

    def test_simulate_drop_column_scd2(self):
        url = reverse('simulate_ddl_api')
        payload = {
            "pipeline_id": self.pipeline.id,
            "ddl_sql": "ALTER TABLE sandbox_table DROP COLUMN name;",
            "target_type": "scd2"
        }
        response = self.client.post(url, json.dumps(payload), content_type="application/json")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data["status"], "success")
        self.assertFalse(data["compatible"])
        self.assertIn("SCD TYPE 2 HISTORY GUARD", data["recipe"])
        self.assertIn("DO NOT DROP the column", data["recipe"])


class PipelineDbtExportTests(TestCase):
    """Test the dbt Schema Generator / Exporter features."""
    
    def setUp(self):
        import os
        import yaml
        from core.views import CONTRACTS_DIR
        
        self.client = Client()
        self.org = Organization.objects.create(name="dbt Org", plan="pro")
        self.user = User.objects.create(
            username="dbtuser",
            email="dbt@test.com",
            password_hash=hash_password("Pass123!"),
            role="operator",
            permissions={"see": True, "create": True, "edit": True, "delete": True},
            organization=self.org,
            is_verified=True,
        )
        
        self.pipeline = Pipeline.objects.create(
            id="dbt_pipeline",
            name="dbt Pipeline",
            db_type="postgres",
            conn_str="postgresql://user:pass@localhost/db",
            schema="public",
            table="dbt_table",
            lock_signature="signature_dbt_123",
            organization=self.org
        )
        
        # Create mock baseline contract yaml file
        self.contract_dir = CONTRACTS_DIR
        os.makedirs(self.contract_dir, exist_ok=True)
        self.contract_path = os.path.join(self.contract_dir, "dbt_table.yaml")
        
        self.contract_data = {
            "source": {
                "name": "dbt_contract",
                "type": "postgres",
                "connection": "postgresql://user:pass@localhost/db",
                "schema": "public",
                "table": "dbt_table"
            },
            "columns": [
                {"name": "id", "type": "integer", "nullable": False},
                {"name": "name", "type": "varchar(255)", "nullable": True}
            ]
        }
        
        with open(self.contract_path, "w") as f:
            yaml.dump(self.contract_data, f)
            
        # Log in user session
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'dbtuser',
            'password': 'Pass123!',
        })

    def tearDown(self):
        import os
        if os.path.exists(self.contract_path):
            try:
                os.remove(self.contract_path)
            except OSError:
                pass

    def test_export_dbt_schema_unauthorized(self):
        self.client.get(reverse('logout'))
        url = reverse('export_dbt_schema_api', args=[self.pipeline.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302) # Redirect to login

    def test_export_dbt_schema_success(self):
        url = reverse('export_dbt_schema_api', args=[self.pipeline.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        
        self.assertEqual(data["status"], "success")
        dbt_yaml = data["dbt_yaml"]
        
        # Verify structure
        self.assertIn("version: 2", dbt_yaml)
        self.assertIn("name: dbt_table", dbt_yaml)
        self.assertIn("name: id", dbt_yaml)
        self.assertIn("name: name", dbt_yaml)
        self.assertIn("tests:\n    - not_null", dbt_yaml) # id is NOT NULL (nullable: false)

    def test_export_dbt_schema_missing_contract(self):
        # Create pipeline without contract
        pipe_no_contract = Pipeline.objects.create(
            id="dbt_no_contract",
            name="dbt No Contract",
            db_type="postgres",
            conn_str="postgresql://user:pass@localhost/db",
            schema="public",
            table="no_contract_table",
            organization=self.org
        )
        url = reverse('export_dbt_schema_api', args=[pipe_no_contract.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertIn("not found on server", data["detail"])


class PipelineAirflowIntegrationTests(TestCase):
    """Test the Apache Airflow operator and sensor module."""
    
    def setUp(self):
        self.client = Client()
        self.org = Organization.objects.create(name="Airflow Org", plan="pro")
        self.user = User.objects.create(
            username="airflowuser",
            email="airflow@test.com",
            password_hash=hash_password("Pass123!"),
            role="operator",
            permissions={"see": True},
            organization=self.org,
            is_verified=True,
        )
        # Log in session
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'airflowuser',
            'password': 'Pass123!',
        })

    def test_download_operator_unauthorized(self):
        self.client.get(reverse('logout'))
        response = self.client.get(reverse('download_airflow_operator'))
        self.assertEqual(response.status_code, 302)

    def test_download_operator_success(self):
        response = self.client.get(reverse('download_airflow_operator'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/x-python')
        self.assertIn('attachment; filename="airflow_operator.py"', response['Content-Disposition'])
        content = response.content.decode('utf-8')
        self.assertIn('class SchemaGuardOperator', content)
        self.assertIn('class SchemaGuardSensor', content)

    @patch('urllib.request.urlopen')
    def test_airflow_operator_success(self, mock_urlopen):
        # Mock urllib context manager response
        mock_response = Mock()
        mock_response.getcode.return_value = 200
        mock_response.read.return_value = b'{"compatible": true, "violations": [], "warnings": []}'
        mock_urlopen.return_value.__enter__.return_value = mock_response
        
        from core.airflow_operator import SchemaGuardOperator
        operator = SchemaGuardOperator(
            task_id="test_schema_check",
            endpoint_url="http://mock-server/api/pipelines/123/validate-gate",
            token="sig_xyz"
        )
        
        res = operator.execute()
        self.assertTrue(res["compatible"])
        mock_urlopen.assert_called_once()

    @patch('urllib.request.urlopen')
    def test_airflow_operator_fail_on_drift(self, mock_urlopen):
        mock_response = Mock()
        mock_response.getcode.return_value = 200
        mock_response.read.return_value = b'{"compatible": false, "violations": ["CRITICAL: Column \'email\' is missing."]}'
        mock_urlopen.return_value.__enter__.return_value = mock_response
        
        from core.airflow_operator import SchemaGuardOperator
        operator = SchemaGuardOperator(
            task_id="test_schema_check",
            endpoint_url="http://mock-server/api/pipelines/123/validate-gate",
            token="sig_xyz"
        )
        
        with self.assertRaises(ValueError) as ctx:
            operator.execute()
        self.assertIn("Schema drift detected", str(ctx.exception))
        self.assertIn("Column 'email' is missing", str(ctx.exception))

    @patch('urllib.request.urlopen')
    def test_airflow_sensor_poke(self, mock_urlopen):
        from core.airflow_operator import SchemaGuardSensor
        sensor = SchemaGuardSensor(
            task_id="test_schema_sensor",
            endpoint_url="http://mock-server/api/pipelines/123/validate-gate",
            token="sig_xyz"
        )
        
        # Test sensor poke when contract is valid
        mock_response_pass = Mock()
        mock_response_pass.getcode.return_value = 200
        mock_response_pass.read.return_value = b'{"compatible": true}'
        mock_urlopen.return_value.__enter__.return_value = mock_response_pass
        self.assertTrue(sensor.poke())
        
        # Test sensor poke when contract is drifted/invalid
        mock_response_fail = Mock()
        mock_response_fail.getcode.return_value = 200
        mock_response_fail.read.return_value = b'{"compatible": false}'
        mock_urlopen.return_value.__enter__.return_value = mock_response_fail
        self.assertFalse(sensor.poke())
        
        # Test sensor poke on API network failure
        mock_urlopen.side_effect = Exception("Timeout connection")
        self.assertFalse(sensor.poke())


class WebhookAlertTests(TestCase):
    """Test Custom Webhook Dispatcher alert alerts."""

    @patch('urllib.request.urlopen')
    def test_send_custom_webhook_alert_success(self, mock_urlopen):
        from core.views import send_custom_webhook_alert
        
        mock_response = Mock()
        mock_response.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response
        
        violations = ["Column 'name' was dropped."]
        dq_report = {"status": "PASS", "checks": []}
        
        res = send_custom_webhook_alert(
            violations=violations,
            dq_report=dq_report,
            webhook_url="https://api.test.com/webhook",
            pipeline_name="test_pipeline",
            status_str="Drifted"
        )
        
        self.assertTrue(res)
        mock_urlopen.assert_called_once()
        
        # Verify request parameters
        args, kwargs = mock_urlopen.call_args
        req = args[0]
        self.assertEqual(req.full_url, "https://api.test.com/webhook")
        self.assertEqual(req.headers["Content-type"], "application/json")
        self.assertEqual(req.method, "POST")

    @patch('urllib.request.urlopen')
    def test_send_custom_webhook_alert_failure(self, mock_urlopen):
        from core.views import send_custom_webhook_alert
        mock_urlopen.side_effect = Exception("HTTP 500 Server Error")
        
        violations = []
        dq_report = {"status": "FAIL", "checks": []}
        
        res = send_custom_webhook_alert(
            violations=violations,
            dq_report=dq_report,
            webhook_url="https://api.test.com/webhook",
            pipeline_name="test_pipeline",
            status_str="Drifted"
        )
        
        self.assertFalse(res)


class DemoPipelineAndRateLimitTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.org = Organization.objects.create(name="Demo Org", plan="pro")
        self.user = User.objects.create(
            username="demouser",
            email="demo@test.com",
            password_hash=hash_password("DemoPass123!"),
            role="operator",
            organization=self.org,
            is_verified=True,
        )
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'demouser',
            'password': 'DemoPass123!',
        })

    def test_create_demo_pipeline_success(self):
        url = reverse('create_demo_pipeline_api')
        res = self.client.post(url)
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.content)
        self.assertIn("demo_orders_", data["id"])
        self.assertEqual(data["status"], "Drifted")
        self.assertIn("contractYaml", data)
        self.assertIn("total_amount", data["contractYaml"])

    def test_ai_diagnostics_rate_limit(self):
        # Create pipeline for testing
        p = Pipeline.objects.create(
            id="pipe_rate_test",
            name="Rate Test Pipe",
            db_type="postgres",
            conn_str="postgresql://u:p@localhost/db",
            schema="public",
            table="orders",
            organization=self.org
        )
        url = reverse('run_ai_diagnostics_api', args=[p.id])
        from django.core.cache import cache
        cache.set(f"ai_diag_rate_{self.user.username}", 20, timeout=60)
        res = self.client.post(url, json.dumps({"query_type": "explain"}), content_type="application/json")
        self.assertEqual(res.status_code, 429)
        cache.delete(f"ai_diag_rate_{self.user.username}")


class TeamInvitationAndRBACTests(TestCase):
    def setUp(self):
        self.pro_org = Organization.objects.create(name="Pro Company", plan="pro")
        self.free_org = Organization.objects.create(name="Free Solo Org", plan="free")

        self.subadmin = User.objects.create(
            username="pro_admin",
            email="admin@procompany.com",
            password_hash=hash_password("Pass123!"),
            role="subadmin",
            organization=self.pro_org,
            is_verified=True,
            permissions={"see": True, "create": True, "edit": True, "delete": True}
        )

        self.operator = User.objects.create(
            username="pro_operator",
            email="op@procompany.com",
            password_hash=hash_password("Pass123!"),
            role="operator",
            organization=self.pro_org,
            is_verified=True,
            permissions={"see": True, "create": True, "edit": True, "delete": False}
        )

        self.free_user = User.objects.create(
            username="free_user",
            email="free@solo.com",
            password_hash=hash_password("Pass123!"),
            role="subadmin",
            organization=self.free_org,
            is_verified=True,
            permissions={"see": True, "create": True, "edit": True, "delete": True}
        )

    def test_seat_quota_calculation(self):
        self.assertEqual(self.free_org.get_seat_quota(), 1)
        self.assertEqual(self.pro_org.get_seat_quota(), 10)
        # free_user is 1 active user => active seat count is 1
        self.assertEqual(self.free_org.get_active_seat_count(), 1)

    def test_free_plan_invitation_quota_blocked(self):
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'free_user',
            'password': 'Pass123!',
        })
        res = self.client.post(
            reverse('organization_members_api'),
            data=json.dumps({"email": "colleague@solo.com", "role": "operator"}),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 403)
        data = json.loads(res.content)
        self.assertIn("quota reached", data["detail"].lower())

    def test_pro_plan_invite_success_and_acceptance(self):
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'pro_admin',
            'password': 'Pass123!',
        })
        res = self.client.post(
            reverse('organization_members_api'),
            data=json.dumps({"email": "newteammate@procompany.com", "role": "operator"}),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.content)
        self.assertTrue(data["success"])
        invite_data = data["invitation"]
        token = invite_data["invite_url"].split('/')[-1]

        from core.models import OrganizationInvitation
        inv = OrganizationInvitation.objects.get(email="newteammate@procompany.com")
        self.assertTrue(inv.is_valid())

        # Test accept invitation page GET
        accept_url = reverse('accept_invitation', args=[token])
        get_res = self.client.get(accept_url)
        self.assertEqual(get_res.status_code, 200)
        self.assertContains(get_res, "newteammate@procompany.com")

        # Test accept invitation POST creates new user
        post_res = self.client.post(
            accept_url,
            data=json.dumps({
                "username": "new_operator",
                "password": "SecurePassword123!",
                "full_name": "New Teammate"
            }),
            content_type="application/json"
        )
        self.assertEqual(post_res.status_code, 200)
        accept_data = json.loads(post_res.content)
        self.assertTrue(accept_data["success"])
        self.assertEqual(accept_data["redirect_url"], "/dashboard")

        new_u = User.objects.get(username="new_operator")
        self.assertEqual(new_u.organization, self.pro_org)
        self.assertEqual(new_u.role, "operator")
        self.assertTrue(new_u.is_verified)

        inv.refresh_from_db()
        self.assertEqual(inv.status, "accepted")

    def test_revoke_invitation(self):
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'pro_admin',
            'password': 'Pass123!',
        })
        res = self.client.post(
            reverse('organization_members_api'),
            data=json.dumps({"email": "cancelme@procompany.com", "role": "viewer"}),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        invite_id = json.loads(res.content)["invitation"]["id"]

        del_res = self.client.delete(reverse('revoke_invitation_api', args=[invite_id]))
        self.assertEqual(del_res.status_code, 200)

        from core.models import OrganizationInvitation
        inv = OrganizationInvitation.objects.get(id=invite_id)
        self.assertEqual(inv.status, "revoked")
        self.assertFalse(inv.is_valid())

    def test_remove_organization_member(self):
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'pro_admin',
            'password': 'Pass123!',
        })
        del_res = self.client.delete(reverse('remove_organization_member_api', args=["pro_operator"]))
        self.assertEqual(del_res.status_code, 200)

        self.operator.refresh_from_db()
        self.assertIsNone(self.operator.organization)


class RichAlertingTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Alert Test Org", plan="pro")
        self.user = User.objects.create(
            username="alert_user",
            email="alert@test.com",
            password_hash=hash_password("Pass123!"),
            role="operator",
            organization=self.org,
            is_verified=True,
            permissions={"see": True, "create": True, "edit": True, "delete": True}
        )
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'alert_user',
            'password': 'Pass123!',
        })

    def test_ssrf_validation_blocks_internal_and_private_hosts(self):
        from core.notifications import validate_webhook_url
        ok, reason = validate_webhook_url("http://169.254.169.254/latest/meta-data")
        self.assertFalse(ok)
        self.assertIn("SSRF", reason)

        ok, reason = validate_webhook_url("https://localhost:8080/hook")
        self.assertFalse(ok)
        self.assertIn("SSRF", reason)

        ok, reason = validate_webhook_url("https://hooks.slack.com/services/T00/B00/X00")
        self.assertTrue(ok)

    @patch("urllib.request.urlopen")
    def test_test_pipeline_alert_slack_success(self, mock_urlopen):
        mock_res = MagicMock()
        mock_res.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_res

        url = reverse('test_pipeline_alert_api')
        res = self.client.post(
            url,
            data=json.dumps({
                "channel": "slack",
                "target": "https://hooks.slack.com/services/T00/B00/X00",
                "pipeline_name": "Orders Test Pipe"
            }),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.content)
        self.assertTrue(data["success"])
        self.assertIn("delivered", data["message"].lower())

    @patch("urllib.request.urlopen")
    def test_test_pipeline_alert_teams_success(self, mock_urlopen):
        mock_res = MagicMock()
        mock_res.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_res

        url = reverse('test_pipeline_alert_api')
        res = self.client.post(
            url,
            data=json.dumps({
                "channel": "teams",
                "target": "https://outlook.office.com/webhook/123-abc/IncomingWebhook/xyz",
                "pipeline_name": "Orders Teams Pipe"
            }),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.content)
        self.assertTrue(data["success"])
        self.assertIn("delivered", data["message"].lower())

    def test_test_pipeline_alert_ssrf_blocked(self):
        url = reverse('test_pipeline_alert_api')
        res = self.client.post(
            url,
            data=json.dumps({
                "channel": "slack",
                "target": "http://127.0.0.1:5000/webhook",
                "pipeline_name": "Malicious Pipe"
            }),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 400)
        data = json.loads(res.content)
        self.assertIn("ssrf", data["detail"].lower())

    def test_test_pipeline_alert_empty_target_rejected(self):
        url = reverse('test_pipeline_alert_api')
        res = self.client.post(
            url,
            data=json.dumps({"channel": "slack", "target": ""}),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 400)


class RazorpayBillingTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Razorpay Workspace", plan="free", max_pipelines=5)
        self.user = User.objects.create(
            username="rzp_user",
            email="rzp@example.com",
            password_hash=hash_password("SecurePass123!"),
            organization=self.org,
            role="admin",
            is_verified=True
        )

    def test_razorpay_create_order_authenticated(self):
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'rzp_user',
            'password': 'SecurePass123!',
        })
        url = reverse('razorpay_create_order_api')
        res = self.client.post(
            url,
            data=json.dumps({"plan": "pro"}),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.content)
        self.assertTrue(data["success"])
        self.assertEqual(data["amount"], 399900)
        self.assertEqual(data["currency"], "INR")
        self.assertTrue(data["order_id"].startswith("order_"))

    def test_razorpay_create_order_unauthenticated(self):
        url = reverse('razorpay_create_order_api')
        res = self.client.post(
            url,
            data=json.dumps({"plan": "pro"}),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 302)

    def test_razorpay_verify_payment_simulated_success(self):
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'rzp_user',
            'password': 'SecurePass123!',
        })
        url = reverse('razorpay_verify_payment_api')
        res = self.client.post(
            url,
            data=json.dumps({
                "plan": "pro",
                "razorpay_order_id": "order_sim_test123",
                "razorpay_payment_id": "pay_test_abc999",
                "razorpay_signature": ""
            }),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.content)
        self.assertTrue(data["success"])

        self.org.refresh_from_db()
        self.assertEqual(self.org.plan, "pro")
        self.assertEqual(self.org.max_pipelines, 50)
        self.assertEqual(self.org.subscription_status, "active")

        # Verify PaymentTransaction created
        from core.models import PaymentTransaction
        tx = PaymentTransaction.objects.filter(transaction_id="pay_test_abc999").first()
        self.assertIsNotNone(tx)
        self.assertEqual(tx.plan, "pro")
        self.assertEqual(tx.payment_method, "RAZORPAY")
        self.assertEqual(tx.status, "approved")

    def test_razorpay_webhook_captured_success(self):
        url = reverse('razorpay_webhook_api')
        payload = {
            "event": "payment.captured",
            "payload": {
                "payment": {
                    "entity": {
                        "id": "pay_webhook_999",
                        "amount": 1599900,
                        "notes": {
                            "org_id": str(self.org.id),
                            "plan": "enterprise"
                        }
                    }
                }
            }
        }
        res = self.client.post(
            url,
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.content)
        self.assertEqual(data["status"], "received")

        self.org.refresh_from_db()
        self.assertEqual(self.org.plan, "enterprise")
        self.assertEqual(self.org.max_pipelines, 1000)


class ReverseEngineerContractTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Contract Eng Org", plan="pro")
        self.user = User.objects.create(
            username="contract_dev",
            email="contract_dev@example.com",
            password_hash=hash_password("DevPass123!"),
            organization=self.org,
            role="admin",
            is_verified=True
        )
        yaml_content = """version: 1
source:
  name: orders_contract
  type: postgres
  connection: "env:DB_CONNECTION_STRING"
  schema: public
  table: orders

columns:
  - name: order_id
    type: integer
    nullable: false
    primary_key: true
  - name: customer_email
    type: character varying(255)
    nullable: false
  - name: total_price
    type: numeric(10,2)
    nullable: true
"""
        self.pipeline = Pipeline.objects.create(
            id="pipe-reveng-test-01",
            name="Orders Live Ingestion",
            db_type="postgres",
            conn_str="postgresql://user:pass@localhost:5432/testdb",
            schema="public",
            table="orders",
            contract_yaml=yaml_content,
            organization=self.org
        )

    @patch('core.db_connector.get_db_columns')
    @patch('core.db_connector.test_db_connection')
    def test_reverse_engineer_contract_from_pipeline(self, mock_test, mock_get_cols):
        mock_test.return_value = (True, "Connection OK")
        mock_get_cols.return_value = {
            "columns": [
                {"name": "order_id", "type": "integer", "nullable": False, "primary_key": True},
                {"name": "customer_email", "type": "varchar(255)", "nullable": False, "primary_key": False},
                {"name": "total_price", "type": "numeric(10,2)", "nullable": True, "primary_key": False}
            ]
        }
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'contract_dev',
            'password': 'DevPass123!',
        })
        url = reverse('reverse_engineer_contract_api')
        res = self.client.post(
            url,
            data=json.dumps({"pipeline_id": self.pipeline.id}),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.content)
        self.assertEqual(data["status"], "success")
        self.assertEqual(len(data["columns"]), 3)
        self.assertTrue(len(data["signature"]) == 64)  # SHA-256
        self.assertIn("version: 1", data["contract_yaml"])
        self.assertIn("OrdersContractModel", data["pydantic_code"])
        self.assertIn("IOrdersContract", data["typescript_code"])
        self.assertIn("CREATE TABLE public.orders", data["sql_ddl"])
        self.assertFalse(data["saved"])

    @patch('core.db_connector.get_db_columns')
    @patch('core.db_connector.test_db_connection')
    def test_reverse_engineer_and_save_to_pipeline(self, mock_test, mock_get_cols):
        mock_test.return_value = (True, "Connection OK")
        mock_get_cols.return_value = {
            "columns": [
                {"name": "order_id", "type": "integer", "nullable": False, "primary_key": True},
                {"name": "customer_email", "type": "varchar(255)", "nullable": False, "primary_key": False},
                {"name": "total_price", "type": "numeric(10,2)", "nullable": True, "primary_key": False}
            ]
        }
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'contract_dev',
            'password': 'DevPass123!',
        })
        url = reverse('reverse_engineer_contract_api')
        res = self.client.post(
            url,
            data=json.dumps({
                "pipeline_id": self.pipeline.id,
                "save_to_pipeline": True
            }),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.content)
        self.assertTrue(data["saved"])

        self.pipeline.refresh_from_db()
        self.assertEqual(self.pipeline.lock_signature, data["signature"])
        self.assertEqual(self.pipeline.status, "Clean")
        self.assertIn("order_id", self.pipeline.contract_yaml)

    def test_reverse_engineer_unauthenticated(self):
        url = reverse('reverse_engineer_contract_api')
        res = self.client.post(
            url,
            data=json.dumps({"pipeline_id": self.pipeline.id}),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 302)

    def test_reverse_engineer_nonexistent_pipeline(self):
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'contract_dev',
            'password': 'DevPass123!',
        })
        url = reverse('reverse_engineer_contract_api')
        res = self.client.post(
            url,
            data=json.dumps({"pipeline_id": "nonexistent-pipeline-id-999"}),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 404)


class PipelinePromotionTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Promo Org", plan="pro")
        self.admin = User.objects.create(
            username="promo_admin",
            email="admin@promo.com",
            password_hash=hash_password("AdminPass123!"),
            organization=self.org,
            role="admin",
            is_verified=True,
            permissions={"see": True, "create": True, "edit": True, "delete": True}
        )
        self.viewer = User.objects.create(
            username="promo_viewer",
            email="viewer@promo.com",
            password_hash=hash_password("ViewerPass123!"),
            organization=self.org,
            role="viewer",
            is_verified=True,
            permissions={"see": True, "create": False, "edit": False, "delete": False}
        )
        self.dev_pipeline = Pipeline.objects.create(
            id="pipe-promo-dev-01",
            organization=self.org,
            name="Orders Stream DEV",
            environment="dev",
            db_type="postgres",
            conn_str="postgresql://user:pass@localhost:5432/testdb",
            schema="public",
            table="orders",
            cron="0 * * * *",
            cron_text="Hourly",
            alerts={},
            contract_yaml="columns:\n  - name: id\n    type: integer\n  - name: amount\n    type: numeric\n",
            lock_signature="f3a5b6c7d8e90123456789abcdef0123456789abcdef0123456789abcdef0123",
            schema_map={"id": "integer", "amount": "numeric"},
            status="Clean"
        )

    def test_promote_dev_to_staging_clones_new_pipeline(self):
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'promo_admin',
            'password': 'AdminPass123!',
        })
        url = reverse('promote_pipeline_api', args=[self.dev_pipeline.id])
        res = self.client.post(
            url,
            data=json.dumps({
                "target_env": "staging",
                "mode": "new"
            }),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.content)
        self.assertTrue(data["success"])
        self.assertEqual(data["mode"], "new")
        self.assertEqual(data["pipeline"]["environment"], "staging")
        self.assertEqual(data["pipeline"]["lockSignature"], self.dev_pipeline.lock_signature)

        # Check DB pipeline count
        promoted = Pipeline.objects.get(id=data["pipeline"]["id"])
        self.assertEqual(promoted.environment, "staging")
        self.assertIn("STAGING", promoted.name)
        self.assertEqual(promoted.table, "orders")

        # Check AuditLog
        log = AuditLog.objects.filter(action="pipeline.promoted", actor="promo_admin").first()
        self.assertIsNotNone(log)
        self.assertEqual(log.details.get("target_environment"), "staging")

    def test_promote_staging_to_prod_syncs_existing_pipeline(self):
        staging_pipeline = Pipeline.objects.create(
            id="pipe-promo-staging-01",
            organization=self.org,
            name="Payments Stream STAGING",
            environment="staging",
            db_type="postgres",
            conn_str="postgresql://user:pass@localhost:5432/testdb",
            schema="public",
            table="payments",
            cron="0 * * * *",
            contract_yaml="columns:\n  - name: txn_id\n    type: varchar\n",
            lock_signature="aaaaabbbbbcccccdddddeeeeefffff0000011111222223333344444555556666",
            schema_map={"txn_id": "varchar"},
            status="Clean"
        )
        prod_pipeline = Pipeline.objects.create(
            id="pipe-promo-prod-01",
            organization=self.org,
            name="Payments Stream PROD",
            environment="prod",
            db_type="postgres",
            conn_str="postgresql://user:pass@localhost:5432/testdb",
            schema="public",
            table="payments",
            cron="0 * * * *",
            contract_yaml="",
            lock_signature="",
            schema_map={},
            status="Drifted"
        )

        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'promo_admin',
            'password': 'AdminPass123!',
        })
        url = reverse('promote_pipeline_api', args=[staging_pipeline.id])
        res = self.client.post(
            url,
            data=json.dumps({
                "target_env": "prod",
                "mode": "sync",
                "target_pipeline_id": prod_pipeline.id
            }),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.content)
        self.assertTrue(data["success"])
        self.assertEqual(data["mode"], "sync")

        prod_pipeline.refresh_from_db()
        self.assertEqual(prod_pipeline.contract_yaml, staging_pipeline.contract_yaml)
        self.assertEqual(prod_pipeline.lock_signature, staging_pipeline.lock_signature)
        self.assertEqual(prod_pipeline.status, "Clean")

    def test_promote_viewer_role_rejected_403(self):
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'promo_viewer',
            'password': 'ViewerPass123!',
        })
        url = reverse('promote_pipeline_api', args=[self.dev_pipeline.id])
        res = self.client.post(
            url,
            data=json.dumps({
                "target_env": "staging",
                "mode": "new"
            }),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 403)

    def test_promote_missing_contract_rejected_400(self):
        empty_pipeline = Pipeline.objects.create(
            id="pipe-promo-empty-01",
            organization=self.org,
            name="Empty DEV",
            environment="dev",
            db_type="postgres",
            conn_str="postgresql://user:pass@localhost:5432/testdb",
            schema="public",
            table="empty_table",
            cron="0 * * * *",
            contract_yaml="",
            lock_signature=""
        )
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'promo_admin',
            'password': 'AdminPass123!',
        })
        url = reverse('promote_pipeline_api', args=[empty_pipeline.id])
        res = self.client.post(
            url,
            data=json.dumps({
                "target_env": "staging",
                "mode": "new"
            }),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 400)
        data = json.loads(res.content)
        self.assertIn("YAML contract", data.get("detail", ""))

    def test_promote_invalid_environment_transition_400(self):
        prod_pipe = Pipeline.objects.create(
            id="pipe-promo-top-prod-01",
            organization=self.org,
            name="Top PROD",
            environment="prod",
            db_type="postgres",
            conn_str="postgresql://user:pass@localhost:5432/testdb",
            schema="public",
            table="orders",
            cron="0 * * * *",
            contract_yaml="col: int",
            lock_signature="12345"
        )
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'promo_admin',
            'password': 'AdminPass123!',
        })
        url = reverse('promote_pipeline_api', args=[prod_pipe.id])
        res = self.client.post(
            url,
            data=json.dumps({
                "target_env": "dev",
                "mode": "new"
            }),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 400)


class SchemaMigrationGeneratorTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Migration Org", plan="pro")
        self.user = User.objects.create(
            username="mig_user",
            email="mig@org.com",
            password_hash=hash_password("MigPass123!"),
            organization=self.org,
            role="admin",
            is_verified=True,
            permissions={"see": True, "create": True, "edit": True, "delete": True}
        )
        self.pipeline = Pipeline.objects.create(
            id="pipe-mig-test-01",
            organization=self.org,
            name="Invoices Stream",
            environment="prod",
            db_type="postgres",
            conn_str="postgresql://user:pass@localhost:5432/testdb",
            schema="public",
            table="invoices",
            cron="0 * * * *",
            contract_yaml=(
                "columns:\n"
                "  - name: id\n"
                "    type: integer\n"
                "    nullable: false\n"
                "  - name: amount\n"
                "    type: numeric(12,2)\n"
                "    nullable: true\n"
                "  - name: invoice_status\n"
                "    type: varchar(50)\n"
                "    nullable: false\n"
            ),
            lock_signature="abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            schema_map={
                "left": [
                    {"name": "id", "type": "integer", "nullable": False, "status": "clean"},
                    {"name": "amount", "type": "numeric(12,2)", "nullable": True, "status": "clean"},
                    {"name": "invoice_status", "type": "varchar(50)", "nullable": False, "status": "clean"}
                ],
                "right": [
                    {"name": "id", "type": "integer", "nullable": False, "status": "clean"}
                ]
            },
            status="Drifted"
        )

    def test_generate_migration_bundle_missing_columns(self):
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'mig_user',
            'password': 'MigPass123!',
        })
        url = reverse('generate_pipeline_migration_api', args=[self.pipeline.id])
        res = self.client.post(
            url,
            data=json.dumps({"target_engine": "postgres"}),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.content)
        self.assertTrue(data["success"])
        self.assertEqual(data["table"], "invoices")
        self.assertEqual(data["db_type"], "postgres")
        self.assertEqual(data["diff_count"], 2)

        # Check SQL UP contains ADD COLUMN for amount and invoice_status
        self.assertIn("ADD COLUMN IF NOT EXISTS amount numeric(12,2)", data["sql"]["up"])
        self.assertIn("ADD COLUMN IF NOT EXISTS invoice_status varchar(50)", data["sql"]["up"])
        # Check SQL DOWN contains DROP COLUMN
        self.assertIn("DROP COLUMN IF EXISTS amount", data["sql"]["down"])
        self.assertIn("DROP COLUMN IF EXISTS invoice_status", data["sql"]["down"])

        # Check Flyway
        self.assertIn("Flyway Versioned Migration", data["flyway"]["versioned_sql"])
        self.assertTrue(data["flyway"]["versioned_filename"].startswith("V"))

        # Check Liquibase
        self.assertIn("databaseChangeLog:", data["liquibase"]["yaml"])
        self.assertIn("addColumn:", data["liquibase"]["yaml"])

        # Check Alembic
        self.assertIn("def upgrade() -> None:", data["alembic"]["python"])
        self.assertIn("op.add_column('invoices'", data["alembic"]["python"])

    def test_generate_migration_bundle_mysql_dialect(self):
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'mig_user',
            'password': 'MigPass123!',
        })
        url = reverse('generate_pipeline_migration_api', args=[self.pipeline.id])
        res = self.client.post(
            url,
            data=json.dumps({"target_engine": "mysql"}),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.content)
        self.assertEqual(data["db_type"], "mysql")
        self.assertIn("ALTER TABLE `invoices` ADD COLUMN `amount`", data["sql"]["up"])

    def test_download_migration_file_sql_up(self):
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'mig_user',
            'password': 'MigPass123!',
        })
        url = reverse('download_pipeline_migration_api', args=[self.pipeline.id]) + "?format=sql_up&target_engine=postgres"
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)
        self.assertIn("attachment; filename=", res["Content-Disposition"])
        self.assertIn(".sql", res["Content-Disposition"])
        self.assertIn("ADD COLUMN IF NOT EXISTS amount", res.content.decode("utf-8"))

    def test_download_migration_file_alembic(self):
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'mig_user',
            'password': 'MigPass123!',
        })
        url = reverse('download_pipeline_migration_api', args=[self.pipeline.id]) + "?format=alembic"
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)
        self.assertIn("attachment; filename=", res["Content-Disposition"])
        self.assertIn(".py", res["Content-Disposition"])
        self.assertIn("def upgrade() -> None:", res.content.decode("utf-8"))

    def test_generate_migration_unauthenticated(self):
        url = reverse('generate_pipeline_migration_api', args=[self.pipeline.id])
        res = self.client.post(url, data=json.dumps({}), content_type="application/json")
        self.assertEqual(res.status_code, 302)


class ContractVersioningTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Version Org", plan="pro")
        self.admin = User.objects.create(
            username="ver_admin",
            email="admin@ver.com",
            password_hash=hash_password("AdminPass123!"),
            organization=self.org,
            role="admin",
            is_verified=True,
            permissions={"see": True, "create": True, "edit": True, "delete": True}
        )
        self.viewer = User.objects.create(
            username="ver_viewer",
            email="viewer@ver.com",
            password_hash=hash_password("ViewerPass123!"),
            organization=self.org,
            role="viewer",
            is_verified=True,
            permissions={"see": True, "create": False, "edit": False, "delete": False}
        )
        self.pipeline = Pipeline.objects.create(
            id="pipe-version-test-01",
            organization=self.org,
            name="Audited Orders",
            environment="prod",
            db_type="postgres",
            conn_str="postgresql://user:pass@localhost:5432/testdb",
            schema="public",
            table="orders",
            cron="0 * * * *",
            contract_yaml="columns:\n  - name: id\n    type: integer\n",
            lock_signature="1111111111111111111111111111111111111111111111111111111111111111",
            schema_map={"columns": [{"name": "id", "type": "integer"}]},
            status="Clean"
        )

    def test_list_contract_versions_auto_creates_v1_baseline(self):
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'ver_admin',
            'password': 'AdminPass123!',
        })
        url = reverse('list_contract_versions_api', args=[self.pipeline.id])
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.content)
        self.assertTrue(data["success"])
        self.assertEqual(len(data["versions"]), 1)
        self.assertEqual(data["versions"][0]["version_number"], 1)
        self.assertTrue(data["versions"][0]["is_active"])

    def test_get_version_detail(self):
        ContractVersion.objects.create(
            pipeline=self.pipeline,
            version_number=1,
            contract_yaml="columns:\n  - name: id\n    type: integer\n",
            lock_signature="1111111111111111111111111111111111111111111111111111111111111111",
            change_summary="Initial baseline",
            created_by="ver_admin"
        )
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'ver_admin',
            'password': 'AdminPass123!',
        })
        url = reverse('get_contract_version_detail_api', args=[self.pipeline.id, 1])
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.content)
        self.assertTrue(data["success"])
        self.assertEqual(data["version_number"], 1)
        self.assertIn("columns:", data["contract_yaml"])

    def test_rollback_contract_version_creates_new_version(self):
        # Create v1
        ContractVersion.objects.create(
            pipeline=self.pipeline,
            version_number=1,
            contract_yaml="columns:\n  - name: id\n    type: integer\n",
            lock_signature="1111111111111111111111111111111111111111111111111111111111111111",
            change_summary="Initial baseline v1",
            created_by="ver_admin"
        )
        # Create v2 and mutate pipeline to v2
        ContractVersion.objects.create(
            pipeline=self.pipeline,
            version_number=2,
            contract_yaml="columns:\n  - name: id\n    type: integer\n  - name: bad_col\n    type: text\n",
            lock_signature="2222222222222222222222222222222222222222222222222222222222222222",
            change_summary="Faulty change v2",
            created_by="ver_admin"
        )
        self.pipeline.contract_yaml = "columns:\n  - name: id\n    type: integer\n  - name: bad_col\n    type: text\n"
        self.pipeline.lock_signature = "2222222222222222222222222222222222222222222222222222222222222222"
        self.pipeline.status = "Drifted"
        self.pipeline.save()

        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'ver_admin',
            'password': 'AdminPass123!',
        })
        url = reverse('rollback_contract_version_api', args=[self.pipeline.id, 1])
        res = self.client.post(url)
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.content)
        self.assertTrue(data["success"])
        self.assertEqual(data["restored_version"], 1)
        self.assertEqual(data["new_version"], 3)

        # Verify pipeline state restored to v1
        self.pipeline.refresh_from_db()
        self.assertEqual(self.pipeline.lock_signature, "1111111111111111111111111111111111111111111111111111111111111111")
        self.assertNotIn("bad_col", self.pipeline.contract_yaml)
        self.assertEqual(self.pipeline.status, "Clean")

        # Verify AuditLog logged
        log = AuditLog.objects.filter(action="contract.rollback", actor="ver_admin").first()
        self.assertIsNotNone(log)
        self.assertEqual(log.details.get("restored_version"), 1)

    def test_rollback_viewer_role_rejected_403(self):
        ContractVersion.objects.create(
            pipeline=self.pipeline,
            version_number=1,
            contract_yaml="columns:\n  - name: id\n    type: integer\n",
            lock_signature="1111111111111111111111111111111111111111111111111111111111111111",
            change_summary="Initial baseline v1",
            created_by="ver_admin"
        )
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'ver_viewer',
            'password': 'ViewerPass123!',
        })
        url = reverse('rollback_contract_version_api', args=[self.pipeline.id, 1])
        res = self.client.post(url)
        self.assertEqual(res.status_code, 403)

    def test_rollback_nonexistent_version_404(self):
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'ver_admin',
            'password': 'AdminPass123!',
        })
        url = reverse('rollback_contract_version_api', args=[self.pipeline.id, 999])
        res = self.client.post(url)
        self.assertEqual(res.status_code, 404)


class CiCdGateTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="CI Org", plan="pro")
        self.raw_api_key = "sg_live_secret_key_12345"
        self.api_key = ApiKey.objects.create(
            name="CI Pipeline Key",
            key_hash=hash_api_key(self.raw_api_key),
            organization=self.org,
            is_active=True
        )
        self.pipeline = Pipeline.objects.create(
            id="pipe-ci-test-01",
            organization=self.org,
            name="Production Orders",
            environment="prod",
            db_type="postgres",
            conn_str="postgresql://user:pass@localhost:5432/testdb",
            schema="public",
            table="orders",
            cron="0 * * * *",
            contract_yaml=(
                "columns:\n"
                "  - name: id\n"
                "    type: integer\n"
                "    nullable: false\n"
                "  - name: customer_id\n"
                "    type: integer\n"
                "    nullable: false\n"
                "  - name: amount\n"
                "    type: numeric(10,2)\n"
                "    nullable: true\n"
            ),
            lock_signature="9999999999999999999999999999999999999999999999999999999999999999",
            status="Clean"
        )

    def test_ci_gate_passed_with_compatible_schema(self):
        url = reverse('ci_cd_gate_api')
        payload = {
            "pipeline_id": self.pipeline.id,
            "branch": "feature/add-notes",
            "commit_sha": "abc1234567890",
            "schema": {
                "columns": [
                    {"name": "id", "type": "integer", "nullable": False},
                    {"name": "customer_id", "type": "integer", "nullable": False},
                    {"name": "amount", "type": "numeric(10,2)", "nullable": True},
                    {"name": "notes", "type": "text", "nullable": True}
                ]
            }
        }
        res = self.client.post(
            url,
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_X_SCHEMA_GUARD_TOKEN=self.raw_api_key
        )
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.content)
        self.assertTrue(data["passed"])
        self.assertEqual(data["status"], "PASSED")
        self.assertEqual(data["exit_code"], 0)
        self.assertEqual(data["violations_count"], 0)
        self.assertIn("PASSED", data["github_markdown"])
        self.assertIn("Production Orders", data["github_markdown"])

    def test_ci_gate_blocked_when_contract_column_missing(self):
        url = reverse('ci_cd_gate_api')
        # Missing 'amount' which is defined in contract
        payload = {
            "pipeline_id": self.pipeline.id,
            "branch": "feature/drop-amount",
            "schema": {
                "columns": [
                    {"name": "id", "type": "integer", "nullable": False},
                    {"name": "customer_id", "type": "integer", "nullable": False}
                ]
            }
        }
        res = self.client.post(
            url,
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_X_SCHEMA_GUARD_TOKEN=self.raw_api_key
        )
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.content)
        self.assertFalse(data["passed"])
        self.assertEqual(data["status"], "BLOCKED")
        self.assertEqual(data["exit_code"], 1)
        self.assertGreaterEqual(data["violations_count"], 1)
        self.assertIn("BLOCKED", data["github_markdown"])
        self.assertIn("Missing column 'amount'", data["violations"][0])

    def test_ci_gate_by_table_name_resolution(self):
        url = reverse('ci_cd_gate_api')
        payload = {
            "table": "orders",
            "environment": "prod",
            "schema": {
                "columns": [
                    {"name": "id", "type": "integer", "nullable": False},
                    {"name": "customer_id", "type": "integer", "nullable": False},
                    {"name": "amount", "type": "numeric(10,2)", "nullable": True}
                ]
            }
        }
        res = self.client.post(
            url,
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_X_SCHEMA_GUARD_TOKEN=self.raw_api_key
        )
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.content)
        self.assertTrue(data["passed"])
        self.assertEqual(data["pipeline"]["id"], self.pipeline.id)

    def test_ci_gate_unauthorized_missing_token(self):
        url = reverse('ci_cd_gate_api')
        payload = {"pipeline_id": self.pipeline.id}
        res = self.client.post(
            url,
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 401)

    def test_ci_workflow_template_github(self):
        url = reverse('ci_cd_workflow_template_api') + f"?pipeline_id={self.pipeline.id}&platform=github"
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.content)
        self.assertEqual(data["filename"], ".github/workflows/schema-guard.yml")
        self.assertIn("actions/checkout", data["content"])
        self.assertIn(self.pipeline.id, data["content"])

    def test_ci_workflow_template_download(self):
        url = reverse('ci_cd_workflow_template_api') + f"?pipeline_id={self.pipeline.id}&platform=github&download=1"
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)
        self.assertIn("attachment; filename=", res["Content-Disposition"])
        self.assertIn("schema-guard.yml", res["Content-Disposition"])


class ScheduledCronRunnerTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Cron Org", plan="pro")
        self.admin = User.objects.create(
            username="cron_admin",
            email="admin@cron.com",
            password_hash=hash_password("CronPass123!"),
            organization=self.org,
            role="admin",
            is_verified=True,
            permissions={"see": True, "create": True, "edit": True, "delete": True}
        )
        self.pipeline = Pipeline.objects.create(
            id="pipe-cron-test-01",
            organization=self.org,
            name="Daily Orders",
            environment="prod",
            db_type="postgres",
            conn_str="postgresql://user:pass@localhost:5432/testdb",
            schema="public",
            table="orders",
            cron="0 0 * * *",
            contract_yaml="columns:\n  - name: id\n    type: integer\n",
            lock_signature="1111111111111111111111111111111111111111111111111111111111111111",
            status="Clean"
        )

    def test_is_pipeline_due_with_none_last_checked(self):
        from core.management.commands.run_scheduled_checks import is_pipeline_due
        from datetime import datetime, timezone
        self.pipeline.last_checked = None
        self.assertTrue(is_pipeline_due(self.pipeline, datetime.now(timezone.utc)))

    def test_is_pipeline_due_with_past_cron(self):
        from core.management.commands.run_scheduled_checks import is_pipeline_due
        from datetime import datetime, timezone, timedelta
        # Last checked 2 days ago for a daily cron -> definitely due
        self.pipeline.last_checked = datetime.now(timezone.utc) - timedelta(days=2)
        self.assertTrue(is_pipeline_due(self.pipeline, datetime.now(timezone.utc)))

    def test_is_pipeline_not_due_when_recently_checked(self):
        from core.management.commands.run_scheduled_checks import is_pipeline_due
        from datetime import datetime, timezone, timedelta
        # Last checked 5 minutes ago for a daily cron -> NOT due
        self.pipeline.last_checked = datetime.now(timezone.utc) - timedelta(minutes=5)
        self.assertFalse(is_pipeline_due(self.pipeline, datetime.now(timezone.utc)))

    @patch('core.management.commands.run_scheduled_checks.perform_pipeline_check')
    def test_execute_pipeline_sweep_with_force(self, mock_check):
        mock_check.return_value = {"status": "Clean", "logs": []}
        from core.management.commands.run_scheduled_checks import execute_pipeline_sweep
        stats = execute_pipeline_sweep(pipeline_id_filter=self.pipeline.id, force=True)
        self.assertEqual(stats["total_monitored"], 1)
        self.assertEqual(stats["executed_count"], 1)
        self.assertEqual(stats["clean_count"], 1)
        self.assertEqual(stats["drifted_count"], 0)
        mock_check.assert_called_once_with(self.pipeline.id)

    @patch('core.management.commands.run_scheduled_checks.perform_pipeline_check')
    def test_run_scheduled_sweep_api(self, mock_check):
        mock_check.return_value = {"status": "Clean", "logs": []}
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'cron_admin',
            'password': 'CronPass123!',
        })
        url = reverse('run_scheduled_sweep_api')
        res = self.client.post(url, data=json.dumps({"force": True}), content_type="application/json")
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.content)
        self.assertTrue(data["success"])
        self.assertIn("stats", data)
        self.assertGreaterEqual(data["stats"]["executed_count"], 1)


class WebhookDeliveryTests(TestCase):
    def setUp(self):
        from core.models import Organization, User, Pipeline
        from core.views import hash_password
        self.org = Organization.objects.create(name="Webhook Org", plan="pro")
        self.user = User.objects.create(
            username="wh_user",
            email="wh_user@example.com",
            password_hash=hash_password("WhPass123!"),
            organization=self.org,
            role="admin",
            is_verified=True,
            permissions={"see": True, "create": True, "edit": True, "delete": True}
        )
        self.pipeline = Pipeline.objects.create(
            id="pipe-wh-test-01",
            organization=self.org,
            name="Analytics Ingestion",
            environment="prod",
            db_type="postgres",
            conn_str="postgresql://user:pass@localhost:5432/testdb",
            schema="public",
            table="events",
            contract_yaml="columns:\n  - name: event_id\n    type: varchar\n",
            alerts={"webhook": "https://hooks.external.com/schema-events", "webhook_secret": "whsec_test_secret_123"},
            status="Clean"
        )

    def test_hmac_signature_generation_and_verification(self):
        from core.notifications import sign_webhook_payload, verify_webhook_signature
        payload_bytes = b'{"event":"schema_drift","violations":["MISSING COLUMN: age"]}'
        secret = "super_secure_key_456"

        sig = sign_webhook_payload(payload_bytes, secret)
        self.assertTrue(len(sig) == 64)  # SHA256 hex digest length
        self.assertTrue(verify_webhook_signature(payload_bytes, secret, f"sha256={sig}"))
        self.assertFalse(verify_webhook_signature(payload_bytes, "wrong_secret", f"sha256={sig}"))
        self.assertFalse(verify_webhook_signature(b'different payload', secret, f"sha256={sig}"))

    @patch('urllib.request.urlopen')
    def test_dispatch_signed_webhook_success_creates_log(self, mock_urlopen):
        from io import BytesIO
        from unittest.mock import MagicMock
        from core.notifications import dispatch_signed_webhook
        from core.models import WebhookDeliveryLog

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"received": true}'
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        payload = {"event": "schema_drift", "pipeline": "Analytics Ingestion"}
        ok, msg, meta = dispatch_signed_webhook(
            url="https://hooks.external.com/schema-events",
            payload=payload,
            secret="whsec_test_secret_123",
            event="schema_guard.drift_detected",
            pipeline=self.pipeline,
            allow_internal=True
        )

        self.assertTrue(ok)
        self.assertEqual(meta["status_code"], 200)

        log = WebhookDeliveryLog.objects.filter(pipeline=self.pipeline).first()
        self.assertIsNotNone(log)
        self.assertTrue(log.success)
        self.assertEqual(log.status_code, 200)
        self.assertEqual(log.event, "schema_guard.drift_detected")
        self.assertIn("X-Schema-Guard-Signature", log.request_headers)
        self.assertIn("masked", log.request_headers["X-Schema-Guard-Signature"].lower())

    def test_dispatch_signed_webhook_ssrf_blocked(self):
        from core.notifications import dispatch_signed_webhook
        from core.models import WebhookDeliveryLog

        ok, msg, meta = dispatch_signed_webhook(
            url="http://169.254.169.254/latest/meta-data",
            payload={"event": "test"},
            allow_internal=False
        )
        self.assertFalse(ok)
        self.assertIn("SSRF", msg)
        log = WebhookDeliveryLog.objects.filter(url__contains="169.254.169.254").first()
        self.assertIsNotNone(log)
        self.assertFalse(log.success)

    def test_get_webhook_logs_api(self):
        from core.models import WebhookDeliveryLog
        WebhookDeliveryLog.objects.create(
            pipeline=self.pipeline,
            url="https://hooks.external.com/schema-events",
            event="schema_guard.drift_detected",
            status_code=200,
            success=True,
            latency_ms=120,
            request_payload={"event": "drift"}
        )

        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'wh_user',
            'password': 'WhPass123!',
        })
        url = reverse('get_webhook_logs_api', args=[self.pipeline.id])
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)
        logs = json.loads(res.content)
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["status_code"], 200)
        self.assertTrue(logs[0]["success"])

    @patch('urllib.request.urlopen')
    def test_retry_webhook_log_api(self, mock_urlopen):
        from unittest.mock import MagicMock
        from core.models import WebhookDeliveryLog, AuditLog

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"ok": true}'
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        failed_log = WebhookDeliveryLog.objects.create(
            pipeline=self.pipeline,
            url="https://hooks.external.com/schema-events",
            event="schema_guard.drift_detected",
            status_code=500,
            success=False,
            latency_ms=45,
            request_payload={"event": "drift", "retry": True}
        )

        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'wh_user',
            'password': 'WhPass123!',
        })
        url = reverse('retry_webhook_log_api', args=[self.pipeline.id, failed_log.id])
        res = self.client.post(url)
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.content)
        self.assertTrue(data["success"])

        audit = AuditLog.objects.filter(action="webhook.delivery", actor="wh_user").first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.details.get("action"), "retry_webhook")


class ComplianceReportTests(TestCase):
    def setUp(self):
        from core.models import Organization, User, Pipeline, GateValidationLog
        from core.views import hash_password

        self.org = Organization.objects.create(name="Acme Corp Enterprise", plan="enterprise")
        self.user = User.objects.create(
            username="compliance_officer",
            email="officer@acme.com",
            password_hash=hash_password("CompliancePass123!"),
            organization=self.org,
            role="admin",
            is_verified=True,
            permissions={"see": True, "create": True, "edit": True, "delete": True}
        )
        self.pipeline1 = Pipeline.objects.create(
            id="pipe-comp-01",
            organization=self.org,
            name="Billing Engine",
            environment="prod",
            db_type="postgres",
            conn_str="postgresql://user:pass@localhost:5432/testdb",
            schema="public",
            table="invoices",
            contract_yaml="columns:\n  - name: inv_id\n    type: varchar\n",
            lock_signature="f" * 64,
            schema_map={"inv_id": "varchar", "amount": "decimal"},
            status="Clean"
        )
        self.pipeline2 = Pipeline.objects.create(
            id="pipe-comp-02",
            organization=self.org,
            name="Inventory Stream",
            environment="prod",
            db_type="mysql",
            conn_str="mysql://user:pass@localhost:3306/testdb",
            schema="inventory",
            table="items",
            contract_yaml="columns:\n  - name: sku\n    type: varchar\n",
            lock_signature="e" * 64,
            schema_map={"sku": "varchar"},
            status="Drifted"
        )
        GateValidationLog.objects.create(
            pipeline=self.pipeline1,
            commit_sha="abcdef1234567890abcdef1234567890abcdef12",
            branch="feature/invoice-uuid",
            status="PASS",
            violations_count=0
        )
        GateValidationLog.objects.create(
            pipeline=self.pipeline2,
            commit_sha="9876543210fedcba9876543210fedcba98765432",
            branch="fix/drop-sku",
            status="FAIL",
            violations_count=1
        )

    def test_compliance_report_json_export(self):
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'compliance_officer',
            'password': 'CompliancePass123!',
        })
        url = reverse('compliance_report_export_api')
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res['Content-Type'], 'application/json')
        data = json.loads(res.content)

        summary = data["compliance_summary"]
        self.assertEqual(summary["organization"], "Acme Corp Enterprise")
        self.assertIn("cryptographic_seal", summary)
        self.assertTrue(summary["cryptographic_seal"].startswith("sha256:"))

        metrics = summary["metrics"]
        self.assertEqual(metrics["total_monitored_pipelines"], 2)
        self.assertEqual(metrics["clean_pipelines"], 1)
        self.assertEqual(metrics["drifted_pipelines"], 1)
        self.assertEqual(metrics["contract_adherence_rate_pct"], 50.0)
        self.assertEqual(metrics["ci_cd_gate_evaluations"], 2)
        self.assertEqual(metrics["ci_cd_blocked_breaking_changes"], 1)
        self.assertEqual(metrics["ci_cd_gate_pass_rate_pct"], 50.0)

        # Baseline registry check
        baselines = data["contract_baselines"]
        self.assertEqual(len(baselines), 2)
        self.assertEqual(baselines[0]["lock_signature"], "f" * 64)

        # Gate evidence check
        gates = data["cicd_gate_evidence"]
        self.assertEqual(len(gates), 2)

    def test_compliance_report_csv_export(self):
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'compliance_officer',
            'password': 'CompliancePass123!',
        })
        url = reverse('compliance_report_export_api') + "?format=csv"
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res['Content-Type'], 'text/csv')
        csv_text = res.content.decode('utf-8')
        self.assertIn("SCHEMA GUARD SOC2 & ISO 27001 COMPLIANCE EVIDENCE PACK", csv_text)
        self.assertIn("Acme Corp Enterprise", csv_text)
        self.assertIn("Contract Adherence Rate Pct", csv_text)
        self.assertIn("Billing Engine", csv_text)
        self.assertIn("Inventory Stream", csv_text)


class PipelineAutoRepairTests(TestCase):
    def setUp(self):
        from core.models import Organization, User, Pipeline
        from core.views import hash_password

        self.org = Organization.objects.create(name="Repair Org", plan="enterprise")
        self.user = User.objects.create(
            username="repair_admin",
            email="repair@org.com",
            password_hash=hash_password("RepairPass123!"),
            organization=self.org,
            role="admin",
            is_verified=True,
            permissions={"see": True, "create": True, "edit": True, "delete": True}
        )
        self.pipeline = Pipeline.objects.create(
            id="pipe-repair-01",
            organization=self.org,
            name="Payments Repair",
            environment="prod",
            db_type="sqlite",
            conn_str="sqlite:///:memory:",
            schema="",
            table="payments",
            contract_yaml="columns:\n  - name: id\n    type: integer\n  - name: currency\n    type: varchar\n",
            lock_signature="a" * 64,
            schema_map={"id": "integer", "currency": "varchar"},
            status="Drifted"
        )

    @patch('core.migration_generator.generate_migration_bundle')
    def test_auto_repair_no_drift_needed(self, mock_bundle):
        mock_bundle.return_value = {
            "diff_count": 0,
            "risk_summary": {"safe": 0, "warning": 0, "breaking": 0, "total": 0},
            "diffs": [],
            "sql": {"up": "", "down": ""}
        }
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'repair_admin',
            'password': 'RepairPass123!',
        })
        url = reverse('auto_repair_pipeline_api', args=[self.pipeline.id])
        res = self.client.post(url, data=json.dumps({}), content_type="application/json")
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.content)
        self.assertTrue(data["success"])
        self.assertFalse(data["repaired"])
        self.assertIn("No repair needed", data["message"])

    @patch('core.migration_generator.generate_migration_bundle')
    def test_auto_repair_blocks_destructive_without_flag(self, mock_bundle):
        mock_bundle.return_value = {
            "diff_count": 1,
            "risk_summary": {"safe": 0, "warning": 0, "breaking": 1, "total": 1},
            "diffs": [{"action": "drop_column", "column": "secret_key", "risk": "BREAKING"}],
            "sql": {"up": "ALTER TABLE payments DROP COLUMN secret_key;", "down": ""}
        }
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'repair_admin',
            'password': 'RepairPass123!',
        })
        url = reverse('auto_repair_pipeline_api', args=[self.pipeline.id])
        res = self.client.post(url, data=json.dumps({"allow_destructive": False}), content_type="application/json")
        self.assertEqual(res.status_code, 400)
        data = json.loads(res.content)
        self.assertIn("Safety Guard", data["detail"])
        self.assertIn("allow_destructive=true", data["detail"])

    @patch('core.migration_generator.generate_migration_bundle')
    def test_auto_repair_dry_run(self, mock_bundle):
        mock_bundle.return_value = {
            "diff_count": 1,
            "risk_summary": {"safe": 1, "warning": 0, "breaking": 0, "total": 1},
            "diffs": [{"action": "add_column", "column": "currency", "risk": "SAFE"}],
            "sql": {"up": "ALTER TABLE payments ADD COLUMN currency VARCHAR(10);", "down": ""}
        }
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'repair_admin',
            'password': 'RepairPass123!',
        })
        url = reverse('auto_repair_pipeline_api', args=[self.pipeline.id])
        res = self.client.post(url, data=json.dumps({"dry_run": True}), content_type="application/json")
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.content)
        self.assertTrue(data["success"])
        self.assertTrue(data["dry_run"])
        self.assertEqual(len(data["statements_to_execute"]), 1)
        self.assertIn("ADD COLUMN currency", data["statements_to_execute"][0])

    @patch('core.views.perform_pipeline_check')
    @patch('core.views.create_db_engine')
    @patch('core.migration_generator.generate_migration_bundle')
    def test_auto_repair_safe_execution_and_audit(self, mock_bundle, mock_create_engine, mock_check):
        from unittest.mock import MagicMock
        from core.models import AuditLog

        mock_bundle.return_value = {
            "diff_count": 1,
            "risk_summary": {"safe": 1, "warning": 0, "breaking": 0, "total": 1},
            "diffs": [{"action": "add_column", "column": "currency", "risk": "SAFE"}],
            "sql": {"up": "ALTER TABLE payments ADD COLUMN currency VARCHAR(10);", "down": ""}
        }
        mock_engine = MagicMock()
        mock_conn = MagicMock()
        mock_engine.begin.return_value.__enter__.return_value = mock_conn
        mock_create_engine.return_value = (mock_engine, {})
        mock_check.return_value = {"status": "Clean", "logs": []}

        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'repair_admin',
            'password': 'RepairPass123!',
        })
        url = reverse('auto_repair_pipeline_api', args=[self.pipeline.id])
        res = self.client.post(url, data=json.dumps({"dry_run": False}), content_type="application/json")
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.content)
        self.assertTrue(data["success"])
        self.assertTrue(data["repaired"])
        self.assertEqual(len(data["executed_statements"]), 1)

        # Check AuditLog
        log = AuditLog.objects.filter(action="pipeline.auto_repaired", actor="repair_admin").first()
        self.assertIsNotNone(log)
        self.assertEqual(log.target_id, self.pipeline.id)
        self.assertEqual(len(log.details.get("executed_statements")), 1)


class DriftIncidentTests(TestCase):
    def setUp(self):
        from core.models import Organization, User, Pipeline, DriftIncident
        from core.views import hash_password

        self.org = Organization.objects.create(name="Incident Ops Org", plan="enterprise")
        self.user = User.objects.create(
            username="incident_lead",
            email="lead@ops.com",
            password_hash=hash_password("OpsPass123!"),
            organization=self.org,
            role="admin",
            is_verified=True,
            permissions={"see": True, "create": True, "edit": True, "delete": True}
        )
        self.pipeline = Pipeline.objects.create(
            id="pipe-inc-01",
            organization=self.org,
            name="Checkout Service",
            environment="prod",
            db_type="postgres",
            conn_str="postgresql://user:pass@localhost:5432/testdb",
            schema="public",
            table="orders",
            contract_yaml="columns:\n  - name: order_id\n    type: varchar\n",
            lock_signature="b" * 64,
            schema_map={"order_id": "varchar"},
            status="Clean"
        )

    def test_list_drift_incidents_api_and_metrics(self):
        from core.models import DriftIncident
        DriftIncident.objects.create(
            incident_number="INC-2026-0001",
            pipeline=self.pipeline,
            status="OPEN",
            severity="CRITICAL",
            title="Dropped column 'amount'",
            violations=["DROPPED COLUMN: amount"],
            violations_count=1
        )
        DriftIncident.objects.create(
            incident_number="INC-2026-0002",
            pipeline=self.pipeline,
            status="RESOLVED",
            severity="HIGH",
            title="Type mismatch 'status'",
            violations=["TYPE MISMATCH: status"],
            violations_count=1,
            mttr_seconds=300
        )

        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'incident_lead',
            'password': 'OpsPass123!',
        })
        url = reverse('list_drift_incidents_api')
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.content)
        self.assertEqual(len(data["incidents"]), 2)
        metrics = data["metrics"]
        self.assertEqual(metrics["total"], 2)
        self.assertEqual(metrics["open"], 1)
        self.assertEqual(metrics["resolved"], 1)
        self.assertEqual(metrics["avg_mttr_minutes"], 5.0)

    def test_acknowledge_and_resolve_drift_incident_api(self):
        from core.models import DriftIncident, AuditLog
        inc = DriftIncident.objects.create(
            incident_number="INC-2026-0003",
            pipeline=self.pipeline,
            status="OPEN",
            severity="CRITICAL",
            title="Critical schema drift on orders",
            violations=["DROPPED COLUMN: tax_id"],
            violations_count=1
        )

        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'incident_lead',
            'password': 'OpsPass123!',
        })
        # Acknowledge
        ack_url = reverse('acknowledge_drift_incident_api', args=[inc.incident_number])
        ack_res = self.client.post(ack_url)
        self.assertEqual(ack_res.status_code, 200)
        inc.refresh_from_db()
        self.assertEqual(inc.status, "ACKNOWLEDGED")
        self.assertEqual(inc.acknowledged_by, "incident_lead")

        # Resolve
        res_url = reverse('resolve_drift_incident_api', args=[inc.incident_number])
        res_res = self.client.post(
            res_url,
            data=json.dumps({"resolution_notes": "Added missing tax_id column via migration script"}),
            content_type="application/json"
        )
        self.assertEqual(res_res.status_code, 200)
        inc.refresh_from_db()
        self.assertEqual(inc.status, "RESOLVED")
        self.assertEqual(inc.resolved_by, "incident_lead")
        self.assertIsNotNone(inc.mttr_seconds)

        # AuditLog verification
        audit = AuditLog.objects.filter(action="incident.resolve", target_id=inc.incident_number).first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.details.get("resolution_notes"), "Added missing tax_id column via migration script")

    def test_snooze_drift_incident_api(self):
        from core.models import DriftIncident
        inc = DriftIncident.objects.create(
            incident_number="INC-2026-0004",
            pipeline=self.pipeline,
            status="OPEN",
            severity="MEDIUM",
            title="Non-breaking warning",
            violations=["ADDED COLUMN: promo_code"],
            violations_count=1
        )

        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'incident_lead',
            'password': 'OpsPass123!',
        })
        url = reverse('snooze_drift_incident_api', args=[inc.incident_number])
        res = self.client.post(url, data=json.dumps({"hours": 8}), content_type="application/json")
        self.assertEqual(res.status_code, 200)
        inc.refresh_from_db()
        self.assertEqual(inc.status, "SNOOZED")
        self.assertIsNotNone(inc.snoozed_until)


class SchemaTimelineTests(TestCase):
    def setUp(self):
        from core.models import Organization, User, Pipeline, SchemaSnapshot, ContractVersion, DriftIncident
        from core.views import hash_password

        self.org = Organization.objects.create(name="Timeline Org", plan="enterprise")
        self.user = User.objects.create(
            username="timeline_analyst",
            email="analyst@timeline.com",
            password_hash=hash_password("TimePass123!"),
            organization=self.org,
            role="admin",
            is_verified=True,
            permissions={"see": True, "create": True, "edit": True, "delete": True}
        )
        self.pipeline = Pipeline.objects.create(
            id="pipe-time-01",
            organization=self.org,
            name="Subscriptions Engine",
            environment="prod",
            db_type="postgres",
            conn_str="postgresql://user:pass@localhost:5432/testdb",
            schema="public",
            table="subscriptions",
            contract_yaml="columns:\n  - name: sub_id\n    type: varchar\n",
            lock_signature="c" * 64,
            schema_map={"sub_id": "varchar"},
            status="Clean"
        )
        self.snap1 = SchemaSnapshot.objects.create(
            pipeline=self.pipeline,
            version=1,
            schema_data={"columns": [{"name": "sub_id", "type": "varchar"}, {"name": "plan", "type": "varchar"}]},
            status="Clean",
            captured_by="system"
        )
        self.snap2 = SchemaSnapshot.objects.create(
            pipeline=self.pipeline,
            version=2,
            schema_data={"columns": [{"name": "sub_id", "type": "varchar"}, {"name": "plan", "type": "varchar"}, {"name": "tier_code", "type": "integer"}]},
            status="Drifted",
            captured_by="migration"
        )
        ContractVersion.objects.create(
            pipeline=self.pipeline,
            version_number=1,
            contract_yaml="columns:\n  - name: sub_id\n    type: varchar\n",
            lock_signature="c" * 64,
            change_summary="Initial contract baseline"
        )
        DriftIncident.objects.create(
            incident_number="INC-2026-9999",
            pipeline=self.pipeline,
            status="RESOLVED",
            severity="MEDIUM",
            title="Added tier_code",
            violations=["ADDED COLUMN: tier_code"],
            mttr_seconds=120
        )

    def test_get_pipeline_timeline_api(self):
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'timeline_analyst',
            'password': 'TimePass123!',
        })
        url = reverse('get_pipeline_timeline_api', args=[self.pipeline.id])
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.content)
        self.assertTrue(data["success"])
        self.assertEqual(data["pipeline_id"], self.pipeline.id)
        timeline = data["timeline"]
        self.assertGreaterEqual(len(timeline), 4)

        event_types = {e["event_type"] for e in timeline}
        self.assertIn("snapshot", event_types)
        self.assertIn("contract_version", event_types)
        self.assertIn("incident", event_types)

    def test_diff_pipeline_timeline_api_snapshots(self):
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'timeline_analyst',
            'password': 'TimePass123!',
        })
        url = reverse('diff_pipeline_timeline_api', args=[self.pipeline.id]) + f"?snap1={self.snap1.id}&snap2={self.snap2.id}"
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.content)
        self.assertTrue(data["success"])

        diff_summary = data["diff_summary"]
        self.assertEqual(diff_summary["added_count"], 1)
        self.assertEqual(diff_summary["removed_count"], 0)
        self.assertFalse(diff_summary["has_breaking_changes"])
        self.assertEqual(data["added_columns"][0]["name"], "tier_code")

    def test_diff_pipeline_timeline_api_breaking_change(self):
        # Diff snap2 -> snap1 (removing tier_code)
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'timeline_analyst',
            'password': 'TimePass123!',
        })
        url = reverse('diff_pipeline_timeline_api', args=[self.pipeline.id]) + f"?snap1={self.snap2.id}&snap2={self.snap1.id}"
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.content)
        diff_summary = data["diff_summary"]
        self.assertEqual(diff_summary["removed_count"], 1)
        self.assertTrue(diff_summary["has_breaking_changes"])
        self.assertEqual(data["removed_columns"][0]["name"], "tier_code")


class ColumnDataQualityRulesTests(TestCase):
    def setUp(self):
        from core.models import Organization, User, Pipeline
        from core.views import hash_password

        self.org = Organization.objects.create(name="DQ Rules Org", plan="enterprise")
        self.user = User.objects.create(
            username="dq_engineer",
            email="dq@rules.com",
            password_hash=hash_password("DqPass123!"),
            organization=self.org,
            role="admin",
            is_verified=True,
            permissions={"see": True, "create": True, "edit": True, "delete": True}
        )
        self.pipeline = Pipeline.objects.create(
            id="pipe-dq-01",
            organization=self.org,
            name="Invoicing Ledger",
            environment="prod",
            db_type="postgres",
            conn_str="postgresql://user:pass@localhost:5432/testdb",
            schema="public",
            table="invoices",
            contract_yaml="""columns:
  - name: inv_id
    type: varchar
    primary_key: true
  - name: status
    type: varchar
    nullable: false
  - name: amount
    type: numeric
""",
            lock_signature="d" * 64,
            schema_map={"inv_id": "varchar", "status": "varchar", "amount": "numeric"},
            status="Clean"
        )

    def test_get_pipeline_dq_rules_api(self):
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'dq_engineer',
            'password': 'DqPass123!',
        })
        url = reverse('pipeline_dq_rules_api', args=[self.pipeline.id])
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.content)
        self.assertTrue(data["success"])
        self.assertEqual(data["total_rules"], 3)
        cols = {r["column"]: r for r in data["rules"]}
        self.assertTrue(cols["inv_id"]["primary_key"])
        self.assertFalse(cols["status"]["nullable"])

    @patch('core.views.lock_contract')
    def test_update_pipeline_dq_rules_api(self, mock_lock):
        mock_lock.return_value = "e" * 64
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'dq_engineer',
            'password': 'DqPass123!',
        })
        url = reverse('pipeline_dq_rules_api', args=[self.pipeline.id])
        res = self.client.post(
            url,
            data=json.dumps({
                "rules": [
                    {"column": "status", "allowed_values": ["PAID", "PENDING", "REFUNDED"]},
                    {"column": "amount", "min_value": 0, "max_value": 1000000}
                ]
            }),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.content)
        self.assertTrue(data["success"])

        self.pipeline.refresh_from_db()
        import yaml
        doc = yaml.safe_load(self.pipeline.contract_yaml)
        cols = {c["name"]: c for c in doc["columns"]}
        self.assertEqual(cols["status"]["allowed_values"], ["PAID", "PENDING", "REFUNDED"])
        self.assertEqual(cols["amount"]["min_value"], 0)
        self.assertEqual(cols["amount"]["max_value"], 1000000)

    def test_perform_data_quality_validation_with_enum_and_range_sqlite(self):
        import sqlite3
        import tempfile
        import os
        from core.views import perform_data_quality_validation

        # Create temporary sqlite db with test data
        fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            conn = sqlite3.connect(db_path)
            conn.execute("CREATE TABLE orders (id INT PRIMARY KEY, status TEXT, amount REAL);")
            conn.execute("INSERT INTO orders VALUES (1, 'PAID', 50.0);")
            conn.execute("INSERT INTO orders VALUES (2, 'PENDING', 120.0);")
            conn.commit()
            conn.close()

            schema_cols = [
                {"name": "id", "primary_key": True},
                {"name": "status", "allowed_values": ["PAID", "PENDING", "CANCELLED"]},
                {"name": "amount", "min_value": 0, "max_value": 500}
            ]

            # 1. Passes all constraints
            res = perform_data_quality_validation(
                db_type="sqlite",
                conn_str=f"sqlite:///{db_path}",
                schema_name="",
                table_name="orders",
                schema_columns=schema_cols
            )
            self.assertEqual(res["status"], "PASS", msg=f"Checks: {res.get('checks')}")

            # 2. Insert invalid enum value -> should FAIL
            conn = sqlite3.connect(db_path)
            conn.execute("INSERT INTO orders VALUES (3, 'UNKNOWN_STATUS', 20.0);")
            conn.commit()
            conn.close()

            res_fail = perform_data_quality_validation(
                db_type="sqlite",
                conn_str=f"sqlite:///{db_path}",
                schema_name="",
                table_name="orders",
                schema_columns=schema_cols
            )
            self.assertEqual(res_fail["status"], "FAIL")
            enum_check = [c for c in res_fail["checks"] if c["name"] == "Enum Domain Compliance"][0]
            self.assertEqual(enum_check["status"], "FAIL")
            self.assertIn("out-of-domain", enum_check["metric"])
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)


class MultiChannelAlertRoutingTests(TestCase):
    def setUp(self):
        from core.models import Organization, User, Pipeline
        from core.views import hash_password

        self.org = Organization.objects.create(name="Routing Ops Org", plan="enterprise")
        self.user = User.objects.create(
            username="routing_lead",
            email="lead@routing.com",
            password_hash=hash_password("RoutePass123!"),
            organization=self.org,
            role="admin",
            is_verified=True,
            permissions={"see": True, "create": True, "edit": True, "delete": True}
        )
        self.pipeline = Pipeline.objects.create(
            id="pipe-route-01",
            organization=self.org,
            name="Payments Ingestion PROD",
            environment="prod",
            db_type="postgres",
            conn_str="postgresql://user:pass@localhost:5432/testdb",
            schema="public",
            table="transactions",
            contract_yaml="columns:\n  - name: txn_id\n    type: varchar\n",
            lock_signature="f" * 64,
            schema_map={"txn_id": "varchar"},
            alerts={
                "email": "legacy@org.com",
                "slack": "https://hooks.slack.com/services/T00/B00/X00",
                "routing": {
                    "enabled": True,
                    "rules": [
                        {
                            "channel": "slack",
                            "target": "https://hooks.slack.com/services/T00/PROD/CRITICAL",
                            "min_severity": "CRITICAL",
                            "environments": ["prod"]
                        },
                        {
                            "channel": "email",
                            "target": "oncall-team@org.com",
                            "min_severity": "HIGH",
                            "environments": ["prod", "staging"]
                        }
                    ]
                }
            },
            status="Clean"
        )

    def test_calculate_drift_severity(self):
        from core.notifications import calculate_drift_severity
        self.assertEqual(calculate_drift_severity([]), "LOW")
        self.assertEqual(calculate_drift_severity(["COLUMN DROPPED: user_id"]), "CRITICAL")
        self.assertEqual(calculate_drift_severity([], dq_status="FAIL"), "HIGH")
        self.assertEqual(calculate_drift_severity(["COLUMN ADDED: new_feature"]), "MEDIUM")

    def test_evaluate_alert_routing_policy(self):
        from core.notifications import evaluate_alert_routing
        alerts_cfg = self.pipeline.alerts

        # 1. Critical in Prod -> matches Slack & Email
        dispatches = evaluate_alert_routing(alerts_cfg, severity="CRITICAL", environment="prod")
        channels = [d["channel"] for d in dispatches]
        self.assertIn("slack", channels)
        self.assertIn("email", channels)

        # 2. Medium in Prod -> below min_severity for both rules -> no dispatch
        dispatches_med = evaluate_alert_routing(alerts_cfg, severity="MEDIUM", environment="prod")
        self.assertEqual(len(dispatches_med), 0)

        # 3. High in Staging -> matches Email only
        dispatches_stg = evaluate_alert_routing(alerts_cfg, severity="HIGH", environment="staging")
        self.assertEqual(len(dispatches_stg), 1)
        self.assertEqual(dispatches_stg[0]["channel"], "email")

    def test_get_and_post_pipeline_alert_routing_api(self):
        self.client.post(reverse('login_or_register'), {
            'action': 'login',
            'username': 'routing_lead',
            'password': 'RoutePass123!',
        })
        url = reverse('pipeline_alert_routing_api', args=[self.pipeline.id])
        get_res = self.client.get(url)
        self.assertEqual(get_res.status_code, 200)
        data = json.loads(get_res.content)
        self.assertTrue(data["success"])
        self.assertTrue(data["routing"]["enabled"])
        self.assertEqual(len(data["routing"]["rules"]), 2)

        # Update rules via POST
        post_res = self.client.post(
            url,
            data=json.dumps({
                "enabled": True,
                "rules": [
                    {
                        "channel": "webhook",
                        "target": "https://api.internal.com/data-alerts",
                        "min_severity": "MEDIUM",
                        "environments": ["*"]
                    }
                ]
            }),
            content_type="application/json"
        )
        self.assertEqual(post_res.status_code, 200)
        self.pipeline.refresh_from_db()
        self.assertEqual(len(self.pipeline.alerts["routing"]["rules"]), 1)
        self.assertEqual(self.pipeline.alerts["routing"]["rules"][0]["channel"], "webhook")

















