"""
Schema Guard – Comprehensive Test Suite
Tests for models, views, API endpoints, authentication, and permission boundaries.
"""
import json
from django.test import TestCase, Client
from django.urls import reverse
from core.models import Organization, User, Pipeline, AuditLog, SchemaSnapshot
from core.views import hash_password, verify_password, generate_code
from unittest.mock import patch, Mock


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
        self.org = Organization.objects.create(name="dbt Org")
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
        self.org = Organization.objects.create(name="Airflow Org")
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




