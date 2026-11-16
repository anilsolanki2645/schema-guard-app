import json
from unittest.mock import patch, MagicMock
from django.test import TestCase, Client
from django.conf import settings
from core.models import User, Organization, AuditLog, Pipeline


class PricingAndShowcaseTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.org = Organization.objects.create(name="Acme Pricing Corp", plan="free", max_pipelines=5)
        self.user = User.objects.create(
            username="test_buyer",
            email="buyer@acme.com",
            password_hash="fakehash",
            role="subadmin",
            organization=self.org,
            is_verified=True
        )

    def test_pricing_page_public_access(self):
        """Pricing page must be publicly accessible without logging in."""
        res = self.client.get('/pricing')
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, "Developer")
        self.assertContains(res, "Team Pro")
        self.assertContains(res, "Enterprise")
        self.assertContains(res, "$49")
        self.assertContains(res, "$199")
        self.assertContains(res, "Detailed Plan Comparison")
        self.assertContains(res, "Frequently Asked Questions")

    def test_pricing_page_authenticated_user(self):
        """Pricing page shows active workspace and current plan for logged in user."""
        session = self.client.session
        session['user'] = {
            'username': self.user.username,
            'role': self.user.role,
            'organization_id': self.org.id,
            'permissions': {'see': True, 'create': True, 'edit': True, 'delete': True}
        }
        session.save()

        res = self.client.get('/pricing')
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, "Current Workspace:")
        self.assertContains(res, "Acme Pricing Corp")
        self.assertContains(res, "Active Plan")

    def test_docs_page_public_access(self):
        """Docs page must be publicly accessible and render all major guide sections."""
        res = self.client.get('/docs')
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, "Documentation & Developer Reference")
        self.assertContains(res, "Product Overview")
        self.assertContains(res, "How Schema Guard Works")
        self.assertContains(res, "Cryptographic Contracts")
        self.assertContains(res, "Multi-Database Connectors")
        self.assertContains(res, "CI/CD Gatekeeper")
        self.assertContains(res, "REST API Specification")

    def test_terms_page_public_access(self):
        """Terms page must be publicly accessible and render contract/liability clauses."""
        res = self.client.get('/terms')
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, "Terms of Service")
        self.assertContains(res, "Zero-Row Guarantee")
        self.assertContains(res, "Limitation of Liability")

    def test_privacy_page_public_access(self):
        """Privacy page must be publicly accessible and explain encryption & data privacy."""
        res = self.client.get('/privacy')
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, "Privacy Policy")
        self.assertContains(res, "Zero Customer Row Data")
        self.assertContains(res, "AES-256")

    def test_pipeline_badge_api(self):
        """Pipeline badge returns dynamic SVG badge for READMEs."""
        pipe = Pipeline.objects.create(
            id="pipe-badge-test-1",
            name="Badge Test Pipe",
            organization=self.org,
            status="Clean",
            db_type="postgres",
            schema="public",
            table="orders",
            cron="0 * * * *"
        )
        res = self.client.get(f'/api/pipelines/{pipe.id}/badge')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res['Content-Type'], 'image/svg+xml')
        self.assertIn(b'<svg', res.content)
        self.assertIn(b'passing', res.content)

    def test_audit_logs_export_csv(self):
        """Audit trail export returns downloadable CSV with headers."""
        session = self.client.session
        session['user'] = {
            'username': self.user.username,
            'role': self.user.role,
            'organization_id': self.org.id,
            'permissions': {'see': True, 'create': True, 'edit': True, 'delete': True}
        }
        session.save()

        AuditLog.objects.create(
            action='pipeline.create',
            target_type='pipeline',
            target_id='pipe-123',
            actor=self.user.username,
            organization=self.org,
            details={'test': True}
        )

        res = self.client.get('/api/audit-logs/export')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res['Content-Type'], 'text/csv')
        self.assertIn('attachment; filename="schema_guard_audit_trail.csv"', res['Content-Disposition'])
        self.assertIn(b'pipeline.create', res.content)




class StripeBillingTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.org = Organization.objects.create(name="Stripe Test Org", plan="free", max_pipelines=5)
        self.user = User.objects.create(
            username="billing_admin",
            email="billing@stripe-test.com",
            password_hash="fakehash",
            role="subadmin",
            organization=self.org,
            is_verified=True
        )

    def _login(self):
        session = self.client.session
        session['user'] = {
            'username': self.user.username,
            'role': self.user.role,
            'organization_id': self.org.id,
            'permissions': {'see': True, 'create': True, 'edit': True, 'delete': True}
        }
        session.save()

    def test_checkout_unauthenticated(self):
        """Unauthenticated checkout request redirects to login."""
        res = self.client.post('/api/billing/checkout', data=json.dumps({"plan": "pro"}), content_type="application/json")
        self.assertEqual(res.status_code, 302)

    def test_checkout_invalid_plan(self):
        """Invalid plan choice returns HTTP 400."""
        self._login()
        res = self.client.post('/api/billing/checkout', data=json.dumps({"plan": "invalid_plan"}), content_type="application/json")
        self.assertEqual(res.status_code, 400)
        self.assertIn("Invalid plan", res.json().get("detail", ""))

    def test_checkout_simulated_mode(self):
        """In development mode without live Stripe secret key, simulated checkout link is generated."""
        self._login()
        res = self.client.post('/api/billing/checkout', data=json.dumps({"plan": "pro"}), content_type="application/json")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data.get("status"), "success")
        self.assertTrue(data.get("simulated"))
        self.assertIn("billing=success", data.get("url"))

    @patch('stripe.Customer.create')
    @patch('stripe.checkout.Session.create')
    def test_checkout_live_stripe_mocked(self, mock_session_create, mock_customer_create):
        """With live Stripe keys configured, calls stripe SDK and returns stripe session URL."""
        self._login()
        mock_customer_create.return_value = MagicMock(id="cus_test_123")
        mock_session_create.return_value = MagicMock(id="cs_live_456", url="https://checkout.stripe.com/c/pay/cs_live_456")

        with patch.object(settings, 'STRIPE_SECRET_KEY', 'sk_live_real_key_12345'):
            res = self.client.post('/api/billing/checkout', data=json.dumps({"plan": "pro"}), content_type="application/json")
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertEqual(data.get("url"), "https://checkout.stripe.com/c/pay/cs_live_456")
            self.assertEqual(data.get("session_id"), "cs_live_456")

        # Verify audit log
        audit = AuditLog.objects.filter(action='billing.checkout_created').first()
        self.assertIsNotNone(audit)

    def test_customer_portal_api(self):
        """Customer portal returns redirect URL."""
        self._login()
        res = self.client.post('/api/billing/portal')
        self.assertEqual(res.status_code, 200)
        self.assertIn("url", res.json())

    def test_stripe_webhook_checkout_completed(self):
        """Webhook checkout.session.completed upgrades organization tier to Pro."""
        event_payload = {
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "customer": "cus_webhook_test",
                    "subscription": "sub_webhook_test",
                    "metadata": {
                        "org_id": str(self.org.id),
                        "plan": "pro"
                    }
                }
            }
        }

        res = self.client.post(
            '/api/billing/webhook',
            data=json.dumps(event_payload),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json().get("status"), "handled")

        # Reload organization from DB
        self.org.refresh_from_db()
        self.assertEqual(self.org.plan, "pro")
        self.assertEqual(self.org.max_pipelines, 50)
        self.assertEqual(self.org.stripe_customer_id, "cus_webhook_test")
        self.assertEqual(self.org.stripe_subscription_id, "sub_webhook_test")
        self.assertEqual(self.org.subscription_status, "active")

        # Check Audit Log
        audit = AuditLog.objects.filter(action='billing.subscription_updated').first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.details.get('plan'), 'pro')

    def test_stripe_webhook_subscription_deleted_downgrade(self):
        """Webhook customer.subscription.deleted downgrades organization tier back to Free."""
        self.org.plan = "pro"
        self.org.max_pipelines = 50
        self.org.stripe_customer_id = "cus_downgrade_test"
        self.org.stripe_subscription_id = "sub_downgrade_test"
        self.org.save()

        event_payload = {
            "type": "customer.subscription.deleted",
            "data": {
                "object": {
                    "customer": "cus_downgrade_test"
                }
            }
        }

        res = self.client.post(
            '/api/billing/webhook',
            data=json.dumps(event_payload),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)

        self.org.refresh_from_db()
        self.assertEqual(self.org.plan, "free")
        self.assertEqual(self.org.max_pipelines, 5)
        self.assertEqual(self.org.subscription_status, "canceled")

        # Check Audit Log
        audit = AuditLog.objects.filter(action='billing.subscription_cancelled').first()
        self.assertIsNotNone(audit)


class OAuthAuthenticationTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_github_login_redirect(self):
        """GitHub login initializes OAuth state and renders authorization flow."""
        res = self.client.get('/auth/github')
        self.assertIn(res.status_code, [200, 302])
        self.assertIn('oauth_state', self.client.session)

    def test_github_callback_invalid_state(self):
        """Callback with mismatched state token rejects."""
        session = self.client.session
        session['oauth_state'] = 'correct_state_token'
        session.save()

        res = self.client.get('/auth/github/callback?state=wrong_state&code=test_code')
        self.assertEqual(res.status_code, 302)
        self.assertIn('error_message', res.url)

    def test_github_callback_mock_dev_flow(self):
        """GitHub OAuth callback provisions new user and workspace, and signs them in."""
        session = self.client.session
        session['oauth_state'] = 'mock_valid_state'
        session.save()

        res = self.client.get(
            '/auth/github/callback?state=mock_valid_state&code=mock_github_code&mock_user=octocat_coder&mock_email=octocat@github.test'
        )
        self.assertEqual(res.status_code, 302)
        self.assertEqual(res.url, '/dashboard')

        # Check session
        user_sess = self.client.session.get('user')
        self.assertIsNotNone(user_sess)
        self.assertEqual(user_sess['username'], 'octocat_coder')
        self.assertTrue(user_sess['is_verified'])

        # Check DB
        user = User.objects.filter(username='octocat_coder').first()
        self.assertIsNotNone(user)
        self.assertEqual(user.email, 'octocat@github.test')
        self.assertIsNotNone(user.organization)
        self.assertEqual(user.organization.plan, 'free')

        # Check Audit Log
        audit = AuditLog.objects.filter(action='user.oauth_login', actor='octocat_coder').first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.details.get('provider'), 'github')

    def test_google_login_and_callback(self):
        """Google OAuth callback logs in user."""
        session = self.client.session
        session['oauth_state'] = 'google_state_token'
        session.save()

        res = self.client.get(
            '/auth/google/callback?state=google_state_token&code=mock_google_code&mock_name=GoogleUser&mock_email=googler@example.com'
        )
        self.assertEqual(res.status_code, 302)
        self.assertEqual(res.url, '/dashboard')

        user = User.objects.filter(email='googler@example.com').first()
        self.assertIsNotNone(user)
        self.assertEqual(user.organization.plan, 'free')
