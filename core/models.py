import uuid
from django.db import models


class Organization(models.Model):
    name = models.CharField(max_length=255, unique=True)
    plan = models.CharField(max_length=50, default='free')  # 'free', 'pro', 'enterprise'
    max_pipelines = models.IntegerField(default=5)
    stripe_customer_id = models.CharField(max_length=100, blank=True, default='')
    stripe_subscription_id = models.CharField(max_length=100, blank=True, default='')
    subscription_status = models.CharField(max_length=50, default='active')
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if self.plan:
            self.plan = str(self.plan).lower().strip()
            if self.plan not in ('free', 'pro', 'enterprise'):
                self.plan = 'free'
        else:
            self.plan = 'free'
        super().save(*args, **kwargs)

    def get_seat_quota(self):
        plan = (self.plan or 'free').lower().strip()
        if plan == 'enterprise':
            return 999999
        elif plan == 'pro':
            return 10
        return 1

    def get_active_seat_count(self):
        from django.utils import timezone
        active_members = self.users.count()
        # Pending valid invitations also reserve a seat
        pending_invites = self.invitations.filter(status='pending', expires_at__gt=timezone.now()).count()
        return active_members + pending_invites

    def __str__(self):
        return self.name


class User(models.Model):
    username = models.CharField(max_length=150, unique=True, primary_key=True)
    email = models.EmailField(unique=True)
    password_hash = models.CharField(max_length=255)
    role = models.CharField(max_length=50, default='operator')  # 'admin', 'subadmin', 'operator', 'viewer'
    full_name = models.CharField(max_length=255, blank=True, default='')
    avatar_data = models.TextField(blank=True, default='')
    job_title = models.CharField(max_length=150, blank=True, default='')
    bio = models.TextField(blank=True, default='')
    permissions = models.JSONField(default=dict)  # e.g., {"see": True, "create": True, "edit": True, "delete": True}
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True, blank=True, related_name='users')
    is_verified = models.BooleanField(default=False)
    verification_code = models.CharField(max_length=50, null=True, blank=True)
    reset_code = models.CharField(max_length=50, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.username


class Pipeline(models.Model):
    id = models.CharField(max_length=150, unique=True, primary_key=True)
    name = models.CharField(max_length=255)
    db_type = models.CharField(max_length=50)
    conn_str = models.TextField()  # Encrypted at rest via core.security
    schema = models.CharField(max_length=255)
    table = models.CharField(max_length=255)
    cron = models.CharField(max_length=50, default='0 0 * * *')
    cron_text = models.CharField(max_length=255, default='Daily preset')
    alerts = models.JSONField(default=dict)
    status = models.CharField(max_length=50, default='Clean')
    last_checked = models.DateTimeField(null=True, blank=True)
    lock_signature = models.CharField(max_length=255, null=True, blank=True)
    schema_map = models.JSONField(default=dict)
    contract_yaml = models.TextField(blank=True, default='')  # Persistent database storage for contract
    logs = models.JSONField(default=list)
    compliance_history = models.JSONField(default=list)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True, blank=True, related_name='pipelines')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class AuditLog(models.Model):
    """Immutable audit trail for tracking all user actions across the system."""
    
    ACTION_CHOICES = [
        ('user.login', 'User Login'),
        ('user.logout', 'User Logout'),
        ('user.register', 'User Registration'),
        ('user.create', 'User Created'),
        ('user.update', 'User Updated'),
        ('user.delete', 'User Deleted'),
        ('user.password_reset', 'Password Reset'),
        ('pipeline.create', 'Pipeline Created'),
        ('pipeline.update', 'Pipeline Updated'),
        ('pipeline.delete', 'Pipeline Deleted'),
        ('pipeline.check', 'Pipeline Check Executed'),
        ('pipeline.drift_detected', 'Schema Drift Detected'),
        ('pipeline.alert_sent', 'Alert Dispatched'),
        ('org.create', 'Organization Created'),
        ('contract.lock', 'Contract Locked'),
        ('apikey.create', 'API Key Created'),
        ('apikey.revoke', 'API Key Revoked'),
        ('billing.checkout_created', 'Stripe Checkout Created'),
        ('billing.subscription_updated', 'Stripe Subscription Updated'),
        ('billing.subscription_cancelled', 'Stripe Subscription Cancelled'),
        ('billing.qr_payment', 'UPI QR Payment Verified'),
        ('user.oauth_login', 'User OAuth Login'),
        ('org.member_invited', 'Team Member Invited'),
        ('org.invite_revoked', 'Invitation Revoked'),
        ('org.member_joined', 'Team Member Joined'),
        ('org.member_removed', 'Team Member Removed'),
    ]
    
    action = models.CharField(max_length=50, choices=ACTION_CHOICES, db_index=True)
    actor = models.CharField(max_length=150, db_index=True)  # Username who performed the action
    target_type = models.CharField(max_length=50, blank=True, default='')  # e.g., 'pipeline', 'user', 'organization'
    target_id = models.CharField(max_length=150, blank=True, default='')  # ID of the affected resource
    details = models.JSONField(default=dict)  # Additional context (e.g., what changed)
    organization = models.ForeignKey(Organization, on_delete=models.SET_NULL, null=True, blank=True, related_name='audit_logs')
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['action', 'timestamp']),
            models.Index(fields=['actor', 'timestamp']),
        ]

    def __str__(self):
        return f"[{self.timestamp}] {self.actor}: {self.action} -> {self.target_type}:{self.target_id}"


class SchemaSnapshot(models.Model):
    """Stores historical schema snapshots for version tracking and timeline diffing."""
    
    pipeline = models.ForeignKey(Pipeline, on_delete=models.CASCADE, related_name='schema_snapshots')
    version = models.PositiveIntegerField()
    schema_data = models.JSONField()  # Full schema columns data at this point in time
    hash = models.CharField(max_length=64, blank=True, default='')
    status = models.CharField(max_length=20, default='Clean')  # Status at capture time: Clean, Drifted
    violations_count = models.PositiveIntegerField(default=0)
    captured_at = models.DateTimeField(auto_now_add=True)
    captured_by = models.CharField(max_length=150, blank=True, default='system')  # Who triggered the capture

    class Meta:
        ordering = ['-captured_at']
        unique_together = [['pipeline', 'version']]
        indexes = [
            models.Index(fields=['pipeline', '-captured_at']),
        ]

    def __str__(self):
        return f"{self.pipeline_id} v{self.version} ({self.status})"


class GateValidationLog(models.Model):
    """Tracks historical CI/CD schema gate checks against data contracts."""
    
    pipeline = models.ForeignKey(Pipeline, on_delete=models.CASCADE, related_name='gate_logs')
    commit_sha = models.CharField(max_length=40, blank=True, default='')
    branch = models.CharField(max_length=255, blank=True, default='')
    status = models.CharField(max_length=20)  # PASS, FAIL
    violations_count = models.PositiveIntegerField(default=0)
    details = models.JSONField(default=dict)  # Stores compatibility details (warnings, errors, columns check)
    checked_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-checked_at']
        indexes = [
            models.Index(fields=['pipeline', '-checked_at']),
        ]

    def __str__(self):
        return f"{self.pipeline_id} check {self.commit_sha[:7]} -> {self.status}"


class ConnectionProfile(models.Model):
    name = models.CharField(max_length=150)
    db_type = models.CharField(max_length=50)
    conn_str = models.TextField()  # Encrypted at rest via core.security
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True, blank=True, related_name='connection_profiles')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [['organization', 'name']]

    def __str__(self):
        return self.name


class ApiKey(models.Model):
    """Cryptographically secure API keys for programmatic access and CI/CD gates."""
    key_id = models.CharField(max_length=64, unique=True, db_index=True)
    key_hash = models.CharField(max_length=128, db_index=True)
    name = models.CharField(max_length=150, default='CI/CD Gate Token')
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='api_keys')
    created_by = models.CharField(max_length=150, default='system')
    is_active = models.BooleanField(default=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} ({self.key_id})"


class PaymentTransaction(models.Model):
    transaction_id = models.CharField(max_length=100, unique=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='payment_transactions')
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='payment_transactions')
    plan = models.CharField(max_length=50)  # 'pro', 'enterprise'
    amount = models.CharField(max_length=50, default='')
    payment_method = models.CharField(max_length=50, default='UPI_QR')
    status = models.CharField(max_length=50, default='pending')  # 'pending', 'approved', 'rejected'
    screenshot_data = models.TextField(blank=True, default='')  # Base64 image
    approval_token = models.CharField(max_length=64, blank=True, default='')
    notes = models.TextField(blank=True, default='')
    approved_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.transaction_id} - {self.plan} ({self.status})"


class OrganizationInvitation(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='invitations')
    email = models.EmailField(db_index=True)
    role = models.CharField(max_length=50, default='operator')  # 'subadmin', 'operator', 'viewer'
    permissions = models.JSONField(default=dict)
    token = models.CharField(max_length=64, unique=True, db_index=True)
    invited_by = models.CharField(max_length=150)
    status = models.CharField(max_length=20, default='pending')  # 'pending', 'accepted', 'revoked', 'expired'
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(db_index=True)
    accepted_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['organization', 'status']),
            models.Index(fields=['email', 'status']),
        ]

    def is_valid(self):
        from django.utils import timezone
        return self.status == 'pending' and self.expires_at > timezone.now()

    def __str__(self):
        return f"Invite for {self.email} to {self.organization.name} ({self.status})"


