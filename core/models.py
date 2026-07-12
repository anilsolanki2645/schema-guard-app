from django.db import models


class Organization(models.Model):
    name = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class User(models.Model):
    username = models.CharField(max_length=150, unique=True, primary_key=True)
    email = models.EmailField(unique=True)
    password_hash = models.CharField(max_length=255)
    role = models.CharField(max_length=50, default='operator')  # 'admin', 'subadmin', 'operator', 'viewer'
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
    conn_str = models.CharField(max_length=1000)
    schema = models.CharField(max_length=255)
    table = models.CharField(max_length=255)
    cron = models.CharField(max_length=50, default='0 0 * * *')
    cron_text = models.CharField(max_length=255, default='Daily preset')
    alerts = models.JSONField(default=dict)
    status = models.CharField(max_length=50, default='Clean')
    last_checked = models.DateTimeField(null=True, blank=True)
    lock_signature = models.CharField(max_length=255, null=True, blank=True)
    schema_map = models.JSONField(default=dict)
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
    name = models.CharField(max_length=150, unique=True)
    db_type = models.CharField(max_length=50)
    conn_str = models.CharField(max_length=1000)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True, blank=True, related_name='connection_profiles')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

