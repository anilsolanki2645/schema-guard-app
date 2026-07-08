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
