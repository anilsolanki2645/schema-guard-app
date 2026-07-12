# Generated migration for AuditLog and SchemaSnapshot models

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='AuditLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('action', models.CharField(choices=[
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
                ], db_index=True, max_length=50)),
                ('actor', models.CharField(db_index=True, max_length=150)),
                ('target_type', models.CharField(blank=True, default='', max_length=50)),
                ('target_id', models.CharField(blank=True, default='', max_length=150)),
                ('details', models.JSONField(default=dict)),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('timestamp', models.DateTimeField(auto_now_add=True, db_index=True)),
                ('organization', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='audit_logs', to='core.organization')),
            ],
            options={
                'ordering': ['-timestamp'],
            },
        ),
        migrations.CreateModel(
            name='SchemaSnapshot',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('version', models.PositiveIntegerField()),
                ('schema_data', models.JSONField()),
                ('status', models.CharField(default='Clean', max_length=20)),
                ('violations_count', models.PositiveIntegerField(default=0)),
                ('captured_at', models.DateTimeField(auto_now_add=True)),
                ('captured_by', models.CharField(blank=True, default='system', max_length=150)),
                ('pipeline', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='schema_snapshots', to='core.pipeline')),
            ],
            options={
                'ordering': ['-captured_at'],
                'unique_together': {('pipeline', 'version')},
            },
        ),
        migrations.AddIndex(
            model_name='auditlog',
            index=models.Index(fields=['action', 'timestamp'], name='core_auditl_action_idx'),
        ),
        migrations.AddIndex(
            model_name='auditlog',
            index=models.Index(fields=['actor', 'timestamp'], name='core_auditl_actor_idx'),
        ),
        migrations.AddIndex(
            model_name='schemasnapshot',
            index=models.Index(fields=['pipeline', '-captured_at'], name='core_schema_pipelin_idx'),
        ),
    ]
