# Generated migration for GateValidationLog model

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0002_add_auditlog_schemasnapshot'),
    ]

    operations = [
        migrations.CreateModel(
            name='GateValidationLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('commit_sha', models.CharField(blank=True, default='', max_length=40)),
                ('branch', models.CharField(blank=True, default='', max_length=255)),
                ('status', models.CharField(max_length=20)),
                ('violations_count', models.PositiveIntegerField(default=0)),
                ('details', models.JSONField(default=dict)),
                ('checked_at', models.DateTimeField(auto_now_add=True, db_index=True)),
                ('pipeline', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='gate_logs', to='core.pipeline')),
            ],
            options={
                'ordering': ['-checked_at'],
            },
        ),
        migrations.AddIndex(
            model_name='gatevalidationlog',
            index=models.Index(fields=['pipeline', '-checked_at'], name='core_gateva_pipelin_idx'),
        ),
    ]
