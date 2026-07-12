from django.contrib import admin
from core.models import Organization, User, Pipeline, AuditLog, GateValidationLog


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ('name', 'created_at')
    search_fields = ('name',)
    ordering = ('-created_at',)


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'role', 'organization', 'is_verified', 'created_at')
    list_filter = ('role', 'is_verified', 'organization')
    search_fields = ('username', 'email')
    ordering = ('-created_at',)


@admin.register(Pipeline)
class PipelineAdmin(admin.ModelAdmin):
    list_display = ('name', 'db_type', 'schema', 'table', 'status', 'organization', 'last_checked')
    list_filter = ('status', 'db_type', 'organization')
    search_fields = ('name', 'table')
    ordering = ('-created_at',)


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('action', 'actor', 'target_type', 'target_id', 'organization', 'timestamp')
    list_filter = ('action', 'target_type', 'organization')
    search_fields = ('actor', 'target_id', 'details')
    ordering = ('-timestamp',)
    readonly_fields = ('action', 'actor', 'target_type', 'target_id', 'organization', 'details', 'ip_address', 'timestamp')


@admin.register(GateValidationLog)
class GateValidationLogAdmin(admin.ModelAdmin):
    list_display = ('pipeline', 'commit_sha', 'branch', 'status', 'violations_count', 'checked_at')
    list_filter = ('status', 'pipeline')
    search_fields = ('commit_sha', 'branch', 'details')
    ordering = ('-checked_at',)
    readonly_fields = ('pipeline', 'commit_sha', 'branch', 'status', 'violations_count', 'details', 'checked_at')

