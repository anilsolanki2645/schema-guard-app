from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponseNotAllowed
from core import views


def pipelines_api_dispatch(request):
    if request.method == "POST":
        return views.create_pipeline_api(request)
    return views.get_pipelines_api(request)


def pipelines_detail_api_dispatch(request, id):
    if request.method == "PUT":
        return views.edit_pipeline_api(request, id)
    elif request.method == "DELETE":
        return views.delete_pipeline_api(request, id)
    return HttpResponseNotAllowed(["PUT", "DELETE"])


def users_api_dispatch(request):
    if request.method == "POST":
        return views.create_user_api(request)
    return views.get_users_api(request)


def users_detail_api_dispatch(request, username):
    if request.method == "PUT":
        return views.update_user_api(request, username)
    elif request.method == "DELETE":
        return views.delete_user_api(request, username)
    return HttpResponseNotAllowed(["PUT", "DELETE"])


urlpatterns = [
    path('', views.login_page, name='login_page'),
    path('dashboard', views.dashboard_page, name='dashboard'),
    path('builder', views.builder_page, name='builder'),
    path('admin', views.admin_page, name='admin_panel'),
    path('troubleshooting', views.troubleshooting_page, name='troubleshooting'),
    path('auth/action', views.login_or_register_view, name='login_or_register'),
    path('auth/logout', views.logout_view, name='logout'),
    
    # Verification and password reset URLs
    path('verify-email', views.verify_email_page, name='verify_email_page'),
    path('verify-email/submit', views.verify_email_action, name='verify_email_action'),
    path('verify-email/resend', csrf_exempt(views.resend_verification_code_api), name='resend_verification_code'),
    path('forgot-password', views.forgot_password_view, name='forgot_password'),
    path('reset-password', views.reset_password_view, name='reset_password'),
    
    # REST API endpoints — CSRF enforced via X-CSRFToken header from frontend
    path('api/pipelines', pipelines_api_dispatch, name='pipelines_api'),
    path('api/pipelines/list-tables', views.list_tables_api, name='list_tables_api'),
    path('api/pipelines/list-schemas', views.list_schemas_api, name='list_schemas_api'),
    path('api/pipelines/test-connection', views.test_connection_api, name='test_connection_api'),
    path('api/pipelines/download-airflow', views.download_airflow_operator, name='download_airflow_operator'),
    path('api/pipelines/<str:id>', pipelines_detail_api_dispatch, name='pipelines_detail_api'),
    path('api/pipelines/<str:id>/run', views.run_pipeline_check_api, name='run_pipeline_check_api'),
    path('api/pipelines/<str:id>/ai-diagnostics', views.run_ai_diagnostics_api, name='run_ai_diagnostics_api'),
    path('api/pipelines/<str:id>/validate-gate', csrf_exempt(views.validate_pipeline_gate_api), name='validate_pipeline_gate_api'),
    path('api/pipelines/<str:id>/gate-logs', views.get_gate_logs_api, name='get_gate_logs_api'),
    path('api/auth/users', users_api_dispatch, name='get_users_api'),
    path('api/auth/users/<str:username>', users_detail_api_dispatch, name='users_detail_api'),
    
    # Organization API endpoints
    path('api/auth/organizations', views.get_organizations_api, name='get_organizations_api'),
    path('api/auth/organizations/create', views.create_organization_api, name='create_organization_api'),
    
    # Health check endpoint
    path('api/health', views.health_check_api, name='health_check'),
    
    # DDL Simulation Sandbox Page & API
    path('sandbox', views.sandbox_page, name='sandbox_page'),
    path('api/sandbox/simulate', views.simulate_ddl_api, name='simulate_ddl_api'),
    path('api/pipelines/<str:id>/export-dbt', views.export_dbt_schema_api, name='export_dbt_schema_api'),

    # Connection Profiles paths
    path('connections', views.connection_profiles_page, name='connection_profiles'),
    path('api/connection-profiles', views.connection_profiles_api, name='connection_profiles_api'),
    path('api/connection-profiles/<int:id>', views.connection_profile_detail_api, name='connection_profile_detail_api'),
]

