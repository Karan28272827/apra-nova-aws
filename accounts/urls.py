from django.urls import path

from . import views, workspace_views

urlpatterns = [
    path("profile/", views.get_user_profile, name="user-profile"),
    path("callback/", views.oauth_callback, name="oauth-callback"),
    path("update-role/", views.update_user_role, name="update-role"),
    path("login/", views.custom_login, name="custom_login"),
    path("refresh/", views.refresh_token, name="token-refresh"),
    path("logout/", views.logout, name="logout"),
    path("check-email/", views.check_email_exists, name="check_email_exists"),
    path("workspace/create/", workspace_views.create_workspace, name="create_workspace"),
]
