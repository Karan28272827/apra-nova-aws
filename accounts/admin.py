from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import CustomUser


@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    list_display = ["email", "username", "role", "is_staff", "created_at"]
    list_filter = ["role", "is_staff", "is_active"]
    search_fields = ["email", "username"]

    fieldsets = UserAdmin.fieldsets + (
        ("Custom Fields", {"fields": ("role", "profile_image")}),
    )
