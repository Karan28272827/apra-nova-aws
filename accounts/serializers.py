from rest_framework import serializers
from .models import CustomUser
from dj_rest_auth.registration.serializers import SocialLoginSerializer
from dj_rest_auth.registration.serializers import RegisterSerializer
import logging

logger = logging.getLogger(__name__)
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ["id", "email", "username", "role", "profile_image", "created_at"]
        read_only_fields = ["id", "created_at"]


class CustomSocialLoginSerializer(SocialLoginSerializer):
    """Custom serializer to include user role in social login response"""
    
    def get_response_data(self, user):
        data = super().get_response_data(user)
        data['role'] = user.role
        data['redirect_url'] = f"/{user.role}/dashboard"
        return data
    
class CustomRegisterSerializer(RegisterSerializer):
    name = serializers.CharField(required=True)
    track = serializers.CharField(required=False, allow_blank=True)
    role = serializers.CharField(required=True)

    def validate_role(self, value):
        """Prevent superadmin role from being assigned during registration"""
        if value == "superadmin":
            raise serializers.ValidationError("SuperAdmin role cannot be assigned through registration")
        return value

    def get_cleaned_data(self):
        data = super().get_cleaned_data()
        data['name'] = self.validated_data.get('name', '')
        data['track'] = self.validated_data.get('track', '')
        data['role'] = self.validated_data.get('role', '')
        return data
    
    def save(self, request):
        print("********* RegisterSerializer Save called: ", self.validated_data.get('role'))
        user = super().save(request)
        logger.debug(f"Saving user with role: {self.validated_data.get('role')}")
        user.name = self.validated_data.get('name', '')
        user.track = self.validated_data.get('track', '')
        user.role = self.validated_data.get('role', '')
        user.save()
        return user