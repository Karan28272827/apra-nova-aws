from allauth.socialaccount.models import SocialAccount
from django.contrib.auth import get_user_model, authenticate
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from dj_rest_auth.registration.views import RegisterView
from .serializers import CustomRegisterSerializer
from .serializers import UserSerializer

User = get_user_model()


class CustomRegisterView(RegisterView):
    serializer_class = CustomRegisterSerializer

def get_tokens_for_user(user):
    """Generate JWT tokens for user"""
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_user_profile(request):
    """Get current user profile"""
    serializer = UserSerializer(request.user)
    return Response(serializer.data)


@api_view(["POST"])
@permission_classes([AllowAny])
def oauth_callback(request):
    """
    Handle OAuth callback from frontend
    This endpoint receives the JWT access token and returns user data
    """
    access_token = request.data.get("access_token")
    
    if not access_token:
        return Response(
            {"error": "Access token is required"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        # Decode and validate JWT token
        from rest_framework_simplejwt.tokens import AccessToken
        
        token = AccessToken(access_token)
        user_id = token['user_id']
        user = User.objects.get(id=user_id)
        
        serializer = UserSerializer(user)
        return Response({
            "user": serializer.data,
            "access_token": access_token,
            "redirect_url": f"/{user.role}/dashboard",
        })
        
    except (TokenError, User.DoesNotExist) as e:
        return Response(
            {"error": "Invalid or expired token"}, 
            status=status.HTTP_401_UNAUTHORIZED
        )


@api_view(["POST"])
@permission_classes([AllowAny])
def social_login(request):
    """
    Handle social login (Google/GitHub)
    Accepts: provider (google/github), code, redirect_uri
    Returns: JWT tokens and user data
    """
    provider = request.data.get('provider')
    code = request.data.get('code')
    
    if not provider or not code:
        return Response(
            {"error": "Provider and code are required"},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Process OAuth with allauth
    # This is handled by dj-rest-auth automatically
    # Just return the response with tokens
    
    return Response({
        "message": "Use the dj-rest-auth endpoints for social login"
    })

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def update_user_role(request):
    """Update user role (for testing/admin purposes)"""
    role = request.data.get("role")

    if role not in ["student", "teacher", "admin", "superadmin"]:
        return Response({"error": "Invalid role"}, status=status.HTTP_400_BAD_REQUEST)

    request.user.role = role
    request.user.save()

    serializer = UserSerializer(request.user)
    return Response(serializer.data)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def refresh_token(request):
    """Refresh JWT token"""
    refresh_token = request.data.get("refresh")
    
    if not refresh_token:
        return Response(
            {"error": "Refresh token is required"},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        refresh = RefreshToken(refresh_token)
        return Response({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
        })
    except TokenError:
        return Response(
            {"error": "Invalid refresh token"},
            status=status.HTTP_401_UNAUTHORIZED
        )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def logout(request):
    """Logout user by blacklisting refresh token"""
    refresh_token = request.data.get("refresh")
    
    if not refresh_token:
        return Response(
            {"error": "Refresh token is required"},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        token = RefreshToken(refresh_token)
        token.blacklist()
        return Response({"message": "Logout successful"})
    except TokenError:
        return Response(
            {"error": "Invalid token"},
            status=status.HTTP_400_BAD_REQUEST
        )
    

@api_view(["POST"])
@permission_classes([AllowAny])
def custom_login(request):
    email = request.data.get("email")
    password = request.data.get("password")
    role = request.data.get("role")  

    if not email or not password:
        return Response(
            {"error": "Email and password required"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    if not role:
        return Response(
            {"error": "Role is required"}, 
            status=status.HTTP_400_BAD_REQUEST
        )

    # Authenticate user with credentials
    user = authenticate(request, username=email, password=password)
    if user is None:
        return Response(
            {"error": "Invalid credentials"}, 
            status=status.HTTP_401_UNAUTHORIZED
        )

    # Validate if selected role matches user's actual role
    # SuperAdmin can login with any role selection
    if user.role != role and user.role != "superadmin":
        return Response(
            {
                "error": "Unauthorized role access",
                "detail": f"You are registered as '{user.role}' but tried to login as '{role}'",
                "actual_role": user.role
            },
            status=status.HTTP_403_FORBIDDEN
        )

    # Generate tokens
    refresh = RefreshToken.for_user(user)
    access_token = str(refresh.access_token)
    refresh_token = str(refresh)

    serializer = UserSerializer(user)

    return Response({
        "access": access_token,
        "refresh": refresh_token,
        "user": serializer.data,
        "redirect_url": f"/{user.role}/dashboard",
    })



@api_view(["POST"])
@permission_classes([AllowAny])
def check_email_exists(request):
    email = request.data.get("email", "").strip().lower()
    exists = User.objects.filter(email__iexact=email).exists()
    return Response({"exists": exists})

@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    """Health check endpoint for deployment monitoring"""
    return Response({"status": "healthy"}, status=status.HTTP_200_OK)