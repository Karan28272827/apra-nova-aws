from django.shortcuts import redirect
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
from urllib.parse import urlencode


def oauth_callback_handler(request):
    """
    Handle OAuth callback and redirect to frontend with JWT tokens
    """
    user = request.user
    
    if not user.is_authenticated:
        error_params = urlencode({'error': 'authentication_failed'})
        return redirect(f"{settings.FRONTEND_URL}/login?{error_params}")
    
    # Generate JWT tokens
    refresh = RefreshToken.for_user(user)
    access_token = str(refresh.access_token)
    refresh_token = str(refresh)
    
    # Prepare redirect URL with tokens
    params = urlencode({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'role': user.role,
        'email': user.email,
        'name': user.name or user.username,
    })
    
    # Redirect to frontend callback page
    redirect_url = f"{settings.FRONTEND_URL}/auth/callback?{params}"
    return redirect(redirect_url)
