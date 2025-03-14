# In api/views.py
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from allauth.socialaccount.providers.github.views import GitHubOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from dj_rest_auth.registration.views import SocialLoginView
from rest_framework.permissions import AllowAny
from django.conf import settings
from allauth.socialaccount.models import SocialAccount, SocialToken
import requests
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework.response import Response
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView
from rest_framework import status
from .serializers import RefreshTokenSerializer
from drf_spectacular.utils import extend_schema, OpenApiParameter

User = get_user_model()

def get_unique_username(base_username):
    """
    Generate a unique username based on the given base username.
    Checks if the username exists and appends a number if needed.
    """
    existing_usernames = User.objects.filter(username__startswith=base_username).values_list('username', flat=True)
    username = base_username
    if username in existing_usernames:
        i = 1
        while f"{username}{i}" in existing_usernames:
            i += 1
        username = f"{username}{i}"
    return username

def handle_oauth_login(user_info, provider, access_token):
    """
    Common logic for handling OAuth login process.
    
    Args:
        user_info: Dictionary containing user information from the OAuth provider
        provider: String identifying the OAuth provider (e.g., 'google', 'github')
        access_token: The access token received from the OAuth provider
        
    Returns:
        A tuple containing (user, tokens, response_data)
    """
    # Step 3: Get or create the user
    if provider == 'google':
        google_id = user_info.get("id")
        email = user_info.get("email")
        given_name = user_info.get("given_name", "")
        family_name = user_info.get("family_name", "")
        picture = user_info.get("picture", "")
        
        # Username from email (before @) or use the first part of the name
        base_username = email.split('@')[0] if email else given_name.lower()
        username = get_unique_username(base_username)
        
        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                "username": username,
                "first_name": given_name,
                "last_name": family_name,
            }
        )
        uid = google_id
        avatar_url = picture
        
    elif provider == 'github':
        github_username = user_info.get("login")
        github_id = user_info.get("id")
        email = user_info.get("email") or f"{github_username}@github.com"
        avatar_url = user_info.get("avatar_url")
        name = user_info.get("name", "")
        
        # Try to split the name if available
        name_parts = name.split() if name else []
        first_name = name_parts[0] if name_parts else ""
        last_name = " ".join(name_parts[1:]) if len(name_parts) > 1 else ""
        
        user, created = User.objects.get_or_create(
            username=github_username, 
            defaults={
                "email": email,
                "first_name": first_name,
                "last_name": last_name,
            }
        )
        uid = str(github_id)
    else:
        raise ValueError(f"Unsupported provider: {provider}")
    
    # Step 4: Generate JWT tokens
    refresh = RefreshToken.for_user(user)
    tokens = {
        "refresh": str(refresh),
        "access": str(refresh.access_token),
    }
    
    # Step 5: Create or update social account
    social_account, _ = SocialAccount.objects.get_or_create(
        user=user,
        provider=provider,
        defaults={
            "uid": uid,
            "extra_data": user_info
        }
    )
    
    social_token, token_created = SocialToken.objects.get_or_create(
        account=social_account,
        defaults={"token": access_token}
    )
    
    if not token_created and social_token.token != access_token:
        # Update the token if it has changed
        social_token.token = access_token
        social_token.save()
    
    print(f"[DEBUG]: {provider.capitalize()} token: {access_token}")
    
    # Return user data for response
    response_data = {
        "message": "Login successful",
        "tokens": tokens,
        "user": {
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "avatar_url": avatar_url
        }
    }
    
    return user, tokens, response_data

@extend_schema(
    parameters=[
        OpenApiParameter(
            name="code",
            type=str,
            location=OpenApiParameter.QUERY,
            description="OAuth authorization code."
        )
    ]
)
@api_view(['GET'])
@authentication_classes([])  # Disable authentication
@permission_classes([AllowAny])  # Allow all users to access
def google_callback(request):
    """
    Handles Google OAuth callback.
    Exchanges code for an access token, retrieves user info, and logs in or creates a user.
    """
    code = request.GET.get("code")
    if not code:
        return Response({"error": "Code is required"}, status=400)

    # Step 1: Exchange code for access token
    token_url = "https://oauth2.googleapis.com/token"
    payload = {
        "client_id": settings.SOCIALACCOUNT_PROVIDERS['google']['APP']['client_id'],
        "client_secret": settings.SOCIALACCOUNT_PROVIDERS['google']['APP']['secret'],
        "code": code,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code"
    }
    headers = {"Accept": "application/json"}

    token_response = requests.post(token_url, data=payload, headers=headers)
    if token_response.status_code != 200:
        return Response({"error": "Failed to fetch access token"}, status=400)

    token_data = token_response.json()
    access_token = token_data.get("access_token")
    
    # Step 2: Use the access token to fetch Google user info
    user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"
    user_info_headers = {"Authorization": f"Bearer {access_token}"}
    user_info_response = requests.get(user_info_url, headers=user_info_headers)

    if user_info_response.status_code != 200:
        return Response({"error": "Failed to fetch user info"}, status=400)

    user_info = user_info_response.json()
    
    # Handle the common OAuth login flow
    _, _, response_data = handle_oauth_login(user_info, 'google', access_token)
    
    return Response(response_data, status=200)

@extend_schema(
    parameters=[
        OpenApiParameter(
            name="code",
            type=str,
            location=OpenApiParameter.QUERY,
            description="OAuth authorization code."
        )
    ]
)
@api_view(['GET'])
@authentication_classes([])  # Disable authentication
@permission_classes([AllowAny])  # Allow all users to access
def github_callback(request):
    """
    Handles GitHub OAuth callback.
    Exchanges code for an access token, retrieves user info, and logs in or creates a user.
    """
    code = request.GET.get("code")
    if not code:
        return Response({"error": "Code is required"}, status=400)

    # Step 1: Exchange code for access token
    token_url = "https://github.com/login/oauth/access_token"
    payload = {
        "client_id": settings.SOCIALACCOUNT_PROVIDERS['github']['APP']['client_id'],
        "client_secret": settings.SOCIALACCOUNT_PROVIDERS['github']['APP']['secret'],
        "code": code,
    }
    headers = {"Accept": "application/json"}

    token_response = requests.post(token_url, data=payload, headers=headers)
    if token_response.status_code != 200:
        return Response({"error": "Failed to fetch access token"}, status=400)

    access_token = token_response.json().get("access_token")
    
    # Step 2: Use the access token to fetch GitHub user info
    user_info_url = "https://api.github.com/user"
    user_info_headers = {"Authorization": f"Bearer {access_token}"}
    user_info_response = requests.get(user_info_url, headers=user_info_headers)

    if user_info_response.status_code != 200:
        return Response({"error": "Failed to fetch user info"}, status=400)

    user_info = user_info_response.json()
    
    # Handle the common OAuth login flow
    _, _, response_data = handle_oauth_login(user_info, 'github', access_token)
    
    return Response(response_data, status=200)


class RefreshTokenView(APIView):
    """
    View to refresh the access token using the refresh token.
    """
    serializer_class = RefreshTokenSerializer
    authentication_classes = []  # Disable authentication
    permission_classes = [AllowAny]  # Allow all users to access

    def post(self, request):
        # Use the serializer to validate the incoming refresh token
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            refresh_token = serializer.validated_data['refresh']
            try:
                # Decode and validate the refresh token
                refresh = RefreshToken(refresh_token)
                new_access_token = str(refresh.access_token)

                return Response({
                    "refresh": refresh_token,
                    "access": new_access_token
                }, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({"error": "Invalid or expired refresh token"}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
