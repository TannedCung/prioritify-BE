from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import github_callback, RefreshTokenView, google_callback


# Define a router for the viewsets
router = DefaultRouter()

# Add other non-viewset endpoints
urlpatterns = [
    path('github/callback/', github_callback, name='github-callback'),
    path('google/callback/', google_callback, name='github-callback'),
    path('refresh-token/', RefreshTokenView.as_view(), name='refresh_token'),  # Add the refresh token URL
    path('', include(router.urls)),
]
