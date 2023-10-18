from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import UserSerializer
from rest_framework.response import Response


def get_login_response(user, request):
    """Get access and refresh token, information for a user.

    :args
        - user
    """
    refresh = RefreshToken.for_user(user)
    serializer = UserSerializer(user, context={"request": request})
    return {
        **serializer.data,
        "refresh": str(refresh),
        "access": str(refresh.access_token),
    }


def error_response(message, status_code):
    """Return error response."""
    return Response({"detail": message}, status_code)
