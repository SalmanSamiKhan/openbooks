from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .serializers import UserSerializer


# Handles the authenticated user's account.
class MeView(APIView):
    permission_classes = [IsAuthenticated]

    # Returns the current user's profile.
    def get(self, request):
        return Response(UserSerializer(request.user).data)

    # Updates the current user's profile.
    def patch(self, request):
        serializer = UserSerializer(
            request.user,
            data=request.data,
            partial=True,
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data)

    # Deactivates the current user's account.
    def delete(self, request):
        request.user.is_active = False
        request.user.save(update_fields=["is_active"])

        return Response(status=204)