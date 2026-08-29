from rest_framework.parsers import JSONParser, MultiPartParser, FormParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .serializers import UserSerializer


class MeView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser, MultiPartParser, FormParser]

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

    # Deactivates the current user's account after confirmation.
    def delete(self, request):
        if request.user.is_superuser:
            return Response(
                {"detail": "Superusers cannot deactivate their own account."},
                status=403,
            )

        if request.data.get("confirm") is not True:
            return Response(
                {"detail": "Set confirm to true to deactivate your account."},
                status=400,
            )

        request.user.is_active = False
        request.user.save(update_fields=["is_active"])

        return Response(status=204)
