from rest_framework import serializers

from .models import User


class UserSerializer(serializers.ModelSerializer):
    # Serializes the authenticated user's profile.
    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "first_name",
            "last_name",
            "bio",
            "avatar",
            "date_joined",
        ]
        read_only_fields = ["id", "email", "date_joined"]
