from rest_framework import serializers

from .models import User


# Serializes the authenticated user's profile data.
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "email"]
        read_only_fields = ["id", "email"]