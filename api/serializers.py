from rest_framework import serializers
from sms.models import Message, Staff, User


class SMSSerializer(serializers.ModelSerializer):
    class Meta:
        model = Message
        fields = ('id', 'message', 'created_by', 'created_at', 'is_sent', 'receiver')


class StaffSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=100)
    first_name = serializers.CharField(max_length=100, required=False)
    last_name = serializers.CharField(max_length=100, required=False)
    email = serializers.EmailField()
    is_active = serializers.BooleanField(required=False)
    date_joined = serializers.DateTimeField(required=False)
    institution = serializers.CharField(max_length=100, required=False)

    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email', 'is_active', 'date_joined', 'created_by', 'institution')

    def validate(self, data):
        if not data['username']:
            raise serializers.ValidationError("username is required")
        if not data['email']:
            raise serializers.ValidationError("email is required")

        userExists = Staff.objects.filter(username=data['username'])
        emailExists = Staff.objects.filter(email=data['email'])
        if emailExists:
            raise serializers.ValidationError("email already exists")
        return data


class ReadUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'first_name', 'last_name', 'email',
                  'is_superuser', 'is_admin', 'is_active',)
        lookup_field = 'email'
        read_only_fields = ('id', 'first_name', 'last_name',
                            'email', 'is_superuser', 'is_admin', 'is_active',)


class UserSerializer(serializers.ModelSerializer):
    """Serializer for user object."""

    password = serializers.CharField(write_only=True)
    roles = serializers.ListField(source="get_roles", required=False)

    class Meta:
        """Meta class."""

        model = User
        fields = (
            "idx",
            "email",
            "first_name",
            "last_name",
            "is_active",
            "roles",
            "password",
        )
        read_only_fields = (
            "idx",
            "is_active",
        )


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()
