from sms.models import Message, Staff, User
from rest_framework.views import APIView
from .extra_methods import error_response, get_login_response
from rest_framework.status import HTTP_401_UNAUTHORIZED
from .serializers import SMSSerializer, StaffSerializer, LoginSerializer
from rest_framework.response import Response
from django.contrib.auth import authenticate
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny


# Retrieve all SMS
# GET /api/sms/
# Retrieve all SMS created by the user,
# and if the user is a superuser, retrieve all SMS
class RetrieveSMS(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        if self.request.user.is_superuser:
            messages = Message.objects.all()
        else:
            messages = Message.objects.filter(created_by=self.request.user)
        if len(messages) == 0:
            return Response({"message": "No any messages found"}, status=404)

        serializer = SMSSerializer(messages, many=True)
        return Response(serializer.data)

class StaffAPIView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]
    
    def get(self, request, format=None):
        return Response(StaffSerializer(Staff.objects.all(), many=True).data)

    def delete(self, request, format=None):
        staff = Staff.objects.filter(id=request.data['id'])
        if len(staff) == 0:
            return Response({"message": "Staff not found"}, status=404)
        staff.delete()
        return Response({"message": "Staff deleted successfully"}, status=200)

    def post(self, request, format=None):
        data = request.data
        user = User.objects.filter(username=request.user.username)
        data['created_by'] = user[0].id
        serializer = StaffSerializer(data=data)
        if not serializer.is_valid():
            return Response({"message": "invalid data", 'errors': serializer.errors}, status = 400)

        serializer.save()
        return Response({"message": "staff created successfully"}, status = 200)

    def put(self, request, format=None):
        data = request.data
        staff = User.objects.filter(username=data['username'])
        if len(staff) == 0:
            return Response({"message": "User not found"}, status=404)

        serializer = StaffSerializer(staff[0], data=data)
        if not serializer.is_valid():
            return Response({"message": "invalid data", 'errors': serializer.errors}, status = 400)

        User.objects.filter(username=data['username']).first().__dict__.update(**data).save()
        return Response({"message": "staff updated successfully"}, status = 200)


class LoginAPIView(APIView):
    permission_classes = [AllowAny]
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        user = User.objects.filter(username=data["username"])
        if not user:
            return error_response(
                "User with this email address does not exist",
                HTTP_401_UNAUTHORIZED,
            )
        undeleted_user = user.filter(is_deleted=False)
        if not undeleted_user.exists():
            return error_response(
                "This account has been deleted.",
                HTTP_401_UNAUTHORIZED,
            )
        user = undeleted_user.first()
        user = authenticate(**data)
        print(user)
        if not user:
            return error_response(
                "Invalid credentials. Please try again.", HTTP_401_UNAUTHORIZED
            )

        return Response(
            get_login_response(user, request),
        )
