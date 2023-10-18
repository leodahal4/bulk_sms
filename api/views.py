from django.shortcuts import render
from sms.models import Message
from rest_framework.views import APIView
from .serializers import SMSSerializer
from rest_framework.response import Response
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.permissions import IsAuthenticated


# Retrieve all SMS
# GET /api/sms/
# Retrieve all SMS created by the user,
# and if the user is a superuser, retrieve all SMS
class RetrieveSMS(APIView):
    authentication_classes = [SessionAuthentication, BasicAuthentication]
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
