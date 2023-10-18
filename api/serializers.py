from rest_framework import serializers
from sms.models import Message
class SMSSerializer(serializers.ModelSerializer):
    class Meta:
        model = Message
        fields = ('id', 'message', 'created_by', 'created_at', 'is_sent', 'receiver')
