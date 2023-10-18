from django.urls import path
from .views import RetrieveSMS

urlpatterns = [
    path('sms/', RetrieveSMS.as_view())
]

