from django.urls import path
from .views import RetrieveSMS, StaffAPIView, LoginAPIView

urlpatterns = [
    path('auth/login/', LoginAPIView.as_view()),
    path('sms/', RetrieveSMS.as_view()),
    path('staff/', StaffAPIView.as_view()),
]
