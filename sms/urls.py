from django.urls import path, include
from django.conf.urls import url

from .views import *

app_name = 'sms'

urlpatterns = [
    path('login/',SMSLogin.as_view(),name='login'),
    path('logout/',SMSLogout.as_view(),name='logout'),
    path('admin/',BaseTemplate.as_view(),name='sms_admin'),

    # Institution CRUD
    path('institution/create/', InstitutionCreate.as_view(), name='institution_create'),
    path('institutions/', InstitutionList.as_view(), name='institution_list'),
    path('institutions/<int:pk>/update/', InstitutionUpdate.as_view(), name='institution_update'),
    path('institutions/<int:pk>/delete/', InstitutionDelete.as_view(), name='institution_delete'),

    # Staff CRUD
    path('staff/create/', StaffCreate.as_view(), name='staff_create'),
    path('staffs/', StaffList.as_view(), name='staff_list'),
    path('staff/<int:pk>/update/', StaffUpdate.as_view(), name='staff_update'),
    path('staff/<int:pk>/delete/', StaffDelete.as_view(), name='staff_delete'),

    #  User CRUD
    path('user/create/', UserCreate.as_view(), name='user_create'),
    path('users/', UserList.as_view(), name='user_list'),
    path('user/delete/<int:pk>', UserDelete.as_view(), name='user_delete'),
    path('password-reset-user/<int:user_id>/', UserPwdReset.as_view(), name='password_reset_user'),
    path('password/change/', ChangePassword.as_view(), name='password_change'),

    #  Receiver CRUD
    path('receiver/create/', ReceiverCreate.as_view(), name='receiver_create'),
    path('receivers/', ReceiverList.as_view(), name='receiver_list'),
    path('receiver/delete/<int:pk>/', ReceiverDelete.as_view(), name='receiver_delete'),
    path('receiver/update/<int:pk>/', ReceiverUpdate.as_view(), name='receiver_update'),

    #  Message Group CRUD
    path('messagegroup/create/', MessageGroupCreate.as_view(), name='messagegroup_create'),
    path('messagegroup/update/<int:pk>/', MessageGroupUpdate.as_view(), name='messagegroup_update'),
    path('messagegroups/', MessageGroupList.as_view(), name='messagegroup_list'),
    path('messagegroup/delete/<int:pk>/', MessageGroupDelete.as_view(), name='messagegroup_delete'),

    # AuditTrails
    path('logs/', AuditTrailList.as_view(), name='logs'),
    path('audit/detail/<int:pk>/', AuditTrailDetail.as_view(), name='audit_detail'),

    #Message
    path('sms/create',MessageCreate.as_view(),name='message_create'),
    path('sms/list/',MessageList.as_view(),name='message_list'),
    path('words-count/',wordscount,name='words_count'),

]

