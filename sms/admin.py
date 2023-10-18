from django.contrib import admin
from django.contrib.admin import AdminSite
from django.contrib.auth.models import Group
from .models import *


class UserAdmin(admin.ModelAdmin):
    list_display = (
        'username',
        'first_name',
        'last_name',
        'user_type',
    )
    list_filter = (
        'user_type',
    )


class InstitutionAdmin(admin.ModelAdmin):
    list_display = (
        'institution_name',
    )


class StaffAdmin(admin.ModelAdmin):
    list_display = (
        'username',
        'first_name',
        'last_name',
        'user_type',
        'institution',
    )
    list_filter = (
        'user_type',
    )

admin.site.register(User, UserAdmin)
admin.site.register(Institution, InstitutionAdmin)
admin.site.register(Staff, StaffAdmin)
admin.site.register(Receiver)
admin.site.register(MessageGroup)
admin.site.register(Message)
admin.site.register(AuditTrail)
