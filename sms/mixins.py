from django.contrib.auth.mixins import AccessMixin
from django.shortcuts import redirect


class StaffRequiredMixin(AccessMixin):
    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('sms:sms_admin')
        return super().dispatch(request, *args, **kwargs)


class AdminRequiredMixin(AccessMixin):
    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated or request.user.user_type == 3:
            return redirect('sms:sms_admin')
        return super().dispatch(request, *args, **kwargs)


class SuperAdminRequiredMixin(AccessMixin):
    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated or not request.user.user_type == 1:
            return redirect('sms:sms_admin')
        return super().dispatch(request, *args, **kwargs)
