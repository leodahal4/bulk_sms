import os
import tempfile
from django.db.models.fields import CommaSeparatedIntegerField
import xlrd
import json
import requests

from django.contrib.auth import authenticate, login, logout
from django.core import serializers
from django.core.mail import send_mail
from django.http import HttpResponse, HttpResponseRedirect, request
from django.urls import reverse_lazy
from django.shortcuts import redirect, render
from django.utils.crypto import get_random_string
from django.views.generic import CreateView, DeleteView, ListView, TemplateView, View, UpdateView, DetailView, FormView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils import timezone
from django.contrib.auth.models import Group
from django.db.models import Q
from django.views.generic.edit import DeletionMixin

from .mixins import *
from .forms import *

AUDIT_CHOICES = {a[1]: a[0] for a in AUDIT_TYPE_CHOICES}


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[-1].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def storeAuditTrail(prevObjModel, objModel, actionType, request):
    aTrail = AuditTrail()
    aTrail.modelType = objModel._meta.verbose_name.title()
    aTrail.objectId = objModel.pk
    aTrail.action = actionType
    aTrail.user = request.user
    aTrail.ip = get_client_ip(request)
    if prevObjModel:
        aTrail.fromObj = serializers.serialize("json", [prevObjModel])
    aTrail.toObj = serializers.serialize("json", [objModel])
    aTrail.save()


class AuthMixin(LoginRequiredMixin):
    login_url = reverse_lazy('sms:login')


class SMSLogin(TemplateView):
    template_name = "sms-2/login.html"

    def get(self, request):
        form = LoginForm()
        return render(request, self.template_name, {'form': form})

    def post(self, request):
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(username=username, password=password)
            form = LoginForm()
            if user is not None:
                if user.is_active:
                    login(request, user)

                    storeAuditTrail(
                        None, user, AUDIT_CHOICES['LOGIN'], request)
                    return HttpResponseRedirect(reverse_lazy('sms:sms_admin'))
            else:
                return render(request, self.template_name, {
                    'form': form, 'user': username, 'error': 'Incorrect username or password'})


class SMSLogout(AuthMixin, View):
    template_name = 'sms-2/logout.html'

    def get(self, request):
        return render(request, self.template_name)

    def post(self, request):
        storeAuditTrail(None, self.request.user, AUDIT_CHOICES['LOGOUT'], self.request)
        logout(self.request)
        return redirect('sms:login')


class BaseTemplate(AuthMixin, TemplateView):
    template_name = 'sms-2/dashboard.html'

    def get_context_data(self, **kwargs):
        user = self.request.user
        context =  super().get_context_data(**kwargs)

        if user.user_type == 1:
            context = {
                'logs': AuditTrail.objects.all().exclude(
                    Q(action=1) | Q(action=2)
                    ).order_by('-created_at')[:15],
                'groups': MessageGroup.objects.all().order_by('created_by'),
                'staffs': Staff.objects.all().order_by('created_by')
            }
        elif user.user_type == 2:
            logs_by_user = AuditTrail.objects.filter(user=user).values_list('id', flat=True)
            staffs = Staff.objects.filter(created_by=user).values_list('id', flat=True)
            staff_logs = AuditTrail.objects.filter(user__in=staffs).values_list('id', flat=True)
            all_logs = list(logs_by_user) + list(staff_logs)
            final_logs = AuditTrail.objects.filter(id__in=all_logs).exclude(
                    Q(action=1) | Q(action=2)
                    ).order_by('-created_at')
            
            groups_by_user = MessageGroup.objects.filter(created_by=user).values_list('id', flat=True)
            staffs = Staff.objects.filter(created_by=user).values_list('id', flat=True)
            staff_groups = MessageGroup.objects.filter(created_by__in=staffs).values_list('id', flat=True)
            all_groups = list(groups_by_user) + list(staff_groups)
            final_groups = MessageGroup.objects.filter(id__in=all_groups).order_by('created_by', 'created_at')
            
            staffs = Staff.objects.filter(
                created_by = user).order_by('created_by')

            context = {
                'logs': final_logs[:15],
                'groups': final_groups,
                'staffs': staffs
            }

        else:
            context = {
                'logs': AuditTrail.objects.filter(user=user).exclude(
                    Q(action=1) | Q(action=2)
                    ).order_by('-created_at')[:15],
                'groups': MessageGroup.objects.filter(created_by=user).order_by('created_by'),
                'staffs': Staff.objects.filter(created_by=user).order_by('created_by')
            }

        return context


class CreateMixin(AuthMixin, CreateView):
    def form_valid(self, form):
        creater = User.objects.get(username=self.request.user)
        form.instance.created_by = creater
        obj = form.save()
        storeAuditTrail(None, obj, AUDIT_CHOICES['CREATE'], self.request)
        return super(CreateMixin, self).form_valid(form)


class UpdateMixin(AuthMixin, UpdateView):
    def form_valid(self, form):
        prev_obj = self.get_object()
        obj = form.save()
        storeAuditTrail(prev_obj, obj, AUDIT_CHOICES['UPDATE'], self.request)
        return super(UpdateMixin, self).form_valid(form)


class DeleteMixin(AuthMixin, UpdateView):
    # fields = ['deleted_at']

    def form_valid(self, form):
        form.instance.deleted_at = timezone.now()
        obj = form.save()
        obj.is_active = False
        storeAuditTrail('', obj, AUDIT_CHOICES['DELETE'], self.request)
        return super(DeleteMixin, self).form_valid(form)


# Institution CRUD
class InstitutionCreate(SuperAdminRequiredMixin, CreateMixin):
    template_name = 'institution/institution_form.html'
    form_class = InstitutionForm
    success_url = reverse_lazy('sms:institution_list')


class InstitutionList(SuperAdminRequiredMixin, ListView):
    template_name = 'institution/institution_list.html'
    context_object_name = 'institutions'
    queryset = Institution.objects.all()


class InstitutionUpdate(SuperAdminRequiredMixin, UpdateMixin):
    template_name = 'institution/institution_form.html'
    form_class = InstitutionForm
    queryset = Institution.objects.all()
    success_url = reverse_lazy('sms:institution_list')


class InstitutionDelete(SuperAdminRequiredMixin, DeleteMixin, DeletionMixin):
    model = Institution
    success_url = reverse_lazy('sms:institution_list')

    def post(self, request, pk, *args, **kwargs):
        if 'confirm_delete' in self.request.POST:
            institution = Institution.objects.get(id=pk)
            institution.deleted_at = timezone.now()
            storeAuditTrail('', institution, AUDIT_CHOICES['DELETE'], self.request)
            institution.delete()
        return redirect('sms:institution_list')


#Staff CRUD

class StaffCreate(AdminRequiredMixin, CreateMixin):
    template_name = 'staff/staff_form.html'
    form_class = StaffForm

    def get(self, request, *args, **kwargs):
        user= self.request.user
        form = StaffForm()
        if not user.is_superadmin():
            form.fields['institution'].widget = forms.HiddenInput()
            form.fields['institution'].initial = user.staff.institution
            form.fields['institution'].label = ''
            form.fields['user_type'].widget = forms.HiddenInput()
            form.fields['user_type'].initial = 3
            form.fields['user_type'].label = ''
        return render(request, 'staff/staff_form.html', {'form': form})

    def form_valid(self, form):
        creater = User.objects.get(username=self.request.user)
        form.instance.created_by = creater
        form.instance.is_staff = False
        obj = form.save()
        password = get_random_string(10)
        obj.set_password(password)
        
        msg = obj.first_name + '(' + obj.username + '), ' + 'your account has been created. Please use <strong>Username: </strong>' + obj.username + '<br> <strong>Password: </strong>' + password + '<br> to login now.'

        send_mail('Account Created', '', 'no-reply@qubit.com',
                      [obj.email], fail_silently=True, html_message=msg)

        return super(StaffCreate, self).form_valid(form)


    def get_queryset(self):
        return Staff.objects.all()

    def get_success_url(self):
        return reverse_lazy('sms:staff_list')


class StaffList(AdminRequiredMixin, ListView):
    template_name = 'staff/staff_list.html'
    context_object_name = 'staffs'

    def get_queryset(self):
        user = self.request.user
        if user.user_type == 1:
            queryset = Staff.objects.all().order_by('created_by')
        elif user.user_type == 2:
            queryset = Staff.objects.filter(
                created_by = user
            )
        
        return queryset


class StaffUpdate(AdminRequiredMixin, UpdateMixin):
    template_name = 'staff/staff_form.html'
    form_class = StaffUpdateForm

    def get_queryset(self):
        return Staff.objects.all()

    def get_success_url(self):
        return reverse_lazy('sms:staff_list')


class StaffDelete(AdminRequiredMixin, DeleteMixin):
    model = Staff
    success_url = reverse_lazy('sms:staff_list')

    def post(self, request, pk, *args, **kwargs):
        if 'confirm_delete' in self.request.POST:
            staff = Staff.objects.get(id=pk)
            staff.deleted_at = timezone.now()
            storeAuditTrail('', staff, AUDIT_CHOICES['DELETE'], self.request)
            staff.delete()
        return redirect('sms:staff_list')

    # def form_valid(self, form):
    #     form.instance.deleted_at = timezone.now()
    #     obj = form.save()
    #     storeAuditTrail('', obj, AUDIT_CHOICES['DELETE'], self.request)
    #     obj.delete()
    #     return super().form_valid(form)

# User CRUD
class UserCreate(SuperAdminRequiredMixin, View):

    def get(self, request, *args, **kwargs):
        form = UserForm()
        return render(request, 'users-2/user_form.html', {'form': form})

    def post(self, request, *args, **kwargs):
        form = UserForm(request.POST)
        
        if form.is_valid():
            obj = form.save(commit=False)
            password = get_random_string(10)

            user = User.objects.create_user(
                obj.username, obj.email, password
                )

            user.first_name = obj.first_name
            user.last_name = obj.last_name
            user.is_superuser = False
            user.is_staff = False
            user.is_active = True
            user.user_type = obj.user_type
            user.created_by = self.request.user.username
            user.save()

            storeAuditTrail(None, user, AUDIT_CHOICES['CREATE'], request)
            msg = user.first_name + ', ' + 'your account has been created. Please use <strong>Username: </strong>' + user.username + '<br> <strong>Password: </strong>' + password

            send_mail('Account Created', '', 'no-reply@qubit.com',
                      [user.email], fail_silently=True, html_message=msg)

            return HttpResponseRedirect(reverse_lazy('sms:user_list'))

        else:
            return render(request, 'users/user_form.html',
                          {'msg_error': 'Something\'s not right, See Below !', 'form': form})


class UserList(SuperAdminRequiredMixin, ListView):
    template_name = 'users-2/user_list.html'
    model = User
    # queryset = User.objects.filter(is_active=True)
    paginate_by = 100

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['url_name'] = 'users'
        return context

    def get_queryset(self):
        user = self.request.user

        user = self.request.user
        if user.is_superadmin or user.is_superuser:
            queryset = Staff.objects.all()
        else:
            queryset = Staff.objects.filter(institution=user.institution)

        return queryset


class UserPwdReset(SuperAdminRequiredMixin, View):

    def get(self, request, *args, **kwargs):
        userModel = User.objects.get(pk=self.kwargs['user_id'])
        userCopy = userModel
        password = get_random_string(10)
        userModel.set_password(password)
        userModel.save()

        storeAuditTrail(userCopy, userModel, AUDIT_CHOICES['RESET_PASSWORD'], request)
        msg = userModel.first_name + ', ' + 'your account has been created. Please use <br/> <strong>Password: </strong>' + password

        send_mail('Your Account Has been Created', '', 'no-reply@qubit.com', [userModel.email], fail_silently=True,
                  html_message=msg)

        return HttpResponseRedirect(reverse_lazy('sms:user_list'))


class UserDelete(SuperAdminRequiredMixin, DeleteView):
    model = User
    success_url = reverse_lazy('sms:user_list')

    def get_context_data(self, request, **kwargs):
        context = super().get_context_data(**kwargs)
        prev_obj = self.get_object()
        prev_obj.delete()
        storeAuditTrail(prev_obj, None, AUDIT_CHOICES['DELETE'], self.request)
        context['url_name'] = 'user_delete'
        return context


class AuditTrailList(AuthMixin, ListView):
    template_name = 'sms-2/logs.html'
    model = AuditTrail
    paginate_by = 100
    queryset= AuditTrail.objects.all()

    def get_context_data(self, **kwargs):
        user = self.request.user
        context =  super().get_context_data(**kwargs)
        context['url_name'] = 'logs'

        if user.user_type == 1:
            context = {
                'logs': AuditTrail.objects.all().exclude(
                    Q(action=1) | Q(action=2)
                    ).order_by('-created_at')
            }
        elif user.user_type == 2:
            logs_by_user = AuditTrail.objects.filter(user=user).values_list('id', flat=True)
            staffs = Staff.objects.filter(created_by=user).values_list('id', flat=True)
            staff_logs = AuditTrail.objects.filter(user__in=staffs).values_list('id', flat=True)
            all_logs = list(logs_by_user) + list(staff_logs)
            final_logs = AuditTrail.objects.filter(id__in=all_logs).exclude(
                    Q(action=1) | Q(action=2)
                    ).order_by('-created_at')
            
            context = {
                'logs': final_logs
            }
        else:
            context = {
                'logs': AuditTrail.objects.filter(user=user).exclude(
                    Q(action=1) | Q(action=2)
                    ).order_by('-created_at')
            }
        return context


class AuditTrailDetail(AuthMixin, DetailView):
    template_name = 'sms-2/audit_detail.html'
    model = AuditTrail

    def get_context_data(self, **kwargs):
        context = super().get_context_data()
        pk = self.kwargs.get('pk')
        audit = AuditTrail.objects.get(pk=pk)
        try:
            previousObject = json.loads(audit.fromObj)
            context['previousObject'] = previousObject[0]['fields']
        except:
            pass
        try:
            updatedObject = json.loads(audit.toObj)
            updatedObjects_values = []
            for key, value in updatedObject[0]['fields'].items():
                updatedObjects_values.append(value)
            context['updatedObject'] = updatedObject[0]['fields']
            context['updatedObject_values'] = updatedObjects_values
        except:
            pass

        return context


# Receiver CRUD
class ReceiverCreate(CreateMixin):
    template_name = 'receiver-2/receiver_form.html'
    model = Receiver
    form_class = ReceiverForm
    success_url = reverse_lazy('sms:receiver_list')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['url_name'] = 'receiver'
        return context

    def form_valid(self, form):
        receiver = form.save(commit=False)
        receiver.created_by = self.request.user
        receiver.save()
        return super(ReceiverCreate, self).form_valid(form)


class ReceiverUpdate(UpdateMixin):
    template_name = 'receiver-2/receiver_form.html'
    model = Receiver
    form_class = ReceiverForm
    success_url = reverse_lazy('sms:receiver_list')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['url_name'] = 'receiver'
        return context


class ReceiverList(AuthMixin, ListView):
    template_name = 'receiver-2/receiver_list.html'
    paginate_by = 100
    queryset = Receiver.objects.all()

    def get_context_data(self, **kwargs):
        user = self.request.user
        context = super().get_context_data(**kwargs)
        context['url_name'] = 'receiver'

        if user.user_type == 1:
            context = {
                'receivers': Receiver.objects.all().order_by('created_by', 'created_at')
            }
        elif user.user_type == 2:
            receivers_by_user = Receiver.objects.filter(created_by=user).values_list('id', flat=True)
            staffs = Staff.objects.filter(created_by=user).values_list('id', flat=True)
            staff_receivers = Receiver.objects.filter(created_by__in=staffs).values_list('id', flat=True)
            all_receivers = list(receivers_by_user) + list(staff_receivers)
            final_receivers = Receiver.objects.filter(id__in=all_receivers).order_by('created_by', 'created_at')
            
            context = {
                'receivers': final_receivers,
            }
        else:
            context = {
                'receivers': Receiver.objects.filter(
                    created_by = user.pk
                    ).order_by('created_at')
            }
        return context


class ReceiverDelete(DeleteMixin, DeletionMixin):
    model = Receiver
    success_url = reverse_lazy('sms:receiver_list')

    def post(self, request, pk, *args, **kwargs):
        if 'confirm_delete' in self.request.POST:
            receiver = Receiver.objects.get(id=pk)
            receiver.deleted_at = timezone.now()
            storeAuditTrail('', receiver, AUDIT_CHOICES['DELETE'], self.request)
            receiver.delete()
        return redirect('sms:receiver_list')


class MessageGroupCreate(AuthMixin, CreateView):
    template_name = 'receiver-2/messagegroup_form.html'
    model = MessageGroup
    form_class = MessageGroupForm
    success_url = reverse_lazy('sms:messagegroup_list')

    def form_valid(self, form):
        creater = User.objects.get(username=self.request.user)
        form.instance.created_by = creater
        obj = form.save()
        if obj.contacts_upload:
            contacts_file = obj.contacts_upload
            i = 0
            try:
                fd, tmp = tempfile.mkstemp()
                with os.fdopen(fd, 'wb') as out:
                    out.write(contacts_file.read())
                book = xlrd.open_workbook(tmp)
                sh = book.sheet_by_index(0)
                for rx in range(1, sh.nrows):
                    receiver_obj, created = Receiver.objects.get_or_create(full_name=sh.row(rx)[0].value,
                                                                           contact_number=int(sh.row(rx)[1].value))
                    if receiver_obj:

                        obj.receiver.add(receiver_obj)
                        obj.save()

                    i = i + 1

            finally:
                os.unlink(tmp)
        storeAuditTrail(None, obj, AUDIT_CHOICES['CREATE'], self.request)
        return super(MessageGroupCreate, self).form_valid(form)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['url_name'] = 'message_group'
        return context


class MessageGroupUpdate(AuthMixin,UpdateView):
    template_name = 'receiver-2/messagegroup_form.html'
    model = MessageGroup
    form_class = MessageGroupForm
    success_url = reverse_lazy('sms:messagegroup_list')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['url_name'] = 'message_group'
        return context

    def form_valid(self, form):
        prev_obj = self.get_object()
        obj = form.save()
        if obj.contacts_upload:
            contacts_file = obj.contacts_upload
            i = 0
            try:
                fd, tmp = tempfile.mkstemp()
                with os.fdopen(fd, 'wb') as out:
                    out.write(contacts_file.read())
                book = xlrd.open_workbook(tmp)
                sh = book.sheet_by_index(0)
                for rx in range(1, sh.nrows):
                    receiver_obj, created = Receiver.objects.get_or_create(full_name=sh.row(rx)[0].value,
                                                                           contact_number=int(sh.row(rx)[1].value))
                    if receiver_obj:
                        msg_group = MessageGroup.objects.get(id=obj.id)
                        msg_group.receiver.add(receiver_obj)
                        msg_group.save()
                    i = i + 1;
            finally:
                os.unlink(tmp)
        storeAuditTrail(prev_obj, obj, AUDIT_CHOICES['UPDATE'], self.request)
        return super(MessageGroupUpdate, self).form_valid(form)


class MessageGroupList(AuthMixin, ListView):
    template_name = 'receiver-2/messagegroup_list.html'
    paginate_by = 100
    queryset = MessageGroup.objects.all()

    def get_context_data(self, **kwargs):
        user = self.request.user
        context = super().get_context_data(**kwargs)
        context['url_name'] = 'messagegroup'

        if user.user_type == 1:
            context = {
                'messagegroups': MessageGroup.objects.all().order_by('created_by', 'created_at')
            }
        elif user.user_type == 2:
            groups_by_user = MessageGroup.objects.filter(created_by=user).values_list('id', flat=True)
            staffs = Staff.objects.filter(created_by=user).values_list('id', flat=True)
            staff_groups = MessageGroup.objects.filter(created_by__in=staffs).values_list('id', flat=True)
            all_groups = list(groups_by_user) + list(staff_groups)
            final_groups = MessageGroup.objects.filter(id__in=all_groups).order_by('created_by', 'created_at')
            
            context = {
                'messagegroups': final_groups,
            }
        else:
            context = {
                'messagegroups': MessageGroup.objects.filter(
                    created_by = user.pk
                    ).order_by('created_at')
            }
        return context


class MessageGroupDelete(DeleteMixin, DeletionMixin):
    model = MessageGroup
    success_url = reverse_lazy('sms:messagegroup_list')

    def post(self, request, pk, *args, **kwargs):
        if 'confirm_delete' in self.request.POST:
            messagegroup = MessageGroup.objects.get(id=pk)
            messagegroup.deleted_at = timezone.now()
            storeAuditTrail('', messagegroup, AUDIT_CHOICES['DELETE'], self.request)
            messagegroup.delete()
        return redirect('sms:messagegroup_list')


class MessageCreate(AuthMixin,CreateView):
    template_name = 'message-2/message_form.html'
    model = Message
    form_class = MessageForm
    success_url = reverse_lazy('sms:sms_admin')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['url_name'] = 'message'
        return context

    def form_valid(self, form):
        if form.is_valid():
            obj = form.save()
            if obj.receiver:
                contacts_list=obj.receiver.values_list('contact_number',flat=True)
                recipients = ",".join([str(x) for x in contacts_list])
                r = requests.post('http://aakashsms.com/admin/public/sms/v1/send', data={'auth_token': '127742dcdda0e4dba2aa5ae33f96551379bfe4189fcedd5afb4ed3d589dc6b05',
                                                                                         'from': '31001','to':str(recipients),'text':str(obj.message)})
                if r.status_code == 201:
                    obj.is_sent= True
                    obj.recipients = str(recipients)
                    obj.created_by = self.request.user
                    obj.save()

            if obj.groups:
                contacts_list = []
                for x in obj.groups.all():
                    for y in x.receiver.all():
                        contacts_list.append(y.contact_number)
                contacts_list = (set(contacts_list))
                list(contacts_list)
                recipients = ",".join([str(x) for x in contacts_list])
                r = requests.post('http://aakashsms.com/admin/public/sms/v1/send', data={'auth_token': '127742dcdda0e4dba2aa5ae33f96551379bfe4189fcedd5afb4ed3d589dc6b05',
                                                                                         'from': '31001','to':str(recipients),'text':str(obj.message)})
                if r.status_code == 201:
                    obj.is_sent= True
                    obj.recipients = str(recipients)
                    obj.created_by = self.request.user
                    obj.save()
            if obj.contacts_upload:
                excel_file = obj.contacts_upload
                i = 0
                try:
                    fd, tmp = tempfile.mkstemp()
                    with os.fdopen(fd, 'wb') as out:
                        out.write(excel_file.read())
                    book = xlrd.open_workbook(tmp)
                    sh = book.sheet_by_index(0)
                    contacts_list = []
                    for rx in range(1, sh.nrows):
                        receiver_obj, created = Receiver.objects.get_or_create(full_name=sh.row(rx)[0].value,
                                                                               contact_number=int(sh.row(rx)[1].value))
                        if receiver_obj:
                            contacts_list.append(receiver_obj.contact_number)
                        i = i + 1;
                    contacts_list = (set(contacts_list))
                    list(contacts_list)
                    recipients = ",".join([str(x) for x in contacts_list])
                    r = requests.post('http://aakashsms.com/admin/public/sms/v1/send', data={
                        'auth_token': '127742dcdda0e4dba2aa5ae33f96551379bfe4189fcedd5afb4ed3d589dc6b05',
                        'from': '31001', 'to': str(recipients), 'text': str(obj.message)})
                    if r.status_code == 201:
                        obj.is_sent = True
                        obj.recipients = str(recipients)
                        obj.created_by = self.request.user
                        obj.save()
                finally:
                    os.unlink(tmp)
        return HttpResponseRedirect(reverse_lazy('sms:sms_admin'))


def wordscount(request):
    q = request.GET.get('query')
    count = len(str(q))
    credit = 1
    credit = credit + int(count/160)
    return HttpResponse(json.dumps({'count':count,'credit':credit}))


class MessageList(AuthMixin,ListView):
    template_name = 'message-2/message_list.html'
    model = Message
    paginate_by = 100

    def get_queryset(self):
        if self.request.user.is_superadmin:
            qs = Message.objects.filter(deleted_at=None)
        else:
            qs = Message.objects.filter(created_by=self.request.user, deleted_at=None)
        return qs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['url_name'] = 'message'
        return context


class ChangePassword(AuthMixin, FormView):
    model = User
    form_class = ChangePasswordForm
    template_name = 'users-2/change_password.html'
    success_url = reverse_lazy('sms:login')

    def form_valid(self, form):
        password = form.cleaned_data
        user = self.request.user
        user.set_password(password)
        user.save()
        storeAuditTrail(
            None, self.request.user, AUDIT_CHOICES['RESET_PASSWORD'], self.request
            )
        return super(ChangePassword, self).form_valid(form)
