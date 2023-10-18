from django import forms
from django.contrib.auth import password_validation
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm
from .models import *

from .middleware import get_user


class LoginForm(forms.Form):
    username = forms.CharField(
        widget=forms.TextInput(
            attrs={'class': 'form-control'}))
    password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={'class': 'form-control'}))


class UserForm(forms.ModelForm):    
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'username', 'email', 'user_type']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in iter(self.fields):
            self.fields[field].widget.attrs.update({
                'class': 'form-control'
            })


class InstitutionForm(forms.ModelForm):
    class Meta:
        model = Institution
        fields = ['institution_name']

    def clean_institution_name(form):
        new_institution_name = form.cleaned_data['institution_name']
        q =  Institution.objects.filter(institution_name=new_institution_name)

        if q:
            raise forms.ValidationError('Institution with that name already exists.')
        else:
            return new_institution_name

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in iter(self.fields):
            self.fields[field].widget.attrs.update({
                'class': 'form-control'
            })


class StaffForm(forms.ModelForm):
    class Meta:
        model = Staff
        fields = ['first_name', 'last_name', 'username', 'email', 'user_type', 'institution']
        # if not user_type == 1:
        # labels = {
        #     'institution': None,
        #     'user_type': None,
        # }

    def clean_staff_username(form):
        new_staff_name = form.cleaned_data['username']
        q =  Staff.objects.filter(username=new_staff_name)

        if q:
            raise forms.ValidationError('A staff with that username already exists.')
        else:
            return new_staff_name

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['institution'].queryset = Institution.objects.all()
        # if not self.user.user_type == 1:
            # self.fields['institution'].label = ''
        for field in iter(self.fields):
            self.fields[field].widget.attrs.update({
                'class': 'form-control'
            })


class StaffUpdateForm(forms.ModelForm):
    class Meta(StaffForm.Meta):
        model = Staff
        fields = ['first_name', 'last_name', 'username', 'email', 'user_type', 'institution']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in iter(self.fields):
            self.fields[field].widget.attrs.update({
                'class': 'form-control'
            })


class ReceiverForm(forms.ModelForm):
    class Meta:
        model = Receiver
        fields = ['full_name', 'contact_number']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in iter(self.fields):
            self.fields[field].widget.attrs.update({
                'class': 'form-control'
            })


class MessageGroupForm(forms.ModelForm):

    receiver = forms.ModelMultipleChoiceField(
        queryset=Receiver.objects.all(), required=False,
        widget=forms.SelectMultiple(
            attrs={'class': 'select2 form-control', 'multiple': 'true'}))


    class Meta:
        model = MessageGroup
        fields = ['group_name', 'receiver', 'contacts_upload']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        receivers_by_user = Receiver.objects.filter(created_by=get_user()).values_list('id', flat=True)
        staffs = Staff.objects.filter(created_by=get_user()).values_list('id', flat=True)
        receivers = Receiver.objects.filter(created_by__in=staffs).values_list('id', flat=True)
        final_receivers= list(receivers_by_user) + list(receivers)
        final_receivers = Receiver.objects.filter(id__in=final_receivers).order_by('created_by', 'created_at')
        self.fields['receiver'].queryset = final_receivers
        for field in iter(self.fields):
            self.fields['group_name'].widget.attrs.update({
                'class': 'form-control'
            })


class MessageForm(forms.ModelForm):

    receiver = forms.ModelMultipleChoiceField(
        queryset=Receiver.objects.filter(deleted_at=None), required=False,
        widget=forms.SelectMultiple(
            attrs={'class': 'select2 form-control', 'multiple': 'true'}))

    groups = forms.ModelMultipleChoiceField(
        queryset=MessageGroup.objects.filter(deleted_at=None), required=False,
        widget=forms.SelectMultiple(
            attrs={'class': 'select2 form-control', 'multiple': 'true'}))


    class Meta:
        model = Message
        fields = ['message_type', 'message', 'receiver','groups','contacts_upload']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in iter(self.fields):
            self.fields['message_type'].widget.attrs.update({
                'class': 'form-control'
            })
            self.fields['message'].widget.attrs.update({
                'class': 'form-control'
            })


class ChangePasswordForm(forms.Form):    
    password = forms.CharField(
        label="New Password",
        strip=False,
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Password', 'id': 'pass'}),
    )
    confirm_password = forms.CharField(
        label="New password confirmation",
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Confirm Password', 'id': 'confirmpass'}),
        strip=False,
        help_text=password_validation.password_validators_help_text_html(),
    )

    def clean(form):
        password = form.cleaned_data.get('password')
        confirm_password = form.cleaned_data.get('confirm_password')

        if (password == confirm_password):
            try:
                password_validation.validate_password(password, confirm_password)
                return password
            except forms.ValidationError as error:
                form.add_error('password', error)
        else:
            raise forms.ValidationError('The two password fields didn’t match.')


class CustomPasswordResetForm(PasswordResetForm):
    email = forms.EmailField(
        label=("Email"),
        max_length=254,
        widget=forms.EmailInput(attrs={'class': 'form-control', 'autocomplete': 'email'})
    )


class CustomPasswordResetConfirmForm(SetPasswordForm):
    error_messages = {
        'password_mismatch': ('The two password fields didn’t match.'),
    }
    new_password1 = forms.CharField(
        label=("New password"),
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'autocomplete': 'new-password'}),
        strip=False,
    )
    new_password2 = forms.CharField(
        label=("New password confirmation"),
        strip=False,
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'autocomplete': 'new-password'}),
        help_text=password_validation.password_validators_help_text_html(),
    )