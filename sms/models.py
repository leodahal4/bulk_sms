from django.db import models
from django.contrib.auth.models import AbstractUser


AUDIT_TYPE_CHOICES = (
    (1, 'LOGIN'),
    (2, 'LOGOUT'),
    (3, 'CREATE'),
    (4, 'UPDATE'),
    (5, 'DELETE'),
    (6, 'RESET_PASSWORD'),
    (7, 'CHANGE GROUP'),
)


MESSAGE_TYPE = (
    (1, 'Recipient'),
    (2, 'Group'),
    (3, 'Bulk'),
)


USER_TYPE = (
    (1, 'Superuser'),
    (2, 'Admin'),
    (3, 'Staff'),
)


class User(AbstractUser):
    user_type = models.IntegerField(choices=USER_TYPE, default=1, null=True, blank=True)
    created_by = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True)

    def is_superadmin(self):
        return True if self.user_type == 1 else False 

    def is_administration(self):
        return True if self.user_type == 2 else False 

    def is_staffuser(self):
        return True if self.user_type == 3 else False 


class DateTimeModel(models.Model):
    created_at = models.DateTimeField(
        auto_now_add=True, auto_now=False, null=True, blank=True)
    updated_at = models.DateTimeField(
        auto_now_add=False, auto_now=True, null=True, blank=True)
    deleted_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        abstract = True


class Institution(DateTimeModel):
    institution_name = models.CharField(max_length=50)

    class Meta:
        ordering = ('created_at',)

    def __str__(self):
        return self.institution_name


class Staff(User, DateTimeModel):
    institution = models.ForeignKey(Institution, null=True, blank=True, on_delete=models.CASCADE, related_name='staff_institution')
    # is_admin = models.BooleanField(default=False)

    class Meta:
        verbose_name = "Staff"
        verbose_name_plural = "Staffs"
        ordering = ('created_at',)

    def __str__(self):
        return self.username


class Receiver(DateTimeModel):
    full_name = models.CharField(max_length=255, null=True)
    contact_number = models.BigIntegerField()
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, related_name="receiver_creator",)

    class Meta:
        ordering = ('created_at',)

    def __str__(self):
        return self.full_name + '/' + str(self.contact_number)


class MessageGroup(DateTimeModel):
    group_name = models.CharField(max_length=255)
    receiver = models.ManyToManyField(Receiver, blank=True)
    contacts_upload = models.FileField(null=True, blank=True, upload_to='files')
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name="messagegroup_creator",)


    class Meta:
        ordering = ('created_at',)

    def __str__(self):
        return self.group_name


class Message(DateTimeModel):
    message_type = models.IntegerField(choices=MESSAGE_TYPE,default=1)
    message = models.TextField()
    contacts_upload = models.FileField(null=True, blank=True, upload_to='files')
    receiver = models.ManyToManyField(Receiver,blank=True)
    groups = models.ManyToManyField(MessageGroup,blank=True)
    is_sent = models.BooleanField(default=False)
    recipients = models.TextField(null=True,blank=True)
    created_by = models.ForeignKey(User,null=True,blank=True,on_delete=models.SET_NULL)

    class Meta:
        ordering = ('-created_at',)

    def __str__(self):
        return str(self.id)


class AuditTrail(models.Model):
    modelType = models.CharField('Model Type', max_length=255)
    objectId = models.IntegerField('Model Id')
    action = models.IntegerField(
        choices=AUDIT_TYPE_CHOICES, default=1, null=False)
    user = models.ForeignKey(User, null=True, on_delete=models.SET_NULL, related_name='SMS_user')
    ip = models.GenericIPAddressField(null=True)
    fromObj = models.JSONField(null=True)
    toObj = models.JSONField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "AuditTrail"
        verbose_name_plural = "AuditTrails"
        ordering = ('-created_at',)

    def what_is(self):
        return AUDIT_TYPE_CHOICES[self.action - 1][1]

    def __str__(self):
        return self.modelType + '(' + AUDIT_TYPE_CHOICES[self.action - 1][1] + ')'
