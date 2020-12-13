from django.db import models
from django.contrib.auth.models import (
	BaseUserManager, AbstractBaseUser
) 
# Create your models here.

class UserManager(BaseUserManager):
    def create_user(self, email, password, username=None):
        """
        Creates and saves a User with the given email, date of
        birth and password.
        """
        if not email:
            raise ValueError('Users must have an email address')

        if not username:
            username = email

        user = self.model(
            username=username,
            email=self.normalize_email(email),
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, username=None):
        """
        Creates and saves a superuser with the given email, date of
        birth and password.
        """
        user = self.create_user(
            username=username,
            email=email,
            password=password,
        )
        user.is_admin = True
        user.is_staf = True
        user.is_superuser = True
        user.save(using=self._db)
        return user

class User(AbstractBaseUser):
    CHEAT_OTP = ['001100', '123456', '111111']
    GENDER_CHOICES = (
        ("M", "Male"),
        ("F", "Female"),
        ("O", "Other"),
    )

    def save(self, *args, **kwargs):
        if self.pk == None:
            if not (self.email == None or self.email == ""):
                if User.objects.filter(email=self.email).exists():
                    return ValidationError("User Already Exist in  this mail id")

            if not (self.contact_number == None or self.contact_number == ""):
                if User.objects.filter(contact_number=self.contact_number).exists():
                    return ValidationError("User Already Exist in  this contact_number")

            if  (self.username == None or self.username == ""):
                email = self.email
                if email:
                    mail_id = email.split("@")[0].lower()
                    if User.objects.filter(username_slug=mail_id).exists():
                         self.username = f"{email}"
                    else:
                        self.username = f"{mail_id}"

                contact_number = self.contact_number
                if contact_number:
                     self.username = f"{contact_number}"
            self.username = self.username.lower()

        super(User, self).save(*args, **kwargs)

    def validate_contact_number(value):
        global user_id
        if not (value == None or value == ""):
            if len(value) < 5 or len(value) > 16:
                raise ValidationError("Phone Number Must be in range of 5 to 16 digits")
            # if Us er.objects.filter(contact_number=value).exclude(id=user_id).exists():
                # rai   se ValidationError("User Already Exist in  this contact number")
        else:
            return value


    username = models.CharField(max_length=255, unique=True, blank=False, null=False,)
    email = models.EmailField(blank=True, null=True, db_index=True)
    contact_number = models.CharField(
        validators=[validate_contact_number
                    ],
        max_length=16, blank=True, null=True, db_index=True
    )


    full_name = models.CharField(max_length=255, unique=False, blank=True, null=True,)
    dob = models.DateField(blank=True, null=True,)
    gender = models.CharField(max_length=1,
                              choices=GENDER_CHOICES, blank=True, null=True)

    mobile_otp = models.IntegerField(blank=True, null=True,)
    mobile_otp_validity = models.DateTimeField(blank=True, null=True,)

    email_otp = models.IntegerField(blank=True, null=True,)
    email_otp_validity = models.DateTimeField(blank=True, null=True,)

    email_verified = models.BooleanField(default=False)
    contact_number_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    # avatar = models.ImageField(upload_to='avatars', blank = True, null=True)

    groups = models.ManyToManyField('auth.Group',  blank=True, null=True,)

    objects = UserManager()

    USERNAME_FIELD = "username"
    # REQUIRED_FIELDS = ["contact_number"]

    def has_perm(self, perm, obj=None):
        user_perms = []
        if self.is_staff:
            groups = self.groups.all()
            for group in groups:
                perms = [(f"{x.content_type.app_label}.{x.codename}") for x in group.permissions.all()]
                user_perms += perms

            if perm in user_perms:
                return True
        return (self.is_admin or self.is_superuser)

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        return True

    def send_otp_to_email(self):
        # expiry_time = datetime.now() + timedelta(minutes=10)
        # otp = self.otp
        # otp = random.randrange(99999, 999999, 12)
        # self.otp = otp
        # self.otp_validity = expiry_time
        # self.save()
        # full_msg = OTP_MESSAGES['OTP_RESET']['MESSAGE'] % {'otp': f"{otp}"}
        # if self.email:
        #     send_normal_mail(OTP_MESSAGES['OTP_RESET']['SUBJECT'], full_msg, 'deepak@gloify.com', [self.email])
        return True

    def validate_otp(self, otp):
        valid = (self.otp == int(otp) and self.otp_validity >= utc.localize(datetime.now()))
        if settings.SYS_ENV != 'PROD' and not valid:
            if otp in self.CHEAT_OTP:
                valid = True
        self.otp = None
        self.save()
        return valid

    def get_tokens_for_user(self):
        refresh = RefreshToken.for_user(self)

        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }