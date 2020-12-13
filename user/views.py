
# Create your views here.
from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework import  status

from rest_framework.permissions import (
        AllowAny,
        IsAuthenticated,
    )

from rest_framework.generics import (
        GenericAPIView,
    )

# Local Import
from user.models import *
from social_app.models import SocialAccount, SocialApp
from user.permissions import (
        IsLoggedInUserOrAdmin,
    )
from user.serializers import *

# Create your views here.
class UserViewSet(viewsets.ModelViewSet):
    ''' Create new user. while creating the user send only the required parameters.
        update user profile. access to admin for destroying the user. '''
    queryset = User.objects.all()
    serializer_class = UserSerializer
    # Add this code block
    def get_permissions(self):
        permission_classes = []
        if self.action == 'create':
            permission_classes = [AllowAny]
        elif self.action == 'retrieve':
            permission_classes = [IsLoggedInUserOrAdmin]
        elif self.action == 'update' or self.action == 'partial_update':
            permission_classes = [IsLoggedInUserOrAdmin]
        elif  self.action == 'list' or self.action == 'destroy':
            permission_classes = [IsAdminUser]
        return [permission() for permission in permission_classes]

    def create(self, request, *args, **kwargs):
        try:
            response_data = super(UserViewSet, self).create(request, *args, **kwargs)
            data = response_data.data
            return Response(data, status.HTTP_201_CREATED)
        except Exception as e:
            try:
                exception = e.__dict__
                if exception.get('detail', {}).get('username', None):
                    return Response({"error": "user with this username already exists."},
                                    status.HTTP_422_UNPROCESSABLE_ENTITY)

                other_errors = exception.get('detail', {}).get('non_field_errors', None)
                if other_errors:
                    error_messages = ""
                    for other_error in other_errors:
                        error_messages += str(other_error)
                    return Response({"error": error_messages}, status.HTTP_422_UNPROCESSABLE_ENTITY)

                other_errors = exception.get('detail', {}).get('contact_number', None)
                if other_errors:
                    error_messages = ""
                    for other_error in other_errors:
                        error_messages += str(other_error) + " "
                    return Response({"error": error_messages}, status.HTTP_422_UNPROCESSABLE_ENTITY)

                return Response({"error": "Please check your email or contact number username"},status.HTTP_422_UNPROCESSABLE_ENTITY)
            except Exception as e:
                return Response({"error": "Something Went wrong"}, status.HTTP_422_UNPROCESSABLE_ENTITY)


class LoginWithEmail(GenericAPIView):
    """Custom Login for user to login using password"""

    permission_classes = [AllowAny]
    serializer_class = EmailLoginSerializer
    def post(self, request):
        password = request.data.get('password', None)
        email = request.data.get('email', None)

        if not email:
            return Response({"error": "Please Enter Email"}, status.HTTP_422_UNPROCESSABLE_ENTITY)

        if not password:
            return Response({"error": "Please Enter Password"}, status.HTTP_422_UNPROCESSABLE_ENTITY)

        user = User.objects.filter(email=email).first()

        if user:
            if user.check_password(password):
                token = user.get_tokens_for_user()
                user_serializer = UserSimpleSerializer(user, many=False)
                return Response({"token":token , "user": user_serializer.data}, status=status.HTTP_201_CREATED)
            else:
                return Response({"error": "User Does Not Exist With This Credentials"}, status.HTTP_422_UNPROCESSABLE_ENTITY)
        else:
            return Response({"error": "User Doesn't Exist"}, status.HTTP_422_UNPROCESSABLE_ENTITY)

class ChangePassword(GenericAPIView):
    """End point To reset the password.
     Only loged in user can consume this """
    permission_classes = [IsAuthenticated]
    serializer_class = ChangePasswordSerializer

    def patch(self, request):
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")
        user = request.user

        if not user.check_password(old_password):
            return Response({"message": "Please Enter correct old password"}, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        if user:
            user.set_password(new_password)
            user.save()
            return Response({"message": "Password has been changed Please login using the new password."}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "User Doesn't Exist"}, status.HTTP_404_NOT_FOUND)

class ForgotPassword(GenericAPIView):
    """End point To send the OTP for forgot password. Send email in parameters"""
    permission_classes = [AllowAny]
    serializer_class = ForgotPasswordSerializer
    def post(self, request):
        email = request.data.get("email")
        user = User.objects.filter(email=email).first()
        if user:
            user.send_otp_to_email()
            return Response({"message": "OTP has sent to Your Registered Email"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "User Doesn't Exist"}, status.HTTP_422_UNPROCESSABLE_ENTITY)

class ChangePasswordThroughOTPView(GenericAPIView):
    """End point To reset the password using otp. Use '001100', '123456', '111111' as cheat otp """
    permission_classes = [AllowAny]
    serializer_class = ChangePasswordThroughOTPSerializer

    def post(self, request):
        email = request.data.get("email")
        otp = request.data.get("otp")
        password = request.data.get("new_password")
        user = User.objects.filter(email=email).first()
        print(user)
        if user:
            if user.validate_otp(str(otp)):
                user.set_password(password)
                user.save()
                return Response({"message": "Password has been changed Please login using the new password."}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "OTP is Incorrect or Expired"}, status.HTTP_422_UNPROCESSABLE_ENTITY)
        else:
            return Response({"error": "User Doesn't Exist"}, status.HTTP_404_NOT_FOUND)

class GoogleSignInView(GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = SocialLoginSerializer

    def post(self, request):
        access_token = request.data.get('access_token')
        app_id = request.data.get('app_id')
        if not SocialApp.objects.filter(app_id = app_id, provider='google').exists():
            return Response({"error": "please provide correct App ID"}, status.HTTP_422_UNPROCESSABLE_ENTITY)

        user = SocialAccount.google_auth(access_token)
        if user:
            token = user.get_tokens_for_user()
            user_serializer = UserSimpleSerializer(user, many=False)
            return Response({"token":token , "user": user_serializer.data}, status=status.HTTP_201_CREATED)
        else:
            return Response({"error": "Something went wrong"}, status.HTTP_422_UNPROCESSABLE_ENTITY)