from rest_framework.serializers import (ModelSerializer,
                                        ValidationError,
                                        )
from rest_framework import serializers
from user.models import *

class UserSerializer(ModelSerializer):
    """" User Serializer for creating and updating the user """

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'full_name', 'contact_number', 'password', 'dob', 'gender',]
        extra_kwargs = {'password': {'write_only': True},}

    def validate(self, attrs):
        #write your validations for over all
        return attrs

    def validate_email(self, value):
        #write your validation for particular column
        return value

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user

    def update(self, instance, validated_data):
        instance.username = validated_data.get('username', instance.username)
        instance.email = validated_data.get('email', instance.email)
        instance.full_name = validated_data.get('full_name', instance.full_name)
        instance.contact_number = validated_data.get('contact_number', instance.contact_number)
        instance.dob = validated_data.get('dob', instance.dob)
        instance.gender = validated_data.get('gender', instance.gender)
        instance.save()
        return instance


class UserSimpleSerializer(ModelSerializer):
    """ User Basic Information Serializer """

    class Meta:
        model = User
        fields = ('id', 'avatar', 'username',)

class EmailLoginSerializer(ModelSerializer):
    """ Login Serializer """
    class Meta:
        model = User
        fields = ['email', 'password']
        extra_kwargs = {
                        'password': {'write_only': True, 'required': True},
                        'email': {'required': True}
                        }

class ChangePasswordSerializer(serializers.Serializer):
    """ ChangePassword serializers """
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

class ForgotPasswordSerializer(serializers.Serializer):
    """ ChangePassword serializers """
    email = serializers.CharField(required=True)


class ChangePasswordThroughOTPSerializer(serializers.Serializer):
    """ ChangePassword serializers """
    email = serializers.CharField(required=True)
    otp = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

class SocialLoginSerializer(serializers.Serializer):
    """ ChangePassword serializers """
    access_token = serializers.CharField(required=True)
    app_id = serializers.CharField(required=True)