from django.contrib.auth import authenticate
from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions, serializers
from rest_framework import fields
from rest_framework import status
from .models import User
from rest_framework_simplejwt.tokens import RefreshToken, SlidingToken, UntypedToken
from datetime import datetime
from django.utils.timezone import make_aware
from django.db import transaction
from .helper import get_or_none_raw_sql


class TokenSerializer(serializers.Serializer):
    # token_field = serializers.CharField(max_length=200)

    default_error_messages = {
        'no_active_account': _('No active account found with the given credentials')
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields['username'] = serializers.CharField(max_length=200)
        self.fields['password'] = serializers.CharField(max_length=200)

    def validate(self, attrs):

        username = attrs['username']
        password = attrs['password']
        authenticate_kwargs = {
            'username': username,
            'password': password,
        }
        try:
            authenticate_kwargs['request'] = self.context['request']
        except KeyError:
            pass

        self.user = authenticate(**authenticate_kwargs)
        # Prior to Django 1.10, inactive users could be authenticated with the
        # default `ModelBackend`.  As of Django 1.10, the `ModelBackend`
        # prevents inactive users from authenticating.  App designers can still
        # allow inactive users to authenticate by opting for the new
        # `AllowAllUsersModelBackend`.  However, we explicitly prevent inactive
        # users from authenticating to enforce a reasonable policy and provide
        # sensible backwards compatibility with older Django versions.
        if self.user is None or not self.user.is_active:
            raise exceptions.AuthenticationFailed(
                self.error_messages['no_active_account'],
                'no_active_account',
            )
        self.user.last_login = make_aware(datetime.now())
        self.user.save()
        return {}

    @classmethod
    def get_token(cls, user):
        raise NotImplementedError('Must implement `get_token` method for `TokenObtainSerializer` subclasses')


class TokenPairSerializer(TokenSerializer):
    @classmethod
    def get_token(cls, user):
        return RefreshToken.for_user(user)

    def validate(self, attrs):
        data = super().validate(attrs)
        refresh = self.get_token(self.user)
        data['access'] = str(refresh.access_token)
        data['refresh'] = str(refresh)
        data['id'] = self.user.id
        data['role'] = self.user.role
        data['email'] = self.user.email
        data['username'] = self.user.username
        return data


# User Serializer
class UserSerializer(serializers.ModelSerializer):
    role = fields.ChoiceField(
        choices=User.Roles,
        default=User.USER,
        help_text='Available choices: Admin, Manager, User'
    )
    username = serializers.CharField(max_length=150)
    email = serializers.EmailField()

    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password', 'role', 'create_at', 'update_at', 'is_active')
        extra_kwargs = {
            'username': {'required': True},
            'email': {'required': True},
            'password': {'write_only': True},
            'update_at': {'read_only': True},
            'create_at': {'read_only': True},
            'is_active': {'required': False},
        }

    def validate(self, attrs):

        username = attrs.get('username')
        email = attrs.get('email')
        raw_sql = '''
            SELECT * from users where username = %s and email = %s
        '''
        instance = get_or_none_raw_sql(User, raw_sql, [username, email])
        if instance:
            raise exceptions.APIException(code=status.HTTP_400_BAD_REQUEST, detail="帳號或電郵重複")
        user = self.context['request'].user
        if user.is_Manager():
            role = attrs.get('role')
            if role == User.Admin:
                raise exceptions.APIException(code=status.HTTP_400_BAD_REQUEST, detail="僅能指派Manager或User")
        return attrs

    @transaction.atomic
    def create(self, validated_data):
        self.validate(validated_data)
        data = {}
        data.update(validated_data)
        user = User(**data)
        user.set_password(validated_data.get('password'))
        user.save()
        return user


# User Serializer
class UserEditSerializer(serializers.ModelSerializer):
    role = fields.ChoiceField(
        choices=User.Roles,
        default=User.USER,
        help_text='Available choices: Admin, Manager, User',
        required=False
    )
    is_active = fields.BooleanField(required=False)

    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'role', 'create_at', 'update_at', 'is_active')
        extra_kwargs = {
            'username': {'read_only': True},
            'email': {'read_only': True},
            'update_at': {'read_only': True},
            'create_at': {'read_only': True},
            'is_active': {'required': False},
        }

    def update(self, instance, validated_data):
        user = self.context['request'].user
        if user.is_Manager():
            if instance.is_Admin():
                raise exceptions.APIException(code=status.HTTP_400_BAD_REQUEST, detail="無權限更改此使用者資訊")
            role = validated_data.get('role')
            if role == User.ADMIN:
                raise exceptions.APIException(code=status.HTTP_400_BAD_REQUEST, detail="僅能指派Manager或User")
        instance.role = validated_data.get('role', instance.role)
        instance.is_active = validated_data.get('is_active', instance.is_active)
        instance.save()
        return instance


class ResetPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=200)
    valid_password = serializers.CharField(max_length=200)

    def validate(self, attrs):
        password = attrs.get('password')
        valid_password = attrs.get('valid_password')
        if password != valid_password:
            raise exceptions.APIException(code=status.HTTP_400_BAD_REQUEST, detail="密碼不一至")








