# -*- encoding: utf-8 -*-
from rest_framework_simplejwt.views import TokenObtainPairView
from ..serializers import (
    TokenPairSerializer,
)


class IotHubTokenPairSerializer(TokenPairSerializer):

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        return token


class IotHubTokenPairView(TokenObtainPairView):
    serializer_class = IotHubTokenPairSerializer
