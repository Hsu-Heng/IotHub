# -*- encoding: utf-8 -*-
from rest_framework.routers import DefaultRouter
from .api.auth import IotHubTokenPairView
from rest_framework_simplejwt.views import TokenVerifyView
from .api.user import UserModelViewSet
from django.urls import path, include

# API User Router
user_router = DefaultRouter()
user_router.register('', UserModelViewSet, basename='user')

# API Auth Router
auth_url_patterns = [
    path('login/', IotHubTokenPairView.as_view(), ),
    path('verify-token/', TokenVerifyView.as_view()),
]