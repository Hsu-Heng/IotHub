# -*- encoding: utf-8 -*-
from rest_framework import viewsets, status, filters, mixins
from rest_framework.response import Response
from rest_framework import exceptions
from django.db import transaction
from rest_framework.decorators import action
from django_filters.rest_framework import DjangoFilterBackend
from ..models import User
from ..serializers import UserSerializer, UserEditSerializer, ResetPasswordSerializer
from ..authentication import JWTAuthentication
from ..permission import IsAdminPermission, IsManagerPermission, IsUserPermission
from ..pagination import StandardPagination


class UserModelViewSet(viewsets.ModelViewSet):
    authentication_classes = (JWTAuthentication,)
    pagination_class = StandardPagination
    filter_backends = (filters.SearchFilter, DjangoFilterBackend)
    serializer_class = UserSerializer
    queryset = User.objects.all()
    search_fields = ['username', 'email']
    filter_fields = ['role']
    http_method_names = ['get', 'post', 'put', 'head', 'delete', 'patch']

    def get_permissions(self):
        """
        Instantiates and returns the list of permissions that this view requires.
        """
        if self.action == 'retrieve':
            permission_classes = [IsAdminPermission | IsManagerPermission | IsUserPermission]
        else:
            permission_classes = [IsAdminPermission | IsManagerPermission]

        return [permission() for permission in permission_classes]

    def get_serializer_class(self):
        if self.action == 'update':
            return UserEditSerializer
        else:
            return UserSerializer

    def list(self, request, *args, **kwargs):
        """
        Return a list of objects.
        """
        return super().list(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        return response

    def retrieve(self, request, *args, **kwargs):
        response = super().retrieve(request, *args, **kwargs)
        return response

    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        return response

    def patch(self, request, *args, **kwargs):
        raise exceptions.MethodNotAllowed()

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.is_active = False
        instance.save()
        serializer = UserSerializer(instance=instance)
        return Response(status=status.HTTP_200_OK, data=serializer.data)

    @transaction.atomic
    @action(detail=True, methods=['patch'])
    def reset_password(self, request, pk=None):
        """
        reset_password
        """
        instance = self.get_object()
        if request.user.is_User():
            if instance.id != request.user.id:
                raise exceptions.PermissionDenied(detail="no permission")
        data = request.data
        serializer = ResetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        instance.set_password(data.get('password'))
        instance.save()
        serializer = UserSerializer(instance=instance)
        return Response(status=status.HTTP_200_OK, data=serializer.data)
