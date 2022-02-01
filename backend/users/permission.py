# -*- encoding: utf-8 -*-
from rest_framework.permissions import BasePermission


class IsAdminPermission(BasePermission):
    """
    Global permission check for Admin user
    """
    message = 'User is not Admin'

    def has_permission(self, request, view):

        try:
            return request.user.is_Admin()
        except AttributeError:
            return False

    def has_object_permission(self, request, view, obj):
        try:
            return request.user.is_Admin()
        except AttributeError:
            return False


class IsManagerPermission(BasePermission):
    """
    Global permission check for Manager user
    """
    message = 'User is not manager'

    def has_permission(self, request, view):

        try:
            return request.user.is_Manager()
        except AttributeError:
            return False

    def has_object_permission(self, request, view, obj):
        try:
            return request.user.is_Manager()
        except AttributeError:
            return False


class IsUserPermission(BasePermission):
    """
    Global permission check for user type == User
    """

    def has_permission(self, request, view):
        return request.user.is_authenticated

    def has_object_permission(self, request, view, obj):
        """
        We assumed the role type user cannot edit any platform information
        """
        return False
