# -*- encoding: utf-8 -*-
from django.contrib.auth.models import AbstractUser, UserManager
from django.db import models


class User(AbstractUser):
    class Meta:
        db_table = 'users'

    ADMIN = 'ADMIN'
    MANAGER = 'MANAGER'
    USER = 'USER'

    Roles = [
        (ADMIN, 'ADMIN'),
        (MANAGER, 'MANAGER'),
        (USER, 'USER'),
    ]

    username = models.CharField(error_messages={'unique': '帳號或電郵重複'},
                                help_text='Required. 150 characters or fewer. Letters, digits and @/./_ only.',
                                max_length=150, unique=True,
                                verbose_name='username'
                                )
    email = models.EmailField(max_length=255, unique=True, verbose_name='email', error_messages={'unique': '帳號或電郵重複'}, )
    role = models.CharField(max_length=15, choices=Roles, default=USER,
                            verbose_name='role')
    create_at = models.DateTimeField(auto_now_add=True)
    update_at = models.DateTimeField(auto_now=True)
    is_delete = models.BooleanField(default=False)
    objects = UserManager()

    def __init__(self, *args, **kwargs):
        super(User, self).__init__(*args, **kwargs)

    def save(self, *args, **kwargs):
        # Make role admin as same as django root
        if self.is_staff:
            self.role = self.ADMIN
        super(User, self).save(*args, **kwargs)

    def is_Admin(self):
        return self.role == self.ADMIN

    def is_Manager(self):
        return self.role == self.MANAGER

    def is_User(self):
        return self.role == self.USER
