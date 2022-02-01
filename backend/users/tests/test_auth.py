import base64
import datetime
from django.utils import timezone
from django.contrib.auth import get_user_model
from test_plus.test import APITestCase
from .factories import UserFactory, DEFAULT_TEST_PASSWORD

class TestLoginAuth(APITestCase):

    def test_role_user(self):
        user1 = UserFactory.create(role='User')
        response = self.post("/api/auth/login/", data=dict(
                username=user1.username,
                password=DEFAULT_TEST_PASSWORD
            ))
        self.response_200()
        self.assertEqual("User", response.data['role'])
        self.assertEqual(user1.email, response.data['email'])
        self.assertEqual(user1.username, response.data['username'])
        self.assertEqual(user1.id, response.data['id'])

    def test_role_Manager(self):
        user1 = UserFactory.create(role='Manager')
        response = self.post("/api/auth/login/", data=dict(
                username=user1.username,
                password=DEFAULT_TEST_PASSWORD
            ))
        self.response_200()
        self.assertEqual("Manager", response.data['role'])
        self.assertEqual(user1.email, response.data['email'])
        self.assertEqual(user1.username, response.data['username'])
        self.assertEqual(user1.id, response.data['id'])

    def test_role_Admin(self):
        user1 = UserFactory.create(role='Admin')
        response = self.post("/api/auth/login/", data=dict(
                username=user1.username,
                password=DEFAULT_TEST_PASSWORD
            ))
        self.response_200()
        self.assertEqual("Admin", response.data['role'])
        self.assertEqual(user1.email, response.data['email'])
        self.assertEqual(user1.username, response.data['username'])
        self.assertEqual(user1.id, response.data['id'])

    def test_login_invalid_password(self):
        user = UserFactory()
        response = self.post("/api/auth/login/", data=dict(
                username=user.username,
                password="errorpwd"
            ))
        self.response_401()