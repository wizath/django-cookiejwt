import os
from http import cookies

from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import AccessToken

from users.models import User


class TestCokkieJWTTokenVerify(APITestCase):
    def setUp(self):
        user = User(username='testuser', email='test@test.com')
        user.set_password('testpassword')
        user.save()

    def test_cookie_token_verify(self):
        u = User.objects.first()
        token = AccessToken.for_user(u)
        token_cookie = cookies.SimpleCookie({'access_token': token})
        self.client.cookies = token_cookie

        response = self.client.get('/api/token/verify')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['user_id'], u.id)

    def test_cookie_token_verify_wrong_token(self):
        token_cookie = cookies.SimpleCookie({'access_token': str(os.urandom(32))})
        self.client.cookies = token_cookie

        response = self.client.get('/api/token/verify')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_cookie_token_verify_no_cookie(self):
        response = self.client.get('/api/token/verify')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
