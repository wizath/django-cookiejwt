import json
import os
from http import cookies
import datetime

from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from rest_framework_simplejwt.settings import api_settings
from users.authentication import CookieAccessTokenAuthentication
from users.models import User


class TestCookieTokenVerify(APITestCase):

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


class TestCookieTokenObtain(APITestCase):

    def setUp(self):
        user = User(username='testuser', email='test@test.com')
        user.set_password('testpassword')
        user.save()

    def test_cookie_tokens_obtain(self):
        response = self.client.post('/api/token', json.dumps({
            'username': 'testuser',
            'password': 'testpassword',
            # 'remember': False
        }), content_type="application/json")

        raw_token = response.client.cookies['access_token']
        # Morsel dict
        # {'expires': 'Mon, 18 Nov 2019 23:45:35 GMT', 'path': '/', 'comment': '', 'domain': '', 'max-age': 300, 'secure': '', 'httponly': True, 'version': '', 'samesite': ''}

        self.assertTrue(raw_token['httponly'])
        dt = datetime.datetime.strptime(raw_token['expires'], "%a, %d %b %Y %H:%M:%S %Z")
        delta = dt - datetime.datetime.now()
        expire = datetime.timedelta(seconds=round(delta.seconds, -2))
        self.assertEqual(expire, api_settings.ACCESS_TOKEN_LIFETIME)

        raw_refresh = response.client.cookies['refresh_token']
        self.assertTrue(raw_refresh['httponly'])
        dt = datetime.datetime.strptime(raw_refresh['expires'], "%a, %d %b %Y %H:%M:%S %Z")
        delta = dt - datetime.datetime.now()
        expire = datetime.timedelta(seconds=round(delta.seconds, -2))
        self.assertEqual(expire, api_settings.REFRESH_TOKEN_LIFETIME)

        backend = CookieAccessTokenAuthentication()
        validated_token = backend.get_validated_token(raw_token.value)
        user = backend.get_user(validated_token)
        self.assertEqual(user.id, 1)

    def test_cookie_tokens_obtain_wrong_password(self):
        response = self.client.post('/api/token', json.dumps({
            'username': 'testuser',
            'password': 'wrongpassword',
            # 'remember': False
        }), content_type="application/json")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_cookie_tokens_obtain_no_exisiting_user(self):
        response = self.client.post('/api/token', json.dumps({
            'username': 'nonexistinguser',
            'password': 'testpassword',
            # 'remember': False
        }), content_type="application/json")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_cookie_tokens_obtain_no_data(self):
        response = self.client.post('/api/token', content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_cookie_tokens_obtain_wrong_method(self):
        response = self.client.get('/api/token', content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


class TestCookieTokenRefresh(APITestCase):

    def setUp(self):
        user = User(username='testuser', email='test@test.com')
        user.set_password('testpassword')
        user.save()

    def test_token_refresh_endpoint_no_cookie(self):
        response = self.client.post('/api/token/refresh')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_token_refresh_endpoint_bad_refresh_cookie(self):
        token_cookie = cookies.SimpleCookie({'refresh_token': str(os.urandom(32))})
        self.client.cookies = token_cookie

        response = self.client.post('/api/token/refresh')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_cookie_token_refresh(self):
        u = User.objects.first()
        token = RefreshToken.for_user(u)
        token_cookie = cookies.SimpleCookie({'refresh_token': token})
        self.client.cookies = token_cookie

        # verify status code
        response = self.client.post('/api/token/refresh')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # verify token
        raw_token = response.client.cookies['access_token']
        backend = CookieAccessTokenAuthentication()
        validated_token = backend.get_validated_token(raw_token.value)
        user = backend.get_user(validated_token)
        self.assertEqual(user.id, 1)

        self.assertTrue(raw_token['httponly'])
        dt = datetime.datetime.strptime(raw_token['expires'], "%a, %d %b %Y %H:%M:%S %Z")
        delta = dt - datetime.datetime.now()
        expire = datetime.timedelta(seconds=round(delta.seconds, -2))
        self.assertEqual(expire, api_settings.ACCESS_TOKEN_LIFETIME)
