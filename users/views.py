import datetime

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.views import TokenViewBase

from users.authentication import CookieRefreshTokenAuthentication


class CookieTokenVerify(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        return Response({
            'user_id': self.request.user.id
        }, status=status.HTTP_200_OK)


class CookieTokenObtainPair(TokenViewBase):
    serializer_class = TokenObtainPairSerializer
    permission_classes = ()

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        serializer_data = serializer.validated_data
        access_expiration = (datetime.datetime.utcnow() +
                             api_settings.ACCESS_TOKEN_LIFETIME)

        refresh_expiration = (datetime.datetime.utcnow() +
                              api_settings.REFRESH_TOKEN_LIFETIME)

        response_data = {
            # 'user_id': serializer_data['user_id'],
            'refresh_expire': int(refresh_expiration.timestamp()),
            'access_expire': int(access_expiration.timestamp())
        }

        response = Response(response_data, status=status.HTTP_200_OK)

        # append access token
        response.set_cookie('access_token',
                            serializer_data['access'],
                            expires=access_expiration,
                            httponly=True)

        # append refresh token
        response.set_cookie('refresh_token',
                            serializer_data['refresh'],
                            expires=refresh_expiration,
                            httponly=True)

        return response


class CookieTokenRefresh(TokenViewBase):
    serializer_class = TokenRefreshSerializer
    authentication_classes = ()

    def post(self, request, *args, **kwargs):
        raw_token = request.COOKIES.get('refresh_token', None)
        serializer = self.get_serializer(data={
            'refresh': raw_token
        })

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        serializer_data = serializer.validated_data
        access_expiration = (datetime.datetime.utcnow() +
                             api_settings.ACCESS_TOKEN_LIFETIME)

        response_data = {
            'access_expire': int(access_expiration.timestamp())
        }

        response = Response(response_data, status=status.HTTP_200_OK)

        # append access token
        response.set_cookie('access_token',
                            serializer_data['access'],
                            expires=access_expiration,
                            httponly=True)

        return response
