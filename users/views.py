import datetime

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.views import TokenViewBase

from .serializers import TokenDetailPairObtainSerializer


class CookieTokenObtainPair(TokenViewBase):
    serializer_class = TokenDetailPairObtainSerializer

    # override default post call from simplejwt library
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        serializer_data = serializer.validated_data
        remember_session = serializer_data['remember']

        access_expiration = (datetime.datetime.utcnow() +
                             api_settings.ACCESS_TOKEN_LIFETIME)

        refresh_expiration = (datetime.datetime.utcnow() +
                              api_settings.REFRESH_TOKEN_LIFETIME)

        response_data = {
            'user_id': serializer_data['user_id'],
            'refresh_expire': int(refresh_expiration.timestamp()),
            'access_expire': int(access_expiration.timestamp())
        }

        response = Response(response_data, status=status.HTTP_200_OK)

        # clear cookie expiration if session cookie is selected
        if not remember_session:
            access_expiration = None
            refresh_expiration = None

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


class CookieTokenVerifyView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        return Response({
            'user_id': self.request.user.id
        }, status=status.HTTP_200_OK)


class CookieTokenClearView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        response = Response({}, status=status.HTTP_200_OK)
        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')
        return response
