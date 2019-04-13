from rest_framework_simplejwt.authentication import JWTTokenUserAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import RefreshToken


class CookieJWTTokenUserAuthentication(JWTTokenUserAuthentication):

    # override authenticate call to retrieve cookie from request
    # then perform authentication
    def authenticate(self, request):
        """
        Ultimate workaround for passing authorization with valid refresh-token.
        Since in order to refresh inactive access_token we need to provide a valid
        refresh token. But authorization procedure will throw an error while
        access_token is expired -.-. If refresh token is valid, we'll pass auth
        as unauthorized to allow user to acquire new access token.
        """
        raw_token = request.COOKIES.get('access_token', None)

        # return if no token is provided (Unauthorized)
        if raw_token is None:
            return None

        try:
            validated_token = self.get_validated_token(raw_token)
            return self.get_user(validated_token), None
        except InvalidToken as e:
            refresh_token = request.COOKIES.get('refresh_token', None)

            if refresh_token is None:
                raise e

            return None, None
