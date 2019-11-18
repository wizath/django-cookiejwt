from rest_framework_simplejwt.authentication import JWTTokenUserAuthentication


class CookieAccessTokenAuthentication(JWTTokenUserAuthentication):

    def authenticate(self, request):
        raw_token = request.COOKIES.get('access_token', None)
        if raw_token is None:
            return None

        validated_token = self.get_validated_token(raw_token)
        return self.get_user(validated_token), None
