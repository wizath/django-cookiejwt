from rest_framework_simplejwt.authentication import JWTTokenUserAuthentication


class CookieJWTTokenUserAuthentication(JWTTokenUserAuthentication):

    def authenticate(self, request):
        raw_token = self.get_raw_token(request)
        validated_token = self.get_validated_token(raw_token)

        return self.get_user(validated_token), None

    def get_raw_token(self, request):
        return request.COOKIES.get('access_token', None)
