from django.urls import path

from users.views import CookieTokenVerify, CookieTokenObtainPair, CookieTokenRefresh, CookieTokenClear

urlpatterns = [
    path('token/verify', CookieTokenVerify.as_view(), name='token_verify'),
    path('token', CookieTokenObtainPair.as_view(), name='token_obtain'),
    path('token/refresh', CookieTokenRefresh.as_view(), name='token_refresh'),
    path('token/clear', CookieTokenClear.as_view(), name='token_clear')
]
