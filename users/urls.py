from django.urls import path

from users.views import CookieTokenVerify, CookieTokenObtainPair

urlpatterns = [
    path('token/verify', CookieTokenVerify.as_view(), name='token_verify'),
    path('token', CookieTokenObtainPair.as_view(), name='token_obtain'),
]
