from django.urls import path

from users.views import TokenVerify

urlpatterns = [
    path('token/verify', TokenVerify.as_view(), name='token_verify'),
]
