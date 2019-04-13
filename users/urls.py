from django.urls import path
from .views import CookieTokenObtainPair, CookieTokenVerifyView, CookieTokenClearView, CookieTokenRefreshView


urlpatterns = [
    path('api/token/', CookieTokenObtainPair.as_view(), name='token_obtain_pair'),
    path('api/token/verify', CookieTokenVerifyView.as_view(), name='token_verify'),
    path('api/token/clear', CookieTokenClearView.as_view(), name='token_clear'),
    path('api/token/refresh', CookieTokenRefreshView.as_view(), name='token_refresh')
]
