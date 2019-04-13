# django-cookiejwt
DRF simplejwt extension for managing session JWT cookies

Since rest framework is focused on passing JSON data between clients and we need to acquire HTTP Only cookie containing `access_token` and `refresh_token` along with some diagnostic info in JSON.

## Steps to enable cookie JWT authentication
1. Override default authentication class to get cookie instead of request JSON data
2. Override default token obtain methods to set proper cookies and return expiration times in JSON
3. Create method for deleting cookies (since they're HttpOnly)

## Authentication workaround
Since DRF_SimpleJWT rejects call when `access_token` is invalid (missing or expired), new subclassed procedure allows to enter as unauthorized user if token is expired or missing. That allows for requesting new `access_token` based on stored in cookie `refresh_token` info
