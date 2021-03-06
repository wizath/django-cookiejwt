from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainSerializer
from rest_framework_simplejwt.tokens import RefreshToken


class TokenDetailPairObtainSerializer(TokenObtainSerializer):

    def __init__(self, *args, **kwargs):
        super(TokenDetailPairObtainSerializer, self).__init__(*args, **kwargs)
        self.fields['remember'] = serializers.BooleanField()

    @classmethod
    def get_token(cls, user):
        return RefreshToken.for_user(user)

    def validate(self, attrs):
        data = super().validate(attrs)
        refresh = self.get_token(self.user)

        data['refresh'] = str(refresh)
        data['access'] = str(refresh.access_token)
        data['user_id'] = self.user.id
        data['remember'] = attrs.get('remember', False)

        return data
