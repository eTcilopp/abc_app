from django.contrib.auth.models import User
from rest_framework import serializers
from accounts.utils.constants import ShopifyOauth
from accounts.utils.helpers import search_string_match, verify_hash_signature


class ShopifyOauthSerializer(serializers.Serializer):
    code = serializers.CharField(required=False)
    hmac = serializers.CharField(required=True)
    host = serializers.CharField(required=False)
    shop = serializers.CharField(required=True)
    timestamp = serializers.CharField(required=True)

    def check_signature(self, attrs):
        secret = ShopifyOauth.SECRET_KEY
        if attrs.get('code'):
            msg = (f"code={attrs['code']}&host={attrs['host']}"
                   f"&shop={attrs['shop']}&timestamp={attrs['timestamp']}")
        else:
            msg = f"shop={attrs['shop']}&timestamp={attrs['timestamp']}"
        is_verified = verify_hash_signature(secret, msg, attrs['hmac'])
        if not is_verified:
            raise serializers.DjangoValidationError(
                {'signature': ["Signature is not valid"]}
            )
        return attrs

    def validate_shop_url(self, shop_url):
        shop_name_regex = search_string_match(r'[^.\s]+\.myshopify\.com', shop_url)
        if shop_name_regex != shop_url:
            raise serializers.DjangoValidationError(
                {'shop_name': ["Shop name does not end with 'myshopify.com'"]}
            )
        return shop_url

    def validate(self, attrs):
        self.check_signature(attrs)
        return attrs