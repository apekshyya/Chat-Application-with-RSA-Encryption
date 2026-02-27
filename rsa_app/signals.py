from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from .models import UserProfile
from .rsa_encryption import RSAEncryption


@receiver(post_save, sender=User)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    """Create an auth token for newly created users"""
    if created:
        Token.objects.create(user=instance)


@receiver(post_save, sender=User)
def create_user_profile(sender, instance=None, created=False, **kwargs):
    """Create RSA key pair when user is created via admin/direct creation"""
    if created:
        try:
            # Skip if profile already exists (from registration endpoint)
            instance.profile
        except UserProfile.DoesNotExist:
            public_key, private_key = RSAEncryption.generate_key_pair()
            UserProfile.objects.create(
                user=instance,
                public_key=public_key.decode('utf-8'),
                private_key=private_key.decode('utf-8')
            )
