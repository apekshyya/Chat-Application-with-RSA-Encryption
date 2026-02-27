from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    index, register_user, get_user_profile, get_user_public_key, list_users,
    ChatViewSet, MessageViewSet, encrypt_for_recipient, decrypt_message_util
)

router = DefaultRouter()
router.register(r'chats', ChatViewSet, basename='chat')
router.register(r'messages', MessageViewSet, basename='message')

urlpatterns = [
    # Main page
    path('', index, name='index'),
    
    # Authentication & User endpoints
    path('register/', register_user, name='register'),
    path('profile/', get_user_profile, name='profile'),
    path('users/', list_users, name='list-users'),
    path('users/<int:user_id>/public-key/', get_user_public_key, name='user-public-key'),
    
    # Encryption utilities
    path('encrypt/', encrypt_for_recipient, name='encrypt-message'),
    path('decrypt/', decrypt_message_util, name='decrypt-message'),
    
    # Router endpoints
    path('', include(router.urls)),
]
