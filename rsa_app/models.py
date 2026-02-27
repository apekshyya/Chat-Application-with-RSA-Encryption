from django.db import models
from django.contrib.auth.models import User
import os
import base64


class UserProfile(models.Model):
    """User profile with RSA key pairs"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    public_key = models.TextField(help_text="RSA Public Key (PEM format)")
    private_key = models.TextField(help_text="RSA Private Key (PEM format, encrypted)")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.username}'s Profile"

    class Meta:
        verbose_name_plural = "User Profiles"


class Chat(models.Model):
    """Chat group/conversation between users"""
    name = models.CharField(max_length=255)
    participants = models.ManyToManyField(User, related_name='chats')
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_chats')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_private = models.BooleanField(default=False, help_text="Private chat between two users")

    def __str__(self):
        return self.name

    class Meta:
        ordering = ['-updated_at']


class Message(models.Model):
    """Encrypted message in a chat"""
    chat = models.ForeignKey(Chat, on_delete=models.CASCADE, related_name='messages')
    sender = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='sent_messages')
    
    # Original message content (will be encrypted)
    content = models.TextField()
    
    # Encrypted content (stores base64 encoded encrypted data)
    encrypted_content = models.TextField()
    
    # RSA encrypted AES key (if using hybrid encryption)
    encrypted_key = models.TextField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Message from {self.sender.username} in {self.chat.name}"

    class Meta:
        ordering = ['created_at']


class MessageRead(models.Model):
    """Track if a user has read a message"""
    message = models.ForeignKey(Message, on_delete=models.CASCADE, related_name='read_by')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    read_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('message', 'user')
        verbose_name_plural = "Message Reads"

    def __str__(self):
        return f"{self.user.username} read message {self.message.id}"
