from django.contrib import admin
from .models import UserProfile, Chat, Message, MessageRead


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'created_at', 'updated_at')
    search_fields = ('user__username', 'user__email')
    readonly_fields = ('created_at', 'updated_at')


@admin.register(Chat)
class ChatAdmin(admin.ModelAdmin):
    list_display = ('name', 'created_by', 'is_private', 'created_at')
    filter_horizontal = ('participants',)
    search_fields = ('name', 'created_by__username')
    readonly_fields = ('created_at', 'updated_at')


@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ('id', 'chat', 'sender', 'created_at')
    search_fields = ('chat__name', 'sender__username')
    readonly_fields = ('created_at', 'updated_at')
    fields = ('chat', 'sender', 'content', 'encrypted_content', 'encrypted_key', 'created_at', 'updated_at')


@admin.register(MessageRead)
class MessageReadAdmin(admin.ModelAdmin):
    list_display = ('message', 'user', 'read_at')
    search_fields = ('user__username', 'message__id')
    readonly_fields = ('read_at',)
