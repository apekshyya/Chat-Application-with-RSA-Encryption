from rest_framework import serializers
from django.contrib.auth.models import User
from .models import UserProfile, Chat, Message, MessageRead
from .rsa_encryption import RSAEncryption


class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model"""
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'first_name', 'last_name')
        read_only_fields = ('id',)


class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for UserProfile with public key"""
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = UserProfile
        fields = ('id', 'user', 'public_key', 'created_at', 'updated_at')
        read_only_fields = ('id', 'created_at', 'updated_at', 'private_key')


class MessageReadSerializer(serializers.ModelSerializer):
    """Serializer for tracking message reads"""
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = MessageRead
        fields = ('id', 'user', 'read_at')
        read_only_fields = ('id', 'read_at')


class MessageSerializer(serializers.ModelSerializer):
    """Serializer for Message model"""
    sender = UserSerializer(read_only=True)
    read_by = MessageReadSerializer(many=True, read_only=True)
    
    class Meta:
        model = Message
        fields = ('id', 'chat', 'sender', 'content', 'encrypted_content', 
                 'encrypted_key', 'created_at', 'read_by')
        read_only_fields = ('id', 'sender', 'created_at', 'read_by')
    
    def create(self, validated_data):
        """Create message and encrypt content"""
        validated_data['sender'] = self.context['request'].user
        message = Message.objects.create(**validated_data)
        return message


class MessageDetailSerializer(MessageSerializer):
    """Detailed message serializer with decrypted content for authorized users"""
    is_read = serializers.SerializerMethodField()
    
    def get_is_read(self, obj):
        """Check if current user has read this message"""
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return MessageRead.objects.filter(
                message=obj,
                user=request.user
            ).exists()
        return False


class ChatSerializer(serializers.ModelSerializer):
    """Serializer for Chat model"""
    participants = UserSerializer(many=True, read_only=True)
    created_by = UserSerializer(read_only=True)
    message_count = serializers.SerializerMethodField()
    last_message = serializers.SerializerMethodField()
    
    class Meta:
        model = Chat
        fields = ('id', 'name', 'participants', 'created_by', 'created_at', 
                 'updated_at', 'is_private', 'message_count', 'last_message')
        read_only_fields = ('id', 'created_by', 'created_at', 'updated_at')
    
    def get_message_count(self, obj):
        """Get count of messages in this chat"""
        return obj.messages.count()
    
    def get_last_message(self, obj):
        """Get the last message in the chat"""
        last_msg = obj.messages.last()
        if last_msg:
            return {
                'id': last_msg.id,
                'sender': last_msg.sender.username,
                'preview': last_msg.content[:100],
                'created_at': last_msg.created_at
            }
        return None


class ChatDetailSerializer(ChatSerializer):
    """Detailed chat serializer with recent messages"""
    recent_messages = serializers.SerializerMethodField()
    
    class Meta(ChatSerializer.Meta):
        fields = ChatSerializer.Meta.fields + ('recent_messages',)
    
    def get_recent_messages(self, obj):
        """Get recent messages in this chat"""
        recent = obj.messages.all()[:10]
        return MessageSerializer(recent, many=True, context=self.context).data


class CreateChatSerializer(serializers.ModelSerializer):
    """Serializer for creating new chats"""
    participant_ids = serializers.ListField(
        child=serializers.IntegerField(),
        write_only=True,
        required=True
    )
    
    class Meta:
        model = Chat
        fields = ('name', 'participant_ids', 'is_private')
    
    def create(self, validated_data):
        """Create chat and add participants"""
        participant_ids = validated_data.pop('participant_ids')
        user = self.context['request'].user
        
        # Create chat
        chat = Chat.objects.create(
            created_by=user,
            **validated_data
        )
        
        # Add participants (including creator)
        participants = list(set([user.id] + participant_ids))
        chat.participants.set(participants)
        
        return chat


class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for user registration"""
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True, min_length=8)
    
    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'password_confirm', 
                 'first_name', 'last_name')
    
    def validate(self, data):
        """Validate passwords match"""
        if data['password'] != data.pop('password_confirm'):
            raise serializers.ValidationError("Passwords do not match")
        return data
    
    def create(self, validated_data):
        """Create user and generate RSA key pair via signal"""
        # Signal handlers will create auth token and UserProfile automatically
        user = User.objects.create_user(**validated_data)
        return user


class EncryptMessageSerializer(serializers.Serializer):
    """Serializer for encrypting messages"""
    message = serializers.CharField()
    recipient_id = serializers.IntegerField()
    
    def validate_recipient_id(self, value):
        """Validate recipient exists"""
        try:
            User.objects.get(id=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("Recipient user not found")
        return value


class DecryptMessageSerializer(serializers.Serializer):
    """Serializer for decrypting messages"""
    message_id = serializers.IntegerField()
    
    def validate_message_id(self, value):
        """Validate message exists"""
        try:
            Message.objects.get(id=value)
        except Message.DoesNotExist:
            raise serializers.ValidationError("Message not found")
        return value
