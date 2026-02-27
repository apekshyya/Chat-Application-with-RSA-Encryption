from rest_framework import viewsets, status
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404, render
from django.db.models import Q

from .models import UserProfile, Chat, Message, MessageRead
from .serializers import (
    UserSerializer, UserProfileSerializer, ChatSerializer, 
    ChatDetailSerializer, MessageSerializer, MessageDetailSerializer,
    UserRegistrationSerializer, EncryptMessageSerializer, 
    CreateChatSerializer
)
from .rsa_encryption import RSAEncryption, HybridEncryption


def index(request):
    """Serve the main chat application"""
    return render(request, 'index.html')


@api_view(['POST'])
@permission_classes([AllowAny])
def register_user(request):
    """Register a new user and create RSA key pair"""
    serializer = UserRegistrationSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        return Response(
            {
                'message': 'User registered successfully',
                'user': UserSerializer(user).data,
                'public_key': user.profile.public_key
            },
            status=status.HTTP_201_CREATED
        )
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_profile(request):
    """Get current user's profile with public key"""
    try:
        profile = request.user.profile
        serializer = UserProfileSerializer(profile)
        return Response(serializer.data)
    except UserProfile.DoesNotExist:
        return Response(
            {'error': 'User profile not found'},
            status=status.HTTP_404_NOT_FOUND
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_public_key(request, user_id):
    """Get any user's public key for encryption"""
    try:
        user = User.objects.get(id=user_id)
        profile = user.profile
        return Response({
            'user_id': user.id,
            'username': user.username,
            'public_key': profile.public_key
        })
    except User.DoesNotExist:
        return Response(
            {'error': 'User not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    except UserProfile.DoesNotExist:
        return Response(
            {'error': 'User profile not found'},
            status=status.HTTP_404_NOT_FOUND
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_users(request):
    """List all users (for selecting chat participants)"""
    users = User.objects.exclude(id=request.user.id)
    serializer = UserSerializer(users, many=True)
    return Response(serializer.data)


class ChatViewSet(viewsets.ModelViewSet):
    """ViewSet for managing chats"""
    serializer_class = ChatSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    
    def get_queryset(self):
        """Get chats for current user"""
        return Chat.objects.filter(participants=self.request.user)
    
    def get_serializer_class(self):
        """Use detailed serializer for retrieve action"""
        if self.action == 'retrieve':
            return ChatDetailSerializer
        elif self.action == 'create':
            return CreateChatSerializer
        return self.serializer_class
    
    def create(self, request, *args, **kwargs):
        """Create a new chat"""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        
        # Return detailed chat info
        headers = self.get_success_headers(serializer.data)
        return Response(
            ChatDetailSerializer(
                serializer.instance,
                context=self.get_serializer_context()
            ).data,
            status=status.HTTP_201_CREATED,
            headers=headers
        )
    
    @action(detail=False, methods=['post'])
    def create_direct_chat(self, request):
        """Create or get a direct chat with another user"""
        recipient_id = request.data.get('recipient_id')
        
        if not recipient_id:
            return Response(
                {'error': 'recipient_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            recipient = User.objects.get(id=recipient_id)
        except User.DoesNotExist:
            return Response(
                {'error': 'Recipient not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Find or create direct chat
        chat = Chat.objects.filter(
            is_private=True,
            participants=request.user
        ).filter(participants=recipient).first()
        
        if not chat:
            chat = Chat.objects.create(
                name=f"{request.user.username} - {recipient.username}",
                created_by=request.user,
                is_private=True
            )
            chat.participants.set([request.user, recipient])
        
        serializer = ChatDetailSerializer(chat, context=self.get_serializer_context())
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def add_participant(self, request, pk=None):
        """Add a participant to a chat"""
        chat = self.get_object()
        user_id = request.data.get('user_id')
        
        if not user_id:
            return Response(
                {'error': 'user_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        chat.participants.add(user)
        serializer = ChatSerializer(chat)
        return Response(serializer.data)


class MessageViewSet(viewsets.ModelViewSet):
    """ViewSet for managing encrypted messages"""
    serializer_class = MessageSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    
    def get_queryset(self):
        """Get messages for chats the user is part of"""
        return Message.objects.filter(
            chat__participants=self.request.user
        )
    
    def get_serializer_class(self):
        """Use detailed serializer for retrieve action"""
        if self.action == 'retrieve':
            return MessageDetailSerializer
        return self.serializer_class
    
    def create(self, request, *args, **kwargs):
        """Create and encrypt a new message"""
        chat_id = request.data.get('chat')
        content = request.data.get('content')
        use_hybrid = request.data.get('use_hybrid', True)
        
        if not chat_id or not content:
            return Response(
                {'error': 'chat and content are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            chat = Chat.objects.get(id=chat_id, participants=request.user)
        except Chat.DoesNotExist:
            return Response(
                {'error': 'Chat not found or access denied'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        try:
            sender_profile = request.user.profile
        except UserProfile.DoesNotExist:
            return Response(
                {'error': 'User profile not found'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Encrypt message for each participant
        message = Message.objects.create(
            chat=chat,
            sender=request.user,
            content=content,
            encrypted_content='',  # Will be set below
        )
        
        # Encrypt content with sender's public key (so sender can read their own messages)
        sender_public_key = sender_profile.public_key
        
        if use_hybrid:
            encryption_result = HybridEncryption.encrypt_message(content, sender_public_key)
            message.encrypted_content = encryption_result['encrypted_message']
            message.encrypted_key = encryption_result['encrypted_key']
        else:
            message.encrypted_content = RSAEncryption.encrypt_message(content, sender_public_key)
        
        message.save()
        
        serializer = MessageSerializer(message)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    
    @action(detail=False, methods=['get'])
    def by_chat(self, request):
        """Get all messages in a specific chat"""
        chat_id = request.query_params.get('chat_id')
        
        if not chat_id:
            return Response(
                {'error': 'chat_id parameter is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            chat = Chat.objects.get(id=chat_id, participants=request.user)
        except Chat.DoesNotExist:
            return Response(
                {'error': 'Chat not found or access denied'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        messages = chat.messages.all()
        serializer = MessageSerializer(messages, many=True, context={'request': request})
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def decrypt(self, request, pk=None):
        """Decrypt a specific message"""
        message = self.get_object()
        
        # Check access
        if request.user not in message.chat.participants.all():
            return Response(
                {'error': 'Access denied'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            user_profile = request.user.profile
        except UserProfile.DoesNotExist:
            return Response(
                {'error': 'User profile not found'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Decrypt based on whether hybrid encryption was used
            if message.encrypted_key:
                decrypted_content = HybridEncryption.decrypt_message(
                    message.encrypted_content,
                    message.encrypted_key,
                    user_profile.private_key
                )
            else:
                decrypted_content = RSAEncryption.decrypt_message(
                    message.encrypted_content,
                    user_profile.private_key
                )
            
            # Mark as read
            MessageRead.objects.get_or_create(
                message=message,
                user=request.user
            )
            
            return Response({
                'id': message.id,
                'content': decrypted_content,
                'sender': message.sender.username,
                'created_at': message.created_at
            })
        except Exception as e:
            return Response(
                {'error': f'Decryption failed: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @action(detail=True, methods=['post'])
    def mark_as_read(self, request, pk=None):
        """Mark a message as read"""
        message = self.get_object()
        
        MessageRead.objects.get_or_create(
            message=message,
            user=request.user
        )
        
        return Response({'status': 'Message marked as read'})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def encrypt_for_recipient(request):
    """Encrypt a message for a specific recipient (utility endpoint)"""
    serializer = EncryptMessageSerializer(data=request.data)
    
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    message = serializer.validated_data['message']
    recipient_id = serializer.validated_data['recipient_id']
    
    try:
        recipient = User.objects.get(id=recipient_id)
        recipient_profile = recipient.profile
    except UserProfile.DoesNotExist:
        return Response(
            {'error': 'Recipient profile not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    try:
        encrypted = RSAEncryption.encrypt_message(message, recipient_profile.public_key)
        return Response({
            'message': message,
            'recipient': recipient.username,
            'encrypted_message': encrypted
        })
    except Exception as e:
        return Response(
            {'error': f'Encryption failed: {str(e)}'},
            status=status.HTTP_400_BAD_REQUEST
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def decrypt_message_util(request):
    """Decrypt a message using user's private key (utility endpoint)"""
    encrypted_message = request.data.get('encrypted_message')
    
    if not encrypted_message:
        return Response(
            {'error': 'encrypted_message is required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        user_profile = request.user.profile
    except UserProfile.DoesNotExist:
        return Response(
            {'error': 'User profile not found'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        decrypted = RSAEncryption.decrypt_message(
            encrypted_message,
            user_profile.private_key
        )
        return Response({'decrypted_message': decrypted})
    except Exception as e:
        return Response(
            {'error': f'Decryption failed: {str(e)}'},
            status=status.HTTP_400_BAD_REQUEST
        )



