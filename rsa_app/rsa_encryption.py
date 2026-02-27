"""
RSA Encryption/Decryption utility module for secure messaging
"""
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


class RSAEncryption:
    """
    Handles RSA encryption and decryption operations
    Uses 2048-bit RSA keys for security
    """
    
    KEY_SIZE = 2048
    BACKEND = default_backend()
    
    @staticmethod
    def generate_key_pair():
        """
        Generate a new RSA key pair (public and private keys)
        
        Returns:
            tuple: (public_key_pem, private_key_pem) as bytes
        """
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=RSAEncryption.KEY_SIZE,
            backend=RSAEncryption.BACKEND
        )
        
        # Extract public key
        public_key = private_key.public_key()
        
        # Serialize to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return public_pem, private_pem
    
    @staticmethod
    def encrypt_message(message, public_key_pem):
        """
        Encrypt a message using RSA public key
        
        Args:
            message (str): The plaintext message to encrypt
            public_key_pem (bytes or str): The PEM-encoded public key
            
        Returns:
            str: Base64-encoded encrypted message
        """
        # Convert string to bytes if necessary
        if isinstance(public_key_pem, str):
            public_key_pem = public_key_pem.encode()
        
        if isinstance(message, str):
            message = message.encode()
        
        # Load public key
        public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=RSAEncryption.BACKEND
        )
        
        # Encrypt message with OAEP padding
        encrypted = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Return base64 encoded for safe transmission
        return base64.b64encode(encrypted).decode('utf-8')
    
    @staticmethod
    def decrypt_message(encrypted_message, private_key_pem):
        """
        Decrypt a message using RSA private key
        
        Args:
            encrypted_message (str): Base64-encoded encrypted message
            private_key_pem (bytes or str): The PEM-encoded private key
            
        Returns:
            str: The decrypted plaintext message
        """
        # Convert string to bytes if necessary
        if isinstance(private_key_pem, str):
            private_key_pem = private_key_pem.encode()
        
        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=RSAEncryption.BACKEND
        )
        
        # Decode from base64
        encrypted_data = base64.b64decode(encrypted_message)
        
        # Decrypt message with OAEP padding
        decrypted = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return decrypted.decode('utf-8')
    
    @staticmethod
    def sign_message(message, private_key_pem):
        """
        Sign a message using RSA private key (for authentication)
        
        Args:
            message (str): The message to sign
            private_key_pem (bytes or str): The PEM-encoded private key
            
        Returns:
            str: Base64-encoded signature
        """
        if isinstance(private_key_pem, str):
            private_key_pem = private_key_pem.encode()
        
        if isinstance(message, str):
            message = message.encode()
        
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=RSAEncryption.BACKEND
        )
        
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return base64.b64encode(signature).decode('utf-8')
    
    @staticmethod
    def verify_signature(message, signature, public_key_pem):
        """
        Verify a message signature using RSA public key
        
        Args:
            message (str): The original message
            signature (str): Base64-encoded signature
            public_key_pem (bytes or str): The PEM-encoded public key
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        try:
            if isinstance(public_key_pem, str):
                public_key_pem = public_key_pem.encode()
            
            if isinstance(message, str):
                message = message.encode()
            
            public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=RSAEncryption.BACKEND
            )
            
            sig_data = base64.b64decode(signature)
            
            public_key.verify(
                sig_data,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False


class HybridEncryption:
    """
    Hybrid encryption using RSA + AES for large messages
    More efficient for large messages than pure RSA
    """
    
    @staticmethod
    def encrypt_message(message, public_key_pem):
        """
        Encrypt message using AES-256 and encrypt AES key with RSA
        
        Args:
            message (str): The plaintext message
            public_key_pem (bytes or str): The PEM-encoded RSA public key
            
        Returns:
            dict: {'encrypted_message': base64, 'encrypted_key': base64}
        """
        if isinstance(message, str):
            message = message.encode()
        
        # Generate random AES key and IV
        aes_key = os.urandom(32)  # 256-bit key
        iv = os.urandom(16)  # 128-bit IV
        
        # Encrypt message with AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Add padding to message (PKCS7)
        padding_length = 16 - (len(message) % 16)
        padded_message = message + bytes([padding_length] * padding_length)
        
        encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
        
        # Encrypt AES key with RSA (convert bytes to base64 string for RSA encryption)
        aes_key_b64 = base64.b64encode(aes_key).decode('utf-8')
        encrypted_key = RSAEncryption.encrypt_message(aes_key_b64, public_key_pem)
        
        # Combine IV + encrypted message and encode
        encrypted_data = base64.b64encode(iv + encrypted_message).decode('utf-8')
        
        return {
            'encrypted_message': encrypted_data,
            'encrypted_key': encrypted_key
        }
    
    @staticmethod
    def decrypt_message(encrypted_data, encrypted_key, private_key_pem):
        """
        Decrypt message using RSA (for AES key) and AES
        
        Args:
            encrypted_data (str): Base64-encoded (IV + encrypted message)
            encrypted_key (str): Base64-encoded RSA-encrypted AES key
            private_key_pem (bytes or str): The PEM-encoded RSA private key
            
        Returns:
            str: The decrypted plaintext message
        """
        # Decrypt AES key with RSA
        aes_key_b64 = RSAEncryption.decrypt_message(encrypted_key, private_key_pem)
        aes_key = base64.b64decode(aes_key_b64.encode() if isinstance(aes_key_b64, str) else aes_key_b64)
        
        # Decode encrypted data
        encrypted_data_bytes = base64.b64decode(encrypted_data)
        
        # Extract IV and encrypted message
        iv = encrypted_data_bytes[:16]
        encrypted_message = encrypted_data_bytes[16:]
        
        # Decrypt message with AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
        
        # Remove padding (PKCS7)
        padding_length = padded_message[-1]
        message = padded_message[:-padding_length]
        
        return message.decode('utf-8')
