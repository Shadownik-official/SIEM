import os
import base64
import json
import hashlib
import logging
from typing import Any, Dict, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .error_handler import error_handler, ErrorSeverity
from .performance import performance_monitor

class SecurityUtils:
    """
    Advanced security utilities for data protection and encryption
    """
    @staticmethod
    @performance_monitor.track_performance
    def generate_encryption_key(password: str, salt: Optional[bytes] = None) -> bytes:
        """
        Generate a secure encryption key using PBKDF2
        
        :param password: User-provided password
        :param salt: Optional salt for key derivation
        :return: Derived encryption key
        """
        try:
            if salt is None:
                salt = os.urandom(16)
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000
            )
            
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            return key, salt
        except Exception as e:
            error_handler.handle_error(
                'KeyGeneration', 
                e, 
                ErrorSeverity.CRITICAL
            )
            raise
    
    @staticmethod
    @performance_monitor.track_performance
    def encrypt_data(data: Any, key: bytes) -> str:
        """
        Encrypt data using Fernet symmetric encryption
        
        :param data: Data to encrypt
        :param key: Encryption key
        :return: Encrypted data as base64 string
        """
        try:
            # Serialize data
            serialized_data = json.dumps(data).encode()
            
            # Encrypt
            f = Fernet(key)
            encrypted_data = f.encrypt(serialized_data)
            
            return base64.urlsafe_b64encode(encrypted_data).decode()
        except Exception as e:
            error_handler.handle_error(
                'DataEncryption', 
                e, 
                ErrorSeverity.HIGH
            )
            raise
    
    @staticmethod
    @performance_monitor.track_performance
    def decrypt_data(encrypted_data: str, key: bytes) -> Any:
        """
        Decrypt data using Fernet symmetric encryption
        
        :param encrypted_data: Base64 encoded encrypted data
        :param key: Decryption key
        :return: Decrypted and deserialized data
        """
        try:
            # Decrypt
            f = Fernet(key)
            decoded_data = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted_data = f.decrypt(decoded_data)
            
            # Deserialize
            return json.loads(decrypted_data.decode())
        except Exception as e:
            error_handler.handle_error(
                'DataDecryption', 
                e, 
                ErrorSeverity.HIGH
            )
            raise

class DataProcessor:
    """
    Advanced data processing and transformation utilities
    """
    @staticmethod
    @performance_monitor.track_performance
    def hash_sensitive_data(data: str, salt: Optional[str] = None) -> str:
        """
        Securely hash sensitive data
        
        :param data: Data to hash
        :param salt: Optional salt for additional security
        :return: Hashed data
        """
        try:
            if salt is None:
                salt = os.urandom(16).hex()
            
            # Use SHA-256 with salt
            salted_data = f"{salt}{data}".encode()
            return hashlib.sha256(salted_data).hexdigest()
        except Exception as e:
            error_handler.handle_error(
                'DataHashing', 
                e, 
                ErrorSeverity.MEDIUM
            )
            return ''
    
    @staticmethod
    @performance_monitor.track_performance
    def sanitize_input(input_data: str, max_length: int = 1000) -> str:
        """
        Sanitize and validate input data
        
        :param input_data: Input to sanitize
        :param max_length: Maximum allowed length
        :return: Sanitized input
        """
        try:
            # Remove potentially dangerous characters
            sanitized = ''.join(
                char for char in input_data 
                if char.isprintable() and char not in ['<', '>', '&', '"', "'"]
            )
            
            # Truncate if too long
            return sanitized[:max_length]
        except Exception as e:
            error_handler.handle_error(
                'InputSanitization', 
                e, 
                ErrorSeverity.LOW
            )
            return ''

class SystemUtils:
    """
    Cross-platform system utility functions
    """
    @staticmethod
    def get_system_info() -> Dict[str, Any]:
        """
        Retrieve comprehensive system information
        
        :return: Dictionary of system details
        """
        try:
            import platform
            import psutil
            
            return {
                'os': platform.system(),
                'os_version': platform.version(),
                'architecture': platform.machine(),
                'processor': platform.processor(),
                'cpu_cores': psutil.cpu_count(),
                'memory_total': psutil.virtual_memory().total,
                'disk_usage': psutil.disk_usage('/').percent
            }
        except Exception as e:
            error_handler.handle_error(
                'SystemInfoRetrieval', 
                e, 
                ErrorSeverity.LOW
            )
            return {}

# Expose utility classes
__all__ = [
    'SecurityUtils', 
    'DataProcessor', 
    'SystemUtils',
    'encrypt_data',
    'decrypt_data'
]

def encrypt_data(data, key=None):
    """
    Wrapper function for data encryption
    """
    if key is None:
        key, _ = SecurityUtils.generate_encryption_key("default_key")
    
    return SecurityUtils.encrypt_data(data, key)

def decrypt_data(encrypted_data, key=None):
    """
    Wrapper function for data decryption
    """
    if key is None:
        key, _ = SecurityUtils.generate_encryption_key("default_key")
    
    return SecurityUtils.decrypt_data(encrypted_data, key)
