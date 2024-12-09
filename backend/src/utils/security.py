import secrets
import hashlib
import base64
from typing import Optional

class SecurityUtils:
    """
    Utility class for security-related operations.
    """
    @staticmethod
    def generate_salt(length: int = 16) -> str:
        """
        Generate a cryptographically secure random salt.
        
        :param length: Length of the salt in bytes
        :return: Base64 encoded salt
        """
        salt = secrets.token_bytes(length)
        return base64.b64encode(salt).decode('utf-8')

    @staticmethod
    def hash_password(password: str, salt: Optional[str] = None) -> tuple:
        """
        Hash a password using SHA-256 with an optional salt.
        
        :param password: Plain text password
        :param salt: Optional salt (will generate if not provided)
        :return: Tuple of (salt, hashed_password)
        """
        if salt is None:
            salt = SecurityUtils.generate_salt()
        
        # Combine password and salt
        salted_password = f"{password}{salt}".encode('utf-8')
        
        # Hash using SHA-256
        hashed_password = hashlib.sha256(salted_password).hexdigest()
        
        return salt, hashed_password

    @staticmethod
    def verify_password(plain_password: str, stored_salt: str, stored_hash: str) -> bool:
        """
        Verify a password against its stored salt and hash.
        
        :param plain_password: Plain text password to verify
        :param stored_salt: Salt used during original hashing
        :param stored_hash: Original hashed password
        :return: True if password is correct, False otherwise
        """
        _, new_hash = SecurityUtils.hash_password(plain_password, stored_salt)
        return secrets.compare_digest(new_hash, stored_hash)

    @staticmethod
    def generate_token(length: int = 32) -> str:
        """
        Generate a cryptographically secure random token.
        
        :param length: Length of the token in bytes
        :return: Hex-encoded token
        """
        return secrets.token_hex(length)

    @staticmethod
    def generate_jwt_secret(length: int = 32) -> str:
        """
        Generate a secure secret key for JWT signing.
        
        :param length: Length of the secret key in bytes
        :return: Base64 encoded secret key
        """
        secret = secrets.token_bytes(length)
        return base64.b64encode(secret).decode('utf-8')

    @staticmethod
    def mask_sensitive_data(data: str, show_chars: int = 4) -> str:
        """
        Mask sensitive data like emails or phone numbers.
        
        :param data: Data to mask
        :param show_chars: Number of characters to show at the end
        :return: Masked data
        """
        if len(data) <= show_chars:
            return data
        
        return '*' * (len(data) - show_chars) + data[-show_chars:]
