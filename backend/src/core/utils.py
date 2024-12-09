from cryptography.fernet import Fernet

def encrypt_data(data: bytes, key: bytes = None) -> tuple[bytes, bytes]:
    """Encrypt data using Fernet symmetric encryption.
    
    Args:
        data: Data to encrypt
        key: Optional encryption key. If not provided, a new key will be generated.
        
    Returns:
        Tuple of (encrypted_data, key)
    """
    if key is None:
        key = Fernet.generate_key()
    f = Fernet(key)
    encrypted_data = f.encrypt(data)
    return encrypted_data, key

def decrypt_data(encrypted_data: bytes, key: bytes) -> bytes:
    """Decrypt Fernet-encrypted data.
    
    Args:
        encrypted_data: Data to decrypt
        key: Encryption key used to encrypt the data
        
    Returns:
        Decrypted data
    """
    f = Fernet(key)
    return f.decrypt(encrypted_data)
