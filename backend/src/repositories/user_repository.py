from sqlalchemy.orm import Session
from sqlalchemy import or_
from typing import Optional

from ..models.user import User, UserRole
from .base import BaseRepository

class UserRepository(BaseRepository[User]):
    """
    Repository for user-specific database operations.
    """
    def __init__(self, db_session: Session):
        super().__init__(db_session, User)

    def get_by_username(self, username: str) -> Optional[User]:
        """
        Retrieve a user by username.
        
        :param username: Username to search for
        :return: User or None if not found
        """
        return self.session.query(User).filter(User.username == username).first()

    def get_by_email(self, email: str) -> Optional[User]:
        """
        Retrieve a user by email.
        
        :param email: Email to search for
        :return: User or None if not found
        """
        return self.session.query(User).filter(User.email == email).first()

    def get_by_username_or_email(self, username_or_email: str) -> Optional[User]:
        """
        Retrieve a user by username or email.
        
        :param username_or_email: Username or email to search for
        :return: User or None if not found
        """
        return self.session.query(User).filter(
            or_(User.username == username_or_email, User.email == username_or_email)
        ).first()

    def create_user(self, username: str, email: str, password: str, role: UserRole = UserRole.VIEWER) -> User:
        """
        Create a new user with hashed password.
        
        :param username: User's username
        :param email: User's email
        :param password: User's password (will be hashed)
        :param role: User's role, defaults to VIEWER
        :return: Created user
        """
        # Validate inputs
        if not User.validate_email(email):
            raise ValueError("Invalid email format")
        
        if not User.validate_password(password):
            raise ValueError("Password does not meet complexity requirements")
        
        # In a real implementation, you would hash the password
        # Here we're using a placeholder
        hashed_password = self._hash_password(password)
        
        new_user = User(
            username=username,
            email=email,
            password_hash=hashed_password,
            role=role
        )
        
        return self.create(new_user)

    def _hash_password(self, password: str) -> str:
        """
        Hash the password (placeholder method).
        
        :param password: Plain text password
        :return: Hashed password
        """
        # In a real implementation, use a secure hashing library like bcrypt
        import hashlib
        return hashlib.sha256(password.encode()).hexdigest()

    def authenticate_user(self, username_or_email: str, password: str) -> Optional[User]:
        """
        Authenticate a user.
        
        :param username_or_email: Username or email
        :param password: Password to verify
        :return: User if authenticated, None otherwise
        """
        user = self.get_by_username_or_email(username_or_email)
        
        if user and self._verify_password(password, user.password_hash):
            return user
        
        return None

    def _verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash.
        
        :param plain_password: Plain text password
        :param hashed_password: Stored hashed password
        :return: True if password matches, False otherwise
        """
        return self._hash_password(plain_password) == hashed_password
