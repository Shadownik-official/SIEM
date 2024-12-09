from sqlalchemy import Column, String, Boolean, Enum
from sqlalchemy.orm import relationship
from .base import BaseModel
import enum
import re

class UserRole(enum.Enum):
    """
    Enumeration of user roles in the SIEM system.
    """
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"

class User(BaseModel):
    """
    User model representing users in the SIEM system.
    """
    __tablename__ = 'users'

    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(120), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), nullable=False, default=UserRole.VIEWER)
    is_active = Column(Boolean, default=True)
    
    # Optional: Relationship with other models
    # events = relationship("Event", back_populates="user")

    @classmethod
    def validate_email(cls, email: str) -> bool:
        """
        Validate email format.
        
        :param email: Email address to validate
        :return: True if email is valid, False otherwise
        """
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(email_regex, email) is not None

    @classmethod
    def validate_password(cls, password: str) -> bool:
        """
        Validate password strength.
        
        :param password: Password to validate
        :return: True if password meets complexity requirements
        """
        # At least 12 characters, one uppercase, one lowercase, one number, one special char
        password_regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$'
        return re.match(password_regex, password) is not None

    def __repr__(self):
        return f"<User {self.username} ({self.role.value})>"
