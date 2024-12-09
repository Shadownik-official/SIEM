from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional

from ...models.user import UserRole
from .base import BaseSchema

class UserRegisterSchema(BaseModel):
    """
    Schema for user registration.
    """
    username: str = Field(..., min_length=3, max_length=50, description="Username")
    email: EmailStr = Field(..., description="User's email address")
    password: str = Field(..., min_length=8, description="User password")
    
    @validator('username')
    def validate_username(cls, username):
        """
        Validate username format.
        
        :param username: Username to validate
        :return: Validated username
        """
        if not username.isalnum():
            raise ValueError("Username must be alphanumeric")
        return username

    @validator('password')
    def validate_password(cls, password):
        """
        Validate password complexity.
        
        :param password: Password to validate
        :return: Validated password
        """
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")
        
        # Optional: Add more complex password validation
        # Uncomment and modify as needed
        # if not re.search(r'[A-Z]', password):
        #     raise ValueError("Password must contain at least one uppercase letter")
        # if not re.search(r'[a-z]', password):
        #     raise ValueError("Password must contain at least one lowercase letter")
        # if not re.search(r'\d', password):
        #     raise ValueError("Password must contain at least one number")
        
        return password

class UserLoginSchema(BaseModel):
    """
    Schema for user login.
    """
    username_or_email: str = Field(..., description="Username or email for login")
    password: str = Field(..., description="User password")

class UserResponseSchema(BaseSchema):
    """
    Schema for user response, excluding sensitive information.
    """
    username: str
    email: str
    role: UserRole
    is_active: Optional[bool] = True

    class Config:
        """
        Pydantic configuration for user response.
        """
        orm_mode = True
        use_enum_values = True

class UserUpdateSchema(BaseModel):
    """
    Schema for updating user details.
    """
    email: Optional[EmailStr] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None

    @validator('email')
    def validate_email(cls, email):
        """
        Validate email if provided.
        
        :param email: Email to validate
        :return: Validated email
        """
        if email is not None and not EmailStr.validate(email):
            raise ValueError("Invalid email format")
        return email
