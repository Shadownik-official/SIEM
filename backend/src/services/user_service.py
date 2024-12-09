from typing import Optional
from sqlalchemy.orm import Session

from ..models.user import User, UserRole
from ..repositories.user_repository import UserRepository
from ..core.exceptions import AuthenticationError, AuthorizationError
from .base import BaseService

class UserService(BaseService[UserRepository]):
    """
    Service layer for user-related operations.
    """
    def __init__(self, db_session: Session):
        user_repository = UserRepository(db_session)
        super().__init__(user_repository, db_session)

    def register_user(self, username: str, email: str, password: str, role: UserRole = UserRole.VIEWER) -> User:
        """
        Register a new user in the system.
        
        :param username: User's username
        :param email: User's email
        :param password: User's password
        :param role: User's role, defaults to VIEWER
        :return: Created user
        :raises ValueError: If username or email already exists
        """
        # Check if username or email already exists
        if self.repository.get_by_username(username):
            raise ValueError(f"Username {username} already exists")
        
        if self.repository.get_by_email(email):
            raise ValueError(f"Email {email} already exists")
        
        try:
            return self.repository.create_user(username, email, password, role)
        except Exception as e:
            self.rollback_transaction()
            raise

    def authenticate_user(self, username_or_email: str, password: str) -> User:
        """
        Authenticate a user and return the user object.
        
        :param username_or_email: Username or email
        :param password: User's password
        :return: Authenticated user
        :raises AuthenticationError: If authentication fails
        """
        user = self.repository.authenticate_user(username_or_email, password)
        
        if not user:
            raise AuthenticationError("Invalid credentials")
        
        if not user.is_active:
            raise AuthorizationError("User account is not active")
        
        return user

    def change_user_role(self, admin_user: User, target_username: str, new_role: UserRole):
        """
        Change a user's role (requires admin privileges).
        
        :param admin_user: User performing the role change
        :param target_username: Username of the user whose role is being changed
        :param new_role: New role to assign
        :raises AuthorizationError: If the admin does not have sufficient privileges
        """
        if admin_user.role != UserRole.ADMIN:
            raise AuthorizationError("Only administrators can change user roles")
        
        target_user = self.repository.get_by_username(target_username)
        
        if not target_user:
            raise ValueError(f"User {target_username} not found")
        
        target_user.role = new_role
        
        try:
            self.repository.update(target_user)
            self.commit_transaction()
        except Exception as e:
            self.rollback_transaction()
            raise

    def deactivate_user(self, admin_user: User, target_username: str):
        """
        Deactivate a user account (requires admin privileges).
        
        :param admin_user: User performing the deactivation
        :param target_username: Username of the user to deactivate
        :raises AuthorizationError: If the admin does not have sufficient privileges
        """
        if admin_user.role != UserRole.ADMIN:
            raise AuthorizationError("Only administrators can deactivate user accounts")
        
        target_user = self.repository.get_by_username(target_username)
        
        if not target_user:
            raise ValueError(f"User {target_username} not found")
        
        target_user.is_active = False
        
        try:
            self.repository.update(target_user)
            self.commit_transaction()
        except Exception as e:
            self.rollback_transaction()
            raise
