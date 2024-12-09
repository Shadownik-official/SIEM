from fastapi import Request, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from typing import Optional, Dict, Any

from ...core.config import SIEMConfig
from ...models.user import UserRole
from ...utils.logger import logger

class JWTBearer(HTTPBearer):
    """
    Custom JWT authentication middleware for FastAPI.
    """
    def __init__(self, auto_error: bool = True, required_roles: Optional[list] = None):
        """
        Initialize JWT bearer with optional role-based access control.
        
        :param auto_error: Automatically raise HTTPException on auth failure
        :param required_roles: List of roles allowed to access the endpoint
        """
        super().__init__(auto_error=auto_error)
        self.required_roles = required_roles or []
        self.config = SIEMConfig.load_config()

    async def __call__(self, request: Request) -> Optional[Dict[str, Any]]:
        """
        Validate JWT token and optional role-based access.
        
        :param request: Incoming HTTP request
        :return: Decoded token payload
        :raises HTTPException: If authentication fails
        """
        credentials: HTTPAuthorizationCredentials = await super().__call__(request)
        
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, 
                detail="Invalid authorization credentials"
            )
        
        token = credentials.credentials
        
        try:
            # Decode and validate token
            payload = self.decode_jwt(token)
            
            # Check role-based access if roles are specified
            if self.required_roles:
                user_role = payload.get('role')
                if not user_role or UserRole(user_role) not in self.required_roles:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN, 
                        detail="Insufficient permissions"
                    )
            
            return payload
        
        except JWTError as e:
            logger.error(f"JWT Authentication Error: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="Could not validate credentials"
            )

    def create_jwt(self, user_id: int, username: str, role: UserRole) -> str:
        """
        Create a JWT token for a user.
        
        :param user_id: User's unique identifier
        :param username: User's username
        :param role: User's role
        :return: JWT token
        """
        # Token payload
        payload = {
            "sub": str(user_id),
            "username": username,
            "role": role.value,
            "exp": jwt.get_current_timestamp() + 
                   (self.config.security.get('jwt_expiration_minutes', 30) * 60)
        }
        
        # Sign token
        secret_key = self.config.security.get('jwt_secret_key')
        algorithm = self.config.security.get('jwt_algorithm', 'HS256')
        
        if not secret_key:
            raise ValueError("JWT secret key is not configured")
        
        return jwt.encode(payload, secret_key, algorithm=algorithm)

    def decode_jwt(self, token: str) -> Dict[str, Any]:
        """
        Decode and validate JWT token.
        
        :param token: JWT token
        :return: Decoded token payload
        """
        secret_key = self.config.security.get('jwt_secret_key')
        algorithm = self.config.security.get('jwt_algorithm', 'HS256')
        
        if not secret_key:
            raise ValueError("JWT secret key is not configured")
        
        return jwt.decode(
            token, 
            secret_key, 
            algorithms=[algorithm]
        )

# Global JWT authentication middleware
jwt_bearer = JWTBearer()
