"""
Advanced Authentication and API Gateway Module for Enterprise SIEM
Handles authentication, authorization, and API integration
"""
import logging
import json
from typing import Dict, List, Optional, Union
from dataclasses import dataclass
from datetime import datetime, timedelta
import uuid
import jwt
from fastapi import FastAPI, Security, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from ..core.utils import encrypt_data, decrypt_data
from ..core.database import Database

@dataclass
class User:
    """Represents a system user."""
    id: str
    username: str
    email: str
    role: str
    permissions: List[str]
    last_login: datetime
    created_at: datetime
    status: str

@dataclass
class ApiKey:
    """Represents an API key."""
    id: str
    name: str
    key: str
    owner_id: str
    permissions: List[str]
    created_at: datetime
    expires_at: datetime
    last_used: datetime
    status: str

class AuthGateway:
    """Advanced authentication and API gateway system."""
    
    def __init__(self, config_path: str = None):
        self.logger = logging.getLogger(__name__)
        self.db = Database()
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        self.oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
        self.app = FastAPI()
        self._initialize_gateway()
        
    def _initialize_gateway(self) -> None:
        """Initialize gateway components."""
        try:
            # Initialize JWT settings
            self.secret_key = "your-secret-key"  # Should be loaded from secure config
            self.algorithm = "HS256"
            self.access_token_expire_minutes = 30
            
            # Initialize API rate limiting
            self._initialize_rate_limiting()
            
            # Initialize routes
            self._initialize_routes()
            
        except Exception as e:
            self.logger.error(f"Error initializing gateway: {str(e)}")
            
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate user credentials."""
        try:
            # Get user from database
            user_data = self._get_user(username)
            if not user_data:
                return None
                
            # Verify password
            if not self.pwd_context.verify(password, user_data['hashed_password']):
                return None
                
            # Create user object
            user = User(
                id=user_data['id'],
                username=user_data['username'],
                email=user_data['email'],
                role=user_data['role'],
                permissions=user_data['permissions'],
                last_login=user_data['last_login'],
                created_at=user_data['created_at'],
                status=user_data['status']
            )
            
            # Update last login
            self._update_last_login(user.id)
            
            return user
            
        except Exception as e:
            self.logger.error(f"Error authenticating user: {str(e)}")
            return None
            
    def create_access_token(self, data: Dict) -> str:
        """Create JWT access token."""
        try:
            to_encode = data.copy()
            expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
            to_encode.update({"exp": expire})
            encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
            return encoded_jwt
            
        except Exception as e:
            self.logger.error(f"Error creating access token: {str(e)}")
            return ""
            
    def verify_token(self, token: str) -> Optional[Dict]:
        """Verify JWT token."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
            
        except jwt.ExpiredSignatureError:
            self.logger.error("Token has expired")
            return None
        except jwt.JWTError:
            self.logger.error("Invalid token")
            return None
            
    def create_api_key(self, name: str, owner_id: str, permissions: List[str]) -> Optional[ApiKey]:
        """Create new API key."""
        try:
            api_key = ApiKey(
                id=str(uuid.uuid4()),
                name=name,
                key=self._generate_api_key(),
                owner_id=owner_id,
                permissions=permissions,
                created_at=datetime.now(),
                expires_at=datetime.now() + timedelta(days=365),
                last_used=datetime.now(),
                status='active'
            )
            
            # Store API key
            self._store_api_key(api_key)
            
            return api_key
            
        except Exception as e:
            self.logger.error(f"Error creating API key: {str(e)}")
            return None
            
    def validate_api_key(self, key: str) -> Optional[ApiKey]:
        """Validate API key."""
        try:
            # Get API key from database
            api_key_data = self._get_api_key(key)
            if not api_key_data:
                return None
                
            # Check if expired
            if datetime.now() > api_key_data['expires_at']:
                return None
                
            # Create API key object
            api_key = ApiKey(**api_key_data)
            
            # Update last used
            self._update_api_key_usage(api_key.id)
            
            return api_key
            
        except Exception as e:
            self.logger.error(f"Error validating API key: {str(e)}")
            return None
            
    def check_permission(self, user_id: str, required_permission: str) -> bool:
        """Check if user has required permission."""
        try:
            user_data = self._get_user_by_id(user_id)
            if not user_data:
                return False
                
            return required_permission in user_data['permissions']
            
        except Exception as e:
            self.logger.error(f"Error checking permission: {str(e)}")
            return False
            
    def _initialize_routes(self) -> None:
        """Initialize API routes."""
        @self.app.post("/token")
        async def login(form_data: OAuth2PasswordRequestForm = Depends()):
            user = self.authenticate_user(form_data.username, form_data.password)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect username or password",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            access_token = self.create_access_token(
                data={"sub": user.username}
            )
            return {"access_token": access_token, "token_type": "bearer"}
            
    def _generate_api_key(self) -> str:
        """Generate secure API key."""
        return str(uuid.uuid4())
        
    def get_auth_dashboard(self) -> Dict:
        """Get authentication dashboard data."""
        try:
            dashboard = {
                'active_users': self._get_active_users(),
                'api_key_usage': self._get_api_key_usage(),
                'auth_metrics': self._get_auth_metrics(),
                'permission_usage': self._get_permission_usage(),
                'security_events': self._get_security_events(),
                'system_health': self._get_system_health()
            }
            
            return dashboard
            
        except Exception as e:
            self.logger.error(f"Error getting auth dashboard: {str(e)}")
            return {}
