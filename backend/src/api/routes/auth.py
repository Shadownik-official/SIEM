from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import Dict, Any

from ...services.user_service import UserService
from ...models.user import UserRole
from ...utils.database import db_manager
from ..middleware.auth import jwt_bearer
from ..schemas.user_schema import UserLoginSchema, UserRegisterSchema, UserResponseSchema

router = APIRouter(prefix="/auth", tags=["Authentication"])

def get_user_service(db: Session = Depends(db_manager.get_session_generator)):
    """
    Dependency to get a UserService instance.
    
    :param db: Database session
    :return: UserService instance
    """
    return UserService(db)

@router.post("/register", response_model=UserResponseSchema)
def register_user(
    user_data: UserRegisterSchema, 
    user_service: UserService = Depends(get_user_service)
):
    """
    Register a new user.
    
    :param user_data: User registration details
    :param user_service: User service instance
    :return: Registered user details
    """
    try:
        user = user_service.register_user(
            username=user_data.username,
            email=user_data.email,
            password=user_data.password,
            role=UserRole.VIEWER  # Default role
        )
        return UserResponseSchema.from_orm(user)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

@router.post("/login")
def login_user(
    login_data: UserLoginSchema, 
    user_service: UserService = Depends(get_user_service)
) -> Dict[str, Any]:
    """
    Authenticate a user and generate JWT token.
    
    :param login_data: User login credentials
    :param user_service: User service instance
    :return: JWT token and user details
    """
    try:
        user = user_service.authenticate_user(
            username_or_email=login_data.username_or_email,
            password=login_data.password
        )
        
        # Generate JWT token
        token = jwt_bearer.create_jwt(
            user_id=user.id, 
            username=user.username, 
            role=user.role
        )
        
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": UserResponseSchema.from_orm(user)
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid credentials"
        )

@router.get("/me", dependencies=[Depends(jwt_bearer)])
def get_current_user(
    user_service: UserService = Depends(get_user_service),
    token_payload: Dict[str, Any] = Depends(jwt_bearer)
):
    """
    Get details of the currently authenticated user.
    
    :param user_service: User service instance
    :param token_payload: Decoded JWT token payload
    :return: Current user details
    """
    user_id = int(token_payload.get('sub'))
    user = user_service.repository.get(user_id)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail="User not found"
        )
    
    return UserResponseSchema.from_orm(user)
