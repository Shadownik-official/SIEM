import firebase_admin
from firebase_admin import credentials, auth
from fastapi import HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import os
from pathlib import Path

from .settings import get_settings
from ..utils.logging import LoggerMixin

settings = get_settings()
logger = LoggerMixin().get_logger()

# Get the absolute path to the service account file
service_account_path = Path(__file__).parent.parent.parent / 'firebase-service-account.json'

try:
    # Initialize Firebase Admin
    cred = credentials.Certificate(str(service_account_path))
    firebase_admin.initialize_app(cred)
    logger.info("Firebase Admin SDK initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize Firebase Admin SDK: {str(e)}")
    raise

security = HTTPBearer()

async def verify_firebase_token(credentials: HTTPAuthorizationCredentials = Security(security)) -> dict:
    """Verify Firebase ID token and return user data."""
    try:
        if not credentials:
            raise HTTPException(status_code=401, detail="No credentials provided")
            
        token = credentials.credentials
        try:
            # Verify the token
            decoded_token = auth.verify_id_token(token)
            
            # Get additional user info
            user = auth.get_user(decoded_token['uid'])
            
            # Log successful verification
            logger.info(f"Successfully verified token for user: {user.email}")
            
            return {
                'uid': user.uid,
                'email': user.email,
                'claims': user.custom_claims or {},
                'provider': decoded_token.get('firebase', {}).get('sign_in_provider'),
                'verified': user.email_verified
            }
            
        except auth.InvalidIdTokenError:
            logger.warning("Invalid token provided")
            raise HTTPException(status_code=401, detail="Invalid token")
        except auth.ExpiredIdTokenError:
            logger.warning("Expired token provided")
            raise HTTPException(status_code=401, detail="Token has expired")
        except auth.RevokedIdTokenError:
            logger.warning("Revoked token provided")
            raise HTTPException(status_code=401, detail="Token has been revoked")
        except auth.UserNotFoundError:
            logger.warning("Token from non-existent user")
            raise HTTPException(status_code=401, detail="User not found")
        except Exception as e:
            logger.error(f"Token verification failed: {str(e)}")
            raise HTTPException(status_code=401, detail="Token verification failed")
            
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        raise HTTPException(
            status_code=401,
            detail="Could not validate credentials"
        ) 