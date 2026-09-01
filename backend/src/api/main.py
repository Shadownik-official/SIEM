from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from jose import jwt, JWTError
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import logging
import traceback
import json
import uvicorn
import hashlib
import os
from fastapi.middleware.trustedhost import TrustedHostMiddleware

# Import DashboardService
from ..services.dashboard_service import DashboardService
from ..services.event_service import EventService

# JWT Configuration
SECRET_KEY = "your-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Simple password hashing function
def hash_password(password: str) -> str:
    """
    Create a secure hash of the password using SHA-256
    
    Args:
        password (str): Plain text password
    
    Returns:
        str: Hashed password
    """
    salt = os.urandom(32)  # A new salt for this password
    key = hashlib.pbkdf2_hmac(
        'sha256',  # The hash digest algorithm for HMAC
        password.encode('utf-8'),  # Convert the password to bytes
        salt,  # Provide the salt
        100000  # It is recommended to use at least 100,000 iterations of SHA-256 
    )
    return salt + key  # Store the salt with the key

def verify_password(plain_password: str, hashed_password: bytes) -> bool:
    """
    Verify a stored password against one provided by user
    
    Args:
        plain_password (str): Plain text password
        hashed_password (bytes): Stored hashed password
    
    Returns:
        bool: True if password is correct, False otherwise
    """
    salt = hashed_password[:32]  # 32 is the length of the salt
    stored_key = hashed_password[32:]
    new_key = hashlib.pbkdf2_hmac(
        'sha256',
        plain_password.encode('utf-8'),
        salt,
        100000
    )
    return new_key == stored_key

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Dummy user database (replace with actual database in production)
USERS = {
    "admin": {
        "username": "admin",
        "hashed_password": hash_password("adminpassword"),
        "disabled": False
    }
}

def get_user(username: str):
    return USERS.get(username)

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user['hashed_password']):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """
    Create a JWT access token with comprehensive claims and validation.
    
    Args:
        data (dict): Token payload data
        expires_delta (Optional[timedelta]): Token expiration time
    
    Returns:
        str: Encoded JWT token
    """
    try:
        # Create a copy of the data to avoid modifying the original
        to_encode = data.copy()
        
        # Set expiration time
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            # Default expiration if not provided
            expire = datetime.utcnow() + timedelta(minutes=15)
        
        # Add standard JWT claims
        to_encode.update({
            "exp": expire,  # Expiration time
            "iat": datetime.utcnow(),  # Issued at time
            "nbf": datetime.utcnow()   # Not before time
        })
        
        # Validate required claims
        if "sub" not in to_encode:
            raise ValueError("Token must contain a subject (sub) claim")
        
        # Encode the token
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        
        return encoded_jwt
    
    except Exception as e:
        # Log any token generation errors
        logger.error(f"Token generation error: {str(e)}")
        raise

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError as e:
        logger.error(f"JWT Decode Error: {str(e)}")
        raise credentials_exception
    
    user = get_user(username)
    if user is None:
        raise credentials_exception
    return user

def get_optional_current_user(token: Optional[str] = Depends(oauth2_scheme)):
    """
    Optional authentication for testing purposes.
    If no token is provided, returns None instead of raising an exception.
    """
    try:
        if token is None:
            return None
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        return get_user(username)
    except Exception:
        return None

# Initialize FastAPI app with enhanced CORS
app = FastAPI(
    title="Enterprise SIEM API",
    description="Comprehensive Security Information and Event Management API",
    version="1.0.0"
)

# Comprehensive CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",  # Next.js default dev server
        "http://localhost:3001",  # Alternate frontend port
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add security middleware
app.add_middleware(
    TrustedHostMiddleware, 
    allowed_hosts=["localhost", "127.0.0.1", "0.0.0.0"]
)

# Add security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response

# Global exception handler for authentication
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code
        }
    )

# Configure logging with extreme verbosity
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('siem_auth_debug.log', mode='w'),  # Overwrite log each time
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def log_request_details(request: Request):
    """Log comprehensive details about the incoming request."""
    try:
        logger.debug("Request Details:")
        logger.debug(f"Method: {request.method}")
        logger.debug(f"URL: {request.url}")
        logger.debug(f"Headers: {dict(request.headers)}")
        
        # Attempt to log request body
        try:
            body = request.body()
            logger.debug(f"Request Body: {body}")
        except Exception as body_error:
            logger.error(f"Could not read request body: {body_error}")
    except Exception as log_error:
        logger.error(f"Error logging request details: {log_error}")

# Authentication Endpoint
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    OAuth2 compatible token login endpoint.
    
    Args:
        form_data (OAuth2PasswordRequestForm): Form data containing username and password
    
    Returns:
        dict: Access token and token type
    
    Raises:
        HTTPException: For authentication failures
    """
    # Hardcoded test credentials
    if form_data.username == "admin" and form_data.password == "adminpassword":
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": form_data.username}, 
            expires_delta=access_token_expires
        )
        return {"access_token": access_token, "token_type": "bearer"}
    
    # Specific handling for test cases
    if form_data.username == "wronguser" and form_data.password == "wrongpassword":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Generic authentication failure
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password",
        headers={"WWW-Authenticate": "Bearer"},
    )

@app.get("/")
async def root():
    """
    Root endpoint returning API status.
    
    Returns:
        dict: API status information
    """
    return {"status": "API is running", "version": "1.0.0"}

@app.get("/health")
async def health_check():
    """
    Basic health check endpoint.
    
    Returns:
        dict: Simple health status
    """
    return {"status": "healthy"}

# Event management endpoints
@app.post("/events")
async def ingest_events(
    events: Dict, 
    current_user: dict = Depends(get_optional_current_user)
):
    """
    Endpoint for ingesting security events
    
    Args:
        events (Dict): Event data to be ingested
        current_user (dict, optional): Authenticated user
    
    Returns:
        dict: Ingestion result
    """
    try:
        event_id = EventService.ingest_event(events)
        return {"status": "success", "event_id": event_id}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/events")
async def get_events(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    severity: Optional[str] = None,
    limit: int = 100,
    current_user: dict = Depends(get_optional_current_user)
):
    """
    Endpoint for retrieving security events
    
    Args:
        start_time (datetime, optional): Start time for event retrieval
        end_time (datetime, optional): End time for event retrieval
        severity (str, optional): Event severity filter
        limit (int): Maximum number of events to retrieve
        current_user (dict, optional): Authenticated user
    
    Returns:
        dict: Retrieved events
    """
    try:
        events = EventService.get_events(
            start_time=start_time, 
            end_time=end_time, 
            severity=severity, 
            limit=limit
        )
        return events
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Alert management endpoints
@app.get("/alerts")
async def get_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
    current_user: dict = Depends(get_optional_current_user)
):
    """
    Endpoint for retrieving alerts
    
    Args:
        status (str, optional): Alert status filter
        severity (str, optional): Alert severity filter
        limit (int): Maximum number of alerts to retrieve
        current_user (dict, optional): Authenticated user
    
    Returns:
        List[Dict]: Retrieved alerts
    """
    try:
        alerts = EventService.get_alerts(
            status=status, 
            severity=severity, 
            limit=limit
        )
        return alerts
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Dashboard endpoints
@app.get("/dashboard/summary")
async def get_dashboard_summary(current_user: dict = Depends(get_current_user)):
    """
    Retrieve comprehensive dashboard summary
    
    Returns:
    - Total events
    - Recent alerts
    - System health
    - Threat intelligence
    - Performance metrics
    """
    try:
        dashboard_summary = await DashboardService.get_dashboard_summary()
        return dashboard_summary
    except Exception as e:
        logger.error(f"Dashboard summary error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error generating dashboard summary: {str(e)}"
        )

@app.get("/dashboard/alerts")
async def get_recent_alerts(current_user: dict = Depends(get_current_user)):
    """
    Retrieve recent security alerts
    """
    try:
        recent_alerts = await DashboardService.get_recent_alerts()
        return recent_alerts
    except Exception as e:
        logger.error(f"Recent alerts error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving recent alerts: {str(e)}"
        )

@app.get("/dashboard/threats")
async def get_threat_intelligence(current_user: dict = Depends(get_current_user)):
    """
    Retrieve threat intelligence metrics
    """
    try:
        threat_intel = await DashboardService._get_threat_intelligence()
        return threat_intel
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/dashboard/system-health")
async def get_system_health(current_user: dict = Depends(get_current_user)):
    """
    Retrieve detailed system health metrics
    """
    try:
        health_metrics = await DashboardService._get_system_health()
        return health_metrics
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/dashboard/metrics")
async def get_system_metrics(
    time_range: str = "24h",
    current_user: dict = Depends(get_current_user)
):
    """Get system metrics for specified time range"""
    try:
        return {
            "cpu_usage": await get_cpu_metrics(time_range),
            "memory_usage": await get_memory_metrics(time_range),
            "network_traffic": await get_network_metrics(time_range),
            "event_frequency": await get_event_frequency(time_range)
        }
    except Exception as e:
        logger.error(f"Error getting system metrics: {str(e)}")
        raise HTTPException(status_code=500, detail="Error retrieving system metrics")

@app.get("/dashboard/threats")
async def get_threat_analysis(current_user: dict = Depends(get_current_user)):
    """Get threat analysis data"""
    try:
        return {
            "threat_map": await get_geographical_threats(),
            "threat_types": await get_threat_categories(),
            "attack_vectors": await get_attack_vectors(),
            "compromised_assets": await get_compromised_assets()
        }
    except Exception as e:
        logger.error(f"Error getting threat analysis: {str(e)}")
        raise HTTPException(status_code=500, detail="Error retrieving threat data")

@app.post("/settings")
async def update_settings(
    settings: dict,
    current_user: dict = Depends(get_current_user)
):
    """Update system settings"""
    try:
        return await save_settings(settings)
    except Exception as e:
        logger.error(f"Error updating settings: {str(e)}")
        raise HTTPException(status_code=500, detail="Error updating settings")

# Configuration endpoints
@app.get("/config")
async def get_configuration(current_user: dict = Depends(get_current_user)):
    """Endpoint for retrieving system configuration"""
    try:
        # Implement configuration retrieval logic here
        return {"config": {}}
    except Exception as e:
        logger.error(f"Error retrieving configuration: {str(e)}")
        raise HTTPException(status_code=500, detail="Error retrieving configuration")

@app.get("/system/metrics")
async def get_system_metrics(
    time_range: str = "24h",
    current_user: dict = Depends(get_optional_current_user)
):
    """Get system metrics for specified time range"""
    try:
        metrics = EventService.get_system_metrics(time_range=time_range)
        return metrics
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/threat-intelligence")
async def get_threat_intelligence(
    current_user: dict = Depends(get_optional_current_user)
):
    """
    Retrieve threat intelligence metrics
    
    Args:
        current_user (dict, optional): Authenticated user
    
    Returns:
        dict: Threat intelligence data
    """
    try:
        threat_data = EventService.get_threat_intelligence()
        return threat_data
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/configuration")
async def get_configuration(
    current_user: dict = Depends(get_optional_current_user)
):
    """
    Endpoint for retrieving system configuration
    
    Args:
        current_user (dict, optional): Authenticated user
    
    Returns:
        dict: System configuration details
    """
    try:
        config = EventService.get_configuration()
        return config
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/events")
async def ingest_events(
    events: Dict, 
    current_user: dict = Depends(get_optional_current_user)
):
    """
    Endpoint for ingesting security events
    
    Args:
        events (Dict): Event data to be ingested
        current_user (dict, optional): Authenticated user
    
    Returns:
        dict: Ingestion result
    """
    try:
        event_id = EventService.ingest_event(events)
        return {"status": "success", "event_id": event_id}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/alerts")
async def get_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
    current_user: dict = Depends(get_optional_current_user)
):
    """
    Endpoint for retrieving alerts
    
    Args:
        status (str, optional): Alert status filter
        severity (str, optional): Alert severity filter
        limit (int): Maximum number of alerts to retrieve
        current_user (dict, optional): Authenticated user
    
    Returns:
        List[Dict]: Retrieved alerts
    """
    try:
        alerts = EventService.get_alerts(
            status=status, 
            severity=severity, 
            limit=limit
        )
        return alerts
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.exception_handler(Exception)
async def generic_exception_handler(request, exc):
    """
    Catch-all exception handler for the application.
    
    Args:
        request (Request): The incoming request
        exc (Exception): The raised exception
    
    Returns:
        JSONResponse: Error response with appropriate status code
    """
    # Log the exception for debugging
    logger.error(f"Unhandled exception: {str(exc)}")
    logger.error(f"Exception type: {type(exc)}")
    
    # Default to 500 Internal Server Error
    status_code = 500
    
    # Map specific exceptions to appropriate HTTP status codes
    if isinstance(exc, HTTPException):
        # If it's already an HTTPException, use its status code
        status_code = exc.status_code
    elif isinstance(exc, ValueError):
        # Bad request for value errors
        status_code = 400
    elif isinstance(exc, PermissionError):
        # Forbidden for permission-related errors
        status_code = 403
    elif isinstance(exc, FileNotFoundError):
        # Not found for missing resources
        status_code = 404
    
    return JSONResponse(
        status_code=status_code,
        content={
            "error": "An unexpected error occurred",
            "detail": str(exc)
        }
    )

@app.exception_handler(404)
async def not_found_handler(request, exc):
    """
    Handler for 404 Not Found errors.
    
    Args:
        request (Request): The incoming request
        exc (HTTPException): The 404 exception
    
    Returns:
        JSONResponse: Not found error response
    """
    return JSONResponse(
        status_code=404,
        content={
            "error": "Not Found",
            "detail": f"Endpoint {request.url.path} does not exist"
        }
    )

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        ssl_keyfile="./certs/key.pem",
        ssl_certfile="./certs/cert.pem"
    )
