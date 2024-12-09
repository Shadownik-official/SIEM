import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .core.config import SIEMConfig
from .core.exceptions import SIEMBaseException
from .utils.database import db_manager
from .utils.logger import logger

# Import API routes
from .api.routes import auth, threat_intelligence

def create_application() -> FastAPI:
    """
    Create and configure the FastAPI application.
    
    :return: Configured FastAPI application
    """
    # Load configuration
    config = SIEMConfig.load_config()

    # Create FastAPI application
    app = FastAPI(
        title="SIEM Backend",
        description="Security Information and Event Management System",
        version="0.1.0",
        debug=config.debug
    )

    # Database initialization
    db_manager.create_tables()

    # Middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Allows all origins
        allow_credentials=True,
        allow_methods=["*"],  # Allows all methods
        allow_headers=["*"],  # Allows all headers
    )

    # Global exception handler
    @app.exception_handler(SIEMBaseException)
    async def siem_exception_handler(request: Request, exc: SIEMBaseException):
        """
        Global exception handler for SIEM-specific exceptions.
        
        :param request: Incoming request
        :param exc: Raised exception
        :return: JSON response with error details
        """
        logger.error(f"SIEM Exception: {exc}")
        return JSONResponse(
            status_code=500,
            content={
                "error": "Internal SIEM Error",
                "message": str(exc)
            }
        )

    # Include API routes
    app.include_router(auth.router, prefix="/api/v1")
    app.include_router(threat_intelligence.router, prefix="/api/v1")

    return app

# Create FastAPI application
app = create_application()

def start_server():
    """
    Start the SIEM backend server.
    """
    config = SIEMConfig.load_config()
    
    uvicorn.run(
        "src.main:app", 
        host="0.0.0.0", 
        port=8000, 
        reload=config.debug
    )

if __name__ == "__main__":
    start_server()
