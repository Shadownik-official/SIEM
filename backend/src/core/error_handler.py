import logging
import traceback
from typing import Any, Dict, Optional
import uuid
from enum import Enum, auto

class ErrorSeverity(Enum):
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()

class SIEMErrorHandler:
    """
    Centralized error handling and logging mechanism for SIEM system
    """
    _instance = None
    
    def __new__(cls):
        if not cls._instance:
            cls._instance = super().__new__(cls)
            cls._instance._setup_logging()
        return cls._instance
    
    def _setup_logging(self):
        """Configure comprehensive logging"""
        self.logger = logging.getLogger('siem_error_handler')
        self.logger.setLevel(logging.DEBUG)
        
        # Console Handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # File Handler
        file_handler = logging.FileHandler('siem_errors.log')
        file_handler.setLevel(logging.DEBUG)
        
        # Formatters
        console_formatter = logging.Formatter('%(asctime)s - %(levelname)s: %(message)s')
        file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s: %(message)s')
        
        console_handler.setFormatter(console_formatter)
        file_handler.setFormatter(file_formatter)
        
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)
    
    def log_error(
        self, 
        component: str, 
        error: Exception, 
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Log an error with comprehensive details
        
        :param component: Component where error occurred
        :param error: Exception object
        :param severity: Error severity level
        :param context: Additional context information
        :return: Unique error tracking ID
        """
        error_id = str(uuid.uuid4())
        
        error_details = {
            'error_id': error_id,
            'component': component,
            'message': str(error),
            'severity': severity.name,
            'traceback': traceback.format_exc(),
            'context': context or {}
        }
        
        # Log based on severity
        if severity == ErrorSeverity.CRITICAL:
            self.logger.critical(f"[{error_id}] {component}: {error}")
        elif severity == ErrorSeverity.HIGH:
            self.logger.error(f"[{error_id}] {component}: {error}")
        elif severity == ErrorSeverity.MEDIUM:
            self.logger.warning(f"[{error_id}] {component}: {error}")
        else:
            self.logger.info(f"[{error_id}] {component}: {error}")
        
        return error_id
    
    def handle_error(
        self, 
        component: str, 
        error: Exception, 
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        recovery_action: Optional[callable] = None
    ):
        """
        Comprehensive error handling with optional recovery
        
        :param component: Component where error occurred
        :param error: Exception object
        :param severity: Error severity level
        :param recovery_action: Optional function to attempt recovery
        """
        error_id = self.log_error(component, error, severity)
        
        if recovery_action:
            try:
                recovery_action()
            except Exception as recovery_error:
                self.log_error(f"{component}_recovery", recovery_error, ErrorSeverity.CRITICAL)
        
        return error_id

# Global error handler instance
error_handler = SIEMErrorHandler()
