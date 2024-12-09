"""
Custom exceptions for the SIEM application.
"""

class SIEMBaseException(Exception):
    """Base exception for all SIEM-related errors."""
    pass

class AuthenticationError(SIEMBaseException):
    """Raised when authentication fails."""
    pass

class AuthorizationError(SIEMBaseException):
    """Raised when authorization fails."""
    pass

class ConfigurationError(SIEMBaseException):
    """Raised when configuration loading or validation fails."""
    pass

class DatabaseError(SIEMBaseException):
    """Raised when database operations encounter issues."""
    pass

class CollectorError(SIEMBaseException):
    """Raised when data collection encounters problems."""
    pass

class EventProcessingError(SIEMBaseException):
    """Raised when event processing fails."""
    pass

class ThreatIntelligenceError(SIEMBaseException):
    """Raised when threat intelligence processing encounters issues."""
    pass
