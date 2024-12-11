from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
from datetime import datetime
import uuid

from src.core.error_handler import error_handler, ErrorSeverity
from src.core.performance import performance_monitor

Base = declarative_base()

class DatabaseManager:
    """
    Enhanced Database Management with connection pooling and advanced error handling
    """
    _instance = None
    
    def __new__(cls, config=None):
        if not cls._instance:
            cls._instance = super().__new__(cls)
            cls._instance._initialize(config)
        return cls._instance
    
    @performance_monitor.track_performance
    def _initialize(self, config):
        """
        Initialize database connection with robust configuration
        """
        try:
            # Determine database type and connection string
            db_type = config.database.get('type', 'sqlite')
            
            if db_type == 'sqlite':
                db_path = config.database.get('path', 'siem.db')
                self.engine = create_engine(f'sqlite:///{db_path}', 
                    connect_args={'check_same_thread': False},
                    pool_size=10,
                    max_overflow=20
                )
            elif db_type == 'postgresql':
                connection_string = (
                    f"postgresql://{config.database.get('user', '')}:"
                    f"{config.database.get('password', '')}@"
                    f"{config.database.get('host', 'localhost')}:"
                    f"{config.database.get('port', 5432)}/"
                    f"{config.database.get('name', 'siem_db')}"
                )
                self.engine = create_engine(connection_string, 
                    pool_size=10,
                    max_overflow=20
                )
            else:
                raise ValueError(f"Unsupported database type: {db_type}")
            
            # Create session factory
            self.session_factory = sessionmaker(bind=self.engine)
            self.Session = scoped_session(self.session_factory)
            
            # Create tables
            Base.metadata.create_all(self.engine)
            
            self.logger.info(f"Database initialized: {db_type}")
        
        except Exception as e:
            error_handler.handle_error(
                'DatabaseInitialization', 
                e, 
                ErrorSeverity.CRITICAL
            )
            raise
    
    def get_session(self):
        """
        Get a database session with error handling
        """
        try:
            return self.Session()
        except Exception as e:
            error_handler.handle_error(
                'DatabaseSession', 
                e, 
                ErrorSeverity.HIGH
            )
            raise
    
    def close_session(self, session):
        """
        Close and remove a database session
        """
        try:
            self.Session.remove()
        except Exception as e:
            error_handler.handle_error(
                'SessionClose', 
                e, 
                ErrorSeverity.LOW
            )

class EventLog(Base):
    """
    Enhanced event logging model with comprehensive tracking
    """
    __tablename__ = 'event_logs'
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=datetime.utcnow)
    source_ip = Column(String)
    destination_ip = Column(String)
    event_type = Column(String)
    severity = Column(Integer)
    details = Column(JSON)
    
    @classmethod
    @performance_monitor.track_performance
    def log_event(cls, session, event_data):
        """
        Log an event with performance tracking
        """
        try:
            event = cls(**event_data)
            session.add(event)
            session.commit()
            return event
        except Exception as e:
            session.rollback()
            error_handler.handle_error(
                'EventLogging', 
                e, 
                ErrorSeverity.MEDIUM
            )
            return None

class ThreatIndicator(Base):
    """
    Enhanced threat indicator model
    """
    __tablename__ = 'threat_indicators'
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    type = Column(String)
    value = Column(String)
    confidence = Column(Integer)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    
    @classmethod
    def update_or_create(cls, session, indicator_data):
        """
        Update existing or create new threat indicator
        """
        try:
            existing = session.query(cls).filter_by(
                type=indicator_data['type'], 
                value=indicator_data['value']
            ).first()
            
            if existing:
                for key, value in indicator_data.items():
                    setattr(existing, key, value)
                existing.last_seen = datetime.utcnow()
            else:
                existing = cls(**indicator_data)
                session.add(existing)
            
            session.commit()
            return existing
        except Exception as e:
            session.rollback()
            error_handler.handle_error(
                'ThreatIndicatorUpdate', 
                e, 
                ErrorSeverity.MEDIUM
            )
            return None

# Export key models and managers
__all__ = [
    'Base', 
    'DatabaseManager', 
    'EventLog', 
    'ThreatIndicator'
]
