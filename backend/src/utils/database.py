from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.declarative import declarative_base
from typing import Generator

from ..core.config import SIEMConfig

class DatabaseManager:
    """
    Centralized database connection and session management.
    """
    _instance = None
    _engine = None
    _SessionLocal = None

    def __new__(cls, config: SIEMConfig = None):
        """
        Singleton implementation for database manager.
        """
        if not cls._instance:
            cls._instance = super().__new__(cls)
            cls._instance._initialize(config)
        return cls._instance

    def _initialize(self, config: SIEMConfig = None):
        """
        Initialize database connection.
        
        :param config: SIEM configuration object
        """
        if self._engine:
            return

        # Use configuration or default connection
        if not config:
            config = SIEMConfig.load_config()

        # Get connection string from configuration
        connection_string = config.get_database_connection_string()

        # Create engine with connection pooling
        self._engine = create_engine(
            connection_string,
            pool_size=config.database.get('pool_size', 10),
            max_overflow=20,
            pool_timeout=30,
            pool_recycle=1800,  # Recycle connections every 30 minutes
            echo=config.debug  # Enable SQL logging in debug mode
        )

        # Create session factory
        self._SessionLocal = sessionmaker(
            autocommit=False, 
            autoflush=False, 
            bind=self._engine
        )

    def get_session(self) -> Session:
        """
        Get a database session.
        
        :return: SQLAlchemy Session
        """
        if not self._SessionLocal:
            raise RuntimeError("Database not initialized")
        return self._SessionLocal()

    def create_tables(self):
        """
        Create all database tables.
        """
        from ..models import Base  # Import Base model dynamically
        Base.metadata.create_all(bind=self._engine)

    def drop_tables(self):
        """
        Drop all database tables.
        """
        from ..models import Base  # Import Base model dynamically
        Base.metadata.drop_all(bind=self._engine)

    def start(self):
        """
        Start database operations.
        """
        # Create tables if they don't exist
        self.create_tables()

    def shutdown(self):
        """
        Shutdown database connection.
        """
        if self._engine:
            self._engine.dispose()

# Global database manager instance
db_manager = DatabaseManager()
