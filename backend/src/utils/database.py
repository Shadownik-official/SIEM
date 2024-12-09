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

    def __new__(cls):
        """
        Singleton implementation for database manager.
        """
        if not cls._instance:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, config: SIEMConfig = None):
        """
        Initialize database connection.
        
        :param config: SIEM configuration object
        """
        if self._engine:
            return

        # Use configuration or default connection
        if not config:
            config = SIEMConfig.load_config()

        db_config = config.database
        connection_string = (
            f"postgresql://{db_config['user']}:{db_config['password']}@"
            f"{db_config['host']}:{db_config['port']}/{db_config['name']}"
        )

        # Create engine with connection pooling
        self._engine = create_engine(
            connection_string,
            pool_size=db_config.get('pool_size', 10),
            max_overflow=20,
            pool_timeout=30,
            pool_recycle=1800,  # Recycle connections every 30 minutes
            echo=config.debug  # Enable SQL logging in debug mode
        )

        # Create session factory
        self._SessionLocal = sessionmaker(
            bind=self._engine, 
            autocommit=False, 
            autoflush=False
        )

    def get_engine(self):
        """
        Get SQLAlchemy engine.
        
        :return: SQLAlchemy engine
        """
        if not self._engine:
            raise RuntimeError("Database not initialized. Call __init__ first.")
        return self._engine

    def get_session(self) -> Session:
        """
        Create a new database session.
        
        :return: SQLAlchemy session
        """
        if not self._SessionLocal:
            raise RuntimeError("Database not initialized. Call __init__ first.")
        return self._SessionLocal()

    def get_session_generator(self) -> Generator[Session, None, None]:
        """
        Session generator for dependency injection.
        
        :yield: SQLAlchemy session
        """
        session = self.get_session()
        try:
            yield session
        finally:
            session.close()

    def create_tables(self):
        """
        Create all defined database tables.
        """
        from ..models.base import Base
        Base.metadata.create_all(bind=self._engine)

    def drop_tables(self):
        """
        Drop all database tables (use with caution).
        """
        from ..models.base import Base
        Base.metadata.drop_all(bind=self._engine)

# Global database manager instance
db_manager = DatabaseManager()
