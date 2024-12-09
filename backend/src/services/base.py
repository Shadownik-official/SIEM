from typing import TypeVar, Generic, Type
from sqlalchemy.orm import Session

RepositoryType = TypeVar("RepositoryType")

class BaseService(Generic[RepositoryType]):
    """
    Base service providing common service layer operations.
    """
    def __init__(self, repository: RepositoryType, db_session: Session):
        """
        Initialize the service with a repository and database session.
        
        :param repository: Repository for database operations
        :param db_session: SQLAlchemy database session
        """
        self.repository = repository
        self.session = db_session

    def begin_transaction(self):
        """
        Begin a new database transaction.
        """
        self.session.begin()

    def commit_transaction(self):
        """
        Commit the current database transaction.
        """
        self.session.commit()

    def rollback_transaction(self):
        """
        Rollback the current database transaction.
        """
        self.session.rollback()

    def close_session(self):
        """
        Close the current database session.
        """
        self.session.close()
