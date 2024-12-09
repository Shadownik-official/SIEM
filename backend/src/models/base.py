from sqlalchemy import Column, Integer, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func

# Base class for all SQLAlchemy models
Base = declarative_base()

class BaseModel(Base):
    """
    Base model that provides common fields for all database models.
    """
    __abstract__ = True

    id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    def __repr__(self):
        """
        Provide a string representation of the model.
        """
        return f"<{self.__class__.__name__} (id={self.id})>"

    def to_dict(self):
        """
        Convert model to dictionary representation.
        """
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}
