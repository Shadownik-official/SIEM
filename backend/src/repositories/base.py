from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import TypeVar, Generic, Type, List, Optional

ModelType = TypeVar("ModelType")

class BaseRepository(Generic[ModelType]):
    """
    Base repository providing generic CRUD operations.
    """
    def __init__(self, db_session: Session, model: Type[ModelType]):
        """
        Initialize the repository with a database session and model.
        
        :param db_session: SQLAlchemy database session
        :param model: SQLAlchemy model class
        """
        self.session = db_session
        self.model = model

    def get(self, id: int) -> Optional[ModelType]:
        """
        Retrieve an item by its ID.
        
        :param id: Primary key of the item
        :return: Item or None if not found
        """
        return self.session.query(self.model).get(id)

    def get_all(self, skip: int = 0, limit: int = 100) -> List[ModelType]:
        """
        Retrieve multiple items with optional pagination.
        
        :param skip: Number of items to skip
        :param limit: Maximum number of items to return
        :return: List of items
        """
        return self.session.query(self.model).offset(skip).limit(limit).all()

    def create(self, obj: ModelType) -> ModelType:
        """
        Create a new item.
        
        :param obj: Item to create
        :return: Created item
        """
        self.session.add(obj)
        self.session.commit()
        self.session.refresh(obj)
        return obj

    def update(self, obj: ModelType) -> ModelType:
        """
        Update an existing item.
        
        :param obj: Item to update
        :return: Updated item
        """
        self.session.merge(obj)
        self.session.commit()
        return obj

    def delete(self, id: int) -> bool:
        """
        Delete an item by its ID.
        
        :param id: Primary key of the item to delete
        :return: True if deletion was successful
        """
        obj = self.get(id)
        if obj:
            self.session.delete(obj)
            self.session.commit()
            return True
        return False

    def count(self) -> int:
        """
        Count total number of items.
        
        :return: Total number of items
        """
        return self.session.query(func.count(self.model.id)).scalar()
