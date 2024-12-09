from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional

class BaseSchema(BaseModel):
    """
    Base Pydantic schema with common fields.
    """
    id: Optional[int] = Field(None, description="Unique identifier")
    created_at: Optional[datetime] = Field(None, description="Creation timestamp")
    updated_at: Optional[datetime] = Field(None, description="Last update timestamp")

    class Config:
        """
        Pydantic configuration for the schema.
        """
        orm_mode = True  # Allows reading data from ORM models
        json_encoders = {
            datetime: lambda dt: dt.isoformat()  # Custom JSON serialization for datetime
        }
        allow_population_by_field_name = True  # Allow setting values by field names
        validate_assignment = True  # Validate data on assignment
