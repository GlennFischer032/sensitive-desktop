from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import DeclarativeMeta


Base: DeclarativeMeta = declarative_base()


class APIModel(BaseModel):
    """Base model for API responses with common configuration."""

    model_config = ConfigDict(from_attributes=True)
