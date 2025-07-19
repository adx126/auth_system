from sqlalchemy import String, Integer, Column
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class DefaultUserModel(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)