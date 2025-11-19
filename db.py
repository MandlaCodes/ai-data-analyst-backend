from sqlalchemy import create_engine, Column, String, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# SQLite DB
DATABASE_URL = "sqlite:///tokens.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

# Token model
class Token(Base):
    __tablename__ = "tokens"
    user_id = Column(String, primary_key=True, index=True)
    token_data = Column(Text)  # Store JSON as text

# Create table
Base.metadata.create_all(bind=engine)
