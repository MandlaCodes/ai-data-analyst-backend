# db.py
import os
from sqlalchemy import create_engine, Column, Integer, String, Boolean, JSON, TIMESTAMP, text
from sqlalchemy.orm import sessionmaker, Session  # <--- FIX: Added 'Session' import
from sqlalchemy.ext.declarative import declarative_base
from databases import Database
from dotenv import load_dotenv

load_dotenv()

# --- Database Configuration ---

# Use DATABASE_URL from environment variables (e.g., from Render)
DATABASE_URL = os.getenv("DATABASE_URL") 
if not DATABASE_URL:
    # Fallback for local development or if variable is missing
    # Replace with your actual local DB URL if needed
    LOCAL_DB_URL = "postgresql://user:password@localhost/mydb" 
    DATABASE_URL = LOCAL_DB_URL
    print(f"WARNING: Using fallback database URL: {DATABASE_URL}")

# Fix for psycopg2-binary to connect to SSL-enabled Postgres on Render
# Replace 'postgres://' with 'postgresql://' for SQLAlchemy compatibility
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)


engine = create_engine(DATABASE_URL)
# SessionLocal is used by the FastAPI dependency injection system
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
database = Database(DATABASE_URL)

# --- Database Models ---

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    # Add unique user_id for external systems (like Google Auth)
    user_id = Column(String, unique=True, index=True, nullable=True) 

class UserSettings(Base):
    __tablename__ = "user_settings"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, unique=True, index=True) # Matches User.user_id
    google_sheet_integration_token = Column(String, nullable=True)
    ai_model_preference = Column(String, default="default_model")
    
class DataSet(Base):
    __tablename__ = "datasets"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, index=True)
    # Stored as JSON to hold the complete dataset structure
    data = Column(JSON) 
    # Use a timestamp to track the latest saved data
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))

# --- Dependency Function ---

# Dependency to get the DB session for use in FastAPI route functions
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- CRUD Functions (Example for UserSettings - this is where the error occurred) ---

def get_user_settings_db(db: Session, user_id: str): # <--- FIX: Using 'Session' for type hint
    """
    Retrieve user settings from the database.
    
    NOTE: The user_id parameter type changed from 'int' to 'str' 
    to match the User.user_id column type, which is safer for external IDs.
    """
    return db.query(UserSettings).filter(UserSettings.user_id == user_id).first()


