# db.py

import os
from sqlalchemy import create_engine, Column, Integer, String, Boolean, JSON, TIMESTAMP, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.declarative import declarative_base
from databases import Database # For async database connections
from dotenv import load_dotenv

load_dotenv()

# --- Database Configuration ---

DATABASE_URL = os.getenv("DATABASE_URL") 
if not DATABASE_URL:
    # Use a secure default for local testing
    LOCAL_DB_URL = "postgresql://postgres:password@localhost/ai_data_analyst" 
    DATABASE_URL = LOCAL_DB_URL
    print(f"WARNING: Using fallback local database URL: {DATABASE_URL}")

# Fix for compatibility with psycopg2 when using 'postgres://' scheme
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)


engine = create_engine(DATABASE_URL)
# SessionLocal is the session factory for synchronous ORM operations
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
# database is the connection object for async databases operations (used by the 'databases' library)
database = Database(DATABASE_URL) 

# --- Database Models ---

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    # user_id is crucial for identifying users across systems/sessions (used in JWT payload)
    user_id = Column(String, unique=True, index=True, nullable=True) 

class Settings(Base): # Renamed from UserSettings to match main.py import
    __tablename__ = "settings"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, unique=True, index=True) # Assuming integer ID here
    settings_data = Column(JSON, nullable=True) 
    google_sheet_integration_token = Column(String, nullable=True)
    ai_model_preference = Column(String, default="default_model")
    
class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    timestamp = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))
    action = Column(String, nullable=False)
    details = Column(JSON, nullable=True) 

class Dashboard(Base):
    __tablename__ = "dashboards"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    layout_data = Column(JSON) 
    last_accessed = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))

class Token(Base):
    __tablename__ = "tokens"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    service_name = Column(String, index=True, nullable=False)
    access_token = Column(String, nullable=True)
    refresh_token = Column(String, nullable=True)
    expires_at = Column(TIMESTAMP(timezone=True), nullable=True)


# --- Dependency Function ---

def get_db():
    """Dependency for providing a synchronous SQLAlchemy database session to FastAPI routes."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- CRUD Functions (Used by main.py) ---

# NOTE: The CRUD functions must match the arguments and return types expected in main.py.

def get_user_settings_db(db: Session, user_id: int):
    """Retrieve user settings."""
    # Assuming user_id is an integer, matching the model definition
    return db.query(Settings).filter(Settings.user_id == user_id).first()

def get_tokens_metadata_db(db: Session, user_id: int):
    """Retrieve metadata about user tokens/integrations."""
    return db.query(Token).filter(Token.user_id == user_id).all()

def get_audit_logs_db(db: Session, user_id: int):
    """Retrieve audit logs for the user."""
    return db.query(AuditLog).filter(AuditLog.user_id == user_id).order_by(AuditLog.timestamp.desc()).all()

def get_latest_dashboard_db(db: Session, user_id: int):
    """Retrieve the latest saved dashboard."""
    return db.query(Dashboard).filter(Dashboard.user_id == user_id).order_by(Dashboard.last_accessed.desc()).first()

def get_user_profile_db(db: Session, user_id: int):
    """Retrieve the user profile."""
    return db.query(User).filter(User.id == user_id).first()