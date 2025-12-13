# db.py
import os
import json
from datetime import datetime
from sqlalchemy import create_engine, Column, String, DateTime, Boolean, Text, Integer 
from sqlalchemy.orm import declarative_base, sessionmaker
from passlib.context import CryptContext

# --- CONFIGURATION & ENGINE ---

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
DB_URL = os.environ.get("DATABASE_URL")
connect_args = {}

if DB_URL:
    # Production PostgreSQL setup
    print(f"Connecting to production database via DATABASE_URL.")
    if DB_URL.startswith("postgres://") and not "?" in DB_URL:
        DB_URL += "?sslmode=require"
else:
    # Local SQLite setup
    print(f"DATABASE_URL not found. Falling back to local SQLite.")
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DB_PATH = os.path.join(BASE_DIR, "tokens.db")
    DB_URL = f"sqlite:///{DB_PATH}"
    connect_args = {"check_same_thread": False} 


engine = create_engine(
    DB_URL,
    connect_args=connect_args,
    pool_pre_ping=True,      
    pool_recycle=3600,        
    pool_size=10,             
    max_overflow=20           
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# --- DATABASE MODELS ---

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True) 
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    # Add other profile fields here (e.g., name)

class Token(Base):
    """Stores third-party integration tokens/data."""
    __tablename__ = "tokens"
    user_id = Column(Integer, primary_key=True, index=True) 
    token_data = Column(String) # JSON string of tokens/status

class Settings(Base):
    """Stores user application settings."""
    __tablename__ = "settings"
    user_id = Column(Integer, primary_key=True, index=True) 
    settings_data = Column(String) 

class Dashboard(Base):
    """Stores individual dashboard sessions, including datasets (for Analytics/Trends)."""
    __tablename__ = "dashboards"
    id = Column(String, primary_key=True, index=True, default=lambda: os.urandom(16).hex()) 
    user_id = Column(Integer, index=True) 
    name = Column(String, default="Primary Session")
    last_accessed = Column(DateTime, default=datetime.utcnow)
    # This column holds the JSON blob of datasets, analysis, and layout
    layout_data = Column(Text) 

class AuditLog(Base):
    """Stores security and login events (for Security page)."""
    __tablename__ = "audit_logs"
    id = Column(String, primary_key=True, default=lambda: os.urandom(16).hex())
    user_id = Column(Integer, index=True) 
    timestamp = Column(DateTime, default=datetime.utcnow)
    event_type = Column(String) 
    ip_address = Column(String)
    device_info = Column(String)
    is_suspicious = Column(Boolean, default=False)


Base.metadata.create_all(engine)

# --- HELPER FUNCTIONS (Used by main.py routes) ---

def get_user_settings_db(db: Session, user_id: int):
    """Retrieves user settings."""
    settings_rec = db.query(Settings).filter(Settings.user_id == user_id).first()
    if settings_rec and settings_rec.settings_data:
        return json.loads(settings_rec.settings_data)
    return {"theme": "dark", "notifications": True} # Default settings

def get_tokens_metadata_db(db: Session, user_id: int):
    """Retrieves integration metadata (e.g., connection status)."""
    token_rec = db.query(Token).filter(Token.user_id == user_id).first()
    if token_rec and token_rec.token_data:
        try:
            return json.loads(token_rec.token_data)
        except json.JSONDecodeError:
            return {"error": "Corrupt token data"}
    return {} # No integrations connected

def get_audit_logs_db(db: Session, user_id: int):
    """Retrieves security logs."""
    logs = db.query(AuditLog).filter(AuditLog.user_id == user_id).order_by(AuditLog.timestamp.desc()).all()
    return [
        {
            "id": log.id,
            "timestamp": log.timestamp.isoformat(),
            "event_type": log.event_type,
            "ip_address": log.ip_address,
            "device_info": log.device_info,
            "is_suspicious": log.is_suspicious
        }
        for log in logs
    ]

def get_latest_dashboard_db(db: Session, user_id: int):
    """Retrieves the single latest dashboard session for a user."""
    return db.query(Dashboard).filter(Dashboard.user_id == user_id).order_by(Dashboard.last_accessed.desc()).first()

def get_user_profile_db(db: Session, user_id: int):
    """Retrieves basic profile information."""
    user = db.query(User).filter(User.id == user_id).first()
    if user:
        # Return a safe dictionary without the password hash
        return {"id": user.id, "email": user.email}
    return None