# src/db.py
import os
import json
from datetime import datetime
from sqlalchemy import create_engine, Column, String, DateTime, Boolean, Text, Integer 
from sqlalchemy.orm import declarative_base, sessionmaker
from passlib.context import CryptContext

# Password Hashing Context (Ensure passlib[bcrypt] is installed)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ---------------------------
# Paths and Engine 
# ---------------------------

# Use the DATABASE_URL environment variable for production (Render, etc.)
# Fallback to local SQLite for local development
DB_URL = os.environ.get("DATABASE_URL")

# Connect Arguments
connect_args = {}

if DB_URL:
    # Production: Use the provided URL (e.g., PostgreSQL)
    print(f"Connecting to production database via DATABASE_URL.")
    # Standard fix for Render/external PostgreSQL connections
    if DB_URL.startswith("postgres://") and not "?" in DB_URL:
        DB_URL += "?sslmode=require"
    pass
else:
    # Development/Local: Use SQLite
    print(f"DATABASE_URL not found. Falling back to local SQLite.")
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DB_PATH = os.path.join(BASE_DIR, "tokens.db")
    DB_URL = f"sqlite:///{DB_PATH}"
    # Required for SQLite + FastAPI to handle threading issues
    connect_args = {"check_same_thread": False} 


engine = create_engine(
    DB_URL,
    connect_args=connect_args
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# ---------------------------
# Database Models (FIXED user_id types to Integer)
# ---------------------------

# 0. User Table
class User(Base):
    """Stores user accounts for authentication."""
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True) 
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    
    @staticmethod
    def hash_password(password: str) -> str:
        return pwd_context.hash(password)

    def verify_password(self, password: str) -> bool:
        return pwd_context.verify(password, self.password_hash)

# 1. Token Table
class Token(Base):
    __tablename__ = "tokens"
    # FIX: Changed to Integer to match User.id
    user_id = Column(Integer, primary_key=True, index=True) 
    token_data = Column(String)

# 2. Settings Table
class Settings(Base):
    """Stores the general application configuration (from Settings.jsx) for a user."""
    __tablename__ = "settings"
    # FIX: Changed to Integer to match User.id
    user_id = Column(Integer, primary_key=True, index=True) 
    settings_data = Column(String) 

# 3. Dashboard Table
class Dashboard(Base):
    """Stores individual dashboard layouts/sessions for a user."""
    __tablename__ = "dashboards"
    # Keeping id as a UUID-like String is fine.
    id = Column(String, primary_key=True, index=True, default=lambda: os.urandom(16).hex()) 
    # FIX: Changed to Integer to match User.id
    user_id = Column(Integer, index=True) 
    name = Column(String, default="Untitled Dashboard")
    last_accessed = Column(DateTime, default=datetime.utcnow)
    layout_data = Column(Text) 

# 4. AuditLog Table
class AuditLog(Base):
    """Stores security and login events for the user's security page."""
    __tablename__ = "audit_logs"
    id = Column(String, primary_key=True, default=lambda: os.urandom(16).hex())
    # FIX: Changed to Integer to match User.id
    user_id = Column(Integer, index=True) 
    timestamp = Column(DateTime, default=datetime.utcnow)
    event_type = Column(String) 
    ip_address = Column(String)
    device_info = Column(String)
    is_suspicious = Column(Boolean, default=False)


# Create tables automatically if they don't exist
Base.metadata.create_all(engine)

# ---------------------------
# Helper functions 
# ---------------------------

def create_default_dashboard(user_id: int, dashboard_name="Getting Started Dashboard"):
    """Creates a basic dashboard entry for a new user."""
    session = SessionLocal()
    try:
        default_layout_data = json.dumps({
            "widgets": [],
            "message": "Welcome! Click here to import your first dataset."
        })
        
        dashboard_entry = Dashboard(
            user_id=user_id, 
            name=dashboard_name,
            layout_data=default_layout_data,
            last_accessed=datetime.utcnow()
        )
        
        session.add(dashboard_entry)
        session.commit()
        return True
    except Exception as e:
        session.rollback()
        print(f"Error creating default dashboard for user {user_id}: {e}")
        return False
    finally:
        session.close()

def save_token(user_id, token_data):
    session = SessionLocal()
    try:
        token_json = json.dumps(token_data)
        token = session.query(Token).filter(Token.user_id == user_id).first()
        if token:
            token.token_data = token_json
        else:
            token = Token(user_id=user_id, token_data=token_json)
            session.add(token)
        session.commit()
    except Exception as e:
        session.rollback()
        print(f"Error saving token: {e}")
    finally:
        session.close()

def get_token(user_id):
    session = SessionLocal()
    try:
        token = session.query(Token).filter(Token.user_id == user_id).first()
        if token:
            return json.loads(token.token_data)
        return None
    finally:
        session.close()

def delete_token(user_id):
    session = SessionLocal()
    try:
        token = session.query(Token).filter(Token.user_id == user_id).first()
        if token:
            session.delete(token)
            session.commit()
    except Exception as e:
        session.rollback()
        print(f"Error deleting token: {e}")
    finally:
        session.close()
    
def create_audit_log(user_id, event_type, ip_address="unknown", device_info="unknown", is_suspicious=False):
    """Creates a new log entry (e.g., for login or password change)."""
    session = SessionLocal()
    try:
        log_entry = AuditLog(
            user_id=user_id,
            event_type=event_type,
            ip_address=ip_address,
            device_info=device_info,
            is_suspicious=is_suspicious
        )
        session.add(log_entry)
        session.commit()
    except Exception as e:
        session.rollback()
        print(f"Error creating audit log: {e}")
    finally:
        session.close()