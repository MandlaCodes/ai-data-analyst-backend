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
# Paths and Engine (CRITICAL UPDATE) 🚀
# ---------------------------

# Use the DATABASE_URL environment variable for production (Render, etc.)
# Fallback to local SQLite for local development
DB_URL = os.environ.get("DATABASE_URL")

# Connect Arguments
connect_args = {}

if DB_URL:
    # Production: Use the provided URL (e.g., PostgreSQL)
    print(f"Connecting to production database via DATABASE_URL.")
    # For Render/Postgres, we often need to ensure the dialect is correctly specified, 
    # but create_engine usually handles it if the URL starts with 'postgresql://'
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
# Database Models
# ---------------------------

# 0. User Table (CRITICAL ADDITION)
class User(Base):
    """Stores user accounts for authentication."""
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True) 
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    
    @staticmethod
    def hash_password(password: str) -> str:
        # Hashing function used in main.py
        return pwd_context.hash(password)

    def verify_password(self, password: str) -> bool:
        # Verification function used in main.py
        return pwd_context.verify(password, self.password_hash)

# 1. Token Table (Existing)
class Token(Base):
    __tablename__ = "tokens"
    user_id = Column(String, primary_key=True, index=True)
    token_data = Column(String)

# 2. Settings Table (New)
class Settings(Base):
    """Stores the general application configuration (from Settings.jsx) for a user."""
    __tablename__ = "settings"
    user_id = Column(String, primary_key=True, index=True)
    settings_data = Column(String) # Stores the JSON payload of all settings

# 3. Dashboard Table (New)
class Dashboard(Base):
    """Stores individual dashboard layouts/sessions for a user."""
    __tablename__ = "dashboards"
    # Use Integer for primary key if possible, but keeping String as in original for now
    id = Column(String, primary_key=True, index=True, default=lambda: os.urandom(16).hex()) 
    user_id = Column(String, index=True)
    name = Column(String, default="Untitled Dashboard")
    last_accessed = Column(DateTime, default=datetime.utcnow)
    layout_data = Column(Text) # JSON structure of the dashboard widgets/layout

# 4. AuditLog Table (New)
class AuditLog(Base):
    """Stores security and login events for the user's security page."""
    __tablename__ = "audit_logs"
    id = Column(String, primary_key=True, default=lambda: os.urandom(16).hex())
    user_id = Column(String, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    event_type = Column(String) # e.g., 'LOGIN_SUCCESS', 'PASSWORD_CHANGE'
    ip_address = Column(String)
    device_info = Column(String)
    is_suspicious = Column(Boolean, default=False)


# Create tables automatically if they don't exist
Base.metadata.create_all(engine)

# ---------------------------
# Helper functions (Updated and Extended)
# ---------------------------

# --- Token Helpers (Existing) ---
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
    
# --- New Audit Helper ---
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