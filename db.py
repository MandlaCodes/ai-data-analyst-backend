import os
import json
from datetime import datetime
from sqlalchemy import create_engine, Column, String, DateTime, Boolean, Text, Integer 
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from passlib.context import CryptContext

# Password Hashing Context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ---------------------------
# Paths and Engine
# ---------------------------

DB_URL = os.environ.get("DATABASE_URL")
connect_args = {}

if DB_URL:
    print(f"Connecting to production database via DATABASE_URL.")
    if DB_URL.startswith("postgres://") and not "?" in DB_URL:
        DB_URL += "?sslmode=require"
else:
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

# ---------------------------
# Database Models
# ---------------------------

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True) 
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    
    @staticmethod
    def hash_password(password: str) -> str:
        return pwd_context.hash(password)

    def verify_password(self, password: str) -> bool:
        return pwd_context.verify(password, self.password_hash)

class Token(Base):
    __tablename__ = "tokens"
    user_id = Column(Integer, primary_key=True, index=True) 
    token_data = Column(String)

class Settings(Base):
    __tablename__ = "settings"
    user_id = Column(Integer, primary_key=True, index=True) 
    settings_data = Column(String) 

class Dashboard(Base):
    __tablename__ = "dashboards"
    id = Column(String, primary_key=True, index=True, default=lambda: os.urandom(16).hex()) 
    user_id = Column(Integer, index=True) 
    name = Column(String, default="Untitled Dashboard")
    last_accessed = Column(DateTime, default=datetime.utcnow)
    layout_data = Column(Text) 

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(String, primary_key=True, default=lambda: os.urandom(16).hex())
    user_id = Column(Integer, index=True) 
    timestamp = Column(DateTime, default=datetime.utcnow)
    event_type = Column(String) 
    ip_address = Column(String)
    device_info = Column(String)
    is_suspicious = Column(Boolean, default=False)


# Create tables automatically if they don't exist
Base.metadata.create_all(engine)

# ---------------------------
# Helper functions (used by main.py)
# ---------------------------

def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

def create_user_db(db: Session, email: str, password: str):
    user = User(email=email, password_hash=User.hash_password(password))
    db.add(user)
    db.flush()
    return user

def get_user_profile_db(db: Session, user_id: int):
    return db.query(User).filter(User.id == user_id).first()

def get_latest_dashboard_db(db: Session, user_id: int):
    return db.query(Dashboard).filter(Dashboard.user_id == user_id).order_by(Dashboard.last_accessed.desc()).first()

def get_user_settings_db(db: Session, user_id: int):
    settings_rec = db.query(Settings).filter(Settings.user_id == user_id).first()
    if settings_rec and settings_rec.settings_data:
        return json.loads(settings_rec.settings_data)
    return {"theme": "dark", "notifications": True}

def get_audit_logs_db(db: Session, user_id: int):
    return db.query(AuditLog).filter(AuditLog.user_id == user_id).order_by(AuditLog.timestamp.desc()).all()

def get_tokens_metadata_db(db: Session, user_id: int):
    return db.query(Token).filter(Token.user_id == user_id).first()

def create_audit_log(db: Session, user_id, event_type, ip_address="unknown", device_info="unknown", is_suspicious=False):
    log_entry = AuditLog(
        user_id=user_id,
        event_type=event_type,
        ip_address=ip_address,
        device_info=device_info,
        is_suspicious=is_suspicious
    )
    db.add(log_entry)

def get_google_token(db: Session, user_id: int):
    token_rec = db.query(Token).filter(Token.user_id == user_id).first()
    return json.loads(token_rec.token_data) if token_rec and token_rec.token_data else None

def save_google_token(db: Session, user_id: int, token_data: dict):
    token_data_str = json.dumps(token_data)
    token_rec = db.query(Token).filter(Token.user_id == user_id).first()
    if token_rec:
        token_rec.token_data = token_data_str
    else:
        db.add(Token(user_id=user_id, token_data=token_data_str))
    db.commit()