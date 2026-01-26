import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Text, Boolean, UniqueConstraint
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Mapped, mapped_column, Session
import uuid 

# --- Configuration ---
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./test.db") 

pwd_context = CryptContext(
    schemes=["bcrypt"], 
    deprecated="auto",
    bcrypt__ident="2b" 
)

# --- SQLAlchemy Setup ---
engine = create_engine(
    DATABASE_URL, 
    pool_pre_ping=True, 
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {} 
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- Models ---

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String, unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String)
    
    # --- Profile Fields ---
    first_name: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    last_name: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    organization: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    industry: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    
    # --- Billing & Access Fields ---
    is_trial_active: Mapped[bool] = mapped_column(Boolean, default=False)
    polar_customer_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    dashboards = relationship("Dashboard", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")
    settings = relationship("Settings", back_populates="user", uselist=False, cascade="all, delete-orphan")
    tokens = relationship("Token", back_populates="user", cascade="all, delete-orphan")
    state_tokens = relationship("StateToken", back_populates="user", cascade="all, delete-orphan")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    event_type: Mapped[str] = mapped_column(String, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    ip_address: Mapped[str] = mapped_column(String, nullable=True)

    user = relationship("User", back_populates="audit_logs")

class Dashboard(Base):
    __tablename__ = "dashboards"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    name: Mapped[str] = mapped_column(String)
    layout_data: Mapped[str] = mapped_column(Text) 
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_accessed: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="dashboards")

class Settings(Base):
    __tablename__ = "settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), unique=True)
    theme: Mapped[str] = mapped_column(String, default="light")
    data_source_config: Mapped[str] = mapped_column(Text, default="{}")

    user = relationship("User", back_populates="settings")

class Token(Base):
    __tablename__ = "tokens"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    service: Mapped[str] = mapped_column(String, index=True) 
    access_token: Mapped[str] = mapped_column(Text)
    refresh_token: Mapped[str] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="tokens")
    
    __table_args__ = (
        UniqueConstraint('user_id', 'service', name='uq_user_service'),
    )


class StateToken(Base):
    __tablename__ = "state_tokens"
    state_uuid: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    return_path: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc) + timedelta(minutes=10)) 

    user = relationship("User", back_populates="state_tokens")


# --- Helper Functions ---

def create_user_db(db: Session, email: str, password: str, **kwargs) -> User:
    hashed_password = pwd_context.hash(password)
    db_user = User(email=email, hashed_password=hashed_password, **kwargs)
    db.add(db_user)
    return db_user

def get_user_by_email(db: Session, email: str) -> Optional[User]:
    return db.query(User).filter(User.email == email).first()

def get_user_profile_db(db: Session, user_id: int) -> Optional[User]:
    return db.query(User).filter(User.id == user_id).first()

def create_audit_log(db: Session, user_id: int, event_type: str, ip_address: Optional[str] = None):
    db_log = AuditLog(user_id=user_id, event_type=event_type, ip_address=ip_address)
    db.add(db_log)

def activate_user_trial_db(db: Session, user_id: int, customer_id: str):
    user = db.query(User).filter(User.id == user_id).first()
    if user:
        user.is_trial_active = True
        user.polar_customer_id = customer_id
        db.commit()
        return True
    return False

def save_google_token(db: Session, user_id: int, token_data: dict):
    service = 'google_sheets'
    existing_token = db.query(Token).filter(Token.user_id == user_id, Token.service == service).first()
    
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=token_data['expires_in']) if token_data.get('expires_in') else None

    if existing_token:
        existing_token.access_token = token_data['access_token']
        if token_data.get('refresh_token'):
            existing_token.refresh_token = token_data['refresh_token']
        existing_token.expires_at = expires_at
        existing_token.created_at = now
    else:
        new_token = Token(
            user_id=user_id,
            service=service,
            access_token=token_data['access_token'],
            refresh_token=token_data.get('refresh_token'),
            expires_at=expires_at
        )
        db.add(new_token)

def get_user_id_from_state_db(db: Session, state_uuid: str) -> Optional[dict]:
    state_record = db.query(StateToken).filter(StateToken.state_uuid == state_uuid).first()
    if not state_record:
        return None
    
    expiry = state_record.expires_at
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
        
    if expiry < datetime.now(timezone.utc):
        db.delete(state_record)
        db.commit() 
        return None
        
    return {
        "user_id": state_record.user_id,
        "return_path": state_record.return_path
    }

def delete_state_from_db(db: Session, state_uuid: str):
    db.query(StateToken).filter(StateToken.state_uuid == state_uuid).delete()

def verify_password_helper(plain_password: str, hashed_password: str) -> bool:
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        return False

def get_google_token(db: Session, user_id: int) -> Optional[Token]:
    return db.query(Token).filter(Token.user_id == user_id, Token.service == 'google_sheets').first()

def save_state_to_db(db: Session, user_id: int, state_uuid: str, return_path: str):
    db.add(StateToken(state_uuid=state_uuid, user_id=user_id, return_path=return_path))

def get_latest_dashboard_db(db: Session, user_id: int) -> Optional[Dashboard]:
    return db.query(Dashboard).filter(Dashboard.user_id == user_id).order_by(Dashboard.last_accessed.desc()).first()

def get_user_settings_db(db: Session, user_id: int) -> Optional[Settings]:
    return db.query(Settings).filter(Settings.user_id == user_id).first()

def get_audit_logs_db(db: Session, user_id: int, limit: int = 10) -> List[AuditLog]:
    return db.query(AuditLog).filter(AuditLog.user_id == user_id).order_by(AuditLog.timestamp.desc()).limit(limit).all()

def get_tokens_metadata_db(db: Session, user_id: int) -> List[Token]:
    return db.query(Token).filter(Token.user_id == user_id).all()
def deactivate_user_subscription_db(db: Session, user_id: int):
    user = db.query(User).filter(User.id == user_id).first()
    if user:
        user.is_trial_active = False  # Or your specific subscription boolean
        # user.polar_customer_id = None # Optional: keep for history or clear it
        db.commit()
    return user
