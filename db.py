import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Text, Boolean, UniqueConstraint
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Mapped, mapped_column, Session
import uuid 

# --- Configuration ---
# Hardcoded Production URL with SQLAlchemy 2.0 fix (postgres -> postgresql)
DATABASE_URL = "postgresql://app1_db_njfw_user:78dlubKbwFhisDuvu17UjbBs4npC4dZC@dpg-d4pcq50gjchc73ao5ac0-a/app1_db_njfw"

pwd_context = CryptContext(
    schemes=["bcrypt"], 
    deprecated="auto",
    bcrypt__ident="2b" 
)

# --- SQLAlchemy Setup ---
engine = create_engine(
    DATABASE_URL, 
    pool_pre_ping=True, # Keeps production connection alive
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- Models ---

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String, unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String)
    
    first_name: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    last_name: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    organization: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    industry: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    
    # Subscription tracking
    is_active: Mapped[bool] = mapped_column(Boolean, default=False)
    subscription_id: Mapped[Optional[str]] = mapped_column(String, nullable=True) 
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    dashboards = relationship("Dashboard", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")
    settings = relationship("Settings", back_populates="user", uselist=False, cascade="all, delete-orphan")
    tokens = relationship("Token", back_populates="user", cascade="all, delete-orphan")
    state_tokens = relationship("StateToken", back_populates="user", cascade="all, delete-orphan")

# ... (Rest of your AuditLog, Dashboard, Settings, Token, StateToken models stay exactly the same) ...

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
    __table_args__ = (UniqueConstraint('user_id', 'service', name='uq_user_service'),)

class StateToken(Base):
    __tablename__ = "state_tokens"
    state_uuid: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    return_path: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc) + timedelta(minutes=10)) 
    user = relationship("User", back_populates="state_tokens")

# --- Helper Functions (Keep your existing helpers here) ---
def create_user_db(db: Session, email: str, password: str, **kwargs) -> User:
    hashed_password = pwd_context.hash(password)
    db_user = User(email=email, hashed_password=hashed_password, **kwargs)
    db.add(db_user)
    db.commit() # Added commit to ensure user is saved before checkout
    db.refresh(db_user)
    return db_user

def get_user_by_email(db: Session, email: str) -> Optional[User]:
    return db.query(User).filter(User.email == email).first()

def activate_user_subscription(db: Session, email: str, subscription_id: Optional[str] = None):
    user = db.query(User).filter(User.email == email).first()
    if user:
        user.is_active = True
        if subscription_id:
            user.subscription_id = subscription_id
        db.commit()
        return user
    return None