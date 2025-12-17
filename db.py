
import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Text, Boolean, UniqueConstraint
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Mapped, mapped_column, Session
import uuid 

# --- Configuration ---
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./test.db") 

# For Bcrypt hashing
pwd_context = CryptContext(
    schemes=["bcrypt"], 
    deprecated="auto",
    # 🚨 CRITICAL FIX: Explicitly set the hash property to ensure proper verification.
    bcrypt__ident="2b" 
)

# --- SQLAlchemy Setup ---
# Set pool_pre_ping to handle idle connection issues in production
engine = create_engine(
    DATABASE_URL, 
    pool_pre_ping=True, 
    # Only for SQLite (not needed for Postgres)
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
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    dashboards = relationship("Dashboard", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")
    settings = relationship("Settings", back_populates="user", uselist=False)
    tokens = relationship("Token", back_populates="user")
    state_tokens = relationship("StateToken", back_populates="user")


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
    layout_data: Mapped[str] = mapped_column(Text) # JSON string for layout and data
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_accessed: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

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
    service: Mapped[str] = mapped_column(String, index=True) # e.g., 'google_sheets'
    access_token: Mapped[str] = mapped_column(Text)
    refresh_token: Mapped[str] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="tokens")
    
    __table_args__ = (
        UniqueConstraint('user_id', 'service', name='uq_user_service'),
    )


# --- NEW: StateToken Model for OAuth State Management ---
class StateToken(Base):
    """
    Model for temporarily storing OAuth state information to securely map 
    the unauthenticated callback to the initiating user.
    """
    __tablename__ = "state_tokens"
    
    # The unique UUID sent to the OAuth provider (Google)
    state_uuid: Mapped[str] = mapped_column(String, primary_key=True)
    
    # The user who initiated the request
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    
    # The frontend path to redirect the user back to (e.g., "/dashboard/integrations")
    return_path: Mapped[str] = mapped_column(String)
    
    # Add an expiration time for security
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    # Expires in 10 minutes
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc) + timedelta(minutes=10)) 

    user = relationship("User", back_populates="state_tokens")


# --- Helper Functions (DB interactions) ---

def create_user_db(db: Session, email: str, password: str) -> User:
    hashed_password = pwd_context.hash(password)
    
    # 🚨 TEMPORARY DIAGNOSTIC PRINT 🚨
    print(f"DIAGNOSTIC: Signup Hash Created: '{hashed_password}'")
    # 🚨 END TEMPORARY DIAGNOSTIC PRINT 🚨

    db_user = User(email=email, hashed_password=hashed_password)
    db.add(db_user)
    # Note: caller (main.py) must commit
    return db_user

def get_user_by_email(db: Session, email: str) -> Optional[User]:
    return db.query(User).filter(User.email == email).first()

def get_user_profile_db(db: Session, user_id: int) -> Optional[User]:
    return db.query(User).filter(User.id == user_id).first()

def create_audit_log(db: Session, user_id: int, event_type: str, ip_address: Optional[str] = None):
    db_log = AuditLog(user_id=user_id, event_type=event_type, ip_address=ip_address)
    db.add(db_log)
    # Note: caller (main.py) must commit

def get_latest_dashboard_db(db: Session, user_id: int) -> Optional[Dashboard]:
    return db.query(Dashboard).filter(Dashboard.user_id == user_id).order_by(Dashboard.last_accessed.desc()).first()

def get_user_settings_db(db: Session, user_id: int) -> Optional[Settings]:
    return db.query(Settings).filter(Settings.user_id == user_id).first()

def get_audit_logs_db(db: Session, user_id: int, limit: int = 10) -> List[AuditLog]:
    return db.query(AuditLog).filter(AuditLog.user_id == user_id).order_by(AuditLog.timestamp.desc()).limit(limit).all()

def get_tokens_metadata_db(db: Session, user_id: int) -> List[Token]:
    return db.query(Token).filter(Token.user_id == user_id).all()

def save_google_token(db: Session, user_id: int, token_data: dict):
    """Saves or updates the Google Sheets OAuth token for the user."""
    service = 'google_sheets'
    existing_token = db.query(Token).filter(Token.user_id == user_id, Token.service == service).first()
    
    expires_at = None
    if token_data.get('expires_in'):
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=token_data['expires_in'])

    if existing_token:
        # Update existing token
        existing_token.access_token = token_data['access_token']
        # Only update refresh token if a new one is provided (Google often omits it after first exchange)
        if token_data.get('refresh_token'):
            existing_token.refresh_token = token_data['refresh_token']
        existing_token.expires_at = expires_at
        existing_token.created_at = datetime.now(timezone.utc)
    else:
        # Create new token
        new_token = Token(
            user_id=user_id,
            service=service,
            access_token=token_data['access_token'],
            refresh_token=token_data.get('refresh_token'),
            expires_at=expires_at
        )
        db.add(new_token)
    # Note: caller (main.py) must commit

def get_google_token(db: Session, user_id: int) -> Optional[Token]:
    """Retrieves the Google Sheets token for the user."""
    return db.query(Token).filter(Token.user_id == user_id, Token.service == 'google_sheets').first()


# --- NEW HELPER FUNCTIONS FOR STATE MANAGEMENT (Crucial for OAuth Fix) ---

def save_state_to_db(db: Session, user_id: int, state_uuid: str, return_path: str):
    """Saves the OAuth state, user_id, and return_path to the StateToken table."""
    # Optional: Delete old state for this specific user if it exists
    # db.query(StateToken).filter(StateToken.user_id == user_id).delete()
    
    new_state = StateToken(
        state_uuid=state_uuid,
        user_id=user_id,
        return_path=return_path
    )
    db.add(new_state)
    # Note: db.commit() is done in main.py

def get_user_id_from_state_db(db: Session, state_uuid: str) -> Optional[dict]:
    """
    Retrieves the user_id and return_path associated with the state_uuid, 
    and checks for expiration.
    """
    state_record = db.query(StateToken).filter(StateToken.state_uuid == state_uuid).first()
    
    if not state_record:
        return None

    # Check for expiration (highly recommended)
    if state_record.expires_at < datetime.now(timezone.utc):
        db.delete(state_record)
        # We commit here because this function is called inside the unauthenticated callback
        # and we need to clean up expired tokens immediately.
        db.commit() 
        return None

    return {
        "user_id": state_record.user_id,
        "return_path": state_record.return_path
    }

def delete_state_from_db(db: Session, state_uuid: str):
    """Cleans up the state record after a successful or failed callback."""
    db.query(StateToken).filter(StateToken.state_uuid == state_uuid).delete()
    # Note: db.commit() is done in main.py

# -------------------- CRITICAL PASSWORD VERIFICATION HELPER --------------------

def verify_password_helper(plain_password: str, hashed_password: str) -> bool:
    """
    Explicitly verifies a plain password against a hashed one using the global CryptContext.
    This resolves the issue where verification fails due to ORM session context/threading.
    """
    return pwd_context.verify(plain_password, hashed_password)