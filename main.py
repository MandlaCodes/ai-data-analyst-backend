# main.py

import os
import json
from datetime import datetime
from typing import Annotated

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleWARE
from sqlalchemy.orm import Session
from jose import jwt, JWTError

# --- IMPORT ALL NECESSARY OBJECTS FROM db.py ---
from db import (
    User,
    AuditLog, 
    Dashboard,  
    Settings,   
    Token,      
    SessionLocal,
    # === ADD THESE IMPORTS FOR TABLE CREATION ===
    Base,       
    engine,
    # ============================================
    get_user_settings_db, 
    get_tokens_metadata_db, 
    get_audit_logs_db,
    get_latest_dashboard_db,
    get_user_profile_db
) 

# --- CONFIGURATION ---
SECRET_KEY = os.environ.get("SECRET_KEY", "your-default-dev-secret")
ALGORITHM = "HS256"

# --- APP & DEPENDENCIES ---
app = FastAPI(title="AI Data Analyst Backend")

origins = ["http://localhost:3000"] 
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================================================================
# === CRITICAL FIX: DATABASE INITIALIZATION ON STARTUP ===
# =========================================================================

@app.on_event("startup")
def on_startup():
    """Create database tables if they do not exist."""
    print("Attempting to create database tables...")
    try:
        # Calls the function to create tables defined in Base
        Base.metadata.create_all(bind=engine)
        print("Database initialization successful.")
    except Exception as e:
        print(f"Database initialization FAILED: {e}")
        # In a real app, you might crash here or log the error severely

# =========================================================================

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

DBSession = Annotated[Session, Depends(get_db)]
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Dependency to validate token and get authenticated user ID
async def get_current_user_id(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id_str: str = payload.get("sub")
        if user_id_str is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
        
    # FIX: Ensure we handle the user_id type correctly
    # If your AuthUserID expects an int, ensure the user_id_str is numeric before converting
    try:
        return int(user_id_str) 
    except ValueError:
        raise credentials_exception

AuthUserID = Annotated[int, Depends(get_current_user_id)]

# =========================================================================
# 0. CORE USER/AUTH ROUTES (Essential for profile data)
# =========================================================================

# NOTE: The LOGIN/TOKEN route is omitted, but assumed to exist and generate the JWT.

# Loads data for the Profile page and general user context (e.g., Sidebar)
@app.get("/api/user/profile", status_code=status.HTTP_200_OK)
async def get_user_profile(auth_user_id: AuthUserID, db: DBSession):
    """Loads authenticated user profile data (for Profile.jsx)."""
    # Assuming get_user_profile_db is implemented
    profile = get_user_profile_db(db, auth_user_id)
    if not profile:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    return profile


# =========================================================================
# 1. ANALYTICS / TRENDS ROUTES (Uses 'dashboards' table)
# =========================================================================

# Saves the entire working session (for Analytics.jsx)
@app.post("/api/datasets/save", status_code=status.HTTP_200_OK)
async def save_datasets(auth_user_id: AuthUserID, db: DBSession, payload: dict):
    """Saves the user's active session data (datasets, analysis) to the dashboards table."""
    datasets = payload.get("datasets")
    if not datasets:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing 'datasets' array.")

    try:
        datasets_json = json.dumps(datasets)
        # Using the standard SQLAlchemy integer ID for querying
        dashboard = db.query(Dashboard).filter(Dashboard.user_id == auth_user_id).first() 

        if dashboard:
            dashboard.layout_data = datasets_json
            dashboard.last_accessed = datetime.utcnow() 
        else:
            new_dashboard = Dashboard(
                user_id=auth_user_id,
                layout_data=datasets_json,
                last_accessed=datetime.utcnow()
            )
            db.add(new_dashboard)

        db.commit()
        return {"message": "Data saved successfully to your account."}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to save data. {str(e)}")

# Loads the active session (for Analytics.jsx and Trends.jsx initial data)
@app.get("/api/datasets/latest", status_code=status.HTTP_200_OK)
async def load_latest_datasets(auth_user_id: AuthUserID, db: DBSession):
    """Loads the user's latest dashboard session data."""
    dashboard = get_latest_dashboard_db(db, auth_user_id)

    if not dashboard or not dashboard.layout_data:
        return [] 
    
    try:
        # Analytics.jsx should request this to load the datasets
        return json.loads(dashboard.layout_data)
    except json.JSONDecodeError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Corrupt dashboard data found.")


# =========================================================================
# 2. SETTINGS ROUTES (Uses 'settings' table)
# =========================================================================

# Loads settings (for Settings.jsx)
@app.get("/api/settings", status_code=status.HTTP_200_OK)
async def fetch_settings(auth_user_id: AuthUserID, db: DBSession):
    return get_user_settings_db(db, auth_user_id)

# Saves settings (for Settings.jsx)
@app.post("/api/settings/save", status_code=status.HTTP_200_OK)
async def save_settings(auth_user_id: AuthUserID, db: DBSession, settings_data: dict):
    try:
        settings_json = json.dumps(settings_data)
        settings_rec = db.query(Settings).filter(Settings.user_id == auth_user_id).first()
        
        if settings_rec:
            settings_rec.settings_data = settings_json
        else:
            settings_rec = Settings(user_id=auth_user_id, settings_data=settings_json)
            db.add(settings_rec)
        
        db.commit()
        return {"message": "Settings saved successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to save settings: {str(e)}")


# =========================================================================
# 3. SECURITY / AUDIT LOGS ROUTES (Uses 'audit_logs' table)
# =========================================================================

# Loads logs (for Security.jsx)
@app.get("/api/security/logs", status_code=status.HTTP_200_OK)
async def fetch_audit_logs(auth_user_id: AuthUserID, db: DBSession):
    return get_audit_logs_db(db, auth_user_id)


# =========================================================================
# 4. INTEGRATIONS ROUTES (Uses 'tokens' table)
# =========================================================================

# Loads integration status (for Integrations.jsx)
@app.get("/api/integrations/status", status_code=status.HTTP_200_OK)
async def get_integrations_status(auth_user_id: AuthUserID, db: DBSession):
    """Retrieves status of connected third-party services."""
    # Integrations.jsx should call this to see what is connected
    return get_tokens_metadata_db(db, auth_user_id)