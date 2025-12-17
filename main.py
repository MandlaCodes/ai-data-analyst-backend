import os
import sys
import json
import httpx  # Added for real Google Token exchange
from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional, List
import uuid
from urllib.parse import urlencode 

# FastAPI and dependencies
from fastapi import FastAPI, Depends, HTTPException, Query, status, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from fastapi.responses import RedirectResponse, JSONResponse
from pydantic import BaseModel, EmailStr 
from jose import jwt, JWTError
from fastapi.security import OAuth2PasswordBearer

# Import all models, engine, and helper functions from our consolidated db.py
from db import (
    User, AuditLog, Dashboard, Settings, Token, StateToken,
    Base, engine, SessionLocal,
    get_user_by_email, create_user_db, create_audit_log,
    get_user_profile_db, get_latest_dashboard_db, get_user_settings_db,
    get_audit_logs_db, get_tokens_metadata_db, 
    save_google_token, get_google_token, 
    save_state_to_db, get_user_id_from_state_db, delete_state_from_db,
    verify_password_helper 
)

# --- Environment and Configuration ---
SECRET_KEY = os.environ.get("SECRET_KEY", "THIS_IS_A_VERY_INSECURE_DEFAULT_SECRET_CHANGE_ME_IN_PROD") 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7
API_TITLE = "AI Data Analyst Backend"

GOOGLE_CLIENT_ID = os.environ.get("CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.environ.get("REDIRECT_URI")
GOOGLE_SCOPES = "https://www.googleapis.com/auth/spreadsheets.readonly https://www.googleapis.com/auth/drive.readonly profile email"


# --- Pydantic Schemas ---

class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class AnalysisSaveRequest(BaseModel):
    name: str
    source: str
    config: dict
    results: dict

class AnalysisAutosaveRequest(BaseModel):
    source: str
    config: dict
    results: dict

# --- Application Initialization ---
app = FastAPI(title=API_TITLE)

# -------------------- CORS Configuration --------------------
origins = [
    "https://aianalyst-gamma.vercel.app", 
    "http://localhost:3000",
    "http://localhost:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins, 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------- DATABASE DEPENDENCY & INITIALIZATION --------------------

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

DBSession = Annotated[Session, Depends(get_db)]

@app.on_event("startup")
def on_startup():
    print("Attempting to create database tables...")
    try:
        Base.metadata.create_all(bind=engine) 
        print("Database initialization successful. Existing data preserved.")
    except Exception as e:
        print(f"Database initialization FAILED. Error: {e}")


# -------------------- AUTHENTICATION LOGIC --------------------

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM) 
    return encoded_jwt

def authenticate_user(db: Session, email: str, password: str):
    user = get_user_by_email(db, email)
    if user:
        is_verified = verify_password_helper(password, user.hashed_password)
        print(f"DIAGNOSTIC: Login for {email}. Verified: {is_verified}")
        if not is_verified:
             raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    else:
        print(f"DIAGNOSTIC: User not found for email: {email}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    return user

def get_current_user_id(token: Annotated[str, Depends(oauth2_scheme)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id_str: str = payload.get("sub")
        if user_id_str is None:
            raise credentials_exception
        user_id = int(user_id_str)
    except (JWTError, ValueError):
        raise credentials_exception
    return user_id

def get_current_user(db: DBSession, user_id: Annotated[int, Depends(get_current_user_id)]):
    user = get_user_profile_db(db, user_id)
    if user is None:
        raise credentials_exception
    return {"id": user.id, "email": user.email}

AuthUser = Annotated[dict, Depends(get_current_user)]
AuthUserID = Annotated[int, Depends(get_current_user_id)]


# -------------------- AUTH ROUTES --------------------

@app.post("/auth/signup", tags=["Auth"])
def signup(payload: UserCreate, db: DBSession, request: Request):
    if get_user_by_email(db, payload.email):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    user = create_user_db(db, payload.email, payload.password)
    db.commit() 
    token = create_access_token({"sub": str(user.id)})
    create_audit_log(db, user_id=user.id, event_type="SIGNUP_SUCCESS", ip_address=request.client.host if request.client else "unknown")
    db.commit()
    return { "user_id": user.id, "email": user.email, "token": token }

@app.post("/auth/login", tags=["Auth"])
def login(payload: UserLogin, db: DBSession, request: Request):
    user = authenticate_user(db, payload.email, payload.password)
    token = create_access_token({"sub": str(user.id)})
    create_audit_log(db, user_id=user.id, event_type="LOGIN_SUCCESS", ip_address=request.client.host if request.client else "unknown")
    db.commit()
    return { "user_id": user.id, "email": user.email, "token": token }

@app.get("/auth/me", tags=["Auth"])
def me(user: AuthUser):
    return { "user_id": user["id"], "email": user["email"] }


# -------------------- GOOGLE OAUTH --------------------

def get_google_auth_url(state: str):
    AUTH_BASE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": GOOGLE_SCOPES,
        "access_type": "offline",
        "prompt": "consent",
        "state": state 
    }
    return f"{AUTH_BASE_URL}?{urlencode(params)}"

@app.get("/auth/google_sheets", tags=["Integrations"])
def google_oauth_start(user: AuthUser, db: DBSession, return_path: str = "/dashboard/integrations"):
    state_uuid = str(uuid.uuid4())
    save_state_to_db(db, user_id=user["id"], state_uuid=state_uuid, return_path=return_path)
    db.commit()
    auth_url = get_google_auth_url(state=state_uuid)
    return {"auth_url": auth_url}

@app.get("/auth/google/callback", tags=["Integrations"], include_in_schema=False)
async def google_oauth_callback(code: str, state: str, db: DBSession, request: Request):
    state_data = get_user_id_from_state_db(db, state_uuid=state)
    if not state_data:
        raise HTTPException(status_code=400, detail="Invalid or expired state parameter.")
        
    user_id = state_data["user_id"]
    final_return_path = state_data["return_path"]

    async with httpx.AsyncClient() as client:
        resp = await client.post("https://oauth2.googleapis.com/token", data={
            "code": code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": GOOGLE_REDIRECT_URI,
            "grant_type": "authorization_code",
        })
        token_data = resp.json()

    if "access_token" in token_data:
        save_google_token(db, user_id, token_data)
        delete_state_from_db(db, state_uuid=state)
        create_audit_log(db, user_id=user_id, event_type="GOOGLE_OAUTH_CONNECTED", ip_address=request.client.host if request.client else "unknown")
        db.commit()
        return RedirectResponse(url=f"https://aianalyst-gamma.vercel.app{final_return_path}?connected=true&type=google_sheets")
    
    return RedirectResponse(url=f"https://aianalyst-gamma.vercel.app{final_return_path}?connected=false&error=token_exchange_failed")


# -------------------- GOOGLE SHEETS ACCESS --------------------

@app.get("/connected-apps", tags=["Integrations"])
def get_connected_apps_status(user: AuthUser, db: DBSession):
    google_token = get_google_token(db, user["id"])
    return {
        "google_sheets": google_token is not None,
        "google_sheets_last_sync": google_token.created_at.isoformat() if google_token and google_token.created_at else None,
    }

@app.post("/disconnect/google_sheets", tags=["Integrations"])
def disconnect_sheets(user: AuthUser, db: DBSession):
    db.query(Token).filter(Token.user_id == user["id"], Token.service == 'google_sheets').delete()
    db.commit()
    return {"status": "success"}


# -------------------- ANALYSIS SESSIONS (ORIGINAL LOGIC) --------------------

@app.post("/analysis/save", tags=["Analysis"])
def save_analysis(payload: AnalysisSaveRequest, user_id: AuthUserID, db: DBSession, request: Request):
    layout_data_json = json.dumps({"config": payload.config, "results": payload.results, "source": payload.source})
    dashboard = Dashboard(user_id=user_id, name=payload.name, layout_data=layout_data_json)
    db.add(dashboard)
    db.commit()
    create_audit_log(db, user_id=user_id, event_type="ANALYSIS_SAVED", ip_address=request.client.host if request.client else "unknown")
    db.commit()
    return {"session_id": dashboard.id}

@app.post("/analysis/autosave", tags=["Analysis"])
def autosave_analysis(payload: AnalysisAutosaveRequest, user_id: AuthUserID, db: DBSession):
    dashboard = db.query(Dashboard).filter(Dashboard.user_id == user_id).order_by(Dashboard.last_accessed.desc()).first()
    layout_data_json = json.dumps({"config": payload.config, "results": payload.results, "source": payload.source})
    if dashboard:
        if dashboard.name == "Implicit Working Session" or not dashboard.name:
            dashboard.name = payload.source or "Implicit Working Session"
        dashboard.layout_data = layout_data_json
        dashboard.last_accessed = datetime.now(timezone.utc)
    else:
        dashboard = Dashboard(user_id=user_id, name=payload.source or "Implicit Working Session", layout_data=layout_data_json)
        db.add(dashboard)
    db.commit()
    return {"session_id": dashboard.id}

@app.get("/analysis/current", tags=["Analysis"])
def get_current_analysis(user_id: AuthUserID, db: DBSession):
    dashboard = db.query(Dashboard).filter(Dashboard.user_id == user_id).order_by(Dashboard.last_accessed.desc()).first()
    if not dashboard or not dashboard.layout_data:
        raise HTTPException(status_code=404, detail="No current analysis session found.")
    try:
        layout_data = json.loads(dashboard.layout_data)
    except:
        raise HTTPException(status_code=500, detail="Corrupt session data found.")
    return {
        "id": dashboard.id, "name": dashboard.name, "source": layout_data.get("source"),
        "config": layout_data.get("config", {}), "results": layout_data.get("results", {})
    }

@app.get("/analysis/sessions", tags=["Analysis"])
def list_analysis_sessions(user_id: AuthUserID, db: DBSession):
    dashboards = db.query(Dashboard).filter(Dashboard.user_id == user_id).order_by(Dashboard.last_accessed.desc()).all()
    sessions = []
    for d in dashboards:
        try:
            layout_data = json.loads(d.layout_data)
        except:
            layout_data = {"source": "Error", "config": {}}
        sessions.append({
            "id": d.id, "name": d.name, "last_accessed": d.last_accessed.isoformat() if d.last_accessed else None,
            "source": layout_data.get("source"), "config_preview": layout_data.get("config", {}) 
        })
    return {"sessions": sessions}

@app.get("/dashboards", tags=["Dashboard"])
def dashboards_alias(user_id: AuthUserID, db: DBSession):
    return list_analysis_sessions(user_id, db)


# -------------------- HEALTH --------------------

@app.get("/health", tags=["System"])
def health():
    return {"status": "ok", "api_version": "1.0"}

@app.get("/", tags=["System"])
def root():
    return {"message": "API is running"}