import os
import sys
import json
from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional, List
import uuid
from urllib.parse import urlencode 
import requests # Used for token exchange HTTP POST request

# --- CRITICAL GOOGLE API IMPORTS ---
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleRequest
from googleapiclient.discovery import build
# -----------------------------------

# FastAPI and dependencies
from fastapi import FastAPI, Depends, HTTPException, Query, status, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, EmailStr 
from jose import jwt, JWTError
from fastapi.security import OAuth2PasswordBearer

# Import all models, engine, and helper functions from our consolidated db.py
from db import (
    User, AuditLog, Dashboard, Settings, Token,
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
# Ensure this matches the allowed redirect URI in your Google Cloud Console
GOOGLE_REDIRECT_URI = os.environ.get("REDIRECT_URI", "http://localhost:10000/auth/google/callback") 
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
    """Dependency for providing a synchronous SQLAlchemy database session to FastAPI routes."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

DBSession = Annotated[Session, Depends(get_db)]

@app.on_event("startup")
def on_startup():
    """CRITICAL: Create database tables if they do not exist."""
    print("Attempting to create database tables...")
    try:
        # Tables will now be created if they don't exist, and existing data will be preserved.
        Base.metadata.create_all(bind=engine) 
        print("Database initialization successful. Existing data preserved.")
    except Exception as e:
        print(f"Database initialization FAILED. Is the DATABASE_URL correct and accessible? Error: {e}")


# -------------------- AUTHENTICATION LOGIC --------------------

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)

def create_access_token(data: dict):
    """Creates a JWT token with an expiration time."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM) 
    return encoded_jwt

def authenticate_user(db: Session, email: str, password: str):
    """Checks credentials and returns the User object or raises an error."""
    user = get_user_by_email(db, email)
    
    if user:
        is_verified = verify_password_helper(password, user.hashed_password)
        
        if not is_verified:
             raise HTTPException(
                 status_code=status.HTTP_401_UNAUTHORIZED, 
                 detail="Incorrect email or password"
             )
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Incorrect email or password"
        )
        
    return user

def get_current_user_id(token: Annotated[str, Depends(oauth2_scheme)]):
    """Dependency that validates the token and returns the user ID (int)."""
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
    """Dependency that returns the user dictionary for the current session."""
    user = get_user_profile_db(db, user_id)
    if user is None:
        raise credentials_exception
    
    return {"id": user.id, "email": user.email}

# Type aliases for dependency injection
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


# -------------------- GOOGLE API HELPER FUNCTIONS (REAL IMPLEMENTATION) --------------------

def get_refreshed_credentials(db_token: Token) -> Optional[Credentials]:
    """Uses a stored Token object (from db.py model) to create/refresh Google Credentials."""
    
    if not db_token or not db_token.access_token:
        return None
    
    # 1. Create Credentials object from DB data
    # NOTE: db_token.expires_at must be a datetime object from your database model
    creds = Credentials(
        token=db_token.access_token,
        refresh_token=db_token.refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        scopes=GOOGLE_SCOPES.split(" "),
        expiry=db_token.expires_at # Use the stored expiration time
    )

    # 2. Check and refresh the token if necessary
    if not creds.valid and creds.refresh_token:
        try:
            print("Attempting to refresh Google token...")
            creds.refresh(GoogleRequest())
            
            # 3. CRITICAL: Save the new refreshed token and expiration back to the database
            if creds.token:
                token_data = {
                    "access_token": creds.token,
                    "refresh_token": creds.refresh_token, 
                    "token_type": "Bearer",
                    "expires_in": (creds.expiry - datetime.now(timezone.utc)).total_seconds() if creds.expiry else None 
                }
                # Since this helper is outside the request scope, we open a new session for the update
                db_refresh = SessionLocal()
                save_google_token(db=db_refresh, user_id=db_token.user_id, token_data=token_data)
                db_refresh.commit()
                db_refresh.close()
                print("Refreshed Google token saved.")
            
        except Exception as e:
            print(f"Error during token refresh: {e}")
            return None # Failed to refresh

    return creds

def exchange_code_for_token(code: str) -> dict:
    """Exchanges Google Authorization Code for Access and Refresh Tokens."""
    
    token_url = "https://oauth2.googleapis.com/token"
    
    payload = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }
    
    response = requests.post(token_url, data=payload)
    response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
    
    return response.json()

def fetch_user_sheets_api(creds: Credentials) -> List[dict]:
    """Uses the Google Drive API to list accessible spreadsheets."""
    try:
        # Use Drive API to list spreadsheets that the user has access to
        service = build('drive', 'v3', credentials=creds)
        
        results = service.files().list(
            q="mimeType='application/vnd.google-apps.spreadsheet'", 
            fields="files(id, name)",
            pageSize=20 
        ).execute()
        
        return results.get('files', [])
        
    except Exception as e:
        print(f"Error fetching sheets list: {e}")
        return []

def fetch_sheet_data_api(creds: Credentials, sheet_id: str):
    """Fetches data from the first sheet/tab of a specific Google Sheet ID."""
    try:
        service = build('sheets', 'v4', credentials=creds)
        
        # Request all cell data from the first sheet (Sheet1!A:Z)
        result = service.spreadsheets().values().get(
            spreadsheetId=sheet_id, 
            range="Sheet1!A:Z"
        ).execute()
        
        values = result.get('values', [])
        
        if not values:
            return {"headers": [], "rows": []}

        # First row is assumed to be headers, rest are rows
        headers = values[0]
        rows = values[1:]
        
        return {"headers": headers, "rows": rows}
        
    except Exception as e:
        print(f"Error fetching sheet data for ID {sheet_id}: {e}")
        # Note: Google API exceptions can be complex; a general 500 is used here.
        raise HTTPException(status_code=500, detail="Failed to fetch sheet data from Google API.")


# -------------------- GOOGLE OAUTH ROUTES --------------------

def get_google_auth_url(state: str):
    """
    Constructs the correct Google OAuth 2.0 authorization URL.
    """
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
    
    query_string = urlencode(params)

    return f"{AUTH_BASE_URL}?{query_string}"
    
# --- 1. Initiate OAuth (Authenticated) ---
@app.get("/auth/google_sheets", tags=["Integrations"])
def google_oauth_start(
    user: AuthUser, 
    db: DBSession,
    return_path: str = "/dashboard/integrations" 
):
    """
    Initiates the Google OAuth flow. Saves the user's ID and return path 
    to the database linked to a unique state UUID.
    """
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
         raise HTTPException(status_code=500, detail="Google credentials not configured on the backend.")

    state_uuid = str(uuid.uuid4())
    
    # CRITICAL: Save the state, user_id, and return_path to the DB
    save_state_to_db(db, user_id=user["id"], state_uuid=state_uuid, return_path=return_path)
    db.commit()
    
    auth_url = get_google_auth_url(state=state_uuid)
    return {"auth_url": auth_url}


# --- 2. OAuth Callback (Unauthenticated) ---
@app.get("/auth/google/callback", tags=["Integrations"], include_in_schema=False)
def google_oauth_callback(
    code: str,
    state: str,
    db: DBSession,
    request: Request
):
    """
    Handles the callback from Google. This route MUST BE UN-AUTHENTICATED.
    It retrieves the user ID from the 'state' parameter stored in the DB.
    """
    
    user_id = None
    final_return_path = "/dashboard/integrations"
    success = False

    try:
        # 1. Retrieve user_id and return_path using the state UUID from the DB
        state_data = get_user_id_from_state_db(db, state_uuid=state)
        
        if not state_data:
            raise HTTPException(status_code=400, detail="Invalid or expired state parameter.")
            
        user_id = state_data["user_id"]
        final_return_path = state_data["return_path"]

        # 2. Exchange code for token (REAL IMPLEMENTATION)
        token_data = exchange_code_for_token(code)
        
        # 3. Save the token data to the DB associated with the user_id
        save_google_token(db, user_id, token_data)
        
        # 4. Clean up the temporary state record
        delete_state_from_db(db, state_uuid=state)
        
        create_audit_log(db, user_id=user_id, event_type="GOOGLE_OAUTH_CONNECTED", ip_address=request.client.host if request.client else "unknown")
        db.commit()
        success = True

    except HTTPException as e:
        print(f"OAuth Error: {e.detail}")
        success = False
    except Exception as e:
        print(f"Critical OAuth Error during token exchange: {e}")
        success = False
    finally:
        # Redirect the user back to the frontend with the status
        status_param = "true" if success else "false"
        redirect_url = f"{final_return_path}?connected={status_param}&type=google_sheets"
        return RedirectResponse(url=redirect_url, status_code=status.HTTP_302_FOUND)


# -------------------- GOOGLE SHEETS ACCESS --------------------

@app.get("/connected-apps", tags=["Integrations"])
def get_connected_apps_status(user: AuthUser, db: DBSession):
    """
    Retrieves the connection status for all external services.
    """
    user_id = user["id"]
    
    # 1. Check Google Sheets Token 
    google_token = get_google_token(db, user_id)
    
    response = {
        "google_sheets": False,
        "google_sheets_last_sync": None,
    }
    
    if google_token:
        response["google_sheets"] = True
        response["google_sheets_last_sync"] = google_token.created_at.isoformat() if google_token.created_at else None
        
    return response

@app.get("/sheets-list", tags=["Integrations"])
def sheets_list(user: AuthUser, db: DBSession):
    """Fetches a list of available Google Sheets for the authenticated user."""
    db_token = get_google_token(db, user["id"])
    if not db_token:
        raise HTTPException(status_code=403, detail="Google not connected. Please authorize.")
    
    # Get potentially refreshed credentials
    creds = get_refreshed_credentials(db_token)
    if not creds:
        # If refresh fails, delete the token and force re-auth
        # This requires implementing a delete_google_token function in db.py
        # raise HTTPException(status_code=403, detail="Google token expired. Please re-authorize.") 
        # For now, let's just return a standard message.
        raise HTTPException(status_code=403, detail="Google token invalid or expired. Please re-authorize.")


    # Call the real Sheets API fetch function
    sheets = fetch_user_sheets_api(creds)
    # Note: get_refreshed_credentials handles saving the new token (via a separate session)
    return {"sheets": sheets}


@app.get("/sheets/{sheet_id}", tags=["Integrations"])
def get_sheet(sheet_id: str, user: AuthUser, db: DBSession):
    """Fetches data from a specific Google Sheet."""
    db_token = get_google_token(db, user["id"])
    if not db_token:
        raise HTTPException(status_code=403, detail="Google not connected. Please authorize.")
        
    # Get potentially refreshed credentials
    creds = get_refreshed_credentials(db_token)
    if not creds:
        raise HTTPException(status_code=403, detail="Google token invalid or expired. Please re-authorize.")

    # Call the real Sheets API fetch function
    data = fetch_sheet_data_api(creds, sheet_id)
    
    return {"data": data}

# -------------------- ANALYSIS SESSIONS --------------------

# Existing endpoint for explicit save
@app.post("/analysis/save", tags=["Analysis"])
def save_analysis(payload: AnalysisSaveRequest, user_id: AuthUserID, db: DBSession, request: Request):
    """Explicitly saves the analysis session with a user-provided name."""
    
    layout_data_json = json.dumps({"config": payload.config, "results": payload.results, "source": payload.source})

    dashboard = Dashboard(
        user_id=user_id,
        name=payload.name,
        layout_data=layout_data_json
    )
    db.add(dashboard)
    db.commit()

    create_audit_log(db, user_id=user_id, event_type="ANALYSIS_SAVED", ip_address=request.client.host if request.client else "unknown")
    db.commit()

    return {"session_id": dashboard.id}


# NEW: Endpoint for implicit autosave (used when navigating away or clearing)
@app.post("/analysis/autosave", tags=["Analysis"])
def autosave_analysis(payload: AnalysisAutosaveRequest, user_id: AuthUserID, db: DBSession):
    """Saves the current in-progress analysis to the user's implicit session (the latest one)."""
    
    # 1. Look for the most recent session (which is the current working session)
    dashboard = db.query(Dashboard).filter(Dashboard.user_id == user_id).order_by(Dashboard.last_accessed.desc()).first()

    layout_data_json = json.dumps({"config": payload.config, "results": payload.results, "source": payload.source})

    if dashboard:
        # Update existing session
        if dashboard.name == "Implicit Working Session" or not dashboard.name:
            dashboard.name = payload.source or "Implicit Working Session"
        
        dashboard.layout_data = layout_data_json
        dashboard.last_accessed = datetime.now(timezone.utc)
    else:
        # Create a new session record if none exists
        dashboard = Dashboard(
            user_id=user_id,
            name=payload.source or "Implicit Working Session",
            layout_data=layout_data_json
        )
        db.add(dashboard)
    
    db.commit()

    return {"session_id": dashboard.id}


# NEW: Endpoint for autoload (used when navigating to the page)
@app.get("/analysis/current", tags=["Analysis"])
def get_current_analysis(user_id: AuthUserID, db: DBSession):
    """Retrieves the most recently accessed dashboard/session for the user."""

    # Fetch the most recent dashboard record (current working session)
    dashboard = db.query(Dashboard).filter(Dashboard.user_id == user_id).order_by(Dashboard.last_accessed.desc()).first()

    if not dashboard or not dashboard.layout_data:
        # Return 404 if no previous session exists
        raise HTTPException(status_code=404, detail="No current analysis session found.")

    # Deserialize the data stored in the database
    try:
        layout_data = json.loads(dashboard.layout_data) if dashboard.layout_data else {} 
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Corrupt session data found.")

    return {
        "id": dashboard.id,
        "name": dashboard.name,
        "source": layout_data.get("source"),
        "config": layout_data.get("config", {}),
        "results": layout_data.get("results", {})
    }


@app.get("/analysis/sessions", tags=["Analysis"])
def list_analysis_sessions(user_id: AuthUserID, db: DBSession):
    """Lists all saved analysis sessions for the user."""
    dashboards = db.query(Dashboard).filter(Dashboard.user_id == user_id).order_by(Dashboard.last_accessed.desc()).all()
    
    sessions = []
    for d in dashboards:
        try:
            layout_data = json.loads(d.layout_data) if d.layout_data else {} 
        except json.JSONDecodeError:
            layout_data = {"source": "Corrupted Data", "config": {}}

        sessions.append({
            "id": d.id,
            "name": d.name,
            "last_accessed": d.last_accessed.isoformat() if d.last_accessed else None,
            "source": layout_data.get("source"),
            "config_preview": layout_data.get("config", {}) 
        })
    
    return {"sessions": sessions}

# -------------------- DASHBOARDS --------------------

@app.get("/dashboards", tags=["Dashboard"])
def dashboards(user_id: AuthUserID, db: DBSession):
    """Alias for listing analysis sessions (dashboards)."""
    return list_analysis_sessions(user_id, db)

# -------------------- HEALTH --------------------

@app.get("/health", tags=["System"])
def health():
    return {"status": "ok", "api_version": "1.0"}