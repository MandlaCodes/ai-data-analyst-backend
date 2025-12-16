import os
import sys
import json
from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional, List
import uuid
from urllib.parse import urlencode 
import requests 

# --- CRITICAL GOOGLE API IMPORTS (Required for Sheets interaction) ---
from google.oauth2.credentials import Credentials 
from google.auth.transport.requests import Request as GoogleRequest
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
# --------------------------------------------------------------------

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

# Ensure these environment variables are set
GOOGLE_CLIENT_ID = os.environ.get("CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.environ.get("REDIRECT_URI", "http://localhost:10000/auth/google/callback")
GOOGLE_SCOPES = "https://www.googleapis.com/auth/spreadsheets.readonly profile email"


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
    """CRITICAL: Create database tables if they do not exist (data is preserved)."""
    print("Attempting to create database tables...")
    try:
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
        # User not found
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

# -------------------- GOOGLE OAUTH --------------------

def get_google_auth_url(state: str):
    """Constructs the correct Google OAuth 2.0 authorization URL."""
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
    
# --- Real Token Exchange (using `requests`) ---
def exchange_code_for_token(code: str):
    """Exchanges the authorization code received from Google for Access and Refresh tokens."""
    
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    
    token_request_data = {
        'code': code,
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'grant_type': 'authorization_code'
    }

    try:
        response = requests.post(TOKEN_URL, data=token_request_data)
        response.raise_for_status() 
        return response.json()
    except requests.exceptions.HTTPError as e:
        print(f"Google Token Exchange HTTP Error ({e.response.status_code}): {e.response.text}")
        raise HTTPException(
            status_code=400, 
            detail=f"Failed to exchange Google code: {e.response.json().get('error_description', e.response.json().get('error'))}"
        )
    except requests.exceptions.RequestException as e:
        print(f"Google Token Exchange Network Error: {e}")
        raise HTTPException(status_code=500, detail="Network error contacting Google for token exchange.")


# -------------------- 🟢 REAL GOOGLE SHEETS API INTEGRATION 🟢 --------------------

def get_refreshed_credentials(db: Session, token_metadata: Token) -> Optional[Credentials]:
    """
    Creates Google Credentials object, handles token refreshing if necessary,
    and updates the database with the new token data.
    """
    if not token_metadata:
        return None

    creds = Credentials(
        token=token_metadata.access_token,
        refresh_token=token_metadata.refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        scopes=GOOGLE_SCOPES.split()
    )

    if creds.expired and creds.refresh_token:
        try:
            creds.refresh(GoogleRequest())
            # Save the new token data back to the database
            token_metadata.access_token = creds.token
            token_metadata.expires_at = datetime.now(timezone.utc) + timedelta(seconds=creds.expires_in)
            db.add(token_metadata)
            db.commit()
            print("Token refreshed successfully and saved to DB.")
        except Exception as e:
            print(f"Error refreshing token: {e}")
            # If refresh fails, the token is effectively dead
            return None
            
    # If the token is expired and no refresh token exists, it's invalid
    if creds.expired and not creds.refresh_token:
        return None
        
    return creds


def fetch_user_sheets_api(db: Session, user_id: int):
    """Fetches list of user's Google Sheets (Spreadsheets)."""
    token_metadata = get_google_token(db, user_id)
    creds = get_refreshed_credentials(db, token_metadata)
    
    if not creds:
        raise HTTPException(status_code=403, detail="Google token expired or invalid. Please reconnect.")

    try:
        # Use the Drive API to list spreadsheets, as Sheets API doesn't have a list method
        drive_service = build('drive', 'v3', credentials=creds)
        # Query for files that are Google Sheets (mimeType)
        results = drive_service.files().list(
            q="mimeType='application/vnd.google-apps.spreadsheet'", 
            pageSize=30, 
            fields="nextPageToken, files(id, name)"
        ).execute()
        
        files = results.get('files', [])
        
        return [{"id": file['id'], "name": file['name']} for file in files]
        
    except HttpError as err:
        print(f"Drive API Error: {err}")
        raise HTTPException(status_code=500, detail=f"Google Sheets API error: {err.content.decode()}")
    except Exception as e:
        print(f"Internal API Error: {e}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred while listing sheets.")


def fetch_sheet_data_api(db: Session, user_id: int, spreadsheet_id: str, range_name: str = 'A1:ZZ'):
    """Fetches all cell data from a specified range in a Google Sheet."""
    token_metadata = get_google_token(db, user_id)
    creds = get_refreshed_credentials(db, token_metadata)
    
    if not creds:
        raise HTTPException(status_code=403, detail="Google token expired or invalid. Please reconnect.")

    try:
        service = build('sheets', 'v4', credentials=creds)
        
        # Call the Sheets API
        result = service.spreadsheets().values().get(
            spreadsheetId=spreadsheet_id, 
            range=range_name
        ).execute()
        
        values = result.get('values', [])
        
        if not values:
            return {"data": {"headers": [], "rows": []}}

        # Assume the first row is headers
        headers = values[0]
        rows = values[1:]
        
        # Ensure all rows have the same number of columns as the header
        num_headers = len(headers)
        rows = [row + [''] * (num_headers - len(row)) for row in rows]
        
        return {"data": {"headers": headers, "rows": rows}}
        
    except HttpError as err:
        print(f"Sheets API Error: {err}")
        raise HTTPException(status_code=500, detail=f"Google Sheets API error: {err.content.decode()}")
    except Exception as e:
        print(f"Internal API Error: {e}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred while fetching sheet data.")
        
# -------------------- 🟢 END REAL GOOGLE SHEETS API INTEGRATION 🟢 --------------------


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
    """
    
    user_id = None
    final_return_path = "/dashboard/integrations"
    success = False
    error_detail = "" 

    try:
        # 1. Retrieve user_id and return_path using the state UUID from the DB
        state_data = get_user_id_from_state_db(db, state_uuid=state)
        
        if not state_data:
            raise HTTPException(status_code=400, detail="Invalid or expired state parameter.")
            
        user_id = state_data["user_id"]
        final_return_path = state_data["return_path"]

        # 2. Exchange code for token
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
        error_detail = e.detail
        success = False
    except Exception as e:
        print(f"Critical OAuth Error: {e}")
        error_detail = "Internal server error during connection process."
        success = False
    finally:
        status_param = "true" if success else "false"
        error_param = f"&error_detail={error_detail}" if not success and error_detail else ""
        
        redirect_url = f"{final_return_path}?connected={status_param}&type=google_sheets{error_param}"
        return RedirectResponse(url=redirect_url, status_code=status.HTTP_302_FOUND)


# -------------------- GOOGLE SHEETS STATUS & ACCESS --------------------

@app.get("/connected-apps", tags=["Integrations"])
def get_connected_apps_status(user: AuthUser, db: DBSession):
    """
    Retrieves the connection status for all external services.
    """
    user_id = user["id"]
    
    # 1. Check Google Sheets Token (checks for persistence)
    google_token = get_google_token(db, user_id)
    
    response = {
        "google_sheets": False,
        "google_sheets_last_sync": None,
    }
    
    if google_token:
        response["google_sheets"] = True
        response["google_sheets_last_sync"] = google_token.created_at.isoformat() if google_token.created_at else None
        
    return response

# --- Replaced mock with Real API Function ---
@app.get("/sheets-list", tags=["Integrations"])
def sheets_list(user: AuthUser, db: DBSession):
    """Fetches a list of available Google Sheets for the authenticated user."""
    # Calls the new API function
    sheets = fetch_user_sheets_api(db, user["id"])
    return {"sheets": sheets}


# --- Replaced mock with Real API Function ---
@app.get("/sheets/{sheet_id}", tags=["Integrations"])
def get_sheet(sheet_id: str, user: AuthUser, db: DBSession):
    """Fetches data from a specific Google Sheet."""
    # Calls the new API function
    data = fetch_sheet_data_api(db, user["id"], spreadsheet_id=sheet_id)
    # Returns in the format: {"data": {"headers": [...], "rows": [...]}}
    return data

# -------------------- ANALYSIS SESSIONS --------------------

# (The Analysis Session routes remain unchanged from the previous version)

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


@app.post("/analysis/autosave", tags=["Analysis"])
def autosave_analysis(payload: AnalysisAutosaveRequest, user_id: AuthUserID, db: DBSession):
    """Saves the current in-progress analysis to the user's implicit session (the latest one)."""
    
    dashboard = db.query(Dashboard).filter(Dashboard.user_id == user_id).order_by(Dashboard.last_accessed.desc()).first()

    layout_data_json = json.dumps({"config": payload.config, "results": payload.results, "source": payload.source})

    if dashboard:
        if dashboard.name == "Implicit Working Session" or not dashboard.name:
            dashboard.name = payload.source or "Implicit Working Session"
        
        dashboard.layout_data = layout_data_json
        dashboard.last_accessed = datetime.now(timezone.utc)
    else:
        dashboard = Dashboard(
            user_id=user_id,
            name=payload.source or "Implicit Working Session",
            layout_data=layout_data_json
        )
        db.add(dashboard)
    
    db.commit()

    return {"session_id": dashboard.id}


@app.get("/analysis/current", tags=["Analysis"])
def get_current_analysis(user_id: AuthUserID, db: DBSession):
    """Retrieves the most recently accessed dashboard/session for the user."""

    dashboard = db.query(Dashboard).filter(Dashboard.user_id == user_id).order_by(Dashboard.last_accessed.desc()).first()

    if not dashboard or not dashboard.layout_data:
        raise HTTPException(status_code=404, detail="No current analysis session found.")

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