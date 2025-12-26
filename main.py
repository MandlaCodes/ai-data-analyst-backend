import os
import sys
import json
import httpx 
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional, List, Union, Any
from urllib.parse import urlencode 

# FastAPI and dependencies
from fastapi import FastAPI, Depends, HTTPException, Query, status, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from fastapi.responses import RedirectResponse, JSONResponse
from pydantic import BaseModel, EmailStr 
from jose import jwt, JWTError
from fastapi.security import OAuth2PasswordBearer

# Official OpenAI SDK
from openai import AsyncOpenAI

# Import all models, engine, and helper functions from db.py
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
SECRET_KEY = os.environ.get("SECRET_KEY", "METRIA_SECURE_PHRASE_2025") 
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7
API_TITLE = "Metria Neural Engine API"

GOOGLE_CLIENT_ID = os.environ.get("CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.environ.get("REDIRECT_URI")
GOOGLE_SCOPES = "https://www.googleapis.com/auth/spreadsheets.readonly https://www.googleapis.com/auth/drive.readonly profile email"

# Initialize Async OpenAI Client
client = AsyncOpenAI(api_key=OPENAI_API_KEY)

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

# -------------------- DATABASE DEPENDENCY --------------------

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

DBSession = Annotated[Session, Depends(get_db)]

@app.on_event("startup")
def on_startup():
    try:
        Base.metadata.create_all(bind=engine) 
        print("Database initialization successful.")
    except Exception as e:
        print(f"Database initialization FAILED: {e}")

# -------------------- AI ANALYST SCHEMAS & UTILITIES --------------------

class AIAnalysisRequest(BaseModel):
    context: Union[dict, List[dict]]
    mode: str = "single"

class AIChatRequest(BaseModel):
    message: str
    context: dict

class CompareTrendsRequest(BaseModel):
    base_id: int
    target_id: int

async def call_openai_analyst(prompt: str, system_instruction: str, json_mode: bool = True):
    if not OPENAI_API_KEY:
        raise HTTPException(status_code=500, detail="OpenAI API Key not configured")

    try:
        response_format = {"type": "json_object"} if json_mode else None
        response = await client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,
            response_format=response_format
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"OpenAI API Call Failed: {e}")
        if json_mode:
            return json.dumps({
                "risk": "Neural core timeout. Verify data density.", 
                "opportunity": "Synthesis interrupted. Retry execution.", 
                "action": "Refresh data stream and re-initialize analysis."
            })
        return "I encountered an error processing that request."

# -------------------- AUTHENTICATION HELPERS --------------------

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
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user_id(token: Annotated[str, Depends(oauth2_scheme)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id_str: str = payload.get("sub")
        if user_id_str is None:
            raise credentials_exception
        return int(user_id_str)
    except (JWTError, ValueError):
        raise credentials_exception

def get_user_from_query_token(token: str, db: Session):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id_str: str = payload.get("sub")
        if user_id_str is None:
            raise credentials_exception
        user = get_user_profile_db(db, int(user_id_str))
        if not user:
            raise credentials_exception
        return {"id": user.id, "email": user.email}
    except (JWTError, ValueError):
        raise credentials_exception

def get_current_user(db: DBSession, user_id: Annotated[int, Depends(get_current_user_id)]):
    user = get_user_profile_db(db, user_id)
    if user is None:
        raise credentials_exception
    return user

AuthUser = Annotated[Any, Depends(get_current_user)]
AuthUserID = Annotated[int, Depends(get_current_user_id)]

# -------------------- AUTH & PROFILE ROUTES --------------------

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    organization: Optional[str] = None
    industry: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class ProfileUpdateRequest(BaseModel):
    first_name: Optional[str]
    last_name: Optional[str]
    organization: Optional[str]
    industry: Optional[str]

@app.post("/auth/signup", tags=["Auth"])
def signup(payload: UserCreate, db: DBSession, request: Request):
    if get_user_by_email(db, payload.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user = create_user_db(
        db, 
        email=payload.email, 
        password=payload.password,
        first_name=payload.first_name,
        last_name=payload.last_name,
        organization=payload.organization,
        industry=payload.industry
    )
    db.commit() 
    
    token = create_access_token({"sub": str(user.id)})
    create_audit_log(db, user_id=user.id, event_type="SIGNUP_SUCCESS", ip_address=request.client.host if request.client else "unknown")
    db.commit()
    
    return { 
        "user_id": user.id, 
        "email": user.email, 
        "token": token,
        "first_name": user.first_name 
    }

@app.post("/auth/login", tags=["Auth"])
def login(payload: UserLogin, db: DBSession, request: Request):
    user = get_user_by_email(db, payload.email)
    if not user or not verify_password_helper(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    
    token = create_access_token({"sub": str(user.id)})
    create_audit_log(db, user_id=user.id, event_type="LOGIN_SUCCESS", ip_address=request.client.host if request.client else "unknown")
    db.commit()
    
    return { 
        "user_id": user.id, 
        "email": user.email, 
        "token": token,
        "first_name": user.first_name 
    }

@app.get("/auth/me", tags=["Auth"])
def me(user: AuthUser):
    return { 
        "user_id": user.id, 
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "organization": user.organization,
        "industry": user.industry
    }

@app.put("/auth/profile/update", tags=["Auth"])
def update_profile(payload: ProfileUpdateRequest, user_id: AuthUserID, db: DBSession):
    user = get_user_profile_db(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user.first_name = payload.first_name
    user.last_name = payload.last_name
    user.organization = payload.organization
    user.industry = payload.industry
    
    db.commit()
    db.refresh(user)
    return user

# -------------------- AI ANALYST ROUTES --------------------

@app.post("/ai/analyze", tags=["AI Analyst"])
async def analyze_data(payload: AIAnalysisRequest, user_id: AuthUserID, db: DBSession):
    user = get_user_profile_db(db, user_id)
    is_comparison = isinstance(payload.context, list)
    
    industry_tag = f" specializing in the {user.industry} sector" if user.industry else ""

    if is_comparison:
        system_prompt = (
            f"You are a Senior Strategic Data Analyst{industry_tag}. "
            "Respond ONLY in valid JSON with keys: 'risk', 'opportunity', 'action'. "
            "Analyze multiple datasets for cross-correlations. Limit values to 2 sentences."
        )
        user_prompt = f"Cross-Stream Analysis: {json.dumps(payload.context)}."
    else:
        system_prompt = (
            f"You are a Senior Strategic Data Analyst{industry_tag}. Respond ONLY in valid JSON. "
            "Analyze data and return keys: 'risk', 'opportunity', 'action'. Limit to 2 sentences."
        )
        user_prompt = f"Data Summary: {json.dumps(payload.context)}."

    raw_ai_response = await call_openai_analyst(user_prompt, system_prompt, json_mode=True)
    return json.loads(raw_ai_response)

@app.post("/ai/chat", tags=["AI Analyst"])
async def chat_with_data(payload: AIChatRequest, user_id: AuthUserID, db: DBSession):
    user = get_user_profile_db(db, user_id)
    industry_context = f"The user works in {user.industry}." if user.industry else ""
    
    system_prompt = (
        f"You are MetriaAI, a data analyst. {industry_context} "
        "Answer questions based on data concisely and professionally."
    )
    user_prompt = f"Context: {json.dumps(payload.context)}\n\nQuestion: {payload.message}"
    response_text = await call_openai_analyst(user_prompt, system_instruction=system_prompt, json_mode=False)
    return {"reply": response_text}

@app.post("/ai/compare-trends", tags=["AI Analyst"])
async def compare_historical_trends(payload: CompareTrendsRequest, user_id: AuthUserID, db: DBSession):
    base_session = db.query(Dashboard).filter(Dashboard.id == payload.base_id, Dashboard.user_id == user_id).first()
    target_session = db.query(Dashboard).filter(Dashboard.id == payload.target_id, Dashboard.user_id == user_id).first()

    if not base_session or not target_session:
        raise HTTPException(status_code=404, detail="One or both sessions not found")

    base_data = json.loads(base_session.layout_data).get("ai_insight", {})
    target_data = json.loads(target_session.layout_data).get("ai_insight", {})

    system_prompt = (
        "You are a Strategic Growth Specialist. Compare two historical AI analysis reports. "
        "Identify what has improved, what risks have emerged, and how the strategy has evolved. "
        "Limit to 3 sentences."
    )
    
    user_prompt = f"Initial Analysis: {json.dumps(base_data)}\nLatest Analysis: {json.dumps(target_data)}"
    comparison = await call_openai_analyst(user_prompt, system_prompt, json_mode=False)
    return {"comparison": comparison}

# -------------------- GOOGLE OAUTH FLOW --------------------

def get_google_auth_url(state: str):
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": GOOGLE_SCOPES,
        "access_type": "offline", 
        "prompt": "consent",      
        "state": state 
    }
    return f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"

@app.get("/auth/google_sheets", tags=["Integrations"])
def google_oauth_start(token: str, db: Session = Depends(get_db), return_path: str = "/dashboard/integrations"):
    user = get_user_from_query_token(token, db)
    state_uuid = str(uuid.uuid4())
    save_state_to_db(db, user_id=user["id"], state_uuid=state_uuid, return_path=return_path)
    db.commit()
    return RedirectResponse(url=get_google_auth_url(state=state_uuid))

@app.get("/auth/callback", tags=["Integrations"], include_in_schema=False)
async def google_oauth_callback(code: str, state: str, db: DBSession, request: Request):
    state_data = get_user_id_from_state_db(db, state_uuid=state)
    if not state_data:
        return RedirectResponse(url="https://aianalyst-gamma.vercel.app/dashboard/integrations?connected=false&error=expired")
        
    user_id = state_data["user_id"]
    final_return_path = state_data.get("return_path", "/dashboard/integrations")

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
        create_audit_log(db, user_id=user_id, event_type="GOOGLE_CONNECTED", ip_address=request.client.host if request.client else None)
        db.commit()
        return RedirectResponse(url=f"https://aianalyst-gamma.vercel.app{final_return_path}?connected=true")
    
    return RedirectResponse(url=f"https://aianalyst-gamma.vercel.app{final_return_path}?connected=false")

# -------------------- GOOGLE API DATA FETCHING --------------------

@app.get("/google/sheets", tags=["Integrations"])
async def list_google_sheets(user_id: AuthUserID, db: DBSession):
    token_obj = get_google_token(db, user_id)
    if not token_obj:
        raise HTTPException(status_code=401, detail="Not connected")

    async with httpx.AsyncClient() as client:
        headers = {"Authorization": f"Bearer {token_obj.access_token}"}
        params = {"q": "mimeType='application/vnd.google-apps.spreadsheet' and trashed=false", "fields": "files(id, name)"}
        resp = await client.get("https://www.googleapis.com/drive/v3/files", headers=headers, params=params)
        
        if resp.status_code == 401 and token_obj.refresh_token:
            r = await client.post("https://oauth2.googleapis.com/token", data={
                "client_id": GOOGLE_CLIENT_ID, "client_secret": GOOGLE_CLIENT_SECRET,
                "refresh_token": token_obj.refresh_token, "grant_type": "refresh_token",
            })
            if r.status_code == 200:
                token_obj.access_token = r.json()["access_token"]
                db.commit()
                headers["Authorization"] = f"Bearer {token_obj.access_token}"
                resp = await client.get("https://www.googleapis.com/drive/v3/files", headers=headers, params=params)

        return resp.json() if resp.status_code == 200 else {"files": []}

@app.get("/google/sheets/{spreadsheet_id}", tags=["Integrations"])
async def get_google_sheet_data(spreadsheet_id: str, user_id: AuthUserID, db: DBSession):
    token_obj = get_google_token(db, user_id)
    if not token_obj: raise HTTPException(status_code=401)
    async with httpx.AsyncClient() as client:
        headers = {"Authorization": f"Bearer {token_obj.access_token}"}
        url = f"https://sheets.googleapis.com/v4/spreadsheets/{spreadsheet_id}/values/A1:Z1000"
        resp = await client.get(url, headers=headers)
        return resp.json()

# -------------------- ANALYSIS SESSIONS & TRENDS --------------------

class PageStateSaveRequest(BaseModel):
    name: str = "Latest Dashboard"
    page_state: dict 

@app.post("/analysis/save", tags=["Analysis"])
def save_analysis(payload: PageStateSaveRequest, user_id: AuthUserID, db: DBSession):
    snapshot_json = json.dumps(payload.page_state)
    # We allow multiple saves now to support "Trends" history
    dashboard = Dashboard(user_id=user_id, name=payload.name, layout_data=snapshot_json)
    db.add(dashboard)
    db.commit()
    return {"message": "Session Saved"}

@app.get("/analysis/current", tags=["Analysis"])
def get_current_analysis(user_id: AuthUserID, db: DBSession):
    dashboard = db.query(Dashboard).filter(Dashboard.user_id == user_id).order_by(Dashboard.last_accessed.desc()).first()
    if not dashboard: return {"page_state": None}
    return {"page_state": json.loads(dashboard.layout_data)}

@app.get("/analysis/trends", tags=["Analysis"])
def get_analysis_trends(user_id: AuthUserID, db: DBSession):
    sessions = db.query(Dashboard).filter(Dashboard.user_id == user_id).order_by(Dashboard.last_accessed.desc()).all()
    trends = []
    for s in sessions:
        try:
            data = json.loads(s.layout_data)
            insight = data.get("ai_insight", {}) 
            if insight:
                trends.append({
                    "id": s.id,
                    "date": s.last_accessed,
                    "session_name": s.name,
                    "risk": insight.get("risk"),
                    "opportunity": insight.get("opportunity"),
                    "action": insight.get("action")
                })
        except: continue
    return trends

# -------------------- SYSTEM --------------------

@app.get("/health")
def health():
    return {"status": "ok", "engine": "Metria Neural Core 4.0"}

@app.get("/")
def root():
    return {"message": "MetriaAI API Online"}