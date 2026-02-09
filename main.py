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
    Base, deactivate_user_subscription_db, engine, SessionLocal,
    get_user_by_email, create_user_db, create_audit_log,
    get_user_profile_db, get_latest_dashboard_db, get_user_settings_db,
    get_audit_logs_db, get_tokens_metadata_db, 
    save_google_token, get_google_token, 
    save_state_to_db, get_user_id_from_state_db, delete_state_from_db,
    verify_password_helper , ChatSession
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
GOOGLE_SCOPES = "https://www.googleapis.com/auth/drive.file profile email"
FRONTEND_URL = "https://metria.dev"

# Initialize Async OpenAI Client
client = AsyncOpenAI(api_key=OPENAI_API_KEY)

# --- Application Initialization ---
app = FastAPI(title=API_TITLE)

# -------------------- CORS Configuration --------------------
origins = [
    FRONTEND_URL, 
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
        print("Database initialization successful. Neural Core Active.")
    except Exception as e:
        print(f"Database initialization FAILED: {e}")

# -------------------- AI ANALYST SCHEMAS & UTILITIES --------------------

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
            model="gpt-4o", 
            messages=[
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1, 
            response_format=response_format
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"OpenAI API Call Failed: {e}")
        if json_mode:
            return json.dumps({
                "summary": "Neural synthesis interrupted.",
                "root_cause": "Core timeout. Connection to data stream lost.",
                "risk": "Operational blindness. Verify data density.", 
                "opportunity": "Synthesis interrupted. Retry execution.", 
                "action": "Refresh data stream and re-initialize analysis.",
                "roi_impact": "Unknown",
                "confidence": 0.0
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
class EmailCheckRequest(BaseModel):
    email: EmailStr

class ProfileUpdateRequest(BaseModel):
    first_name: Optional[str]
    last_name: Optional[str]
    organization: Optional[str]
    industry: Optional[str]
@app.post("/auth/check-email", tags=["Auth"])
def check_email_availability(payload: EmailCheckRequest, db: DBSession):
    """
    Pre-flight check to see if an email is already registered.
    Used by the multi-step signup form to catch errors early.
    """
    user = get_user_by_email(db, payload.email)
    if user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, 
            detail="This email is already linked to an account."
        )
    return {"status": "available", "message": "Email is clear to use."}

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
        "user": {
            "first_name": user.first_name,
            "last_name": user.last_name,
            "organization": user.organization,
            "industry": user.industry
        }
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
        "user": {
            "first_name": user.first_name,
            "last_name": user.last_name,
            "organization": user.organization,
            "industry": user.industry
        }
    }

@app.get("/auth/me", tags=["Auth"])
def me(user: AuthUser):
    return { 
        "user_id": user.id, 
        "email": user.email,
        "is_trial_active": user.is_trial_active, # This tells the frontend to hide the paywall
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

class AIAnalysisRequest(BaseModel):
    context: Union[dict, List[dict]]
    # Add an alias so it works whether frontend sends 'strategy' or 'mode'
    strategy: Optional[str] = "standalone" 
    mode: Optional[str] = None
# -------------------- RE-ENGINEERED ANALYZE ROUTE --------------------

@app.post("/ai/analyze", tags=["AI Analyst"])
async def analyze_data(payload: AIAnalysisRequest, user: AuthUser, db: DBSession):
    org = user.organization if user.organization else "the organization"
    ind = user.industry if user.industry else "the current sector"
    exec_name = user.first_name if user.first_name else "Executive"

    # --- STRATEGIC LOGIC: PIVOTED FROM OBSERVATION TO COMMAND ---
    if payload.strategy == "correlation":
        strategy_prompt = (
            "MISSION: SYSTEM SYNERGY COMMAND. Identify which markets are cannibalizing resources from others. "
            "Expose hidden friction where high HHP markets are being starved of sub-area nodes. "
            "Direct the shift of capital from low-velocity silos to high-growth clusters."
        )
        trigger = "Execute synergy audit and command resource reallocation."
    elif payload.strategy == "compare":
        strategy_prompt = (
            "MISSION: CAPITAL EFFICIENCY ENFORCEMENT. Rank locations by Execution Velocity. "
            "Identify 'Zombie Markets' with high HHP but zero actual output. "
            "Command the immediate termination of underperforming expansion plans."
        )
        trigger = "Enforce capital efficiency and terminate zero-velocity projects."
    else:  # Standalone
        strategy_prompt = (
            "MISSION: OPERATIONAL STRIKE. Detect the precise point of failure in the execution chain. "
            "Diagnose why markets with massive potential show zero sub-area activity. "
            "Generate high-impact tactical pivots to recover lost revenue leaks."
        )
        trigger = "Execute operational strike and identify recovery pivots."

    system_prompt = (f"""
You are the Lead Strategic Data Analyst at {org}, reporting directly to {exec_name}.
You replace a human Senior Data Analyst.

ANALYSIS ORDER (MANDATORY):
1. DATA INTEGRITY: Identify inconsistencies, missing values, naming conflicts.
2. FINANCIAL TRUTH: Calculate revenue, cost, profit, margin, concentration risk.
3. KPI FRAMEWORK: Derive performance indicators used by executives.
4. DIAGNOSIS: Explain WHY results exist using business logic.
5. RISK SURFACE: Identify failure modes and revenue leaks.
6. OPPORTUNITY LEVERAGE: Identify the highest ROI actions.
7. EXECUTIVE DIRECTIVE: Issue a decisive command.

LANGUAGE RULES:
- No speculation.
- No generic advice.
- No filler.

COMMAND LANGUAGE (ONLY IN 'action' and 'directive'):
Use: Execute, Reallocate, Pivot, Terminate, Accelerate.

STRUCTURE RULE:
Every key must contain EXACTLY 3 sentences.

REQUIRED JSON KEYS:
summary,
root_cause,
risk,
opportunity,
action,
roi_impact,
confidence,
directive

Respond ONLY in valid JSON.
"""
    )

    user_prompt = (
        f"INPUT DATA: {json.dumps(payload.context)}. "
        f"TASK: {trigger} Compare the HHP density to Sub-Area execution. "
        "Identify exactly which area to pull resources from and which area to flood with capital."
    )

    try:
        raw_ai_response = await call_openai_analyst(user_prompt, system_prompt, json_mode=True)
        parsed_response = json.loads(raw_ai_response)
        
        # Self-Correction to ensure the UI doesn't break
        if "executive_summary" in parsed_response and "summary" not in parsed_response:
            parsed_response["summary"] = parsed_response.pop("executive_summary")
        
        # Ensure the new 'directive' key exists for the frontend "Top Priority" card
        if "directive" not in parsed_response:
            parsed_response["directive"] = "Accelerate core market node expansion immediately to capture unoptimized HHP density."
            
        return parsed_response
    except Exception as e:
        print(f"Neural Engine Error: {e}")
        raise HTTPException(status_code=500, detail="The Strategic Engine is currently recalibrating for complex data structures.")
@app.post("/ai/compare-trends", tags=["AI Analyst"])
async def compare_historical_trends(payload: CompareTrendsRequest, user_id: AuthUserID, db: DBSession):
    # Using your Dashboard model from db.py
    base_session = db.query(Dashboard).filter(Dashboard.id == payload.base_id, Dashboard.user_id == user_id).first()
    target_session = db.query(Dashboard).filter(Dashboard.id == payload.target_id, Dashboard.user_id == user_id).first()

    if not base_session or not target_session:
        raise HTTPException(status_code=404, detail="One or both sessions not found")

    # Extracting the AI storage from your layout_data Text column
    base_data = json.loads(base_session.layout_data).get("ai_insight", {})
    target_data = json.loads(target_session.layout_data).get("ai_insight", {})

   # Update your system_prompt CONSTRAINTS section:
    system_prompt = (
    f"You are the world's best Lead Strategic Data Analyst at {org}... {strategy_prompt} "
    "Respond ONLY in valid JSON.\n\n"
    "CONSTRAINTS:\n"
    "1. ... (your existing constraints)\n"
    "4. TRUTH OFFSET: If the datasets show NO logical or statistical correlation, "
    "do not invent one. Instead, define the 'Silo Friction'—explain why these "
    "metrics are decoupled and why that decoupling is a risk or an inefficiency."
)
    
    user_prompt = f"Previous Analysis: {json.dumps(base_data)}\nCurrent Analysis: {json.dumps(target_data)}"
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
        # If state missing, redirect to frontend integrations with error param
        return RedirectResponse(url=f"{FRONTEND_URL}/dashboard/integrations?connected=false&error=session_expired")
        
    user_id = state_data["user_id"]
    final_return_path = state_data.get("return_path", "/dashboard/integrations")

    async with httpx.AsyncClient() as client_http:
        resp = await client_http.post("https://oauth2.googleapis.com/token", data={
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
        return RedirectResponse(url=f"{FRONTEND_URL}{final_return_path}?connected=true")

    return RedirectResponse(url=f"{FRONTEND_URL}{final_return_path}?connected=false&error=token_exchange_failed")

# -------------------- GOOGLE API DATA FETCHING --------------------

@app.get("/connected-apps", tags=["Integrations"])
def get_connected_apps(user_id: AuthUserID, db: DBSession):
    token = get_google_token(db, user_id)
    if token:
        return {
            "google_sheets": True,
            "google_sheets_last_sync": token.created_at
        }
    return {"google_sheets": False}

@app.post("/disconnect/google_sheets", tags=["Integrations"])
def disconnect_google(user_id: AuthUserID, db: DBSession):
    db.query(Token).filter(Token.user_id == user_id, Token.service == 'google_sheets').delete()
    db.commit()
    return {"status": "disconnected"}

@app.get("/google/sheets", tags=["Integrations"])
async def list_google_sheets(user_id: AuthUserID, db: DBSession):
    token_obj = get_google_token(db, user_id)
    if not token_obj:
        raise HTTPException(status_code=401, detail="Not connected")

    async with httpx.AsyncClient() as client_http:
        headers = {"Authorization": f"Bearer {token_obj.access_token}"}
        params = {"q": "mimeType='application/vnd.google-apps.spreadsheet' and trashed=false", "fields": "files(id, name)"}
        resp = await client_http.get("https://www.googleapis.com/drive/v3/files", headers=headers, params=params)

        if resp.status_code == 401 and token_obj.refresh_token:
            r = await client_http.post("https://oauth2.googleapis.com/token", data={
                "client_id": GOOGLE_CLIENT_ID, "client_secret": GOOGLE_CLIENT_SECRET,
                "refresh_token": token_obj.refresh_token, "grant_type": "refresh_token",
            })
            if r.status_code == 200:
                token_obj.access_token = r.json()["access_token"]
                db.commit()
                headers["Authorization"] = f"Bearer {token_obj.access_token}"
                resp = await client_http.get("https://www.googleapis.com/drive/v3/files", headers=headers, params=params)

        return resp.json() if resp.status_code == 200 else {"files": []}

@app.get("/google/sheets/{spreadsheet_id}", tags=["Integrations"])
async def get_google_sheet_data(spreadsheet_id: str, user_id: AuthUserID, db: DBSession):
    token_obj = get_google_token(db, user_id)
    if not token_obj: raise HTTPException(status_code=401)
    async with httpx.AsyncClient() as client_http:
        headers = {"Authorization": f"Bearer {token_obj.access_token}"}
        url = f"https://sheets.googleapis.com/v4/spreadsheets/{spreadsheet_id}/values/A1:Z1000"
        resp = await client_http.get(url, headers=headers)
        return resp.json()

# -------------------- ANALYSIS SESSIONS & TRENDS --------------------

class PageStateSaveRequest(BaseModel):
    name: str = "Latest Dashboard"
    page_state: dict 

@app.post("/analysis/save", tags=["Analysis"])
def save_analysis(payload: PageStateSaveRequest, user_id: AuthUserID, db: DBSession):
    snapshot_json = json.dumps(payload.page_state)
    dashboard = Dashboard(user_id=user_id, name=payload.name, layout_data=snapshot_json)
    db.add(dashboard)
    db.commit()
    return {"message": "Session Saved"}

@app.get("/analysis/current", tags=["Analysis"])
def get_current_analysis(user_id: AuthUserID, db: DBSession):
    dashboard = db.query(Dashboard).filter(Dashboard.user_id == user_id).order_by(Dashboard.last_accessed.desc()).first()
    if not dashboard: return {"page_state": None}
    return {
        "id": dashboard.id,
        "updated_at": dashboard.last_accessed,
        "page_state": json.loads(dashboard.layout_data)
    }

@app.get("/analysis/trends", tags=["Analysis"])
def get_analysis_trends(user_id: AuthUserID, db: DBSession):
    sessions = db.query(Dashboard).filter(Dashboard.user_id == user_id).order_by(Dashboard.last_accessed.desc()).all()
    trends = []
    for s in sessions:
        try:
            data = json.loads(s.layout_data)
            insight = data.get("ai_insight")
            if not insight and data.get("allDatasets"):
                insight = data["allDatasets"][0].get("aiStorage")

            if insight:
                trends.append({
                    "id": s.id,
                    "date": s.last_accessed,
                    "session_name": s.name,
                    "summary": insight.get("summary", "No summary available."),
                    "risk": insight.get("risk"),
                    "opportunity": insight.get("opportunity"),
                    "action": insight.get("action"),
                    "root_cause": insight.get("root_cause"),
                    "roi": insight.get("roi_impact"),
                    "confidence": insight.get("confidence")
                })
        except Exception as e:
            print(f"Trend parsing error for ID {s.id}: {e}")
            continue
    return trends

# -------------------- SYSTEM --------------------

@app.get("/health")
def health():
    return {"status": "ok", "engine": "Metria Neural Core 5.0 - High Velocity Tier"}

@app.get("/")
def root():
    return {"message": "MetriaAI API Online - Mission Ready"}
# Add this inside main.py, preferably near the other Google routes

@app.get("/google-token", tags=["Integrations"])
async def get_active_google_token(user_id: AuthUserID, db: DBSession):
    """
    Retrieves the raw Google Access Token for the Picker API.
    Handles automatic refreshing if the token is expired.
    """
    token_obj = get_google_token(db, user_id)
    if not token_obj:
        raise HTTPException(status_code=404, detail="Google account not connected")

    # Check if token is expired or about to expire (within 1 minute)
    now = datetime.now(timezone.utc)
    if token_obj.expires_at and token_obj.expires_at <= (now + timedelta(minutes=1)):
        if token_obj.refresh_token:
            async with httpx.AsyncClient() as client_http:
                r = await client_http.post("https://oauth2.googleapis.com/token", data={
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "refresh_token": token_obj.refresh_token,
                    "grant_type": "refresh_token",
                })
                if r.status_code == 200:
                    new_data = r.json()
                    token_obj.access_token = new_data["access_token"]
                    if "expires_in" in new_data:
                        token_obj.expires_at = now + timedelta(seconds=new_data["expires_in"])
                    db.commit()
                else:
                    raise HTTPException(status_code=401, detail="Session expired. Please reconnect Google.")
        else:
            raise HTTPException(status_code=401, detail="Token expired and no refresh token available.")

    return {"access_token": token_obj.access_token}

## --- BILLING & POLAR INTEGRATION ---

from db import activate_user_trial_db

@app.post("/billing/start-trial", tags=["Billing"])
async def start_trial(user: AuthUser, db: DBSession):
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.polar.sh/v1/checkouts/", 
                headers={
                    "Authorization": f"Bearer {os.environ.get('POLAR_ACCESS_TOKEN')}",
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                },
                json={
                    "product_id": "8cda6e5c-1c89-43ce-91e3-32ad1d18cfce",
                    "success_url": f"{FRONTEND_URL}/dashboard/analytics?session=success",
                    "customer_email": user.email,
                    "metadata": {"user_id": str(user.id)} 
                }
            )

            if response.status_code not in [200, 201]:
                print(f"Polar API Error ({response.status_code}): {response.text}")
                raise HTTPException(status_code=response.status_code, detail=f"Polar Error: {response.text}")

            res_data = response.json()
            create_audit_log(db, user_id=user.id, event_type="CHECKOUT_INITIATED")
            db.commit()

            return {"checkout_url": res_data.get("url")}

    except Exception as e:
        print(f"System Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# --- WEBHOOK VERIFICATION BLOCK ---

import hmac
import hashlib
import json
import os
from fastapi import Request, HTTPException, Depends
from sqlalchemy.orm import Session

import hmac
import hashlib
import base64
import json
import os
from fastapi import Request, HTTPException, Depends
from sqlalchemy.orm import Session

@app.post("/webhooks/polar", tags=["Billing"])
async def polar_webhook(request: Request, db: Session = Depends(get_db)):
    # 1. Get raw bytes and the specific Standard Webhook headers
    payload = await request.body()
    msg_id = request.headers.get("webhook-id")
    msg_timestamp = request.headers.get("webhook-timestamp")
    signature_header = request.headers.get("webhook-signature")

    webhook_secret = os.getenv("POLAR_WEBHOOK_SECRET", "").strip()

    if not all([msg_id, msg_timestamp, signature_header, webhook_secret]):
        print("❌ Missing headers or Secret")
        raise HTTPException(status_code=401, detail="Missing required headers")

    # 2. Extract the actual Base64 hash from the header
    try:
        # Polar format: 'v1,base64_hash'
        received_sig = signature_header.split(",")[1] if "," in signature_header else signature_header
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid signature header format")

    # 3. Construct the signed message exactly as Polar expects
    # Format: <msg_id>.<msg_timestamp>.<payload_bytes>
    to_sign = f"{msg_id}.{msg_timestamp}.".encode("utf-8") + payload

    # 4. Compute HMAC SHA256 (BINARY) and convert to BASE64
    computed_hmac = hmac.new(
        webhook_secret.encode('utf-8'),
        to_sign,
        hashlib.sha256
    ).digest() # Binary digest

    computed_sig = base64.b64encode(computed_hmac).decode('utf-8')

    # 5. Security Compare
    if not hmac.compare_digest(computed_sig, received_sig):
        print(f"❌ Signature Mismatch.")
        print(f"Computed (Base64): {computed_sig[:10]}...")
        print(f"Received (Base64): {received_sig[:10]}...")
        raise HTTPException(status_code=401, detail="Invalid signature")

    print("✅ Webhook Signature Verified!")

    # 6. Process the Event
    try:
        event = json.loads(payload)
        data = event.get("data", {})

        # Check order or subscription events
        if event.get("type") in ["order.created", "subscription.created", "subscription.updated"]:
            # Pull user_id from metadata we set during checkout
            user_id = data.get("metadata", {}).get("user_id")
            if user_id:
                activate_user_trial_db(db, int(user_id), data.get("customer_id"))
                print(f"🚀 Neural Core activated for User {user_id}")
            else:
                print("⚠️ Webhook received but no user_id found in metadata")

        return {"status": "success"}

    except Exception as e:
        print(f"Error processing webhook data: {e}")
        raise HTTPException(status_code=400, detail="Data processing failed")
    # --- CANCELLATION ENDPOINT ---

@app.post("/payments/cancel", tags=["Billing"])
async def cancel_subscription(user: AuthUser, db: DBSession):
    """
    Retrieves the user's active subscription from Polar and revokes it.
    """
    if not user.polar_customer_id:
        raise HTTPException(
            status_code=400, 
            detail="No active subscription record found for this account."
        )

    polar_key = os.environ.get('POLAR_ACCESS_TOKEN')
    
    async with httpx.AsyncClient() as client:
        # 1. Fetch active subscriptions for this customer from Polar
        # Polar allows multiple, but we fetch the most recent active one
        sub_resp = await client.get(
            f"https://api.polar.sh/v1/subscriptions/?customer_id={user.polar_customer_id}&active=true",
            headers={"Authorization": f"Bearer {polar_key}"}
        )

        if sub_resp.status_code != 200:
            raise HTTPException(status_code=500, detail="Failed to reach billing server.")

        subscriptions = sub_resp.json().get("items", [])
        
        if not subscriptions:
            # If no active sub found on Polar, sync our DB to reflect that
            deactivate_user_subscription_db(db, user.id)
            return {"message": "No active subscription found on provider. Local status updated."}

        # 2. Revoke the specific subscription
        # We take the first active one found
        subscription_id = subscriptions[0]["id"]
        
        revoke_resp = await client.post(
            f"https://api.polar.sh/v1/subscriptions/{subscription_id}/revoke",
            headers={"Authorization": f"Bearer {polar_key}"}
        )

        if revoke_resp.status_code in [200, 204, 201]:
            # 3. Update local database
            deactivate_user_subscription_db(db, user.id)
            create_audit_log(db, user_id=user.id, event_type="SUBSCRIPTION_CANCELLED")
            db.commit()
            return {"status": "success", "message": "Subscription revoked successfully."}
        else:
            print(f"Polar Revoke Error: {revoke_resp.text}")
            raise HTTPException(status_code=revoke_resp.status_code, detail="Provider failed to revoke subscription.")

from typing import List, Optional
import json
from fastapi import HTTPException
# Ensure Dashboard is imported from your db module
# from db import Dashboard, ChatSession 

class ChatMessage(BaseModel):
    role: str # 'user' or 'assistant'
    content: str

class AIChatHistoryRequest(BaseModel):
    messages: List[ChatMessage]
    context: Optional[dict] = None
    dashboard_id: Optional[int] = None # Will accept BigInt from frontend
    session_id: Optional[int] = None 

@app.post("/ai/chat", tags=["AI Analyst"])
async def chat_with_analyst(payload: AIChatHistoryRequest, user: AuthUser, db: DBSession):
    """
    Conversational endpoint with 'Referential Integrity Guard'.
    Ensures chats save even if the dashboard_id is missing from the DB.
    """
    org = user.organization or "the organization"
    exec_name = user.first_name or "Executive"

    system_instruction = (
        f"You are the Lead Strategic Data Analyst at {org} reporting to {exec_name}. "
        "Your tone is decisive, high-velocity, and command-oriented. "
        "Answer like a human analyst in a strategy meeting "
        "If context data is provided, use it to justify tactical pivots."
    )

    # 1. Prepare messages for OpenAI
    api_messages = [{"role": "system", "content": system_instruction}]
    
    current_messages = [msg.model_dump() for msg in payload.messages]
    if payload.context and len(current_messages) > 0:
        current_messages[-1]["content"] += f"\n[DATA CONTEXT: {json.dumps(payload.context)}]"

    for msg in current_messages:
        api_messages.append(msg)

    try:
        # 2. Call OpenAI
        response = await client.chat.completions.create(
            model="gpt-4o",
            messages=api_messages,
            temperature=0.3
        )
        ai_response_text = response.choices[0].message.content

        # 3. Persistence Logic: The Resilience Guard
        full_history = payload.messages + [ChatMessage(role="assistant", content=ai_response_text)]
        history_json = json.dumps([m.model_dump() for m in full_history])

        # VALIDATION GATE: Check if dashboard exists before linking
        valid_dashboard_id = None
        if payload.dashboard_id:
            db_dash = db.query(Dashboard).filter(Dashboard.id == payload.dashboard_id).first()
            if db_dash:
                valid_dashboard_id = payload.dashboard_id
            else:
                print(f"Warning: Dashboard {payload.dashboard_id} not found. Saving chat as orphaned.")

        if payload.session_id:
            # Update existing thread
            session = db.query(ChatSession).filter(
                ChatSession.id == payload.session_id, 
                ChatSession.user_id == user.id
            ).first()
            if session:
                session.messages = history_json
                # Update dashboard link if it was missing
                if valid_dashboard_id:
                    session.dashboard_id = valid_dashboard_id
        else:
            # Create a brand new session with validated dashboard_id
            session = ChatSession(
                user_id=user.id,
                dashboard_id=valid_dashboard_id, 
                thread_title=f"Strategy: {payload.messages[0].content[:30]}...",
                messages=history_json
            )
            db.add(session)
        
        db.commit()
        db.refresh(session)

        return {
            "message": ai_response_text, 
            "session_id": session.id,
            "thread_title": session.thread_title
        }

    except Exception as e:
        db.rollback()
     
        print(f"CRITICAL ERROR in /ai/chat: {str(e)}")
        raise HTTPException(status_code=500, detail="Neural link for conversation is unstable.")

@app.get("/analysis/sessions", tags=["Analysis"])
def get_chat_sessions(user_id: AuthUserID, db: DBSession):
     
    sessions = db.query(ChatSession).filter(ChatSession.user_id == user_id).order_by(ChatSession.updated_at.desc()).all()
    return sessions