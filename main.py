import os
import sys
import json
import httpx 
import uuid
import hmac
import hashlib
import os
import json
from fastapi import Request, HTTPException, Header, Depends
from sqlalchemy.orm import Session
# Change this line:
from db import SessionLocal, activate_user_subscription
from checkout import create_metria_checkout  # Import your logic engine
from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional, List, Union, Any
from urllib.parse import urlencode 
from polar_sdk import Polar

# FastAPI and dependencies
from fastapi import FastAPI, Depends, HTTPException, Query, status, Request, Header
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
    verify_password_helper,
    activate_user_subscription  # <--- CRITICAL ADDITION
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
polar = Polar(access_token=os.environ.get("POLAR_ACCESS_TOKEN"))

# Your Webhook Secret from the Polar Dashboard
POLAR_WEBHOOK_SECRET = os.environ.get("POLAR_WEBHOOK_SECRET")

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

def get_current_user(db: Session = Depends(get_db), user_id: int = Depends(get_current_user_id)):
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

class CheckoutRequest(BaseModel):
    email: EmailStr


import hmac
import hashlib
import os
import json
from fastapi import Request, HTTPException
# These two exist in your db.py, so the import will work perfectly
from db import SessionLocal, activate_user_subscription 

@app.post("/webhook/polar")
async def polar_webhook(request: Request):
    payload = await request.body()
    secret = os.environ.get("POLAR_WEBHOOK_SECRET")
    signature = request.headers.get("webhook-signature")

    # 1. Verification (Manual HMAC - No SDK needed)
    if not signature or not secret:
        raise HTTPException(status_code=401)

    expected_sig = hmac.new(
        secret.encode(), 
        payload, 
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected_sig, signature):
        print("WEBHOOK ERROR: Signature Mismatch")
        raise HTTPException(status_code=401)

    # 2. Database Update
    try:
        data = json.loads(payload)
        if data.get("type") == "order.created":
            customer_email = data["data"]["customer_email"]
            sub_id = data["data"].get("subscription_id")

            # We use SessionLocal() directly because it's in your db.py
            db = SessionLocal()
            try:
                user = activate_user_subscription(db, customer_email, sub_id)
                if user:
                    print(f"SUCCESS: {customer_email} activated in DB.")
                else:
                    print(f"NOT FOUND: User {customer_email} doesn't exist.")
            finally:
                db.close()
            
        return {"status": "success"}

    except Exception as e:
        print(f"WEBHOOK PROCESSING ERROR: {e}")
        return {"status": "error"}

@app.get("/api/auth/status")
async def get_subscription_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    db.refresh(current_user)
    return {
        "is_active": current_user.is_active,
        "email": current_user.email
    }

# -------------------- PAYMENT & ACTIVATION --------------------

@app.post("/payments/create-checkout", tags=["Auth"])
async def generate_checkout_link(payload: CheckoutRequest):
    try:
        checkout_url = create_metria_checkout(payload.email)
        if not checkout_url:
            raise HTTPException(status_code=500, detail="Payment Engine failed to initialize.")
        return {"url": checkout_url}
    except Exception as e:
        print(f"Checkout Generation Error: {e}")
        raise HTTPException(status_code=500, detail="Could not connect to payment provider.")

@app.post("/auth/signup", tags=["Auth"])
def signup(payload: UserCreate, db: DBSession, request: Request):
    if get_user_by_email(db, payload.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # is_active will default to False here
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
async def analyze_data(payload: AIAnalysisRequest, user: AuthUser, db: DBSession):
    # Ensure user is active before allowing AI analysis
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Subscription required for AI synthesis.")

    org = user.organization if user.organization else "the organization"
    ind = user.industry if user.industry else "the current sector"
    exec_name = user.first_name if user.first_name else "Executive"

    few_shot = (
        "EXAMPLE_INPUT: Customer churn increased 5% in the Enterprise segment this month.\n"
        "EXAMPLE_OUTPUT: {"
        "\"summary\": \"Enterprise churn spike detected, threatening core recurring revenue.\", "
        "\"root_cause\": \"Technical friction in the API integration layer for Tier-1 clients.\", "
        "\"risk\": \"The current escalation in churn suggests a potential loss of $2M in LTV if the integration friction is not resolved.\", "
        "\"opportunity\": \"By automating the API troubleshooting, we can improve retention by 12% across all high-value accounts.\", "
        "\"action\": \"Immediately deploy the engineering task force to patch the integration gateway.\", "
        "\"roi_impact\": \"-$120,000 ARR risk prevention\", "
        "\"confidence\": 0.94}"
    )

    system_prompt = (
        f"You are the world's best Lead Strategic Data Analyst at {org}, specializing in {ind}. "
        "Respond ONLY in valid JSON.\n\n"
        f"{few_shot}\n\n"
        "REQUIRED KEYS: 'summary', 'root_cause', 'risk', 'opportunity', 'action', 'roi_impact', 'confidence'."
    )

    user_prompt = f"Data Context: {json.dumps(payload.context)}."

    try:
        raw_ai_response = await call_openai_analyst(user_prompt, system_prompt, json_mode=True)
        return json.loads(raw_ai_response)
    except Exception as e:
        print(f"AI Analysis Logic Error: {e}")
        raise HTTPException(status_code=500, detail="Neural Engine failed to synthesize data.")

@app.post("/ai/chat", tags=["AI Analyst"])
async def chat_with_data(payload: AIChatRequest, user: AuthUser, db: DBSession):
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Subscription required.")
    
    org_ctx = f"The user works at {user.organization}." if user.organization else ""
    ind_ctx = f"Industry: {user.industry}." if user.industry else ""
    exec_name = user.first_name if user.first_name else "Client"
    
    system_prompt = (
        f"You are MetriaAI, an elite data analyst for {exec_name}. {org_ctx} {ind_ctx} "
        "Answer questions based on the provided data context with high precision."
    )
    user_prompt = f"Context: {json.dumps(payload.context)}\n\nQuestion: {payload.message}"
    
    response_text = await call_openai_analyst(user_prompt, system_instruction=system_prompt, json_mode=False)
    return {"reply": response_text}

@app.post("/ai/compare-trends", tags=["AI Analyst"])
async def compare_historical_trends(payload: CompareTrendsRequest, user_id: AuthUserID, db: DBSession):
    user = get_user_profile_db(db, user_id)
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Subscription required.")

    base_session = db.query(Dashboard).filter(Dashboard.id == payload.base_id, Dashboard.user_id == user_id).first()
    target_session = db.query(Dashboard).filter(Dashboard.id == payload.target_id, Dashboard.user_id == user_id).first()

    if not base_session or not target_session:
        raise HTTPException(status_code=404, detail="One or both sessions not found")

    base_data = json.loads(base_session.layout_data).get("ai_insight", {})
    target_data = json.loads(target_session.layout_data).get("ai_insight", {})

    system_prompt = "Identify metrics drift between two reports. Limit to 3 powerful sentences."
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

@app.get("/google-token", tags=["Integrations"])
async def get_active_google_token(user_id: AuthUserID, db: DBSession):
    token_obj = get_google_token(db, user_id)
    if not token_obj:
        raise HTTPException(status_code=404, detail="Google account not connected")

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

# -------------------- SYSTEM --------------------

@app.get("/health")
def health():
    return {"status": "ok", "engine": "Metria Neural Core 5.0 - High Velocity Tier"}

@app.get("/")
def root():
    return {"message": "MetriaAI API Online - Mission Ready"}