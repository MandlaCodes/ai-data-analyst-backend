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
    Base, activate_user_trial_db, engine, SessionLocal,
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

    # --- STRATEGIC LOGIC INJECTION: PURE BUSINESS TERMINOLOGY ---
    if payload.strategy == "correlation":
        strategy_prompt = (
            "MISSION: SYSTEM SYNERGY AUDIT. Your goal is to find out if Department A is sabotaging Department B. "
            "Map the ripple effect: How does a win in one area trigger a failure in another? "
            "TRUTH GUARDRAIL: If these datasets are unrelated, do not force a connection. "
            "Instead, flag it as 'Operational Fragmentation'—the right hand doesn't know what the left is doing."
        )
        trigger = "Analyze systemic ripple effects and operational overlap."
    elif payload.strategy == "compare":
        strategy_prompt = (
            "MISSION: CAPITAL ALLOCATION BENCHMARKING. Rank these streams by financial density. "
            "Identify the 'Growth Engine' that deserves more budget and the 'Value Sink' that is "
            "bleeding resources. Contrast their efficiency without looking for causal links."
        )
        trigger = "Benchmark capital efficiency and rank performance tiers."
    else:  # Standalone
        strategy_prompt = (
            "MISSION: P&L ISOLATION AUDIT. Treat this as a single-business deep dive. "
            "Ignore all other noise. Focus exclusively on the internal mechanics, "
            "tactical wins, and immediate threats of this specific stream."
        )
        trigger = "Audit standalone business health and tactical failures."

    system_prompt = (
        f"You are the world's best Lead Strategic Data Analyst at {org}, specializing in {ind}. "
        f"You are reporting to {exec_name}. {strategy_prompt} "
        "Respond ONLY in valid JSON. "
        "LANGUAGE RULE: Avoid technical jargon like 'parameters', 'stochastic', or 'data points'. "
        "Use executive power words: 'Revenue Leak', 'Strategic Friction', 'Growth Engine', 'Capital Risk'. "
        "SENTENCE STRUCTURE RULE: Every reply in every JSON key must be exactly 3 sentences long. "
        "CONSTRAINTS: If the data is junk or unrelated, call it a 'Visibility Gap'—never hallucinate. "
        "REQUIRED KEYS: 'summary', 'root_cause', 'risk', 'opportunity', 'action', 'roi_impact', 'confidence'."
    )

    user_prompt = (
        f"INPUT: {len(payload.context)} distinct business streams. "
        f"Context: {json.dumps(payload.context)}. "
        f"{trigger}"
    )

    try:
        raw_ai_response = await call_openai_analyst(user_prompt, system_prompt, json_mode=True)
        parsed_response = json.loads(raw_ai_response)
        
        # Self-Correction to ensure the UI doesn't break
        if "executive_summary" in parsed_response and "summary" not in parsed_response:
            parsed_response["summary"] = parsed_response.pop("executive_summary")
            
        return parsed_response
    except Exception as e:
        # We use a generic error to keep the executive-facing side clean
        raise HTTPException(status_code=500, detail="The Intelligence Engine encountered a visibility gap.")

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
# --- BILLING & CHECKOUT ---

class CheckoutRequest(BaseModel):
    product_id: str  # The Polar Product ID for your $10 plan

@app.post("/billing/start-trial", tags=["Billing"])
async def create_polar_checkout(
    payload: CheckoutRequest, 
    user: AuthUser, 
    db: DBSession
):
    """
    Creates a Polar Checkout session and returns the URL.
    Attaches user_id to metadata so the webhook can identify them.
    """
    POLAR_API_TOKEN = os.getenv("POLAR_API_TOKEN") # Make sure this is in Render env
    
    if not POLAR_API_TOKEN:
        raise HTTPException(status_code=500, detail="Billing engine not configured")

    async with httpx.AsyncClient() as client_http:
        try:
            # We call the Polar API to create a checkout
            response = await client_http.post(
                "https://api.polar.sh/api/v1/checkouts/custom/",
                headers={
                    "Authorization": f"Bearer {POLAR_API_TOKEN}",
                    "Content-Type": "application/json"
                },
                json={
                    "product_id": payload.product_id,
                    "success_url": f"{FRONTEND_URL}/dashboard/overview?checkout=success",
                    "customer_email": user.email,
                    # CRITICAL: This links the payment to User 49
                    "metadata": {
                        "user_id": str(user.id)
                    }
                }
            )
            
            if response.status_code != 201:
                print(f"Polar Error: {response.text}")
                raise HTTPException(status_code=400, detail="Could not initialize checkout")
            
            checkout_data = response.json()
            # Return the URL to the frontend so it can redirect the user
            return {"url": checkout_data["url"]}
            
        except Exception as e:
            print(f"Checkout Exception: {e}")
            raise HTTPException(status_code=500, detail="Billing uplink failed")
        
import hmac
import hashlib
import json
import os
import base64
from fastapi import Request, HTTPException, Depends
from sqlalchemy.orm import Session

@app.post("/webhooks/polar", tags=["Billing"])
async def polar_webhook(request: Request, db: Session = Depends(get_db)):
    payload = await request.body()
    
    # Polar/StandardWebhooks send these 3 headers
    msg_id = request.headers.get("webhook-id")
    msg_timestamp = request.headers.get("webhook-timestamp")
    signature_header = request.headers.get("webhook-signature")
    
    webhook_secret = os.getenv("POLAR_WEBHOOK_SECRET", "").strip()
    
    if not all([msg_id, msg_timestamp, signature_header]):
        raise HTTPException(status_code=401, detail="Missing required webhook headers")

    try:
        # 1. Clean the signature (Polar format is 'v1,base64string')
        # We need the part after the 'v1,'
        received_sig_base64 = signature_header.split(",")[1] if "," in signature_header else signature_header
        
        # 2. Construct the signed message
        # Format: <webhook-id>.<webhook-timestamp>.<payload>
        signed_payload = f"{msg_id}.{msg_timestamp}.".encode("utf-8") + payload

        # 3. Compute HMAC SHA256 (Binary)
        computed_hmac = hmac.new(
            webhook_secret.encode('utf-8'),
            signed_payload,
            hashlib.sha256
        ).digest()
        
        # 4. Convert to Base64
        computed_sig_base64 = base64.b64encode(computed_hmac).decode('utf-8')

        # 5. Security Compare
        if not hmac.compare_digest(computed_sig_base64, received_sig_base64):
            print(f"❌ Signature Mismatch.")
            print(f"Computed: {computed_sig_base64[:10]}...")
            print(f"Received: {received_sig_base64[:10]}...")
            raise HTTPException(status_code=401, detail="Invalid signature")

        print("✅ SUCCESS! Signature verified.")
        
        # 6. Process the Event
        event = json.loads(payload)
        data = event.get("data", {})
        
        if event.get("type") in ["order.created", "subscription.created", "subscription.updated"]:
            # Check metadata for the user_id we passed during checkout
            user_id = data.get("metadata", {}).get("user_id")
            if user_id:
                activate_user_trial_db(db, int(user_id), data.get("customer_id"))
                print(f"🚀 Neural Core activated for User {user_id}")

        return {"status": "success"}

    except Exception as e:
        print(f"Error: {str(e)}")
        raise HTTPException(status_code=400, detail="Webhook processing failed")