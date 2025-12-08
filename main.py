# src/main.py
import os
import json
from datetime import datetime, timedelta
from dotenv import load_dotenv

from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from starlette.responses import Response 

import httpx
import jwt

# DB imports
from db import (
    SessionLocal, Token, Settings, Dashboard, AuditLog, 
    create_audit_log, User, create_default_dashboard 
)

# Local AI model
from gpt4all import GPT4All

# -----------------------
# Load environment variables
# -----------------------
load_dotenv()

CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
REDIRECT_URI = os.environ.get(
    "REDIRECT_URI",
    "https://ai-data-analyst-backend-1nuw.onrender.com/auth/callback"
)
SCOPES = os.environ.get(
    "SCOPES",
    "https://www.googleapis.com/auth/spreadsheets.readonly https://www.googleapis.com/auth/drive.readonly"
)

# IMPORTANT: Ensure JWT_SECRET is set in Render Env Vars for security!
JWT_SECRET = os.environ.get("JWT_SECRET", "replace_with_strong_secret") 
JWT_ALG = "HS256"
JWT_EXPIRE_DAYS = int(os.environ.get("JWT_EXPIRE_DAYS", "30"))

app = FastAPI()

# -----------------------
# Dependency to get DB session
# -----------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# -----------------------
# CORS Configuration (CRITICAL FINAL FIX FOR DEPLOYMENT)
# -----------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://ai-data-analyst-swart.vercel.app", 
        # 🟢 YOUR CURRENT, CORRECT DEPLOYED FRONTEND URL 🟢
        "https://ai-data-analyst-mlmhlw72c-mandlas-projects-228bb82e.vercel.app"
    ],
    # CRITICAL: Must be True to allow Authorization header
    allow_credentials=True, 
    allow_methods=["*"],
    # CRITICAL: Must explicitly allow the Authorization header for JWTs
    allow_headers=["Authorization", "Content-Type"],
)

# -----------------------
# CORS Pre-flight Fix 
# -----------------------
@app.options("/{full_path:path}")
async def preflight_handler(response: Response):
    # This handler ensures the browser's OPTIONS request gets a 204 No Content response
    # with the correct CORS headers attached by the middleware above.
    return Response(status_code=204) 

# -----------------------
# HEALTH CHECK (For Render's stability)
# -----------------------
@app.get("/")
def health_check():
    """Simple route for Render/load balancers to check service health."""
    return {"status": "ok", "service": "AI Data Analyst Backend"}


# -----------------------
# JWT helpers & dependency
# -----------------------
security = HTTPBearer()

def create_jwt(user_id: int):
    payload = {
        "user_id": user_id,
        "exp": datetime.utcnow() + timedelta(days=JWT_EXPIRE_DAYS),
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def decode_jwt(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.ExpiredSignatureError:
        return None
    except Exception:
        return None

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db_session: Session = Depends(get_db)):
    token = credentials.credentials
    payload = decode_jwt(token)
    if not payload or "user_id" not in payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    try:
        # Use the injected db_session
        user = db_session.query(User).filter(User.id == payload["user_id"]).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return {"id": user.id, "email": user.email}
    except HTTPException:
        # Re-raise explicit HTTP exceptions
        raise
    except Exception as e:
        print(f"Error getting user: {e}")
        raise HTTPException(status_code=500, detail="Internal server error during authentication")


# -----------------------
# DATABASE HELPERS 
# -----------------------
from db import save_token, get_token, get_user_settings, save_user_settings, get_dashboard_sessions_db # Importing helpers from db.py

# -----------------------
# GOOGLE TOKEN REFRESH
# -----------------------
async def get_valid_access_token(user_id):
    token_data = get_token(user_id)
    if not token_data:
        return None
    access_token = token_data.get("access_token")
    expires_in = token_data.get("expires_in", 0)
    refresh_token = token_data.get("refresh_token")
    
    # Safely handle created_at string
    created_at_str = token_data.get("created_at")
    try:
        created_at = datetime.fromisoformat(created_at_str)
    except (TypeError, ValueError):
        # Fallback for old/missing data
        created_at = datetime.utcnow() - timedelta(seconds=expires_in + 1)

    if (datetime.utcnow() - created_at).total_seconds() > expires_in - 60 and refresh_token:
        data = {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token"
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post("https://oauth2.googleapis.com/token", data=data)
            new_token = resp.json()
            token_data["access_token"] = new_token.get("access_token", access_token)
            token_data["expires_in"] = new_token.get("expires_in", 3600)
            save_token(user_id, token_data)
            access_token = token_data["access_token"]
    return access_token

# -----------------------
# GOOGLE OAUTH ROUTES
# -----------------------
@app.get("/auth/google_sheets")
async def auth_google_sheets(user_id: str):
    url = (
        "https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={CLIENT_ID}"
        f"&response_type=code"
        f"&scope={SCOPES}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&access_type=offline"
        f"&prompt=consent"
        f"&state={user_id}"
    )
    return RedirectResponse(url)

@app.get("/auth/callback")
async def auth_callback(request: Request, code: str = None, state: str = None):
    if not code:
        return JSONResponse({"error": "No code received"}, status_code=400)
    data = {
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code"
    }
    async with httpx.AsyncClient() as http_client:
        resp = await http_client.post("https://oauth2.googleapis.com/token", data=data)
        token_data = resp.json()
    user_id = state or "unknown"
    # Ensure user_id is cast to int for DB helpers if it came from the JWT flow
    try:
        user_id_int = int(user_id)
    except ValueError:
        user_id_int = user_id # Keep as string if it's from Google's state payload
        
    save_token(user_id_int, token_data)
    try:
        create_audit_log(user_id_int, "INTEGRATION_GOOGLE_SUCCESS", ip_address=request.client.host)
    except Exception:
        pass
        
    frontend_redirect = (
        # Redirect URL must match one of the allowed CORS origins
        f"https://ai-data-analyst-mlmhlw72c-mandlas-projects-228bb82e.vercel.app/integrations"
        f"?user_id={user_id}&connected=true&type=google_sheets&_ts={int(datetime.utcnow().timestamp())}"
    )
    return RedirectResponse(frontend_redirect)

# -----------------------
# CONNECTED APPS
# -----------------------
@app.get("/connected-apps")
async def connected_apps(user: dict = Depends(get_current_user)):
    token_data = get_token(user["id"])
    return JSONResponse({
        "google_sheets": bool(token_data),
        "google_sheets_last_sync": token_data.get("created_at") if token_data else None
    })

# -----------------------
# LIST GOOGLE SHEETS
# -----------------------
@app.get("/sheets-list")
async def sheets_list(user: dict = Depends(get_current_user)):
    user_id = user["id"]
    access_token = await get_valid_access_token(user_id)
    if not access_token:
        return JSONResponse({"error": "Google Sheets not connected"}, status_code=400)
    headers = {"Authorization": f"Bearer {access_token}"}
    params = {"q": "mimeType='application/vnd.google-apps.spreadsheet'", "fields": "files(id,name)"}
    async with httpx.AsyncClient() as http_client:
        resp = await http_client.get("https://www.googleapis.com/drive/v3/files", headers=headers, params=params)
    files = resp.json().get("files", [])
    return JSONResponse({"sheets": files})

# -----------------------
# GET SHEET DATA
# -----------------------
@app.get("/sheets/{sheet_id}")
async def get_sheet_data(sheet_id: str, user: dict = Depends(get_current_user)):
    user_id = user["id"]
    access_token = await get_valid_access_token(user_id)
    if not access_token:
        return JSONResponse({"error": "Google Sheets not connected"}, status_code=400)
    headers = {"Authorization": f"Bearer {access_token}"}
    url = f"https://sheets.googleapis.com/v4/spreadsheets/{sheet_id}/values:batchGet?ranges=Sheet1"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, headers=headers)
    data = resp.json()
    ranges = data.get("valueRanges", [])
    values = ranges[0].get("values", []) if ranges else []
    return JSONResponse({"values": values})

# -----------------------
# AUTH ROUTES (SIGNUP / LOGIN / ME)
# -----------------------
@app.post("/auth/signup")
async def signup(request: Request, db_session: Session = Depends(get_db)):
    body = await request.json()
    email, password = body.get("email"), body.get("password")
    if not email or not password:
        return JSONResponse({"error": "Email and password required"}, status_code=400)
    
    # --- Truncate password to 72 bytes for bcrypt compatibility ---
    safe_password = password.encode('utf-8')[:72].decode('utf-8', 'ignore')
    # --- END FIX ---
    
    try:
        if db_session.query(User).filter(User.email == email).first():
            return JSONResponse({"error": "Email already registered"}, status_code=400)
        
        # 1. Create the new user record
        password_hash = User.hash_password(safe_password)
        new_user = User(email=email, password_hash=password_hash)
        db_session.add(new_user)
        db_session.commit()
        db_session.refresh(new_user)
        
        # 2. CREATE DEFAULT DASHBOARD FOR NEW USER (user_id is int)
        create_default_dashboard(user_id=new_user.id) 

        # 3. Create the JWT token and audit log
        token = create_jwt(new_user.id)
        create_audit_log(new_user.id, "SIGNUP", ip_address=request.client.host)
        return JSONResponse({"message": "Signup successful", "token": token, "user_id": new_user.id})
    except Exception as e:
        db_session.rollback()
        print("Signup error:", e)
        return JSONResponse({"error": "Signup failed"}, status_code=500)

@app.post("/auth/login")
async def login(request: Request, db_session: Session = Depends(get_db)):
    body = await request.json()
    email, password = body.get("email"), body.get("password")
    if not email or not password:
        return JSONResponse({"error": "Email and password required"}, status_code=400)
    try:
        user = db_session.query(User).filter(User.email == email).first()
        if not user or not user.verify_password(password):
            return JSONResponse({"error": "Invalid email or password"}, status_code=401)
        token = create_jwt(user.id)
        create_audit_log(user.id, "LOGIN", ip_address=request.client.host)
        return JSONResponse({"message": "Login successful", "token": token, "user_id": user.id})
    except Exception as e:
        print("Login error:", e)
        return JSONResponse({"error": "Login failed"}, status_code=500)

@app.get("/auth/me")
async def me(user: dict = Depends(get_current_user)):
    return JSONResponse({"id": user["id"], "email": user["email"]})

# -----------------------
# USER SETTINGS ENDPOINTS
# -----------------------
@app.get("/api/settings")
async def get_settings_endpoint(user: dict = Depends(get_current_user)):
    settings = get_user_settings(user["id"])
    return JSONResponse(settings)

@app.post("/api/settings")
async def save_settings_endpoint(request: Request, user: dict = Depends(get_current_user)):
    try:
        settings_data = await request.json()
        result = save_user_settings(user["id"], settings_data)
        return JSONResponse(result)
    except Exception as e:
        return JSONResponse({"error": f"Failed to save settings: {e}"}, status_code=500)

@app.post("/api/cache/purge")
async def purge_cache_endpoint(user: dict = Depends(get_current_user)):
    print(f"Server-side cache purge executed for user: {user['id']}")
    return JSONResponse({"message": "Server-side cache purge simulated successfully."})

# -----------------------
# DASHBOARD ENDPOINTS
# -----------------------
@app.get("/api/dashboard/sessions")
async def get_dashboard_sessions_endpoint(user: dict = Depends(get_current_user)):
    sessions = get_dashboard_sessions_db(user["id"])
    if not sessions:
        return JSONResponse({
            "message": "No saved sessions found. Please create your first dashboard.",
            "sessions": [], "action": "PROMPT_NEW_DASHBOARD"
        })
    return JSONResponse({"sessions": sessions})

@app.post("/api/dashboard/save")
async def save_dashboard_endpoint(request: Request, user: dict = Depends(get_current_user), db_session: Session = Depends(get_db)):
    body = await request.json()
    name, layout = body.get("name", "Untitled Dashboard"), body.get("layout", {})
    try:
        # user["id"] is already an integer from the JWT payload
        new_dash = Dashboard(user_id=user["id"], name=name, layout_data=json.dumps(layout), last_accessed=datetime.utcnow())
        db_session.add(new_dash)
        db_session.commit()
        db_session.refresh(new_dash)
        create_audit_log(user["id"], "DASHBOARD_SAVE", ip_address=request.client.host)
        return JSONResponse({"message": "Dashboard saved", "id": new_dash.id})
    except Exception as e:
        db_session.rollback()
        print("Save dashboard error:", e)
        return JSONResponse({"error": "Failed to save dashboard"}, status_code=500)

# -----------------------
# SECURITY ENDPOINTS
# -----------------------
@app.post("/api/security/change-password")
async def change_password(request: Request, user: dict = Depends(get_current_user), db_session: Session = Depends(get_db)):
    body = await request.json()
    new_password = body.get("new_password")
    if not new_password:
        return JSONResponse({"error": "New password required"}, status_code=400)
    
    # --- Truncate password to 72 bytes for bcrypt compatibility ---
    safe_new_password = new_password.encode('utf-8')[:72].decode('utf-8', 'ignore')
    # --- END FIX ---
    
    try:
        user_rec = db_session.query(User).filter(User.id == user["id"]).first()
        if not user_rec:
            return JSONResponse({"error": "User not found"}, status_code=404)
            
        # Use the safe_new_password
        user_rec.password_hash = User.hash_password(safe_new_password)
        db_session.commit()
        create_audit_log(user["id"], "PASSWORD_CHANGE", ip_address=request.client.host)
        return JSONResponse({"message": "Password change successful"})
    except Exception as e:
        db_session.rollback()
        print("Password change error:", e)
        return JSONResponse({"error": "Failed to change password"}, status_code=500)

@app.post("/api/security/toggle-2fa")
async def toggle_2fa_mock(request: Request, user: dict = Depends(get_current_user)):
    body = await request.json()
    is_enabled = body.get("enabled", False)
    event_type = "2FA_ENABLED" if is_enabled else "2FA_DISABLED"
    create_audit_log(user["id"], event_type, ip_address=request.client.host)
    return JSONResponse({"message": f"2FA status set to {is_enabled} (Simulated)."})

@app.get("/api/security/logins")
async def get_recent_logins_endpoint(user: dict = Depends(get_current_user), db_session: Session = Depends(get_db)):
    try:
        logs = db_session.query(AuditLog).filter(AuditLog.user_id == user["id"]).order_by(AuditLog.timestamp.desc()).limit(10).all()
        formatted_logs = [
            {"id": log.id, "event": log.event_type, "time": log.timestamp.isoformat(),
             "location": f"IP: {log.ip_address}", "device": log.device_info or "Web Browser",
             "suspicious": log.is_suspicious}
            for log in logs if log.event_type.startswith("LOGIN") or log.event_type.startswith("PASSWORD")
        ]
        return JSONResponse(formatted_logs)
    except Exception as e:
        print(f"Error retrieving audit logs: {e}")
        return JSONResponse({"error": "Failed to retrieve logs"}, status_code=500)

# -----------------------
# GPT4ALL AI MODEL
# -----------------------
MODEL_FILE = "orca-mini-3b-gguf2-q4_0.gguf2"
MODEL_PATH = os.path.join("models", MODEL_FILE)
if not os.path.isfile(MODEL_PATH):
    print(f"ERROR: Model file missing: {MODEL_PATH}")
    gpt_model = None
else:
    gpt_model = GPT4All(model_name=MODEL_FILE, model_path="./models")

@app.post("/ai/analyze")
async def ai_analyze(request: Request):
    if gpt_model is None:
        return JSONResponse({"error": "Local AI model not found"}, status_code=500)
    body = await request.json()
    kpis, categories, row_count = body.get("kpis"), body.get("categories"), body.get("rowCount", 0)
    if not kpis:
        return JSONResponse({"error": "No KPIs provided"}, status_code=400)
    prompt = f"""
You are an expert business analyst.
Dataset Rows: {row_count}
KPIs: {json.dumps(kpis, indent=2)}
Categories: {json.dumps(categories, indent=2)}
Provide:
- Overview
- Trends
- Increasing/decreasing
- Profitability signals
- Anomalies
- Risks
- Opportunities
- Actionable insights
"""
    try:
        output = gpt_model.generate(prompt, max_tokens=400)
        return JSONResponse({"analysis": output})
    except Exception as e:
        print("GPT4All error:", e)
        return JSONResponse({"error": str(e)}, status_code=500)