# src/main.py
import os
import json
from datetime import datetime, timedelta
from dotenv import load_dotenv

from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

import httpx
import jwt

# DB imports
from db import SessionLocal, Token, Settings, Dashboard, AuditLog, create_audit_log, User

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

JWT_SECRET = os.environ.get("JWT_SECRET", "replace_with_strong_secret")
JWT_ALG = "HS256"
JWT_EXPIRE_DAYS = int(os.environ.get("JWT_EXPIRE_DAYS", "30"))

app = FastAPI()

# -----------------------
# CORS
# -----------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://ai-data-analyst-swart.vercel.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = decode_jwt(token)
    if not payload or "user_id" not in payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    session = SessionLocal()
    try:
        user = session.query(User).filter(User.id == payload["user_id"]).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return {"id": user.id, "email": user.email}
    finally:
        session.close()

# -----------------------
# DATABASE HELPERS
# -----------------------
def save_token(user_id, token_data):
    session = SessionLocal()
    token_data["created_at"] = datetime.utcnow().isoformat()
    data_json = json.dumps(token_data)
    token = session.query(Token).filter(Token.user_id == user_id).first()
    if token:
        token.token_data = data_json
    else:
        token = Token(user_id=user_id, token_data=data_json)
        session.add(token)
    session.commit()
    session.close()

def get_token(user_id):
    session = SessionLocal()
    token = session.query(Token).filter(Token.user_id == user_id).first()
    session.close()
    if token:
        return json.loads(token.token_data)
    return None

def get_user_settings(user_id):
    session = SessionLocal()
    try:
        settings_record = session.query(Settings).filter(Settings.user_id == user_id).first()
        if settings_record:
            return json.loads(settings_record.settings_data)
        return {
            "defaultSource": "Google Sheets",
            "analysisRefreshInterval": 300,
            "enablePointerCursor": True,
            "reduceMotion": False,
        }
    except Exception as e:
        print(f"Error retrieving settings for {user_id}: {e}")
        return {}
    finally:
        session.close()

def save_user_settings(user_id, settings_data):
    session = SessionLocal()
    data_json = json.dumps(settings_data)
    try:
        settings_record = session.query(Settings).filter(Settings.user_id == user_id).first()
        if settings_record:
            settings_record.settings_data = data_json
        else:
            settings_record = Settings(user_id=user_id, settings_data=data_json)
            session.add(settings_record)
        session.commit()
        return {"message": "Settings saved successfully"}
    except Exception as e:
        session.rollback()
        print(f"Database error during settings save: {e}")
        raise e
    finally:
        session.close()

def get_dashboard_sessions_db(user_id):
    session = SessionLocal()
    try:
        sessions = session.query(Dashboard).filter(Dashboard.user_id == user_id).order_by(Dashboard.last_accessed.desc()).all()
        return [
            {
                "id": dash.id,
                "name": dash.name,
                "last_accessed": dash.last_accessed.isoformat() if dash.last_accessed else None,
                "layout_preview": f"Widgets: {len(json.loads(dash.layout_data).get('widgets', []))}",
                "is_current": (sessions.index(dash) == 0)
            }
            for dash in sessions
        ]
    except Exception as e:
        print(f"Error retrieving dashboard sessions for {user_id}: {e}")
        return []
    finally:
        session.close()

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
    created_at = datetime.fromisoformat(token_data.get("created_at"))
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
            token_data["access_token"] = new_token["access_token"]
            token_data["expires_in"] = new_token.get("expires_in", 3600)
            save_token(user_id, token_data)
            access_token = new_token["access_token"]
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
    save_token(user_id, token_data)
    try:
        create_audit_log(user_id, "INTEGRATION_GOOGLE_SUCCESS", ip_address=request.client.host)
    except Exception:
        pass
    frontend_redirect = (
        f"https://ai-data-analyst-swart.vercel.app/integrations"
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
async def signup(request: Request):
    body = await request.json()
    email, password = body.get("email"), body.get("password")
    if not email or not password:
        return JSONResponse({"error": "Email and password required"}, status_code=400)
    
    # --- FIX: Truncate password to 72 bytes for bcrypt compatibility ---
    # This prevents the "password cannot be longer than 72 bytes" error.
    # We encode to bytes, truncate, then decode back.
    safe_password = password.encode('utf-8')[:72].decode('utf-8', 'ignore')
    # --- END FIX ---
    
    session = SessionLocal()
    try:
        if session.query(User).filter(User.email == email).first():
            return JSONResponse({"error": "Email already registered"}, status_code=400)
        
        # Use the safe_password
        password_hash = User.hash_password(safe_password)
        new_user = User(email=email, password_hash=password_hash)
        session.add(new_user)
        session.commit()
        session.refresh(new_user)
        token = create_jwt(new_user.id)
        create_audit_log(new_user.id, "SIGNUP", ip_address=request.client.host)
        return JSONResponse({"message": "Signup successful", "token": token, "user_id": new_user.id})
    except Exception as e:
        session.rollback()
        print("Signup error:", e)
        return JSONResponse({"error": "Signup failed"}, status_code=500)
    finally:
        session.close()

@app.post("/auth/login")
async def login(request: Request):
    body = await request.json()
    email, password = body.get("email"), body.get("password")
    if not email or not password:
        return JSONResponse({"error": "Email and password required"}, status_code=400)
    session = SessionLocal()
    try:
        user = session.query(User).filter(User.email == email).first()
        if not user or not user.verify_password(password):
            return JSONResponse({"error": "Invalid email or password"}, status_code=401)
        token = create_jwt(user.id)
        create_audit_log(user.id, "LOGIN", ip_address=request.client.host)
        return JSONResponse({"message": "Login successful", "token": token, "user_id": user.id})
    except Exception as e:
        print("Login error:", e)
        return JSONResponse({"error": "Login failed"}, status_code=500)
    finally:
        session.close()

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
async def save_dashboard_endpoint(request: Request, user: dict = Depends(get_current_user)):
    body = await request.json()
    name, layout = body.get("name", "Untitled Dashboard"), body.get("layout", {})
    session_db = SessionLocal()
    try:
        new_dash = Dashboard(user_id=user["id"], name=name, layout_data=json.dumps(layout), last_accessed=datetime.utcnow())
        session_db.add(new_dash)
        session_db.commit()
        session_db.refresh(new_dash)
        create_audit_log(user["id"], "DASHBOARD_SAVE", ip_address=request.client.host)
        return JSONResponse({"message": "Dashboard saved", "id": new_dash.id})
    except Exception as e:
        session_db.rollback()
        print("Save dashboard error:", e)
        return JSONResponse({"error": "Failed to save dashboard"}, status_code=500)
    finally:
        session_db.close()

# -----------------------
# SECURITY ENDPOINTS
# -----------------------
@app.post("/api/security/change-password")
async def change_password(request: Request, user: dict = Depends(get_current_user)):
    body = await request.json()
    new_password = body.get("new_password")
    if not new_password:
        return JSONResponse({"error": "New password required"}, status_code=400)
        
    # --- FIX: Truncate password to 72 bytes for bcrypt compatibility ---
    safe_new_password = new_password.encode('utf-8')[:72].decode('utf-8', 'ignore')
    # --- END FIX ---
    
    session = SessionLocal()
    try:
        user_rec = session.query(User).filter(User.id == user["id"]).first()
        if not user_rec:
            return JSONResponse({"error": "User not found"}, status_code=404)
            
        # Use the safe_new_password
        user_rec.password_hash = User.hash_password(safe_new_password)
        session.commit()
        create_audit_log(user["id"], "PASSWORD_CHANGE", ip_address=request.client.host)
        return JSONResponse({"message": "Password change successful"})
    except Exception as e:
        session.rollback()
        print("Password change error:", e)
        return JSONResponse({"error": "Failed to change password"}, status_code=500)
    finally:
        session.close()

@app.post("/api/security/toggle-2fa")
async def toggle_2fa_mock(request: Request, user: dict = Depends(get_current_user)):
    body = await request.json()
    is_enabled = body.get("enabled", False)
    event_type = "2FA_ENABLED" if is_enabled else "2FA_DISABLED"
    create_audit_log(user["id"], event_type, ip_address=request.client.host)
    return JSONResponse({"message": f"2FA status set to {is_enabled} (Simulated)."})

@app.get("/api/security/logins")
async def get_recent_logins_endpoint(user: dict = Depends(get_current_user)):
    session = SessionLocal()
    try:
        logs = session.query(AuditLog).filter(AuditLog.user_id == user["id"]).order_by(AuditLog.timestamp.desc()).limit(10).all()
        formatted_logs = [
            {"id": log.id, "event": log.event_type, "time": log.timestamp.isoformat(),
             "location": f"IP: {log.ip_address}", "device": log.device_info or "Web Browser",
             "suspicious": log.is_suspicious}
            for log in logs if log.event_type.startswith("LOGIN") or log.event_type.startswith("PASSWORD")
        ]
        return JSONResponse(formatted_logs)
    finally:
        session.close()

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