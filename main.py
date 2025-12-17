import os
import json
import uuid
import httpx
import jwt
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

# --- Import from your existing db.py ---
from db import (
    SessionLocal, User, Token, StateToken,
    get_google_token, save_google_token,
    save_state_to_db, get_user_id_from_state_db, delete_state_from_db
)

load_dotenv()

# Environment Variables
CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
# The REDIRECT_URI should be https://your-backend.onrender.com/auth/callback
REDIRECT_URI = os.environ.get("REDIRECT_URI")
JWT_SECRET = os.environ.get("JWT_SECRET", "your_production_secret_key")
JWT_ALG = "HS256"

app = FastAPI(title="AI Data Analyst API")

# --- CORS Configuration ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://aianalyst-gamma.vercel.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

# DB Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# JWT Helper
def decode_jwt(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except:
        return None

# Auth Dependency
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    payload = decode_jwt(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid session")
    user = db.query(User).filter(User.id == payload["user_id"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

# --- OAuth Initiation ---
@app.get("/auth/google_sheets")
async def auth_google_sheets(token: str, return_path: str = "/dashboard/integrations", db: Session = Depends(get_db)):
    payload = decode_jwt(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    user_id = payload["user_id"]
    state_uuid = str(uuid.uuid4())
    
    # Save the intent to the database state table
    save_state_to_db(db, user_id, state_uuid, return_path)
    db.commit()
    
    scopes = [
        "https://www.googleapis.com/auth/spreadsheets.readonly",
        "https://www.googleapis.com/auth/drive.readonly"
    ]
    
    url = (
        f"https://accounts.google.com/o/oauth2/v2/auth?client_id={CLIENT_ID}"
        f"&response_type=code&scope={' '.join(scopes)}"
        f"&redirect_uri={REDIRECT_URI}&access_type=offline&prompt=consent"
        f"&state={state_uuid}"
    )
    return RedirectResponse(url)

# --- OAuth Callback ---
@app.get("/auth/callback")
async def auth_callback(code: str, state: str, db: Session = Depends(get_db)):
    # Verify state from DB
    state_info = get_user_id_from_state_db(db, state)
    if not state_info:
        raise HTTPException(status_code=400, detail="OAuth state expired or invalid")
    
    user_id = state_info["user_id"]
    return_path = state_info["return_path"]

    async with httpx.AsyncClient() as client:
        resp = await client.post("https://oauth2.googleapis.com/token", data={
            "code": code,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "redirect_uri": REDIRECT_URI,
            "grant_type": "authorization_code",
        })
        token_data = resp.json()

    if "access_token" in token_data:
        save_google_token(db, user_id, token_data)
        delete_state_from_db(db, state)
        db.commit()
        
        # Success redirect with flags for the frontend
        return RedirectResponse(f"https://aianalyst-gamma.vercel.app{return_path}?connected=true&type=google_sheets")
    
    return JSONResponse(status_code=400, content={"error": "Failed to retrieve Google token"})

# --- Multi-Tenant Connections Status ---
@app.get("/connected-apps")
async def connected_apps(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    token_rec = get_google_token(db, current_user.id)
    return {
        "google_sheets": token_rec is not None,
        "google_sheets_last_sync": token_rec.created_at.isoformat() if token_rec else None
    }

# --- Disconnect ---
@app.post("/disconnect/google_sheets")
async def disconnect_sheets(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db.query(Token).filter(Token.user_id == current_user.id, Token.service == 'google_sheets').delete()
    db.commit()
    return {"status": "success"}

@app.get("/health")
def health():
    return {"status": "healthy"}