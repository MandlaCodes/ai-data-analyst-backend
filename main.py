from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
import os
import json
from datetime import datetime
from db import SessionLocal, Token
from dotenv import load_dotenv

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

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    raise Exception("OPENAI_API_KEY missing")

app = FastAPI()

# -------------------------
# CORS
# -------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://ai-data-analyst-87smeo628-mandlas-projects-228bb82e.vercel.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------
# DATABASE TOKEN HELPERS
# -------------------------
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

# -------------------------
# GOOGLE OAUTH ROUTES
# -------------------------
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

    # ✅ Redirect to Dashboard with query param to open Integrations tab
    frontend_redirect = (
        f"https://ai-data-analyst-87smeo628-mandlas-projects-228bb82e.vercel.app/dashboard"
        f"?user_id={user_id}&connected=true&type=google_sheets"
    )
    return RedirectResponse(frontend_redirect)

# -------------------------
# CONNECTED APPS
# -------------------------
@app.get("/connected-apps")
async def connected_apps(user_id: str):
    token_data = get_token(user_id)
    return JSONResponse({
        "google_sheets": bool(token_data),
        "google_sheets_last_sync": token_data.get("created_at") if token_data else None
    })

# -------------------------
# LIST GOOGLE SHEETS
# -------------------------
@app.get("/sheets-list/{user_id}")
async def sheets_list(user_id: str):
    token_data = get_token(user_id)
    if not token_data:
        return JSONResponse({"error": "Google Sheets not connected"}, status_code=400)

    headers = {"Authorization": f"Bearer {token_data['access_token']}"}
    params = {
        "q": "mimeType='application/vnd.google-apps.spreadsheet'",
        "fields": "files(id,name)"
    }

    async with httpx.AsyncClient() as http_client:
        resp = await http_client.get(
            "https://www.googleapis.com/drive/v3/files",
            headers=headers,
            params=params
        )
    files = resp.json().get("files", [])

    return JSONResponse({"sheets": files})
