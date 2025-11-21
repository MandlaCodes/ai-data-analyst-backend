from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
import os
import logging
import json
from datetime import datetime
from openai import OpenAI

try:
    from dotenv import load_dotenv
    load_dotenv()
except:
    pass

from db import SessionLocal, Token

# ---------------------------------------------------
# ENV VARIABLES
# ---------------------------------------------------
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
    raise Exception("OPENAI_API_KEY is missing in Render environment")

# ---------------------------------------------------
# LOGGING
# ---------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("main")

# ---------------------------------------------------
# APP
# ---------------------------------------------------
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://ai-data-analyst-8f97oj3fy-mandlas-projects-228bb82e.vercel.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------
# OPENAI CLIENT
# ---------------------------------------------------
client = OpenAI(api_key=OPENAI_API_KEY)

# ---------------------------------------------------
# TOKEN HELPERS (SQLite)
# ---------------------------------------------------
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

def delete_token(user_id):
    session = SessionLocal()
    token = session.query(Token).filter(Token.user_id == user_id).first()
    if token:
        session.delete(token)
        session.commit()
    session.close()

# ---------------------------------------------------
# OAUTH ROUTES
# ---------------------------------------------------
@app.get("/auth/google")
async def auth_google(user_id: str):
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

@app.get("/auth/google_sheets")
async def auth_google_sheets(user_id: str):
    return await auth_google(user_id)

@app.get("/auth/callback")
async def auth_callback(request: Request, code: str = None, state: str = None):
    if not code:
        return JSONResponse({"error": "No code in callback"}, status_code=400)

    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code"
    }

    async with httpx.AsyncClient() as http_client:
        resp = await http_client.post(token_url, data=data)
        token_data = resp.json()

    if "access_token" not in token_data:
        return JSONResponse({"error": "Failed to retrieve token", "data": token_data}, status_code=400)

    user_id = state or "unknown_user"
    save_token(user_id, token_data)

    # ---------------------------------------------------
    # Redirect back to dashboard integrations page
    # ---------------------------------------------------
    frontend_redirect = (
        f"https://ai-data-analyst-8f97oj3fy-mandlas-projects-228bb82e.vercel.app/"
        f"dashboard/integrations?user_id={user_id}&connected=true&type=google_sheets"
    )
    return RedirectResponse(frontend_redirect)

# ---------------------------------------------------
# CONNECTED APPS
# ---------------------------------------------------
@app.get("/connected-apps")
async def connected_apps(user_id: str):
    token_data = get_token(user_id)
    return JSONResponse({
        "google_sheets": bool(token_data),
        "google_sheets_last_sync": token_data.get("created_at") if token_data else None
    })

# ---------------------------------------------------
# GOOGLE SHEETS LIST
# ---------------------------------------------------
@app.get("/sheets-list/{user_id}")
async def sheets_list(user_id: str):
    token_data = get_token(user_id)
    if not token_data:
        return JSONResponse({"error": "User not connected"}, status_code=400)

    headers = {"Authorization": f"Bearer {token_data['access_token']}"}
    url = "https://www.googleapis.com/drive/v3/files"
    params = {
        "q": "mimeType='application/vnd.google-apps.spreadsheet'",
        "fields": "files(id,name)"
    }

    async with httpx.AsyncClient() as http_client:
        resp = await http_client.get(url, headers=headers, params=params)
        return JSONResponse({"spreadsheets": resp.json().get("files", [])})

# ---------------------------------------------------
# GET SHEET DATA
# ---------------------------------------------------
@app.get("/sheets/{user_id}/{sheet_id:path}")
async def get_sheet(user_id: str, sheet_id: str):
    token_data = get_token(user_id)
    if not token_data:
        return JSONResponse({"error": "User not connected"}, status_code=400)

    headers = {"Authorization": f"Bearer {token_data['access_token']}"}
    url = f"https://sheets.googleapis.com/v4/spreadsheets/{sheet_id}/values/A1:Z1000"

    async with httpx.AsyncClient() as http_client:
        resp = await http_client.get(url, headers=headers)
        return resp.json()

# ---------------------------------------------------
# DISCONNECT
# ---------------------------------------------------
@app.post("/disconnect")
async def disconnect(payload: dict):
    user_id = payload.get("user_id")
    app_type = payload.get("app")

    if app_type == "google_sheets":
        delete_token(user_id)

    return JSONResponse({"status": "disconnected"})

# ---------------------------------------------------
# AI ANALYSIS
# ---------------------------------------------------
@app.post("/analyze-dataset")
async def analyze_dataset(payload: dict):
    dataset = payload.get("dataset")

    if not dataset or not isinstance(dataset, list):
        return JSONResponse({"error": "Invalid dataset"}, status_code=400)

    dataset_str = "\n".join([str(row) for row in dataset])

    prompt = f"""
Analyze this dataset and provide:
- 3 key trends
- anomalies or warnings
- recommendations

Dataset:
{dataset_str}
"""

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.4,
            max_tokens=350
        )
        summary = response.choices[0].message.content.strip()
    except Exception as e:
        logger.error("OpenAI error: %s", e)
        summary = (
            "AI temporarily unavailable. Example summary:\n"
            "- Sales increased 5%\n"
            "- Slight churn reduction\n"
            "- Consider marketing investment"
        )

    return JSONResponse({"summary": summary})

# ---------------------------------------------------
# HEALTH CHECK
# ---------------------------------------------------
@app.get("/")
async def root():
    return {"status": "ok"}
