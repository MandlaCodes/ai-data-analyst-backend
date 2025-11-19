from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
import json
import os
import logging
from openai import OpenAI
from dotenv import load_dotenv

# ---------------------------
# Load environment variables
# ---------------------------
load_dotenv()  # Load .env file

CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI", "http://127.0.0.1:8000/auth/callback")
SCOPES = os.getenv("SCOPES", "https://www.googleapis.com/auth/spreadsheets.readonly https://www.googleapis.com/auth/drive.readonly")
TOKENS_FILE = os.getenv("TOKENS_FILE", "tokens.json")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# ---------------------------
# Logging
# ---------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("main")

# ---------------------------
# FastAPI app
# ---------------------------
app = FastAPI()

# Allow frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------
# OpenAI client
# ---------------------------
client = OpenAI(api_key=OPENAI_API_KEY)

# ---------------------------
# Token storage
# ---------------------------
if os.path.exists(TOKENS_FILE):
    with open(TOKENS_FILE, "r") as f:
        tokens_store = json.load(f)
else:
    tokens_store = {}

def save_tokens():
    with open(TOKENS_FILE, "w") as f:
        json.dump(tokens_store, f, indent=2)

# ---------------------------
# OAuth routes
# ---------------------------
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

    async with httpx.AsyncClient() as client_http:
        resp = await client_http.post(token_url, data=data)
        token_data = resp.json()

    if "access_token" not in token_data:
        return JSONResponse({"error": "Failed to get access token", "details": token_data}, status_code=400)

    user_id = state or "unknown_user"
    tokens_store[user_id] = token_data
    save_tokens()

    redirect_url = f"http://localhost:3000/integrations?user_id={user_id}&connected=true&type=google_sheets"
    return RedirectResponse(redirect_url)

# ---------------------------
# Connected apps
# ---------------------------
@app.get("/connected-apps")
async def connected_apps(user_id: str):
    return JSONResponse({"google_sheets": user_id in tokens_store})

# ---------------------------
# Google Sheets API
# ---------------------------
@app.get("/sheets-list/{user_id}")
async def sheets_list(user_id: str):
    if user_id not in tokens_store:
        return JSONResponse({"error": "User not connected"}, status_code=400)

    access_token = tokens_store[user_id]["access_token"]

    files_url = "https://www.googleapis.com/drive/v3/files"
    params = {
        "q": "mimeType='application/vnd.google-apps.spreadsheet'",
        "fields": "files(id,name)"
    }
    headers = {"Authorization": f"Bearer {access_token}"}

    async with httpx.AsyncClient() as client_http:
        resp = await client_http.get(files_url, headers=headers, params=params)
        data = resp.json()

    return JSONResponse({"spreadsheets": data.get("files", [])})

@app.get("/sheets/{user_id}/{sheet_id:path}")
async def get_sheet(user_id: str, sheet_id: str):
    if user_id not in tokens_store:
        return JSONResponse({"error": "User not connected"}, status_code=400)

    access_token = tokens_store[user_id]["access_token"]
    url = f"https://sheets.googleapis.com/v4/spreadsheets/{sheet_id}/values/A1:Z1000"
    headers = {"Authorization": f"Bearer {access_token}"}

    async with httpx.AsyncClient() as client_http:
        resp = await client_http.get(url, headers=headers)
        sheet_data = resp.json()

    return sheet_data

# ---------------------------
# Disconnect
# ---------------------------
@app.post("/disconnect")
async def disconnect(payload: dict):
    user_id = payload.get("user_id")
    app_key = payload.get("app")
    if app_key == "google_sheets" and user_id in tokens_store:
        del tokens_store[user_id]
        save_tokens()
    return JSONResponse({"status": "disconnected"})

# ---------------------------
# Analyze dataset (AI)
# ---------------------------
@app.post("/analyze-dataset")
async def analyze_dataset(payload: dict):
    user_id = payload.get("user_id")
    dataset = payload.get("dataset")

    if not dataset or not isinstance(dataset, list):
        return JSONResponse({"error": "Dataset missing or invalid"}, status_code=400)

    dataset_str = "\n".join([str(row) for row in dataset])
    prompt = f"""
You are an AI assistant for business analytics.
Analyze the following dataset and provide:

1. Key trends (top 3 KPIs with biggest change)
2. Any anomalies or warnings
3. Suggested actions or recommendations in bullet points

Dataset:
{dataset_str}

Provide a concise summary suitable for a dashboard.
"""

    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.5,
            max_tokens=400
        )
        summary = response.choices[0].message.content.strip()
    except Exception as e:
        logger.error("OpenAI API error: %s", e)
        summary = (
            "AI insights temporarily unavailable. "
            "Here is a mock summary:\n"
            "- Revenue increased by 5% last month\n"
            "- Customer churn decreased slightly\n"
            "- Consider investing in marketing campaigns targeting new segments"
        )

    return JSONResponse({"summary": summary})

# ---------------------------
# Send alert stub
# ---------------------------
@app.post("/send-alert")
async def send_alert(payload: dict):
    user_id = payload.get("user_id")
    subject = payload.get("subject")
    message = payload.get("message")
    logger.info("send-alert user=%s subject=%s", user_id, subject)
    return JSONResponse({"status": "alert_sent"})

# ---------------------------
# Root health check
# ---------------------------
@app.get("/")
async def root():
    return JSONResponse({"status": "ok"})
