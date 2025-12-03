from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
import os
import json
from datetime import datetime
from db import SessionLocal, Token
from dotenv import load_dotenv
import openai


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

# CORS
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

# DATABASE TOKEN HELPERS
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

# GOOGLE TOKEN REFRESH
async def get_valid_access_token(user_id):
    token_data = get_token(user_id)
    if not token_data:
        return None

    access_token = token_data.get("access_token")
    expires_in = token_data.get("expires_in", 0)
    refresh_token = token_data.get("refresh_token")

    # Refresh if expired
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

# GOOGLE OAUTH ROUTES
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

    frontend_redirect = (
        f"https://ai-data-analyst-swart.vercel.app/integrations"
        f"?user_id={user_id}&connected=true&type=google_sheets&_ts={int(datetime.utcnow().timestamp())}"
    )
    return RedirectResponse(frontend_redirect)

# CONNECTED APPS
@app.get("/connected-apps")
async def connected_apps(user_id: str):
    token_data = get_token(user_id)
    return JSONResponse({
        "google_sheets": bool(token_data),
        "google_sheets_last_sync": token_data.get("created_at") if token_data else None
    })

# LIST GOOGLE SHEETS
@app.get("/sheets-list/{user_id}")
async def sheets_list(user_id: str):
    access_token = await get_valid_access_token(user_id)
    if not access_token:
        return JSONResponse({"error": "Google Sheets not connected"}, status_code=400)

    headers = {"Authorization": f"Bearer {access_token}"}
    params = {
        "q": "mimeType='application/vnd.google-apps.spreadsheet'",
        "fields": "files(id,name)"
    }

    async with httpx.AsyncClient() as http_client:
        resp = await http_client.get("https://www.googleapis.com/drive/v3/files", headers=headers, params=params)

    files = resp.json().get("files", [])
    return JSONResponse({"sheets": files})

# GET SHEET DATA
@app.get("/sheets/{user_id}/{sheet_id}")
async def get_sheet_data(user_id: str, sheet_id: str):
    access_token = await get_valid_access_token(user_id)
    if not access_token:
        return JSONResponse({"error": "Google Sheets not connected"}, status_code=400)

    headers = {"Authorization": f"Bearer {access_token}"}
    url = f"https://sheets.googleapis.com/v4/spreadsheets/{sheet_id}/values:batchGet?ranges=Sheet1"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, headers=headers)

    data = resp.json()
    ranges = data.get("valueRanges", [])
    if not ranges:
        return JSONResponse({"values": []})
    values = ranges[0].get("values", [])
    return JSONResponse({"values": values})

# --------------------------------------------------------------------
# 🔥🔥🔥 AI DATA ANALYSIS ENDPOINT (Option 1) 🔥🔥🔥
# --------------------------------------------------------------------
# --------------------------------------------------------------------
# 🔥 AI DATA ANALYSIS ENDPOINT — METRICS BASED 🔥
# --------------------------------------------------------------------

openai.api_key = os.environ.get("OPENAI_API_KEY")
@app.post("/ai/analyze")
async def ai_analyze(request: Request):
    """
    Analyze data metrics (KPIs, categories) instead of raw rows.
    Returns structured, actionable insights.
    """
    body = await request.json()
    kpis = body.get("kpis")
    categories = body.get("categories")
    row_count = body.get("rowCount", 0)

    if not kpis:
        return JSONResponse({"error": "No KPIs provided"}, status_code=400)

    # Build the prompt
    prompt = f"""
You are an expert business and financial analyst.

You have the following dataset metrics:

- Total rows: {row_count}
- KPIs (numeric metrics per column):
{json.dumps(kpis, indent=2)}

- Categories summary:
{json.dumps(categories, indent=2)}

Analyze the data and provide:
1. High-level overview
2. Trends
3. What is increasing/decreasing
4. Cashflow and profitability signals
5. Anomalies
6. Risks
7. Opportunities
8. Actionable insights to help the business grow

Return your response in a structured format with headings.
"""

    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.7,
            max_tokens=1000
        )
        # Safely access the response
        output = ""
        if response.choices and len(response.choices) > 0:
            output = getattr(response.choices[0].message, "content", "No content returned")
        else:
            output = "No response returned from OpenAI."

        return JSONResponse({"analysis": output})
    except Exception as e:
        # Log the error to server logs
        print("OpenAI API error:", e)
        return JSONResponse({"error": str(e)}, status_code=500)

