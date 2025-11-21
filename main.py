from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
import os
import json
import logging
from datetime import datetime
from db import SessionLocal, Token

# --------------------------
# ENV VARIABLES
# --------------------------
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

FRONTEND_ORIGIN = os.environ.get(
    "FRONTEND_ORIGIN",
    "https://ai-data-analyst-538stxz7v-mandlas-projects-228bb82e.vercel.app"
)

# --------------------------
# LOGGING
# --------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("main")

# --------------------------
# CHECK ENV VARIABLES
# --------------------------
if not CLIENT_ID or not CLIENT_SECRET:
    logger.error("CLIENT_ID or CLIENT_SECRET is missing. Exiting.")
    import sys
    sys.exit(1)

# --------------------------
# APP
# --------------------------
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN, "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# --------------------------
# TOKEN HELPERS
# --------------------------
def save_token(user_email: str, token_data: dict):
    try:
        session = SessionLocal()
        token_data["created_at"] = datetime.utcnow().isoformat()
        data_json = json.dumps(token_data)
        token = session.query(Token).filter(Token.user_id == user_email).first()
        if token:
            token.token_data = data_json
        else:
            token = Token(user_id=user_email, token_data=data_json)
            session.add(token)
        session.commit()
    except Exception as e:
        logger.error(f"Error saving token for {user_email}: {e}")
    finally:
        session.close()

def get_token(user_email: str):
    try:
        session = SessionLocal()
        token = session.query(Token).filter(Token.user_id == user_email).first()
        if token:
            return json.loads(token.token_data)
    except Exception as e:
        logger.error(f"Error getting token for {user_email}: {e}")
    finally:
        session.close()
    return None

def delete_token(user_email: str):
    try:
        session = SessionLocal()
        token = session.query(Token).filter(Token.user_id == user_email).first()
        if token:
            session.delete(token)
            session.commit()
    except Exception as e:
        logger.error(f"Error deleting token for {user_email}: {e}")
    finally:
        session.close()

# --------------------------
# OAUTH ROUTES
# --------------------------
@app.get("/auth/google")
async def auth_google(user_email: str):
    url = (
        "https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={CLIENT_ID}"
        f"&response_type=code"
        f"&scope={SCOPES}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&access_type=offline"
        f"&prompt=consent"
        f"&state={user_email}"
    )
    return RedirectResponse(url)

@app.get("/auth/google_sheets")
async def auth_google_sheets(user_email: str):
    return await auth_google(user_email)

@app.get("/auth/callback")
async def auth_callback(code: str = None, state: str = None):
    if not code:
        return JSONResponse({"error": "No code provided"}, status_code=400)

    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code"
    }

    async with httpx.AsyncClient() as client:
        resp = await client.post(token_url, data=data)
        token_data = resp.json()

    if "access_token" not in token_data:
        return JSONResponse({"error": "Failed to retrieve token", "data": token_data}, status_code=400)

    user_email = state  # Use Google email as user_id
    save_token(user_email, token_data)

    # Redirect to frontend and trigger postMessage
    html_content = f"""
    <html>
      <body>
        <script>
          if (window.opener) {{
            window.opener.postMessage('oauth-success', '{FRONTEND_ORIGIN}');
            window.close();
          }} else {{
            window.location.href = '{FRONTEND_ORIGIN}/integrations?connected=true&type=google_sheets&user_email={user_email}';
          }}
        </script>
        <p>Login successful. You can close this window.</p>
      </body>
    </html>
    """
    return HTMLResponse(html_content)

# --------------------------
# CONNECTED APPS
# --------------------------
@app.get("/connected-apps")
async def connected_apps(user_email: str):
    token_data = get_token(user_email)
    return JSONResponse({
        "google_sheets": bool(token_data),
        "google_sheets_last_sync": token_data.get("created_at") if token_data else None
    })

# --------------------------
# DISCONNECT
# --------------------------
@app.post("/disconnect")
async def disconnect(payload: dict):
    user_email = payload.get("user_email")
    app_type = payload.get("app")
    if app_type == "google_sheets":
        delete_token(user_email)
    return JSONResponse({"status": "disconnected"})
