from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
import json
import os
import logging
from openai import OpenAI

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("main")

from dotenv import load_dotenv
load_dotenv()

CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

FRONTEND_URL = "https://ai-data-analyst-swart.vercel.app"
FRONTEND_URL_2 = "https://ai-data-analyst-538stxz7v-mandlas-projects-228bb82e.vercel.app"

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        FRONTEND_URL,
        FRONTEND_URL_2,
        "http://localhost:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory DB
connected = {}


# ---------------------------
# GOOGLE SHEETS AUTH START
# ---------------------------
@app.get("/auth/google_sheets")
async def auth_google_sheets(user_id: str):

    redirect_uri = "https://ai-data-analyst-backend-1nuw.onrender.com/auth/callback"

    url = (
        "https://accounts.google.com/o/oauth2/v2/auth?"
        f"client_id={CLIENT_ID}&"
        f"redirect_uri={redirect_uri}&"
        f"response_type=code&"
        "scope=https://www.googleapis.com/auth/drive.readonly "
        "https://www.googleapis.com/auth/spreadsheets.readonly&"
        f"state={user_id}&"
        "access_type=offline&prompt=consent"
    )

    return RedirectResponse(url)


@app.get("/auth/callback")
async def auth_callback(request: Request, state: str, code: str):

    redirect_uri = "https://ai-data-analyst-backend-1nuw.onrender.com/auth/callback"

    token_url = "https://oauth2.googleapis.com/token"

    async with httpx.AsyncClient() as client:
        token_res = await client.post(
            token_url,
            data={
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": redirect_uri,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    token_data = token_res.json()
    logger.info(token_data)

    # Save connection
    connected[state] = True

    # Return HTML that posts a message to frontend
    html = f"""
    <html>
      <body>
        <script>
          window.opener.postMessage("oauth-success", "{FRONTEND_URL}");
          window.opener.postMessage("oauth-success", "{FRONTEND_URL_2}");
          window.opener.postMessage("oauth-success", "http://localhost:5173");
          window.close();
        </script>
      </body>
    </html>
    """

    return HTMLResponse(html)


# ---------------------------
# CONNECTED APPS
# ---------------------------
@app.get("/connected-apps")
async def get_connected(user_id: str):
    return {
        "google_sheets": connected.get(user_id, False)
    }


# ---------------------------
# DISCONNECT
# ---------------------------
@app.post("/disconnect")
async def disconnect_app(data: dict):
    user = data["user_id"]
    app = data["app"]

    if app == "google_sheets":
        connected[user] = False

    return {"status": "disconnected"}
