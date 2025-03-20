from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from fastapi.responses import RedirectResponse
import os
import json
from dotenv import load_dotenv
import tensorflow as tf
import pickle
from tensorflow.keras.preprocessing.sequence import pad_sequences
import logging
import pandas as pd
import numpy as np
import requests

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Google OAuth2 Credentials
CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:8000/auth/google/callback")
SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile"
]

# Google Safe Browsing API
SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# OAuth2 Flow setup
flow = Flow.from_client_config(
    {
        "web": {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "redirect_uris": [REDIRECT_URI],
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    },
    scopes=SCOPES,
)

# Constants
MAX_LEN = 100
MODEL_DIR = "models"
FEEDBACK_FILE = "feedback_data.csv"

# Load pre-trained models and tokenizer
try:
    deep_model = tf.keras.models.load_model(os.path.join(MODEL_DIR, "deep_feature_extractor.h5"))
    with open(os.path.join(MODEL_DIR, "rf_classifier.pkl"), "rb") as f:
        rf_model = pickle.load(f)
    with open(os.path.join(MODEL_DIR, "tokenizer.pkl"), "rb") as f:
        tokenizer = pickle.load(f)
    logger.info("Models and tokenizer loaded successfully.")
except Exception as e:
    logger.error(f"Failed to load models: {str(e)}")
    deep_model, rf_model, tokenizer = None, None, None

def preprocess_urls(urls, tokenizer, max_len=MAX_LEN):
    sequences = tokenizer.texts_to_sequences(urls)
    padded_sequences = pad_sequences(sequences, maxlen=max_len, padding='post')
    return padded_sequences

def check_domain_reputation(url):
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        has_ssl = url.startswith("https://")
        is_responsive = response.status_code == 200
        return has_ssl and is_responsive
    except requests.RequestException:
        return False

def check_google_safe_browsing(url):
    """Check URL against Google Safe Browsing API"""
    if not SAFE_BROWSING_API_KEY:
        logger.warning("Safe Browsing API key not provided")
        return False  # Assume safe if API key is missing

    payload = {
        "client": {"clientId": "phishing-url-detection-452208", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(
            SAFE_BROWSING_URL,
            params={"key": SAFE_BROWSING_API_KEY},
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload),
            timeout=5
        )
        if response.status_code == 200:
            result = response.json()
            return bool(result.get("matches"))
        else:
            logger.warning(f"Safe Browsing API error: {response.status_code}")
            return False
    except Exception as e:
        logger.error(f"Error checking Safe Browsing: {str(e)}")
        return False

def classify_url(url):
    if not deep_model or not rf_model or not tokenizer:
        raise Exception("Models not loaded")

    padded_url = preprocess_urls([url], tokenizer)
    features = deep_model.predict(padded_url)
    
    # Debug: Log shapes
    logger.info(f"Padded URL shape: {padded_url.shape}")
    logger.info(f"Features shape: {features.shape}")
    logger.info(f"RF expected features: {rf_model.n_features_in_}")

    # If features don't match rf_model expectation, adjust
    expected_features = rf_model.n_features_in_
    if features.shape[1] != expected_features:
        logger.warning(f"Feature mismatch: got {features.shape[1]}, expected {expected_features}")
        # Pad with zeros (or handle differently based on training logic)
        padding = np.zeros((features.shape[0], expected_features - features.shape[1]))
        features = np.hstack((features, padding))

    prediction = rf_model.predict(features)
    probability = rf_model.predict_proba(features)[0][1]

    is_reputable = check_domain_reputation(url)
    is_threat_in_safe_browsing = check_google_safe_browsing(url)

    if is_threat_in_safe_browsing:
        is_phishing = True
        threat_details = "Confirmed phishing by Google Safe Browsing"
    elif probability > 0.9 and not is_reputable:
        is_phishing = True
        threat_details = "High confidence phishing URL (ML model)"
    elif probability > 0.5:
        is_phishing = False
        threat_details = "Suspicious URL - review recommended"
    else:
        is_phishing = False
        threat_details = None if is_reputable else "Low confidence, but verify"

    return {
        "url": url,
        "is_phishing": is_phishing,
        "confidence": float(probability),
        "threatDetails": threat_details,
        "safeBrowsingThreat": is_threat_in_safe_browsing
    }

@app.get("/")
def home():
    return {"message": "FastAPI Google OAuth Server with Phishing Detection"}

@app.get("/auth/google")
def auth_google():
    flow.redirect_uri = REDIRECT_URI
    authorization_url, _ = flow.authorization_url(prompt="consent", include_granted_scopes="true")
    return {"auth_url": authorization_url}

@app.get("/auth/google/callback")
def auth_google_callback(request: Request):
    try:
        query_params = dict(request.query_params)
        if "code" not in query_params:
            raise HTTPException(status_code=400, detail="Authorization code not found")
        flow.fetch_token(code=query_params["code"])
        credentials = flow.credentials
        return RedirectResponse(
            url=f"http://localhost:5173/?access_token={credentials.token}&refresh_token={credentials.refresh_token}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"OAuth2 Error: {str(e)}")

@app.get("/api/refresh-token")
def refresh_access_token(refresh_token: str):
    try:
        if not refresh_token:
            raise HTTPException(status_code=400, detail="Refresh token is required")
        credentials = Credentials(
            None,
            refresh_token=refresh_token,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET
        )
        credentials.refresh(Request())
        return {
            "access_token": credentials.token,
            "expires_in": credentials.expiry
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to refresh token: {str(e)}")

@app.post("/api/network_data")
async def network_data(request: Request):
    """Analyze URL for phishing"""
    try:
        data = await request.json()
        url = data.get("url")
        if not url:
            raise HTTPException(status_code=400, detail="URL is required")

        result = classify_url(url)
        return {
            "status": "success",
            "result": {
                "url": result["url"],
                "isSafe": not result["is_phishing"],
                "threatDetails": result["threatDetails"],
                "confidence": result["confidence"],
                "safeBrowsingThreat": result["safeBrowsingThreat"]
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing URL: {str(e)}")

@app.post("/api/feedback")
async def submit_feedback(request: Request):
    """Endpoint to collect user feedback on URL classification"""
    try:
        data = await request.json()
        url = data.get("url")
        user_label = data.get("is_phishing")
        if url is None or user_label is None:
            raise HTTPException(status_code=400, detail="URL and label required")

        feedback_data = pd.DataFrame({"url": [url], "label": [1 if user_label else 0]})
        if os.path.exists(FEEDBACK_FILE):
            feedback_data.to_csv(FEEDBACK_FILE, mode='a', header=False, index=False)
        else:
            feedback_data.to_csv(FEEDBACK_FILE, mode='w', header=True, index=False)

        return {"status": "success", "message": "Feedback recorded"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error recording feedback: {str(e)}")

@app.get("/api/gmail/messages")
def get_gmail_messages(access_token: str, max_results: int = 10, page_token: str = None):
    try:
        if not access_token:
            raise HTTPException(status_code=400, detail="Access token is required")
        credentials = Credentials(token=access_token)
        service = build("gmail", "v1", credentials=credentials)
        response = service.users().messages().list(
            userId="me",
            maxResults=max_results,
            pageToken=page_token
        ).execute()
        messages = response.get("messages", [])
        next_page_token = response.get("nextPageToken")
        email_details = []
        for msg in messages:
            msg_data = service.users().messages().get(userId="me", id=msg["id"]).execute()
            email_details.append(msg_data)
        return {
            "messages": email_details,
            "nextPageToken": next_page_token
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch emails: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)