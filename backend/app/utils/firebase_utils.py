import json
import os

import firebase_admin
from firebase_admin import auth, credentials, firestore
from dotenv import load_dotenv

load_dotenv()


def _service_account_from_env_parts() -> dict | None:
    project_id = os.getenv("FIREBASE_PROJECT_ID")
    client_email = os.getenv("FIREBASE_CLIENT_EMAIL")
    private_key = os.getenv("FIREBASE_PRIVATE_KEY")

    if not (project_id and client_email and private_key):
        return None

    return {
        "type": "service_account",
        "project_id": project_id,
        "private_key_id": os.getenv("FIREBASE_PRIVATE_KEY_ID", ""),
        "private_key": private_key.replace("\\n", "\n"),
        "client_email": client_email,
        "client_id": os.getenv("FIREBASE_CLIENT_ID", ""),
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": os.getenv("FIREBASE_CLIENT_CERT_URL", ""),
    }


def initialize_firebase():
    if firebase_admin._apps:
        return firestore.client()

    service_account_path = os.getenv("FIREBASE_SERVICE_ACCOUNT_PATH")
    service_account_json = os.getenv("FIREBASE_SERVICE_ACCOUNT_JSON")

    try:
        if service_account_path and os.path.exists(service_account_path):
            cred = credentials.Certificate(service_account_path)
        elif service_account_json:
            cred = credentials.Certificate(json.loads(service_account_json))
        else:
            service_account_parts = _service_account_from_env_parts()
            if not service_account_parts:
                print("Firebase not configured. Report saving/history will be disabled.")
                return None
            cred = credentials.Certificate(service_account_parts)

        firebase_admin.initialize_app(cred)
        return firestore.client()
    except Exception as exc:
        print(f"Firebase initialization failed: {exc}")
        return None


db = initialize_firebase()


def get_db():
    return db


def verify_token(token: str):
    if not token:
        return None

    cleaned = token.strip().replace('"', '').replace("'", "")
    if cleaned.lower().startswith("bearer "):
        cleaned = cleaned[7:].strip()

    if cleaned.count(".") != 2:
        return None

    try:
        return auth.verify_id_token(cleaned)
    except Exception:
        return None
