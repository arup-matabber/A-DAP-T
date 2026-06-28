import os
import requests
from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from app.schemas.user_schema import UserSignupSchema, UserLoginSchema, UserResponseSchema
from app.utils.firebase_utils import verify_token
from firebase_admin import auth

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Formal security scheme for Swagger UI
security = HTTPBearer(auto_error=False)

# Firebase Web API Key
FIREBASE_WEB_API_KEY = os.getenv("FIREBASE_WEB_API_KEY")

class TokenRefreshSchema(BaseModel):
    refreshToken: str


@router.post("/signup", response_model=UserResponseSchema)
def signup(user_data: UserSignupSchema):
    try:
        user = auth.create_user(
            email=user_data.email,
            password=user_data.password,
            display_name=user_data.display_name
        )
        return {
            "uid": user.uid,
            "email": user.email,
            "display_name": user.display_name
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/login")
def login(user_data: UserLoginSchema):
    if not FIREBASE_WEB_API_KEY:
        raise HTTPException(status_code=500, detail="Firebase Web API Key not configured")

    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_WEB_API_KEY}"
    payload = {
        "email": user_data.email,
        "password": user_data.password,
        "returnSecureToken": True
    }

    response = requests.post(url, json=payload)
    if response.status_code != 200:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    data = response.json()
    return {
        "idToken": data.get("idToken"),
        "refreshToken": data.get("refreshToken"),
        "expiresIn": data.get("expiresIn"),
        "localId": data.get("localId"),
        "email": data.get("email"),
        "displayName": data.get("displayName"),
    }


@router.post("/refresh")
def refresh_token(payload: TokenRefreshSchema):
    """
    Exchange a Firebase refresh token for a fresh ID token.

    Frontend ID tokens expire after a short time. The app should refresh them
    instead of forcing users to sign in again during normal use.
    """
    if not FIREBASE_WEB_API_KEY:
        raise HTTPException(status_code=500, detail="Firebase Web API Key not configured")

    refresh_token_value = (payload.refreshToken or "").strip()
    if not refresh_token_value:
        raise HTTPException(status_code=400, detail="Missing refresh token")

    url = f"https://securetoken.googleapis.com/v1/token?key={FIREBASE_WEB_API_KEY}"
    response = requests.post(url, data={
        "grant_type": "refresh_token",
        "refresh_token": refresh_token_value,
    })

    if response.status_code != 200:
        raise HTTPException(status_code=401, detail="Session refresh failed")

    data = response.json()
    return {
        "idToken": data.get("id_token"),
        "refreshToken": data.get("refresh_token"),
        "expiresIn": data.get("expires_in"),
        "localId": data.get("user_id"),
    }


async def get_current_user(res: HTTPAuthorizationCredentials = Depends(security)):
    """
    Dependency to get the current authenticated user from Firebase.
    """
    if not res:
        return None

    token = res.credentials.strip()

    # Verify the token
    decoded_token = verify_token(token)

    if not decoded_token:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    return decoded_token
