import json
import os
import uvicorn
from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field
from typing import Dict

app = FastAPI(
    title="Setu Sevak Backend",
    description="API services for citizen authentication and portal management",
    version="1.1.0"
)

# 1. Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "null",  # allows requests from file:// pages opened directly in a browser
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 2. Persistent storage (replace with a real SQL/NoSQL database in production)
DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users_db.json")


def load_db() -> Dict[str, dict]:
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def save_db() -> None:
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(db_users, f, indent=2)


db_users: Dict[str, dict] = load_db()

# OAuth2 scheme definition for Bearer token validation
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login-mobile")


# 3. Pydantic Input Validation Models
class UserRegister(BaseModel):
    mobile_number: str = Field(..., min_length=10, max_length=10, description="10-digit mobile number")
    password: str = Field(..., min_length=4, max_length=8, description="4 to 8 digit PIN/Passkey")
    full_name: str = Field(..., min_length=2, description="Full legal name of the citizen")
    security_question: str = Field(..., min_length=5, description="Chosen security question for PIN recovery")
    security_answer: str = Field(..., min_length=1, description="Answer to the chosen security question")

class UserLogin(BaseModel):
    mobile_number: str = Field(..., min_length=10, max_length=10)
    password: str = Field(..., min_length=4, max_length=8)

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class UserProfileResponse(BaseModel):
    mobile_number: str
    full_name: str

class ForgotPinQuestionRequest(BaseModel):
    mobile_number: str = Field(..., min_length=10, max_length=10)

class ForgotPinQuestionResponse(BaseModel):
    security_question: str

class ForgotPinResetRequest(BaseModel):
    mobile_number: str = Field(..., min_length=10, max_length=10)
    security_answer: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=4, max_length=8)

class FingerprintRegisterRequest(BaseModel):
    mobile_number: str = Field(..., min_length=10, max_length=10)
    password: str = Field(..., min_length=4, max_length=8)

class FingerprintLoginRequest(BaseModel):
    mobile_number: str = Field(..., min_length=10, max_length=10)


# 4. Helper Authentication Dependency
def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    # Token format: "mock-token-<mobile_number>"
    if not token.startswith("mock-token-"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token header.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    mobile = token.replace("mock-token-", "")
    user = db_users.get(mobile)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User session profile not found."
        )
    return user


# 5. API Endpoints
@app.get("/")
def root():
    """Simple health check so hitting the base URL doesn't just 404."""
    return {"status": "ok", "service": "Setu Sevak Backend"}


@app.post("/auth/register", status_code=status.HTTP_201_CREATED, response_model=UserProfileResponse)
def register(user_data: UserRegister):
    """Registers a new citizen with mobile number, passkey, and a security question."""
    if user_data.mobile_number in db_users:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Mobile number already registered."
        )

    user_record = {
        "mobile_number": user_data.mobile_number,
        "password": user_data.password,  # In production, hash this password using bcrypt
        "full_name": user_data.full_name,
        "security_question": user_data.security_question,
        "security_answer": user_data.security_answer.strip().lower(),  # normalized for comparison
        "fingerprint_enabled": False
    }
    db_users[user_data.mobile_number] = user_record
    save_db()

    return UserProfileResponse(
        mobile_number=user_record["mobile_number"],
        full_name=user_record["full_name"]
    )


@app.post("/auth/login-mobile", response_model=TokenResponse)
def login_mobile(credentials: UserLogin):
    """Authenticates citizen credentials and returns an access token."""
    user = db_users.get(credentials.mobile_number)

    if not user or user["password"] != credentials.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid mobile number or security PIN."
        )

    generated_token = f"mock-token-{user['mobile_number']}"
    return TokenResponse(access_token=generated_token)


@app.get("/users/me", response_model=UserProfileResponse)
def read_users_me(current_user: dict = Depends(get_current_user)):
    """Retrieves authenticated citizen details for pre-filling application wizards."""
    return UserProfileResponse(
        mobile_number=current_user["mobile_number"],
        full_name=current_user["full_name"]
    )


@app.post("/auth/forgot-pin/question", response_model=ForgotPinQuestionResponse)
def get_security_question(payload: ForgotPinQuestionRequest):
    """Returns the security question for a registered mobile number, so the
    citizen can answer it to reset a forgotten PIN."""
    user = db_users.get(payload.mobile_number)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No account found for this mobile number."
        )
    return ForgotPinQuestionResponse(security_question=user["security_question"])


@app.post("/auth/forgot-pin/reset", response_model=TokenResponse)
def reset_pin(payload: ForgotPinResetRequest):
    """Verifies the security answer and resets the PIN, returning a fresh token."""
    user = db_users.get(payload.mobile_number)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No account found for this mobile number."
        )

    if payload.security_answer.strip().lower() != user["security_answer"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Security answer did not match our records."
        )

    user["password"] = payload.new_password
    save_db()

    generated_token = f"mock-token-{user['mobile_number']}"
    return TokenResponse(access_token=generated_token)


@app.post("/auth/fingerprint/register", status_code=status.HTTP_200_OK)
def enable_fingerprint(payload: FingerprintRegisterRequest):
    """Marks fingerprint/biometric login as enabled for this account.

    NOTE: This is a simplified mock. A production implementation should use a
    real WebAuthn/FIDO2 flow rather than just flipping a boolean flag.
    """
    user = db_users.get(payload.mobile_number)
    if not user or user["password"] != payload.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid mobile number or security PIN."
        )

    user["fingerprint_enabled"] = True
    save_db()
    return {"status": "fingerprint_enabled"}


@app.post("/auth/fingerprint/login", response_model=TokenResponse)
def fingerprint_login(payload: FingerprintLoginRequest):
    """Issues a token after the browser's WebAuthn platform authenticator
    (fingerprint / Face ID) has already succeeded client-side."""
    user = db_users.get(payload.mobile_number)
    if not user or not user.get("fingerprint_enabled"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Fingerprint login is not enabled for this account."
        )

    generated_token = f"mock-token-{user['mobile_number']}"
    return TokenResponse(access_token=generated_token)


# 6. Programmatic Server Launch
if __name__ == "__main__":
    uvicorn.run("backendseva:app", host="127.0.0.1", port=8000, reload=True)
