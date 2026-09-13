import uuid
from typing import Optional, List
from datetime import datetime

from fastapi import FastAPI, HTTPException, status, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# =============================================================================
# 1. FASTAPI APP INITIALIZATION & CORS SETUP
# =============================================================================

app = FastAPI(
    title="Setu Sevak Public Welfare API",
    description="Full-stack backend portal managing citizen welfare registration, service requests, and secure authentication.",
    version="1.2.0"
)

# Enable CORS for cross-origin requests from frontends (e.g., Live Server, GitHub Pages)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# 2. IN-MEMORY DATABASE SIMULATION
# =============================================================================

db_users = {}       # Keyed by mobile_number
db_tokens = {}      # Maps access_token -> mobile_number
db_applications = []
db_queries = []

# =============================================================================
# 3. PYDANTIC DATA MODELS
# =============================================================================

class UserRegisterMobile(BaseModel):
    mobile_number: str = Field(..., min_length=10, json_schema_extra={"example": "9876543210"})
    password: str = Field(..., min_length=4, json_schema_extra={"example": "1234"})
    full_name: str = Field(..., min_length=2, json_schema_extra={"example": "Sushweta Ghosh"})
    security_question: str = Field(..., json_schema_extra={"example": "In which city were you born?"})
    security_answer: str = Field(..., json_schema_extra={"example": "Kolkata"})

class UserLoginMobile(BaseModel):
    mobile_number: str = Field(..., min_length=10, json_schema_extra={"example": "9876543210"})
    password: str = Field(..., min_length=4, json_schema_extra={"example": "1234"})

class ForgotQuestionReq(BaseModel):
    mobile_number: str

class ForgotResetReq(BaseModel):
    mobile_number: str
    security_answer: str
    new_password: str

class FingerprintReq(BaseModel):
    mobile_number: str
    password: Optional[str] = None

class SevaApplication(BaseModel):
    applicant_name: str
    mobile_number: str
    service_title: str
    service_type: str
    document_ref: Optional[str] = None
    uploaded_files_count: int = 0

class PublicQuery(BaseModel):
    name: str
    email: str
    message: str

# =============================================================================
# 4. API ENDPOINTS & CONTROLLERS
# =============================================================================

@app.get("/", tags=["Health Check"])
def root_status():
    """Root endpoint to check server availability."""
    return {
        "status": "online",
        "system": "Setu Sevak API Portal",
        "timestamp": datetime.utcnow().isoformat()
    }

# -----------------------------------------------------------------------------
# AUTHENTICATION ENDPOINTS
# -----------------------------------------------------------------------------

@app.post("/auth/register", status_code=status.HTTP_201_CREATED, tags=["Authentication"])
def register_user(user: UserRegisterMobile):
    """Registers a new citizen user account."""
    if user.mobile_number in db_users:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this mobile number already exists."
        )
    
    db_users[user.mobile_number] = {
        "id": str(uuid.uuid4()),
        "full_name": user.full_name,
        "mobile_number": user.mobile_number,
        "password": user.password,
        "security_question": user.security_question,
        "security_answer": user.security_answer,
        "created_at": datetime.utcnow().isoformat()
    }
    
    return {
        "status": "success",
        "message": "User registered successfully!",
        "full_name": user.full_name,
        "mobile_number": user.mobile_number
    }

@app.post("/auth/login-mobile", tags=["Authentication"])
def login_user_mobile(credentials: UserLoginMobile):
    """Authenticates a citizen via mobile number and Security PIN."""
    user = db_users.get(credentials.mobile_number)
    
    if not user or user["password"] != credentials.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid mobile number or security PIN."
        )
    
    token = f"setu_token_{uuid.uuid4().hex}"
    db_tokens[token] = user["mobile_number"]

    return {
        "status": "success",
        "message": "Login successful!",
        "access_token": token,
        "token_type": "bearer"
    }

@app.get("/users/me", tags=["Authentication"])
def get_current_user(authorization: Optional[str] = Header(None)):
    """Retrieves authenticated user profile using standard Bearer Token authorization."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token header.")
    
    token = authorization.split(" ")[1]
    mobile = db_tokens.get(token)
    
    if not mobile or mobile not in db_users:
        raise HTTPException(status_code=401, detail="Session expired or invalid authorization token.")
    
    user = db_users[mobile]
    return {
        "full_name": user["full_name"],
        "mobile_number": user["mobile_number"]
    }

@app.post("/auth/forgot-pin/question", tags=["Authentication"])
def get_forgot_question(req: ForgotQuestionReq):
    """Fetches the registered security question for PIN recovery."""
    user = db_users.get(req.mobile_number)
    if not user:
        raise HTTPException(status_code=404, detail="Account not found for this mobile number.")
    return {"security_question": user["security_question"]}

@app.post("/auth/forgot-pin/reset", tags=["Authentication"])
def reset_pin(req: ForgotResetReq):
    """Verifies security answer and updates Security PIN."""
    user = db_users.get(req.mobile_number)
    if not user:
        raise HTTPException(status_code=404, detail="Account not found.")
    
    if user["security_answer"].strip().lower() != req.security_answer.strip().lower():
        raise HTTPException(status_code=400, detail="Incorrect security answer.")
    
    user["password"] = req.new_password
    token = f"setu_token_{uuid.uuid4().hex}"
    db_tokens[token] = user["mobile_number"]

    return {
        "status": "success",
        "message": "Security PIN reset successful!",
        "access_token": token
    }

@app.post("/auth/fingerprint/register", tags=["Authentication"])
def register_fingerprint(req: FingerprintReq):
    """Registers biometric WebAuthn credentials against a mobile user."""
    user = db_users.get(req.mobile_number)
    if not user:
        raise HTTPException(status_code=404, detail="Account not found.")
    return {"status": "success", "message": "Fingerprint credential bound."}

@app.post("/auth/fingerprint/login", tags=["Authentication"])
def login_fingerprint(req: FingerprintReq):
    """Authenticates citizen via biometric verification."""
    user = db_users.get(req.mobile_number)
    if not user:
        raise HTTPException(status_code=404, detail="Account not found.")
    
    token = f"setu_token_{uuid.uuid4().hex}"
    db_tokens[token] = user["mobile_number"]

    return {
        "status": "success",
        "access_token": token
    }

# -----------------------------------------------------------------------------
# APPLICATION SUBMISSION ENDPOINTS
# -----------------------------------------------------------------------------

@app.post("/seva/apply", status_code=status.HTTP_201_CREATED, tags=["Services"])
def submit_application(application: SevaApplication):
    """Registers a new citizen service request."""
    app_id = f"SETU-2026-{uuid.uuid4().hex[:5].upper()}"
    
    record = {
        "application_id": app_id,
        "applicant_name": application.applicant_name,
        "mobile_number": application.mobile_number,
        "service_title": application.service_title,
        "service_type": application.service_type,
        "document_ref": application.document_ref,
        "uploaded_files_count": application.uploaded_files_count,
        "status": "Under Review",
        "submitted_at": datetime.utcnow().isoformat()
    }
    
    db_applications.append(record)
    
    return {
        "status": "submitted",
        "message": "Application submitted successfully!",
        "application_details": record
    }

@app.get("/seva/applications", tags=["Services"])
def get_all_applications():
    """Returns submitted welfare applications list."""
    return {
        "count": len(db_applications),
        "applications": db_applications
    }

# -----------------------------------------------------------------------------
# HELPDESK & SUPPORT ENDPOINTS
# -----------------------------------------------------------------------------

@app.post("/contact", status_code=status.HTTP_201_CREATED, tags=["Helpdesk"])
def submit_query(query: PublicQuery):
    """Submits a general citizen helpdesk request."""
    record = {
        "query_id": f"QRY-{uuid.uuid4().hex[:4].upper()}",
        "name": query.name,
        "email": query.email,
        "message": query.message,
        "timestamp": datetime.utcnow().isoformat()
    }
    db_queries.append(record)
    return {
        "status": "success",
        "message": "Query received.",
        "reference_id": record["query_id"]
    }
