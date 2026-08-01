"""
BreachScope — API Server (FastAPI)
"""
from fastapi import FastAPI, HTTPException, Depends, Request, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timedelta, timezone
import uuid
import os
import asyncio
from pathlib import Path

from ..core.database import get_session, init_db, AsyncSessionLocal
from ..core.config import settings
from ..core.crypto import (
    sha256_hash, generate_otp, generate_api_key,
    create_jwt_token, verify_jwt_token, argon2_hash,
    normalize_email, normalize_phone, normalize_username
)
from ..core.models import Breach, BreachRecord, User, VerificationToken, SearchLog, MonitorAlert
from ..core.search import (
    search_by_email, search_by_username, search_by_phone,
    search_by_domain, get_verified_data, get_stats
)
from ..ingestion.parser import ingest_file, detect_format

app = FastAPI(
    title="BreachScope",
    description="Advanced Breach Intelligence Platform",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============ MODELS ============

class SearchRequest(BaseModel):
    query: str
    query_type: str = "email"  # email, username, phone, domain

class VerifyRequest(BaseModel):
    email: EmailStr

class VerifyConfirm(BaseModel):
    email: EmailStr
    otp: str

class IngestRequest(BaseModel):
    breach_name: str
    source_name: str = None
    breach_date: str = None
    description: str = None

class AlertRequest(BaseModel):
    email: EmailStr
    notification_email: EmailStr = None


# ============ RATE LIMITING ============

rate_limit_store: dict = {}  # ip -> [timestamps]

def check_rate_limit(request: Request, limit: int, window: int = 60):
    """Simple in-memory rate limiter."""
    client_ip = request.client.host if request.client else "unknown"
    now = datetime.now(timezone.utc).timestamp()

    if client_ip not in rate_limit_store:
        rate_limit_store[client_ip] = []

    # Clean old entries
    rate_limit_store[client_ip] = [
        ts for ts in rate_limit_store[client_ip]
        if now - ts < window
    ]

    if len(rate_limit_store[client_ip]) >= limit:
        raise HTTPException(429, "Rate limit exceeded. Try again later.")

    rate_limit_store[client_ip].append(now)


# ============ AUTH ============

async def get_current_user(request: Request, session: AsyncSession = Depends(get_session)):
    """Extract and verify JWT from Authorization header."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None

    token = auth.replace("Bearer ", "")
    try:
        payload = verify_jwt_token(token)
        user_id = payload.get("user_id")
        if user_id:
            user = await session.get(User, user_id)
            return user
    except Exception:
        pass
    return None


async def require_admin(request: Request, session: AsyncSession = Depends(get_session)):
    """Require admin user."""
    user = await get_current_user(request, session)
    if not user or not user.is_admin:
        raise HTTPException(403, "Admin access required")
    return user


# ============ ENDPOINTS ============

@app.on_event("startup")
async def startup():
    await init_db()


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}


@app.post("/api/search")
async def api_search(
    req: SearchRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    """Search for breaches — returns BOOLEAN ONLY, never exposes data."""
    check_rate_limit(request, settings.rate_limit_search)

    if req.query_type == "email":
        result = await search_by_email(session, req.query)
    elif req.query_type == "username":
        result = await search_by_username(session, req.query)
    elif req.query_type == "phone":
        result = await search_by_phone(session, req.query)
    elif req.query_type == "domain":
        result = await search_by_domain(session, req.query)
    else:
        raise HTTPException(400, "Invalid query_type. Use: email, username, phone, domain")

    # Log search for audit
    log = SearchLog(
        query=req.query,
        query_type=req.query_type,
        result_found=result.found,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent", "")[:256],
    )
    session.add(log)
    await session.commit()

    return result.to_dict()


@app.post("/api/verify/request")
async def api_verify_request(
    req: VerifyRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    """Request OTP to verify email ownership before viewing breach data."""
    check_rate_limit(request, settings.rate_limit_verify)

    email = normalize_email(req.email)
    otp = generate_otp()
    otp_hash = argon2_hash(otp)

    # Store verification token
    token = VerificationToken(
        email=email,
        token_hash=otp_hash,
        expires_date=datetime.now(timezone.utc) + timedelta(seconds=settings.otp_ttl_seconds),
        ip_address=request.client.host if request.client else None,
        query_identifier=email,
    )
    session.add(token)
    await session.commit()

    # In production: send OTP via email (SMTP/SES/SendGrid)
    # For now: return it (development mode)
    return {
        "message": "OTP sent to your email. Check your inbox.",
        "token_id": token.id,
        "dev_otp": otp,  # REMOVE IN PRODUCTION
        "ttl": settings.otp_ttl_seconds,
    }


@app.post("/api/verify/confirm")
async def api_verify_confirm(
    req: VerifyConfirm,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    """Confirm OTP and return FULL breach data for the verified email."""
    check_rate_limit(request, settings.rate_limit_verify)

    email = normalize_email(req.email)

    # Find unused, non-expired token
    stmt = (
        select(VerificationToken)
        .where(
            VerificationToken.email == email,
            VerificationToken.used == False,
            VerificationToken.expires_date > datetime.now(timezone.utc),
        )
        .order_by(VerificationToken.created_date.desc())
    )
    result = await session.execute(stmt)
    token = result.scalar_one_or_none()

    if not token:
        raise HTTPException(400, "No valid verification token found. Request a new OTP.")

    # Verify OTP
    from ..core.crypto import verify_argon2
    if not verify_argon2(token.token_hash, req.otp):
        raise HTTPException(400, "Invalid OTP code.")

    # Mark token as used
    token.used = True
    await session.commit()

    # Return full breach data
    data = await get_verified_data(session, email)
    return data


@app.get("/api/breaches")
async def list_breaches(session: AsyncSession = Depends(get_session)):
    """List all indexed breaches (metadata only, no records)."""
    stmt = select(Breach).order_by(Breach.ingested_date.desc())
    result = await session.execute(stmt)
    breaches = result.scalars().all()

    return [
        {
            "name": b.name,
            "source": b.source_name,
            "date": b.breach_date.isoformat() if b.breach_date else None,
            "records": b.record_count,
            "data_types": b.data_types,
            "verified": b.is_verified,
            "description": b.description,
        }
        for b in breaches
    ]


@app.post("/api/ingest")
async def api_ingest(
    request: Request,
    file: UploadFile = File(...),
    breach_name: str = Form(...),
    source_name: str = Form(None),
    breach_date: str = Form(None),
    description: str = Form(None),
    session: AsyncSession = Depends(get_session),
):
    """Upload and ingest a breach file. Admin only."""
    user = await get_current_user(request, session)
    if not user or not user.is_admin:
        raise HTTPException(403, "Admin access required to ingest data.")

    # Save uploaded file
    upload_dir = Path(settings.base_dir) / "data" / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    file_path = upload_dir / f"{breach_name}_{file.filename}"

    content = await file.read()
    if len(content) > settings.max_upload_size_mb * 1024 * 1024:
        raise HTTPException(413, f"File too large. Max: {settings.max_upload_size_mb}MB")

    file_path.write_bytes(content)

    # Parse date
    parsed_date = None
    if breach_date:
        try:
            parsed_date = datetime.fromisoformat(breach_date)
        except ValueError:
            pass

    # Ingest
    try:
        stats = await ingest_file(
            file_path=str(file_path),
            breach_name=breach_name,
            source_name=source_name,
            breach_date=parsed_date,
            description=description,
        )
        return stats
    except Exception as e:
        raise HTTPException(400, f"Ingestion failed: {str(e)}")


@app.get("/api/stats")
async def api_stats(session: AsyncSession = Depends(get_session)):
    """Get platform statistics."""
    return await get_stats(session)


@app.post("/api/alerts")
async def create_alert(
    req: AlertRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    """Create a monitoring alert — notifies when email appears in new breaches."""
    email = normalize_email(req.email)

    # Create or get user
    stmt = select(User).where(User.email == email)
    result = await session.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        user = User(email=email, email_verified=False, api_key=generate_api_key())
        session.add(user)
        await session.commit()
        await session.refresh(user)

    # Check for existing alert
    stmt = select(MonitorAlert).where(
        MonitorAlert.user_id == user.id,
        MonitorAlert.email == email,
        MonitorAlert.is_active == True,
    )
    result = await session.execute(stmt)
    existing = result.scalar_one_or_none()

    if existing:
        raise HTTPException(409, "Alert already exists for this email.")

    alert = MonitorAlert(
        user_id=user.id,
        email=email,
        notification_email=req.notification_email or email,
        is_active=True,
    )
    session.add(alert)
    await session.commit()

    return {"message": "Monitoring alert created. We'll notify you if this email appears in new breaches."}


@app.delete("/api/alerts/{alert_id}")
async def delete_alert(
    alert_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    """Delete a monitoring alert."""
    user = await get_current_user(request, session)
    if not user:
        raise HTTPException(401, "Authentication required.")

    alert = await session.get(MonitorAlert, alert_id)
    if not alert or alert.user_id != user.id:
        raise HTTPException(404, "Alert not found.")

    alert.is_active = False
    await session.commit()
    return {"message": "Alert deleted."}


# ============ AUTH ENDPOINTS ============

@app.post("/api/auth/register")
async def register(
    email: EmailStr,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    """Register a new user."""
    email = normalize_email(email)

    stmt = select(User).where(User.email == email)
    result = await session.execute(stmt)
    if result.scalar_one_or_none():
        raise HTTPException(409, "Email already registered.")

    user = User(
        email=email,
        api_key=generate_api_key(),
        is_admin=False,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)

    token = create_jwt_token({"user_id": user.id, "email": user.email})
    return {"token": token, "api_key": user.api_key}


@app.post("/api/auth/login")
async def login(
    email: EmailStr,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    """Login — returns JWT token."""
    email = normalize_email(email)

    stmt = select(User).where(User.email == email)
    result = await session.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(404, "User not found. Register first.")

    token = create_jwt_token({"user_id": user.id, "email": user.email})
    return {"token": token, "api_key": user.api_key}


# ============ WEB UI ============

@app.get("/", response_class=HTMLResponse)
async def index():
    """Serve the web dashboard."""
    web_dir = Path(__file__).parent.parent / "web" / "templates"
    html = (web_dir / "index.html").read_text()
    return HTMLResponse(html)


def run():
    """Run the API server."""
    import uvicorn
    uvicorn.run(
        app,
        host=settings.api_host,
        port=settings.api_port,
    )
