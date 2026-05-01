"""
TOTP-based two-factor authentication.

Setup flow:
  POST /api/auth/totp/setup           → secret + QR code (base64 PNG)
  POST /api/auth/totp/verify-setup    → verify code, enable 2FA, return backup codes

Login flow (when user has 2FA enabled):
  POST /api/auth/login returns { requires_2fa: true, temp_token }
  POST /api/auth/login/2fa { temp_token, code } → full TokenResponse

Management:
  DELETE /api/auth/totp/disable       → disable 2FA (requires password + TOTP)
  POST   /api/auth/totp/backup-codes  → regenerate backup codes (requires TOTP)
"""
import base64
import io
import json
import secrets
from datetime import datetime, timedelta

import pyotp
import qrcode
from fastapi import APIRouter, Depends, HTTPException, status
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import get_db
from models.user import User
from routes.auth import (
    get_current_user, verify_password,
    create_access_token, create_refresh_token,
)
from services.audit_service import audit

router = APIRouter(prefix="/api/auth/totp", tags=["2fa"])

_backup_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

BACKUP_CODE_COUNT  = 8
TOTP_ISSUER        = "SecureWatch SIEM"
TOTP_WINDOW        = 1   # ±1 period tolerance (30 s each side)


# ── helpers ───────────────────────────────────────────────────────────────────

def _gen_backup_codes() -> tuple[list[str], list[str]]:
    """Return (plain_codes, hashed_codes). Plain shown once; hashes stored in DB."""
    plain  = [secrets.token_hex(4) + "-" + secrets.token_hex(4) for _ in range(BACKUP_CODE_COUNT)]
    hashed = [_backup_ctx.hash(c) for c in plain]
    return plain, hashed


def _verify_backup(code: str, hashes: list[str]) -> tuple[bool, list[str]]:
    """Try to match code against stored hashes. Returns (matched, remaining_hashes)."""
    code_clean  = code.strip().lower()
    code_nodash = code_clean.replace("-", "")
    for i, h in enumerate(hashes):
        try:
            if _backup_ctx.verify(code_clean, h) or _backup_ctx.verify(code_nodash, h):
                return True, [x for j, x in enumerate(hashes) if j != i]
        except Exception:
            continue
    return False, hashes


def _qr_base64(uri: str) -> str:
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


# ── request schemas ───────────────────────────────────────────────────────────

class VerifySetupRequest(BaseModel):
    code: str


class DisableRequest(BaseModel):
    password: str
    code: str          # current TOTP or backup code


class RegenerateRequest(BaseModel):
    code: str          # current TOTP to prove ownership


class TwoFALoginRequest(BaseModel):
    temp_token: str
    code: str          # 6-digit TOTP or backup code


# ── setup ─────────────────────────────────────────────────────────────────────

@router.post("/setup")
async def setup_totp(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Generate a new TOTP secret and return the QR code. Does NOT enable 2FA yet."""
    if current_user.totp_enabled:
        raise HTTPException(status_code=400, detail="2FA is already enabled")

    secret = pyotp.random_base32()
    uri    = pyotp.TOTP(secret).provisioning_uri(
        name=current_user.username,
        issuer_name=TOTP_ISSUER,
    )

    # Store secret temporarily (not yet active — totp_enabled stays False)
    await db.execute(
        update(User).where(User.id == current_user.id).values(totp_secret=secret)
    )

    return {
        "secret":   secret,
        "qr_code":  _qr_base64(uri),
        "otpauth":  uri,
    }


@router.post("/verify-setup")
async def verify_setup(
    req: VerifySetupRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Verify the first TOTP code, enable 2FA, return backup codes (shown once)."""
    if current_user.totp_enabled:
        raise HTTPException(status_code=400, detail="2FA is already enabled")
    if not current_user.totp_secret:
        raise HTTPException(status_code=400, detail="Run /setup first")

    totp = pyotp.TOTP(current_user.totp_secret)
    if not totp.verify(req.code.strip(), valid_window=TOTP_WINDOW):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")

    plain_codes, hashed_codes = _gen_backup_codes()

    await db.execute(
        update(User).where(User.id == current_user.id).values(
            totp_enabled=True,
            totp_backup_codes=json.dumps(hashed_codes),
        )
    )
    await audit(db, current_user, "enable_2fa", "user", current_user.id, current_user.username)

    return {
        "enabled":      True,
        "backup_codes": plain_codes,
        "message": "2FA enabled. Save these backup codes — they won't be shown again.",
    }


# ── login/2fa ─────────────────────────────────────────────────────────────────

@router.post("/login")
async def login_2fa(
    req: TwoFALoginRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Second factor of login.
    Accepts the temp_token from /api/auth/login plus a 6-digit TOTP or a backup code.
    Returns full access + refresh tokens on success.
    """
    invalid = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid or expired 2FA token")
    try:
        payload = jwt.decode(req.temp_token, settings.SECRET_KEY,
                             algorithms=[settings.ALGORITHM])
        if payload.get("type") != "2fa_pending":
            raise invalid
        username: str = payload.get("sub")
        if not username:
            raise invalid
    except JWTError:
        raise invalid

    result = await db.execute(
        select(User).where(User.username == username, User.is_active == True)
    )
    user = result.scalar_one_or_none()
    if not user or not user.totp_enabled or not user.totp_secret:
        raise invalid

    code = req.code.strip().replace(" ", "")
    verified = False

    # ── Try TOTP ──────────────────────────────────────────────
    if code.isdigit() and len(code) == 6:
        verified = pyotp.TOTP(user.totp_secret).verify(code, valid_window=TOTP_WINDOW)

    # ── Try backup code ───────────────────────────────────────
    if not verified and user.totp_backup_codes:
        stored = json.loads(user.totp_backup_codes)
        matched, remaining = _verify_backup(code, stored)
        if matched:
            verified = True
            # consume the backup code
            await db.execute(
                update(User).where(User.id == user.id).values(
                    totp_backup_codes=json.dumps(remaining)
                )
            )

    if not verified:
        await audit(db, user, "login_2fa_failed", "user", user.id, user.username)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid 2FA code")

    await db.execute(
        update(User).where(User.id == user.id).values(last_login=datetime.utcnow())
    )
    await audit(db, user, "login", "user", user.id, user.username)

    token_data    = {"sub": user.username, "role": user.role}
    access_token  = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    return {
        "access_token":  access_token,
        "refresh_token": refresh_token,
        "token_type":    "bearer",
        "user": {
            "id":           user.id,
            "username":     user.username,
            "email":        user.email,
            "role":         user.role,
            "totp_enabled": user.totp_enabled,
        },
    }


# ── disable ───────────────────────────────────────────────────────────────────

@router.delete("/disable")
async def disable_totp(
    req: DisableRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Disable 2FA. Requires current password + live TOTP code."""
    if not current_user.totp_enabled:
        raise HTTPException(status_code=400, detail="2FA is not enabled")
    if not verify_password(req.password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect password")

    code     = req.code.strip().replace(" ", "")
    verified = pyotp.TOTP(current_user.totp_secret).verify(code, valid_window=TOTP_WINDOW)

    if not verified and current_user.totp_backup_codes:
        stored   = json.loads(current_user.totp_backup_codes)
        verified, _ = _verify_backup(code, stored)

    if not verified:
        raise HTTPException(status_code=400, detail="Invalid 2FA code")

    await db.execute(
        update(User).where(User.id == current_user.id).values(
            totp_enabled=False,
            totp_secret=None,
            totp_backup_codes=None,
        )
    )
    await audit(db, current_user, "disable_2fa", "user", current_user.id, current_user.username)
    return {"disabled": True}


# ── backup codes ──────────────────────────────────────────────────────────────

@router.post("/backup-codes/regenerate")
async def regenerate_backup_codes(
    req: RegenerateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Regenerate backup codes. Requires a live TOTP code."""
    if not current_user.totp_enabled:
        raise HTTPException(status_code=400, detail="2FA is not enabled")

    code = req.code.strip().replace(" ", "")
    if not pyotp.TOTP(current_user.totp_secret).verify(code, valid_window=TOTP_WINDOW):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")

    plain_codes, hashed_codes = _gen_backup_codes()
    await db.execute(
        update(User).where(User.id == current_user.id).values(
            totp_backup_codes=json.dumps(hashed_codes)
        )
    )
    await audit(db, current_user, "regenerate_backup_codes", "user",
                current_user.id, current_user.username)

    return {
        "backup_codes": plain_codes,
        "message": "New backup codes generated. Save them — they won't be shown again.",
    }


@router.get("/backup-codes/count")
async def backup_codes_count(
    current_user: User = Depends(get_current_user),
):
    """Return how many backup codes remain (without revealing them)."""
    if not current_user.totp_enabled or not current_user.totp_backup_codes:
        return {"count": 0}
    return {"count": len(json.loads(current_user.totp_backup_codes))}
