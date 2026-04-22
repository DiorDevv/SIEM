import hashlib
import re
from datetime import datetime, timedelta
from typing import Optional, Tuple
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
import redis.asyncio as aioredis
from database import get_db
from models.user import User, UserRole
from config import settings

router = APIRouter(prefix="/api/auth", tags=["auth"])

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

_redis: Optional[aioredis.Redis] = None

async def _get_redis() -> Optional[aioredis.Redis]:
    global _redis
    if _redis is None:
        try:
            _redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
            await _redis.ping()
        except Exception:
            _redis = None
    return _redis


def _token_key(token: str) -> str:
    return "blacklist:" + hashlib.sha256(token.encode()).hexdigest()


LOGIN_RATE_LIMIT   = 5   # attempts
LOGIN_RATE_WINDOW  = 300  # seconds (5 min)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: dict


class RefreshRequest(BaseModel):
    refresh_token: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """Enforce enterprise password policy from settings."""
    min_len = settings.PASSWORD_MIN_LENGTH
    if len(password) < min_len:
        return False, f"Password must be at least {min_len} characters long"
    if settings.PASSWORD_REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if settings.PASSWORD_REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if settings.PASSWORD_REQUIRE_DIGIT and not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    if settings.PASSWORD_REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*()\-_=+\[\]{}|;:,.<>?/~`]', password):
        return False, "Password must contain at least one special character (!@#$%^&* etc.)"
    return True, ""


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_temp_token(data: dict) -> str:
    """Short-lived token issued after password check when 2FA is required."""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=5)
    to_encode.update({"exp": expire, "type": "2fa_pending"})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        token_type: str = payload.get("type")
        if username is None or token_type != "access":
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    # Token blacklist check
    redis = await _get_redis()
    if redis:
        try:
            if await redis.exists(_token_key(token)):
                raise credentials_exception
        except Exception:
            pass

    stmt = select(User).where(User.username == username, User.is_active == True)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if user is None:
        raise credentials_exception
    return user


async def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != UserRole.admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


async def require_analyst(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role == UserRole.viewer:
        raise HTTPException(status_code=403, detail="Analyst or Admin access required")
    return current_user


@router.post("/login")
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    redis = await _get_redis()
    rate_key = f"login_rate:{form_data.username}"

    if redis:
        try:
            attempts = await redis.get(rate_key)
            if attempts and int(attempts) >= LOGIN_RATE_LIMIT:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many login attempts. Try again in 5 minutes.",
                )
        except HTTPException:
            raise
        except Exception:
            pass

    stmt = select(User).where(User.username == form_data.username, User.is_active == True)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not verify_password(form_data.password, user.hashed_password):
        if redis:
            try:
                pipe = redis.pipeline()
                await pipe.incr(rate_key)
                await pipe.expire(rate_key, LOGIN_RATE_WINDOW)
                await pipe.execute()
            except Exception:
                pass
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    if redis:
        try:
            await redis.delete(rate_key)
        except Exception:
            pass

    client_ip = request.client.host if request.client else None

    await db.execute(
        update(User).where(User.id == user.id).values(last_login=datetime.utcnow())
    )

    from services.audit_service import audit

    # ── 2FA gate ─────────────────────────────────────────────
    if user.totp_enabled:
        temp_token = create_temp_token({"sub": user.username, "uid": user.id})
        await audit(db, user, "login_2fa_required", "user", user.id, user.username,
                    ip_address=client_ip)
        return {"requires_2fa": True, "temp_token": temp_token}

    # ── normal login ─────────────────────────────────────────
    await db.execute(
        update(User).where(User.id == user.id).values(last_login=datetime.utcnow())
    )
    await audit(db, user, "login", "user", user.id, user.username, ip_address=client_ip)

    token_data = {"sub": user.username, "role": user.role}
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user={
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "totp_enabled": user.totp_enabled,
        }
    )


@router.post("/refresh")
async def refresh_token(request: RefreshRequest, db: AsyncSession = Depends(get_db)):
    credentials_exception = HTTPException(status_code=401, detail="Invalid refresh token")
    try:
        payload = jwt.decode(request.refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username = payload.get("sub")
        token_type = payload.get("type")
        if not username or token_type != "refresh":
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    stmt = select(User).where(User.username == username, User.is_active == True)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user:
        raise credentials_exception

    token_data = {"sub": user.username, "role": user.role}
    new_access = create_access_token(token_data)
    new_refresh = create_refresh_token(token_data)

    return {"access_token": new_access, "refresh_token": new_refresh, "token_type": "bearer"}


@router.post("/logout")
async def logout(
    token: str = Depends(oauth2_scheme),
    current_user: User = Depends(get_current_user),
):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        exp = payload.get("exp")
        ttl = max(int(exp - datetime.utcnow().timestamp()), 1) if exp else settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        redis = await _get_redis()
        if redis:
            await redis.setex(_token_key(token), ttl, "1")
    except Exception:
        pass
    return {"message": "Logged out successfully"}


@router.get("/me")
async def get_me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role,
        "last_login": current_user.last_login,
        "created_at": current_user.created_at,
        "totp_enabled": current_user.totp_enabled,
    }


@router.post("/change-password")
async def change_password(
    request: ChangePasswordRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not verify_password(request.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    ok, msg = validate_password_strength(request.new_password)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)

    new_hash = hash_password(request.new_password)
    await db.execute(
        update(User).where(User.id == current_user.id).values(hashed_password=new_hash)
    )
    return {"message": "Password changed successfully"}
