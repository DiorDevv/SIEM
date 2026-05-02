"""
User management API — admin-only endpoints for creating and managing users.
"""
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.user import User, UserRole
from routes.auth import hash_password, require_admin, get_current_user
from services.audit_service import audit

router = APIRouter(prefix="/api/users", tags=["users"])


class CreateUserRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: UserRole = UserRole.analyst

    @field_validator("username")
    @classmethod
    def username_valid(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 3:
            raise ValueError("Username must be at least 3 characters")
        if len(v) > 64:
            raise ValueError("Username too long")
        return v

    @field_validator("password")
    @classmethod
    def password_valid(cls, v: str) -> str:
        if len(v) < 6:
            raise ValueError("Password must be at least 6 characters")
        return v


class UpdateUserRequest(BaseModel):
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None
    email: Optional[EmailStr] = None


class ResetPasswordRequest(BaseModel):
    new_password: str

    @field_validator("new_password")
    @classmethod
    def pw_valid(cls, v: str) -> str:
        if len(v) < 6:
            raise ValueError("Password must be at least 6 characters")
        return v


def _user_dict(u: User) -> dict:
    return {
        "id":         u.id,
        "username":   u.username,
        "email":      u.email,
        "role":       u.role,
        "is_active":  u.is_active,
        "created_at": u.created_at,
        "last_login": u.last_login,
    }


@router.get("")
async def list_users(
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    result = await db.execute(select(User).order_by(User.created_at.asc()))
    return [_user_dict(u) for u in result.scalars().all()]


@router.post("", status_code=201)
async def create_user(
    req: CreateUserRequest,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    existing = await db.execute(
        select(User).where(
            (User.username == req.username) | (User.email == req.email)
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Username or email already exists")

    user = User(
        username=req.username,
        email=req.email,
        hashed_password=hash_password(req.password),
        role=req.role,
        is_active=True,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    await audit(db, _admin, "create_user", "user", user.id, user.username,
                {"role": req.role, "email": req.email})
    return _user_dict(user)


@router.put("/{user_id}")
async def update_user(
    user_id: int,
    req: UpdateUserRequest,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Admin can't deactivate or demote themselves
    if user.id == admin.id:
        if req.is_active is False:
            raise HTTPException(status_code=400, detail="Cannot deactivate your own account")
        if req.role and req.role != UserRole.admin:
            raise HTTPException(status_code=400, detail="Cannot change your own role")

    values: dict = {"updated_at": datetime.utcnow()}
    if req.role is not None:
        values["role"] = req.role
    if req.is_active is not None:
        values["is_active"] = req.is_active
    if req.email is not None:
        dup = await db.execute(
            select(User).where(User.email == req.email, User.id != user_id)
        )
        if dup.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Email already in use")
        values["email"] = req.email

    await db.execute(update(User).where(User.id == user_id).values(**values))
    await db.refresh(user)
    await audit(db, admin, "update_user", "user", user.id, user.username,
                {k: str(v) for k, v in values.items() if k != "updated_at"})
    return _user_dict(user)


@router.post("/{user_id}/reset-password")
async def reset_password(
    user_id: int,
    req: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    await db.execute(
        update(User).where(User.id == user_id).values(
            hashed_password=hash_password(req.new_password),
            updated_at=datetime.utcnow(),
        )
    )
    await audit(db, _admin, "reset_user_password", "user", user.id, user.username)
    return {"message": "Password reset successfully"}


@router.delete("/{user_id}", status_code=204)
async def delete_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    await audit(db, admin, "delete_user", "user", user.id, user.username)
    await db.delete(user)
