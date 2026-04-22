from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from database import get_db
from models.rule import Rule, RuleSeverity
from routes.auth import get_current_user, require_analyst, require_admin
from models.user import User
from services.audit_service import audit

router = APIRouter(prefix="/api/rules", tags=["rules"])


class RuleCreateRequest(BaseModel):
    name: str
    description: Optional[str] = None
    pattern: Optional[str] = None
    severity: RuleSeverity = RuleSeverity.MEDIUM
    category: Optional[str] = "general"
    enabled: bool = True
    cooldown_seconds: int = 300


class RuleUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    pattern: Optional[str] = None
    severity: Optional[RuleSeverity] = None
    category: Optional[str] = None
    enabled: Optional[bool] = None
    cooldown_seconds: Optional[int] = None


def _rule_to_dict(rule: Rule) -> dict:
    return {
        "id": rule.id,
        "name": rule.name,
        "description": rule.description,
        "pattern": rule.pattern,
        "severity": rule.severity,
        "category": rule.category,
        "enabled": rule.enabled,
        "cooldown_seconds": rule.cooldown_seconds,
        "custom_logic": rule.custom_logic,
        "created_at": rule.created_at,
        "updated_at": rule.updated_at,
    }


@router.get("")
async def list_rules(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(Rule).order_by(Rule.id)
    result = await db.execute(stmt)
    rules = result.scalars().all()
    return [_rule_to_dict(r) for r in rules]


@router.post("")
async def create_rule(
    request: RuleCreateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    stmt = select(Rule).where(Rule.name == request.name)
    result = await db.execute(stmt)
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Rule name already exists")

    rule = Rule(
        name=request.name,
        description=request.description,
        pattern=request.pattern,
        severity=request.severity,
        category=request.category,
        enabled=request.enabled,
        cooldown_seconds=request.cooldown_seconds,
    )
    db.add(rule)
    await db.flush()
    await db.refresh(rule)
    await audit(db, current_user, "create_rule", "rule", rule.id, rule.name,
                {"severity": request.severity, "category": request.category})
    return _rule_to_dict(rule)


@router.get("/{rule_id}")
async def get_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(Rule).where(Rule.id == rule_id)
    result = await db.execute(stmt)
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return _rule_to_dict(rule)


@router.put("/{rule_id}")
async def update_rule(
    rule_id: int,
    request: RuleUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    stmt = select(Rule).where(Rule.id == rule_id)
    result = await db.execute(stmt)
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    if request.name is not None:
        rule.name = request.name
    if request.description is not None:
        rule.description = request.description
    if request.pattern is not None:
        rule.pattern = request.pattern
    if request.severity is not None:
        rule.severity = request.severity
    if request.category is not None:
        rule.category = request.category
    if request.enabled is not None:
        rule.enabled = request.enabled
    if request.cooldown_seconds is not None:
        rule.cooldown_seconds = request.cooldown_seconds

    await db.flush()
    await db.refresh(rule)
    await audit(db, current_user, "update_rule", "rule", rule.id, rule.name)
    return _rule_to_dict(rule)


@router.delete("/{rule_id}")
async def delete_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    stmt = select(Rule).where(Rule.id == rule_id)
    result = await db.execute(stmt)
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    if rule.custom_logic:
        raise HTTPException(status_code=400, detail="Cannot delete built-in rule")
    await audit(db, current_user, "delete_rule", "rule", rule.id, rule.name)
    await db.delete(rule)
    return {"message": "Rule deleted"}
