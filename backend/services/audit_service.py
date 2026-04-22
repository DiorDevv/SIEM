"""
Audit service — fire-and-forget action logger.
Never raises; failures are silently logged so they don't break request flow.
"""
import json
import logging
from typing import Optional, Any
from sqlalchemy.ext.asyncio import AsyncSession
from models.audit_log import AuditLog

logger = logging.getLogger(__name__)


async def audit(
    db: AsyncSession,
    user,
    action: str,
    resource_type: Optional[str] = None,
    resource_id: Optional[Any] = None,
    resource_name: Optional[str] = None,
    details: Optional[dict] = None,
    status: str = "success",
    ip_address: Optional[str] = None,
):
    try:
        entry = AuditLog(
            user_id=getattr(user, "id", None),
            username=getattr(user, "username", str(user) if user else None),
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id is not None else None,
            resource_name=resource_name,
            details=json.dumps(details) if details else None,
            ip_address=ip_address,
            status=status,
        )
        db.add(entry)
        await db.flush()
    except Exception as e:
        logger.warning(f"Audit log failed (action={action}): {e}")
