"""Creates the first admin from ADMIN_USERNAME / ADMIN_PASSWORD when there are no users yet."""

import logging

from fastapi import HTTPException
from pymongo.asynchronous.database import AsyncDatabase

from app.config import Settings
from app.services.users import create_user

logger = logging.getLogger("netmap.bootstrap")


async def ensure_first_admin(db: AsyncDatabase, settings: Settings) -> bool:
    """Returns True if an admin was created."""
    if await db.users.count_documents({}, limit=1):
        return False  # users exist: the env variables are ignored from now on
    if not settings.admin_username or not settings.admin_password:
        logger.warning("No users exist. Set ADMIN_USERNAME and ADMIN_PASSWORD to create an admin.")
        return False
    try:
        await create_user(
            db,
            username=settings.admin_username,
            password=settings.admin_password.get_secret_value(),
            role="admin",
            rounds=settings.bcrypt_rounds,
            created_by=None,
        )
    except HTTPException as exc:
        if exc.status_code == 409:  # another worker created it at the same moment
            return False
        # Only the policy messages are logged, never the password itself.
        logger.error("ADMIN_PASSWORD was rejected, no admin created: %s", exc.detail)
        return False
    logger.info("Created first admin %r. They must change the password at first login.",
                settings.admin_username)
    return True
