"""SERVER ACCESS ONLY: give one user a new temporary password and sign them out.

For the case the admin UI can't handle: the only admin forgot their password, so nobody can
sign in to press "Reset password". Running this needs the database connection string
(MONGODB_URI), which is a stronger credential than any NetMap account.

The script makes a random temporary password, prints it once, and stores only its bcrypt
hash. The user must choose a new password at the next sign-in. The lockout counter is
cleared and every session of the user is signed out.

From the backend folder:
    python scripts/reset_password.py <username>
The reset is written to the audit log as `user.password_reset` (actor: "script").
"""

import argparse
import re
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

from pymongo import MongoClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import get_settings  # noqa: E402
from app.security.passwords import hash_password, policy_problems  # noqa: E402

USERNAME_RE = re.compile(r"[a-z0-9._-]{3,32}")  # the same rule as models/common.py


def temporary_password(username: str) -> str:
    """16 random URL-safe characters (96 bits), re-drawn until it passes the policy."""
    while True:
        candidate = secrets.token_urlsafe(12)
        if not policy_problems(candidate, username):
            return candidate


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("username")
    args = parser.parse_args()
    if not USERNAME_RE.fullmatch(args.username):
        print("Not a valid username.", file=sys.stderr)
        return 2

    settings = get_settings()
    client: MongoClient = MongoClient(settings.mongodb_uri.get_secret_value(), tz_aware=True)
    db = client[settings.mongodb_db]
    user = db.users.find_one({"username": args.username})
    if user is None:
        print(f"No user named {args.username!r}.", file=sys.stderr)
        return 1

    password = temporary_password(user["username"])
    db.users.update_one({"_id": user["_id"]}, {"$set": {
        "password_hash": hash_password(password, settings.bcrypt_rounds),
        "must_change_password": True,  # nosec B105 - boolean flag
        "failed_logins": 0,
        "locked_until": None,
    }})
    signed_out = db.sessions.delete_many({"user_id": user["_id"]}).deleted_count
    db.audit_log.insert_one({
        "at": datetime.now(timezone.utc),
        "action": "user.password_reset",
        "result": "success",
        "actor": {"type": "script", "id": "reset_password.py"},
        "target": {"type": "user", "id": str(user["_id"]), "username": user["username"]},
        "ip": None,
        "request_id": None,
        "details": {},
    })
    print(f"Password reset for {user['username']}; {signed_out} session(s) signed out.")
    print(f"Temporary password (shown once, change it at sign-in): {password}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
