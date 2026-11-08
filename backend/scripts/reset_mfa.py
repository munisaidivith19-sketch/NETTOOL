"""SERVER ACCESS ONLY: turn off two-step sign-in (MFA) for one user and sign them out.

For the case the admin UI can't handle: the only admin lost their phone *and* their recovery
codes, so nobody can sign in to press "Reset MFA". Running this needs the database connection
string (MONGODB_URI), which is a stronger credential than any NetMap account, so it doesn't
weaken the second factor. Admins must set MFA up again at their next sign-in.

From the backend folder:
    python scripts/reset_mfa.py <username>
The reset is written to the audit log as `user.mfa_reset` (actor: "script").
"""

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from pymongo import MongoClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import get_settings  # noqa: E402

USERNAME_RE = re.compile(r"[a-z0-9._-]{3,32}")  # the same rule as models/common.py


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

    had = bool((user.get("mfa") or {}).get("enabled"))
    db.users.update_one({"_id": user["_id"]}, {"$unset": {"mfa": ""}})
    signed_out = db.sessions.delete_many({"user_id": user["_id"]}).deleted_count
    db.audit_log.insert_one({
        "at": datetime.now(timezone.utc),
        "action": "user.mfa_reset",
        "result": "success",
        "actor": {"type": "script", "id": "reset_mfa.py"},
        "target": {"type": "user", "id": str(user["_id"]), "username": user["username"]},
        "ip": None,
        "request_id": None,
        "details": {"was_enabled": had},
    })
    print(f"MFA reset for {user['username']} (was {'on' if had else 'off'}); "
          f"{signed_out} session(s) signed out.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
