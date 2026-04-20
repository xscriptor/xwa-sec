"""Bootstrap an admin user.

Usage (inside backend container):
    python -m app.scripts.create_admin --username admin --email admin@samurai.local
    # password prompted interactively (hidden)

Or non-interactive (CI / automation):
    python -m app.scripts.create_admin --username admin --email admin@samurai.local --password 's3cret!'

Roles: admin | operator | viewer (default: admin).
"""
import argparse
import getpass
import sys

from sqlalchemy.exc import IntegrityError

from app import models
from app.database import SessionLocal, wait_for_db
from app.auth.security import hash_password


ALLOWED_ROLES = {"admin", "operator", "viewer"}


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a Samurai user")
    parser.add_argument("--username", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", help="If omitted, prompted interactively")
    parser.add_argument("--role", default="admin", choices=sorted(ALLOWED_ROLES))
    args = parser.parse_args()

    password = args.password or getpass.getpass("Password: ")
    if len(password) < 8:
        print("[!] Password must be at least 8 characters.", file=sys.stderr)
        return 2

    wait_for_db()
    db = SessionLocal()
    try:
        existing = (
            db.query(models.User)
            .filter((models.User.username == args.username) | (models.User.email == args.email))
            .first()
        )
        if existing:
            print(f"[!] User with username or email already exists (id={existing.id}).", file=sys.stderr)
            return 1

        user = models.User(
            username=args.username,
            email=args.email,
            hashed_password=hash_password(password),
            role=args.role,
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        print(f"[+] Created user '{user.username}' (id={user.id}, role={user.role}).")
        return 0
    except IntegrityError as exc:
        db.rollback()
        print(f"[!] Integrity error: {exc.orig}", file=sys.stderr)
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
