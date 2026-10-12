"""Comptes INPA et sessions opaques stockés dans SQLite."""

import hashlib
import hmac
import re
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path


class AccountStore:
    ITERATIONS = 310_000
    SESSION_TTL = 30 * 24 * 60 * 60

    def __init__(self, database_path: Path | str):
        self.database_path = Path(database_path)

    @contextmanager
    def _connection(self):
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 10000")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self):
        with self._connection() as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS inpa_users (
                    id TEXT PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE,
                    password_salt TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at REAL NOT NULL
                )"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS inpa_sessions (
                    token_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES inpa_users(id) ON DELETE CASCADE,
                    expires_at REAL NOT NULL
                )"""
            )
            connection.execute("CREATE INDEX IF NOT EXISTS inpa_sessions_user_idx ON inpa_sessions(user_id)")
            connection.execute(
                """CREATE TABLE IF NOT EXISTS inpa_access_keys (
                    user_id TEXT PRIMARY KEY,
                    token_hash TEXT NOT NULL UNIQUE,
                    created_at REAL NOT NULL,
                    revoked_at REAL
                )"""
            )

    def create_access_key(self) -> dict:
        user_id = uuid.uuid4().hex
        token = "INPA-" + secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO inpa_access_keys (user_id, token_hash, created_at) VALUES (?, ?, ?)",
                (user_id, token_hash, time.time()),
            )
        return {"user_id": user_id, "access_key": token}

    def rotate_access_key(self, user_id: str) -> str | None:
        token = "INPA-" + secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        with self._connection() as connection:
            cursor = connection.execute(
                "UPDATE inpa_access_keys SET token_hash = ?, created_at = ?, revoked_at = NULL WHERE user_id = ?",
                (token_hash, time.time(), user_id),
            )
        return token if cursor.rowcount == 1 else None

    def get_access_key_user(self, token: str) -> str | None:
        token = str(token or "").strip()
        if not token or len(token) > 256:
            return None
        token_hash = hashlib.sha256(token.encode("ascii", errors="ignore")).hexdigest()
        with self._connection() as connection:
            row = connection.execute(
                "SELECT user_id FROM inpa_access_keys WHERE token_hash = ? AND revoked_at IS NULL",
                (token_hash,),
            ).fetchone()
        return row["user_id"] if row else None

    def revoke_access_key(self, token: str) -> bool:
        token_hash = hashlib.sha256(str(token or "").encode("ascii", errors="ignore")).hexdigest()
        with self._connection() as connection:
            cursor = connection.execute(
                "UPDATE inpa_access_keys SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
                (time.time(), token_hash),
            )
        return cursor.rowcount == 1

    @staticmethod
    def _email(value: str) -> str:
        email = str(value or "").strip().lower()
        if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            raise ValueError("Adresse e-mail invalide.")
        return email

    @classmethod
    def _password_hash(cls, password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, cls.ITERATIONS)

    def register(self, email: str, password: str) -> dict:
        email = self._email(email)
        if not 6 <= len(password or "") <= 10:
            raise ValueError("Le mot de passe doit contenir entre 6 et 10 caractères.")
        user_id = uuid.uuid4().hex
        salt = secrets.token_bytes(16)
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO inpa_users (id, email, password_salt, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
                (user_id, email, salt.hex(), self._password_hash(password, salt).hex(), time.time()),
            )
        return {"id": user_id, "email": email}

    def authenticate(self, email: str, password: str) -> dict | None:
        try:
            email = self._email(email)
        except ValueError:
            return None
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM inpa_users WHERE email = ?", (email,)).fetchone()
        if not row:
            return None
        salt = bytes.fromhex(row["password_salt"])
        expected = bytes.fromhex(row["password_hash"])
        if not hmac.compare_digest(self._password_hash(password or "", salt), expected):
            return None
        return {"id": row["id"], "email": row["email"]}

    def create_session(self, user_id: str) -> str:
        token = secrets.token_urlsafe(48)
        digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        with self._connection() as connection:
            connection.execute("DELETE FROM inpa_sessions WHERE expires_at < ?", (time.time(),))
            connection.execute(
                "INSERT INTO inpa_sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                (digest, user_id, time.time() + self.SESSION_TTL),
            )
        return token

    def get_session_user(self, token: str) -> dict | None:
        if not token or len(token) > 256:
            return None
        digest = hashlib.sha256(token.encode("ascii", errors="ignore")).hexdigest()
        with self._connection() as connection:
            row = connection.execute(
                """SELECT u.id, u.email FROM inpa_sessions s
                   JOIN inpa_users u ON u.id = s.user_id
                   WHERE s.token_hash = ? AND s.expires_at > ?""",
                (digest, time.time()),
            ).fetchone()
        return dict(row) if row else None

    def revoke_session(self, token: str):
        digest = hashlib.sha256(token.encode("ascii", errors="ignore")).hexdigest()
        with self._connection() as connection:
            connection.execute("DELETE FROM inpa_sessions WHERE token_hash = ?", (digest,))

    def get_user(self, user_id: str) -> dict | None:
        with self._connection() as connection:
            row = connection.execute("SELECT id, email FROM inpa_users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None
