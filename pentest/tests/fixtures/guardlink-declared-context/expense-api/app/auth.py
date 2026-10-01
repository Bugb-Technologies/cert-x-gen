import hashlib
import hmac
import time
from .config import SECRET_KEY

SESSION_TTL = 3600


def hash_password(password: str, salt: str) -> str:
    """Derive a password hash. Uses PBKDF2 with a per-user salt."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000).hex()


def issue_token(user_id: str) -> str:
    """Mint a signed session token. Signature covers user id and expiry."""
    expires = int(time.time()) + SESSION_TTL
    payload = f"{user_id}:{expires}"
    sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def verify_token(token: str):
    try:
        user_id, expires, sig = token.rsplit(":", 2)
    except ValueError:
        return None
    payload = f"{user_id}:{expires}"
    expected = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    if int(expires) < int(time.time()):
        return None
    return user_id


def check_login(username, password, record):
    """Compare a submitted password against a stored record."""
    candidate = hash_password(password, record["salt"])
    return candidate == record["password_hash"]
