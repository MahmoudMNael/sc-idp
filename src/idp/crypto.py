import base64
import hashlib
import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from idp.settings import Settings

_dummy_hash: str | None = None


def _hasher(settings: Settings) -> PasswordHasher:
    return PasswordHasher(
        time_cost=settings.argon2_time_cost,
        memory_cost=settings.argon2_memory_cost,
        parallelism=settings.argon2_parallelism,
    )


def hash_password(settings: Settings, password: str) -> str:
    return _hasher(settings).hash(password)


def verify_password(settings: Settings, password_hash: str, password: str) -> tuple[bool, str | None]:
    ph = _hasher(settings)
    try:
        ph.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False, None
    return True, ph.hash(password) if ph.check_needs_rehash(password_hash) else None


def dummy_verify(settings: Settings, password: str) -> None:
    global _dummy_hash
    ph = _hasher(settings)
    if _dummy_hash is None:
        _dummy_hash = ph.hash("not-a-real-password")
    try:
        ph.verify(_dummy_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        pass


def hash_token(pepper: str, token: str) -> str:
    return hmac.new(pepper.encode(), token.encode(), hashlib.sha256).hexdigest()


def random_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def pkce_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def pkce_ok(verifier: str, challenge: str) -> bool:
    if not (43 <= len(verifier) <= 128):
        return False
    return hmac.compare_digest(pkce_s256(verifier), challenge)


def _fernet(secret: str) -> Fernet:
    raw = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"sc-idp-jwk", info=b"enc").derive(
        secret.encode()
    )
    return Fernet(base64.urlsafe_b64encode(raw))


def encrypt_secret(key_secret: str, plaintext: str) -> str:
    return _fernet(key_secret).encrypt(plaintext.encode()).decode()


def decrypt_secret(key_secret: str, blob: str) -> str:
    return _fernet(key_secret).decrypt(blob.encode()).decode()


def sign(secret_key: str, salt: str, value) -> str:
    return URLSafeTimedSerializer(secret_key, salt=salt).dumps(value)


def unsign(secret_key: str, salt: str, value: str, max_age: int):
    try:
        return URLSafeTimedSerializer(secret_key, salt=salt).loads(value, max_age=max_age)
    except (BadSignature, SignatureExpired, Exception):
        return None


def new_csrf(secret_key: str) -> str:
    return sign(secret_key, "csrf", random_token(16))


def csrf_ok(secret_key: str, cookie: str | None, form: str | None) -> bool:
    if not cookie or not form or not hmac.compare_digest(cookie, form):
        return False
    return unsign(secret_key, "csrf", cookie, max_age=3600) is not None


def at_hash(access_token: str) -> str:
    digest = hashlib.sha256(access_token.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode("ascii")
