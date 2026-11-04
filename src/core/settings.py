from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str
    idp_issuer: str
    secret_key: str
    token_hash_pepper: str
    key_encryption_key: str
    idp_admin_api_key: str = ""

    cookie_secure: bool = True
    cookie_samesite: str = "lax"
    cookie_name: str = "idp_session"

    auth_code_ttl: int = 60
    idp_access_ttl: int = 900
    idp_refresh_ttl: int = 2_592_000
    idp_refresh_absolute_ttl: int = 7_776_000
    session_idle_ttl: int = 43_200
    session_absolute_ttl: int = 604_800
    key_cache_seconds: int = 30
    key_retire_seconds: int = 3600

    argon2_time_cost: int = 3
    argon2_memory_cost: int = 65_536
    argon2_parallelism: int = 1

    login_max_failures: int = 5
    lockout_seconds: int = 900

    rate_limit_window: int = 60
    rate_limit_login: int = 10
    rate_limit_register: int = 5
    rate_limit_token: int = 30
    otp_ttl: int = 600
    otp_max_attempts: int = 5
    company_domain: str = "shortcircuitcompany.com"
    company_role: str = "sc_member"

    mail_backend: str = "console"
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    mail_base_url: str = ""

    product_a_client_id: str = ""
    product_a_client_secret: str = ""
    product_a_url: str = ""
    product_a_jwt_secret: str = ""
    product_b_client_id: str = ""
    product_b_client_secret: str = ""
    product_b_url: str = ""
    product_b_jwt_secret: str = ""

    @property
    def sqlalchemy_url(self) -> str:
        url = self.database_url
        if url.startswith("postgresql://"):
            return "postgresql+psycopg://" + url.removeprefix("postgresql://")
        return url

    @property
    def public_base(self) -> str:
        return self.idp_issuer.rstrip("/")

    @property
    def mail_link_base(self) -> str:
        return (self.mail_base_url or self.idp_issuer).rstrip("/")


@lru_cache
def get_settings() -> Settings:
    return Settings()
