from functools import lru_cache
from urllib.parse import urlparse

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.keys import read_key_file


class Settings(BaseSettings):
    app_name: str = "OVSE Web-to-App MVP Shell"
    database_url: str = "sqlite:///ovse_mvp.db"

    verifier_issuer: str = "https://verifier.example.test"
    verifier_audience: str = "https://verifier.example.test"
    verifier_callback_url: str = "https://verifier.example.test/api/ovse/callback"
    uidai_web_intent_action: str = "in.gov.uidai.pehchaan.WEB_INTENT_REQUEST"
    uidai_issuer: str = "https://uidai.gov.in"
    uidai_ovse_client_id: str = "OVSE_CLIENT_ID"
    uidai_ovse_registration_number: str = "OVSE_REGISTRATION_NUMBER"
    intent_language_code: str = "23"
    intent_expiry_seconds: int = 300
    aadhaar_app_id: str | None = None
    aadhaar_app_signature: str | None = None

    verifier_private_key_path: str = "keys/verifier_private.pem"
    verifier_public_key_path: str = "keys/verifier_public.pem"
    verifier_private_key_pem: str | None = None
    verifier_public_key_pem: str | None = None

    mock_mode: bool = True
    uidai_signature_verification_enabled: bool = True
    uidai_sandbox_enabled: bool = False
    uidai_public_key_pem: str | None = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="OVSE_",
        extra="ignore",
    )

    @model_validator(mode="after")
    def load_verifier_keys(self) -> "Settings":
        callback_url = urlparse(self.verifier_callback_url)
        if callback_url.scheme != "https":
            raise ValueError("OVSE_VERIFIER_CALLBACK_URL must be an HTTPS URL")

        if self.verifier_private_key_pem is None:
            self.verifier_private_key_pem = read_key_file(self.verifier_private_key_path)
        if self.verifier_public_key_pem is None:
            self.verifier_public_key_pem = read_key_file(self.verifier_public_key_path)
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
