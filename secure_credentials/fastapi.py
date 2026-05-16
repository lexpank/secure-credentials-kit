from os import getenv
from typing import Callable, Optional, TYPE_CHECKING

from fastapi import FastAPI, Request

if TYPE_CHECKING:
    from secure_credentials.secrets_loader import CredentialsContainer


DEFAULT_STATE_ATTRIBUTE = "credentials"


def resolve_environment(env: Optional[str] = None) -> str:
    """Resolve the credentials environment for a FastAPI application."""
    return (
        env
        or getenv("SECURE_CREDENTIALS_ENV")
        or getenv("FASTAPI_ENV")
        or getenv("ENV")
        or "development"
    )


def load_credentials(env: Optional[str] = None) -> "CredentialsContainer":
    from secure_credentials.secrets_loader import decrypt_credentials

    return decrypt_credentials(resolve_environment(env))


def setup_secure_credentials(
    app: FastAPI,
    env: Optional[str] = None,
    state_attribute: str = DEFAULT_STATE_ATTRIBUTE,
) -> "CredentialsContainer":
    credentials = load_credentials(env)
    setattr(app.state, state_attribute, credentials)
    return credentials


def get_credentials(
    request: Request,
    state_attribute: str = DEFAULT_STATE_ATTRIBUTE,
) -> "CredentialsContainer":
    return getattr(request.app.state, state_attribute)


def credentials_dependency(
    state_attribute: str = DEFAULT_STATE_ATTRIBUTE,
) -> Callable[[Request], "CredentialsContainer"]:
    def dependency(request: Request) -> "CredentialsContainer":
        return get_credentials(request, state_attribute)

    return dependency
