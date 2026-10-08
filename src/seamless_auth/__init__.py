"""A Seamless Auth server adapter for Python, with FastAPI and Django bindings.

The adapter sits in front of the Seamless Auth API. Browsers talk to it over
HttpOnly cookies on the application's own domain, native clients over bearer
tokens, and it talks to the auth API over bearer tokens and a service token.
Which routes it serves, and what each does to the session, comes from the auth
API's adapter manifest.

The framework bindings live in :mod:`seamless_auth.fastapi` and
:mod:`seamless_auth.django`.
"""

from ._adapter import Adapter, CrossSiteRequest, Unauthenticated, User
from ._client_ip import TrustedProxies
from ._delivery import Delivery
from ._http import AuthRequest, AuthResponse, Headers, ResponseCookie
from ._manifest import MANIFEST_PATH, Manifest, ManifestError, ManifestRoute

__all__ = [
    "MANIFEST_PATH",
    "Adapter",
    "AuthRequest",
    "AuthResponse",
    "CrossSiteRequest",
    "Delivery",
    "Headers",
    "Manifest",
    "ManifestError",
    "ManifestRoute",
    "ResponseCookie",
    "TrustedProxies",
    "Unauthenticated",
    "User",
]
