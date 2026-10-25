from __future__ import annotations

from typing import Any

import pytest
from conftest import TEST_SECRET, TEST_SERVICE

from seamless_auth import Adapter


@pytest.mark.parametrize(
    "placeholder",
    [
        "dev-only-cookie-signing-key-replace-me",
        "GRAB_FROM_SEAMLESS_AUTH_PORTAL_DEV",
        "my-own-long-secret-value-REPLACE-ME-please",
    ],
)
@pytest.mark.parametrize("option", ["cookie_secret", "service_secret"])
def test_placeholder_secrets_are_refused(option: str, placeholder: str) -> None:
    settings: dict[str, Any] = {
        "auth_server_url": "https://a",
        "cookie_secret": TEST_SECRET,
        "service_secret": TEST_SERVICE,
        option: placeholder,
    }
    with pytest.raises(ValueError, match=f"seamless-auth: {option} is a placeholder"):
        Adapter(**settings)


def test_placeholder_secrets_are_allowed_in_insecure_local_mode() -> None:
    Adapter(
        auth_server_url="http://localhost:5312",
        cookie_secret="dev-only-cookie-signing-key-replace-me",
        service_secret="GRAB_FROM_SEAMLESS_AUTH_PORTAL_DEV",
        insecure_cookies=True,
    )
