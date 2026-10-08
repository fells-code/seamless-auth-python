"""The FastAPI reference app the Seamless Auth adapter conformance suite drives
(``seamless verify --adapter-url``). Its routes and configuration follow
verify/CONFORMANCE.md in fells-code/seamless-cli. It is a test fixture, not an
example deployment: /__captured exposes one-time codes.

    python conformance/fastapi_app.py
"""

from __future__ import annotations

from typing import Any

import uvicorn
from fastapi import Depends, FastAPI

from seamless_auth import Adapter, User
from seamless_auth.fastapi import RequireUser, auth_router

try:
    from conformance import _shared
except ImportError:
    import _shared  # type: ignore[no-redef]

auth = Adapter(**_shared.adapter_options())
current_user = RequireUser(auth)

app = FastAPI()
app.include_router(auth_router(auth))


@app.get("/")
def health() -> dict[str, bool]:
    return {"ok": True}


@app.get("/__captured/{recipient}")
def captured(recipient: str) -> dict[str, Any] | None:
    return _shared.captured_for(recipient)


@app.get("/api/me")
def me(user: User = Depends(current_user)) -> dict[str, str]:  # noqa: B008
    return {"id": user.id}


if __name__ == "__main__":
    print(f"seamless-auth FastAPI reference app listening on :{_shared.port()}")
    uvicorn.run(app, host="0.0.0.0", port=_shared.port(), log_level="warning")
