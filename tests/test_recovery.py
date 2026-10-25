"""Account recovery: owner notices and the v0.20 routes."""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest
from conftest import (
    TEST_SECRET,
    TEST_SERVICE,
    FakeApi,
    access,
    api_token,
    call,
    pre_auth,
    respond,
    service_claims,
    session,
)

from seamless_auth import Adapter, Delivery, EnrollmentRequired, Manifest
from seamless_auth._adapter import DELIVERY_SUBJECT, PROXY_SUBJECT
from seamless_auth._manifest import bundled_manifest

CANCEL_URL = "https://app.test/recovery/cancel#cancel-token-secret"
NOTICE_TEXT = f"Someone asked to recover your account. If this was not you, cancel it: {CANCEL_URL}"
NOTICES = [
    {
        "kind": "account_notice_email",
        "notice": "account_recovery_opened",
        "to": "a@b.test",
        "subject": "Account recovery requested",
        "text": NOTICE_TEXT,
        "cancelUrl": CANCEL_URL,
    },
    {
        "kind": "account_notice_sms",
        "notice": "account_recovery_opened",
        "to": "+15550100",
        "text": NOTICE_TEXT,
        "cancelUrl": CANCEL_URL,
    },
]
VERIFIED = {
    "message": "Recovery requested",
    "state": "pending",
    "completesAt": "2026-10-25T00:00:00.000Z",
}
BEARER = {"x-seamless-auth-transport": "bearer", "authorization": "Bearer pre-auth"}


def capture() -> tuple[list[Delivery], Any]:
    got: list[Delivery] = []
    return got, got.append


# Owner notices.


def test_notice_delivery_needs_a_callback() -> None:
    with pytest.raises(ValueError, match="deliver_account_notices"):
        Adapter(
            auth_server_url="https://a",
            cookie_secret=TEST_SECRET,
            service_secret=TEST_SERVICE,
            deliver_account_notices=True,
        )


def test_the_bundled_manifest_marks_recovery_verify_for_notices() -> None:
    found = bundled_manifest().find("POST", "/recovery/verify")
    assert found is not None and found.route.notices and not found.route.delivery


def test_a_manifest_carrying_notices_parses() -> None:
    manifest = Manifest.parse(
        json.dumps(
            {
                "schemaVersion": 1,
                "apiVersion": "0.20.0",
                "routes": [
                    {
                        "method": "POST",
                        "path": "/recovery/verify",
                        "credential": "preAuth",
                        "notices": True,
                    },
                    {"method": "POST", "path": "/recovery/start", "credential": "preAuth"},
                ],
            }
        )
    )
    assert [r.notices for r in manifest.routes] == [True, False]


@pytest.mark.parametrize("bearer", [False, True])
def test_notices_are_delivered_and_stripped(
    api: FakeApi, bearer: bool, caplog: pytest.LogCaptureFixture
) -> None:
    api.on("POST", "/recovery/verify", respond(200, {**VERIFIED, "deliveries": NOTICES}))
    got, deliver = capture()
    adapter = api.adapter(deliver=deliver, deliver_account_notices=True)

    with caplog.at_level(logging.DEBUG):
        r = call(
            adapter,
            "POST",
            "/recovery/verify",
            body='{"code":"123456"}',
            cookie=None if bearer else pre_auth(),
            headers=BEARER if bearer else None,
        )

    assert r.status == 200, r.text
    assert r.body == VERIFIED
    assert CANCEL_URL not in r.text
    assert [(d.kind, d.to, d.notice) for d in got] == [
        ("account_notice_email", "a@b.test", "account_recovery_opened"),
        ("account_notice_sms", "+15550100", "account_recovery_opened"),
    ]
    assert got[0].subject == "Account recovery requested"
    assert all(d.cancel_url == CANCEL_URL and d.text == NOTICE_TEXT for d in got)
    assert all(CANCEL_URL not in repr(d) for d in got)
    assert "cancel-token-secret" not in caplog.text

    recorded = api.calls_to("POST", "/recovery/verify")[0]
    assert recorded.headers["x-seamless-auth-delivery-mode"] == "external"
    assert (
        recorded.headers["x-seamless-auth-delivery-kinds"]
        == "account_notice_email,account_notice_sms"
    )
    assert service_claims(recorded)["sub"] == DELIVERY_SUBJECT


@pytest.mark.parametrize("opted_in", [False, None])
def test_without_notice_delivery_the_api_sends_the_notices(
    api: FakeApi, opted_in: bool | None
) -> None:
    api.on("POST", "/recovery/verify", respond(200, {**VERIFIED, "deliveries": NOTICES}))
    got, deliver = capture()
    options: dict[str, Any] = {} if opted_in is None else {"deliver": deliver}

    r = call(
        api.adapter(**options),
        "POST",
        "/recovery/verify",
        body='{"code":"123456"}',
        cookie=pre_auth(),
    )

    assert r.status == 200
    assert r.body == VERIFIED
    assert not got
    recorded = api.calls_to("POST", "/recovery/verify")[0]
    assert "x-seamless-auth-delivery-mode" not in recorded.headers
    assert "x-seamless-auth-delivery-kinds" not in recorded.headers
    assert service_claims(recorded)["sub"] == PROXY_SUBJECT


def test_a_failed_notice_is_reported_after_every_notice_is_tried(
    api: FakeApi, caplog: pytest.LogCaptureFixture
) -> None:
    api.on("POST", "/recovery/verify", respond(200, {**VERIFIED, "deliveries": NOTICES}))
    tried: list[str] = []

    def deliver(d: Delivery) -> None:
        tried.append(d.kind)
        if d.kind == "account_notice_email":
            raise RuntimeError(f"smtp refused message containing {d.cancel_url}")

    adapter = api.adapter(deliver=deliver, deliver_account_notices=True)
    with caplog.at_level(logging.DEBUG):
        r = call(adapter, "POST", "/recovery/verify", body='{"code":"1"}', cookie=pre_auth())

    assert (r.status, r.body) == (502, {"error": "delivery_failed"})
    assert tried == ["account_notice_email", "account_notice_sms"]
    assert "cancel-token-secret" not in caplog.text


def test_recovery_notice_failed_passes_through(api: FakeApi) -> None:
    failed = {"error": "recovery_notice_failed", "message": "The owner could not be notified"}
    api.on("POST", "/recovery/verify", respond(503, failed))
    got, deliver = capture()

    r = call(
        api.adapter(deliver=deliver, deliver_account_notices=True),
        "POST",
        "/recovery/verify",
        body='{"code":"1"}',
        cookie=pre_auth(),
    )

    assert (r.status, r.body) == (503, failed)
    assert not got


def test_an_unknown_delivery_kind_is_a_logged_no_op(
    api: FakeApi, caplog: pytest.LogCaptureFixture
) -> None:
    api.on(
        "POST",
        "/recovery/verify",
        respond(
            200,
            {**VERIFIED, "deliveries": [{"kind": "carrier_pigeon", "to": "a@b.test"}, NOTICES[1]]},
        ),
    )
    got, deliver = capture()

    with caplog.at_level(logging.WARNING):
        r = call(
            api.adapter(deliver=deliver, deliver_account_notices=True),
            "POST",
            "/recovery/verify",
            body='{"code":"1"}',
            cookie=pre_auth(),
        )

    assert r.status == 200
    assert [d.kind for d in got] == ["account_notice_sms"]
    assert "carrier_pigeon" in caplog.text


def test_a_notice_on_a_delivery_route_needs_the_opt_in(api: FakeApi) -> None:
    api.on(
        "POST",
        "/otp/generate-login-email-otp",
        respond(200, {"message": "sent", "delivery": NOTICES[0]}),
    )
    got, deliver = capture()

    r = call(
        api.adapter(deliver=deliver),
        "POST",
        "/otp/generate-login-email-otp",
        cookie=pre_auth(),
    )

    assert (r.status, r.body) == (200, {"message": "sent"})
    assert not got


def test_a_recovery_code_carries_its_purpose(api: FakeApi) -> None:
    code = {"kind": "otp_email", "to": "a@b.test", "token": "654321", "purpose": "account_recovery"}
    api.on("POST", "/recovery/start", respond(200, {"message": "sent", "delivery": code}))
    got, deliver = capture()

    r = call(
        api.adapter(deliver=deliver),
        "POST",
        "/recovery/start",
        body='{"channel":"email"}',
        cookie=pre_auth(),
    )

    assert (r.status, r.body) == (200, {"message": "sent"})
    assert got[0].is_account_recovery and got[0].purpose == "account_recovery"
    assert got[0].token == "654321"
    assert api.calls_to("POST", "/recovery/start")[0].headers["x-seamless-auth-delivery-mode"] == (
        "external"
    )


def test_a_sign_in_code_has_no_purpose(api: FakeApi) -> None:
    code = {"kind": "otp_sms", "to": "+15550100", "token": 123456}
    api.on(
        "POST", "/otp/generate-login-phone-otp", respond(200, {"message": "sent", "delivery": code})
    )
    got, deliver = capture()

    call(api.adapter(deliver=deliver), "POST", "/otp/generate-login-phone-otp", cookie=pre_auth())

    assert got[0].purpose is None and not got[0].is_account_recovery


# The v0.20 routes, from the bundled manifest.

ACCESS_ROUTES = [
    ("GET", "/recovery-codes", "/recovery-codes"),
    ("POST", "/recovery-codes", "/recovery-codes"),
    ("GET", "/recovery/requests", "/recovery/requests"),
    ("DELETE", "/recovery/requests/req-1", "/recovery/requests/req-1"),
    ("GET", "/system-config/policy", "/system-config/policy"),
    ("PUT", "/system-config/policy/draft", "/system-config/policy/draft"),
    ("DELETE", "/system-config/policy/draft", "/system-config/policy/draft"),
    ("POST", "/system-config/policy/publish", "/system-config/policy/publish"),
    ("POST", "/system-config/policy/rollback", "/system-config/policy/rollback"),
    ("GET", "/system-config/policy/versions", "/system-config/policy/versions"),
    ("POST", "/system-config/policy/dry-run", "/system-config/policy/dry-run"),
]


@pytest.mark.parametrize(("method", "path", "upstream"), ACCESS_ROUTES)
def test_the_access_routes_pass_through(
    api: FakeApi, method: str, path: str, upstream: str
) -> None:
    api.on(method, upstream, respond(200, {"ok": True}))
    body = "{}" if method in ("POST", "PUT") else None

    r = call(api.adapter(), method, path, body=body, cookie=access())

    assert (r.status, r.body) == (200, {"ok": True}), r.text
    assert api.calls_to(method, upstream)[0].headers["authorization"] == "Bearer t"


PRE_AUTH_ROUTES = [
    ("POST", "/recovery/start"),
    ("POST", "/recovery/verify"),
    ("GET", "/recovery/status"),
    ("POST", "/recovery/complete"),
]


@pytest.mark.parametrize(("method", "path"), PRE_AUTH_ROUTES)
def test_the_recovery_routes_take_the_pre_auth_token(api: FakeApi, method: str, path: str) -> None:
    api.on(method, path, respond(200, {"state": "pending"}))
    body = "{}" if method == "POST" else None

    r = call(api.adapter(), method, path, body=body, cookie=pre_auth())

    assert r.status == 200, r.text
    assert api.calls_to(method, path)[0].headers["authorization"] == "Bearer pre-auth"


def test_recovery_complete_issues_a_recovery_session(api: FakeApi) -> None:
    recovery = {
        **session(),
        "token": api_token("u1", "access", sid="s-1", recovery=True),
        "recovery": True,
        "nextStep": "enroll_passkey",
    }
    api.on("POST", "/recovery/complete", respond(200, recovery))
    adapter = api.adapter()

    r = call(adapter, "POST", "/recovery/complete", body="{}", cookie=pre_auth())

    assert r.status == 200, r.text
    assert r.body["recovery"] is True and r.body["nextStep"] == "enroll_passkey"
    assert "token" not in r.body and "refreshToken" not in r.body
    cookie = r.cookies["seamless-access"]
    with pytest.raises(EnrollmentRequired):
        adapter.authenticate([("cookie", f"seamless-access={cookie.value}")])


def test_recovery_cancel_needs_no_session(api: FakeApi) -> None:
    api.on("POST", "/recovery/cancel", respond(200, {"message": "ok"}))

    r = call(api.adapter(), "POST", "/recovery/cancel", body='{"cancelToken":"x"}')

    assert r.status == 200
    assert "authorization" not in api.calls_to("POST", "/recovery/cancel")[0].headers


def test_step_up_required_passes_through_on_admin_writes(api: FakeApi) -> None:
    step_up = {
        "error": "step_up_required",
        "message": "Re-authenticate to continue",
        "stepUp": {"required": True, "methods": ["passkey"]},
    }
    api.on("POST", "/system-config/policy/publish", respond(403, step_up))

    r = call(api.adapter(), "POST", "/system-config/policy/publish", body="{}", cookie=access())

    assert (r.status, r.body) == (403, step_up)
