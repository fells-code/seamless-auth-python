from __future__ import annotations

import json

import pytest

from seamless_auth import Manifest, ManifestError
from seamless_auth._manifest import bundled_manifest


def manifest(*routes: dict[str, object]) -> Manifest:
    return Manifest.parse(json.dumps({"schemaVersion": 1, "routes": list(routes)}))


OK = {"method": "GET", "path": "/a", "credential": "access"}


def test_the_bundled_manifest_parses() -> None:
    assert bundled_manifest().routes


@pytest.mark.parametrize(
    "bad",
    [
        {"method": "GET", "path": "/b", "credential": "superuser"},
        {"method": "GET", "path": "/b", "credential": "access", "issues": "everything"},
        {"method": "GET", "path": "/b", "credential": "access", "clears": ["session"]},
        {"method": "TRACE", "path": "/b", "credential": "access"},
        {"method": "GET", "path": "b", "credential": "access"},
        {"method": "GET", "path": "/b", "credential": "access", "body": {"pick": [1]}},
    ],
)
def test_unknown_credentials_and_effects_are_refused_whole(bad: dict[str, object]) -> None:
    with pytest.raises(ManifestError):
        manifest(OK, bad)


def test_versions_and_empty_issues() -> None:
    with pytest.raises(ManifestError):
        Manifest.parse('{"schemaVersion":2,"routes":[]}')
    with pytest.raises(ManifestError):
        Manifest.parse("not json")
    assert manifest(OK)
    assert manifest({**OK, "issues": ""}).routes[0].issues is None


def test_a_static_segment_beats_a_parameter() -> None:
    m = manifest(
        {"method": "POST", "path": "/admin/users/{userId}", "credential": "access"},
        {
            "method": "POST",
            "path": "/admin/users/import",
            "credential": "access",
            "issues": "access",
        },
    )
    found = m.find("POST", "/admin/users/import")
    assert found is not None and found.route.path == "/admin/users/import"
    found = m.find("POST", "/admin/users/IMPORT")
    assert found is not None and found.route.path == "/admin/users/import"
    found = m.find("post", "/admin/users/u-1")
    assert found is not None and found.route.path == "/admin/users/{userId}"
    assert found.params == {"userId": "u-1"}
    assert m.find("GET", "/admin/users/import") is None
    assert m.find("POST", "/admin/users") is None


@pytest.mark.parametrize(
    "path",
    [
        "/sessions/..",
        "/sessions/.",
        "/sessions/%2e%2E",
        "/sessions/%2E",
        "/sessions/%",
        "/sessions/%ff",
        "/sessions/%+1",
    ],
)
def test_dot_and_malformed_parameters_are_refused(path: str) -> None:
    m = manifest({"method": "GET", "path": "/sessions/{id}", "credential": "access"})
    assert m.find("GET", path) is None


def test_parameters_are_re_escaped() -> None:
    route = manifest({"method": "GET", "path": "/sessions/{id}", "credential": "access"}).routes[0]
    assert route.upstream_path({"id": "a b"}) == "/sessions/a%20b"
    assert route.upstream_path({"id": "../x?y#z"}) == "/sessions/..%2Fx%3Fy%23z"
    assert route.upstream_path({"id": "a@b.test"}) == "/sessions/a@b.test"
