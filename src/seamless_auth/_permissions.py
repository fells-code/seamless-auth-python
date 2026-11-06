"""Permission rules, shared by the session guards and the verify-only guard.

Matching is exact and case-sensitive, unlike roles: no trimming, no wildcards, no
implied grants. ``invoices:write`` does not satisfy ``invoices:read``.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Literal

PermissionMode = Literal["any", "all"]


def permission_names(claim: Any) -> tuple[str, ...]:
    """A permission claim as names. A claim that is not a list reads as empty and
    entries that are not strings are ignored, so a malformed claim never fails."""
    return tuple(p for p in claim if isinstance(p, str)) if isinstance(claim, list) else ()


@dataclass(frozen=True)
class PermissionRule:
    """What a guard requires.

    ``permissions`` may be empty, and an empty rule allows nobody, in any mode.
    ``mode`` is ``"any"`` (at least one is held) or ``"all"`` (every one is held).
    With ``organization``, only the active organization's permissions count and the
    token must have an active organization. ``organization_param`` implies that, and
    also names the route parameter that must equal the active organization's id.
    Without it, a token for organization A passes on a route for organization B.
    """

    permissions: tuple[str, ...] = ()
    mode: PermissionMode = "any"
    organization: bool = False
    organization_param: str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.permissions, str):
            raise TypeError("seamless-auth: pass a list of permissions, not a string")
        names = tuple(self.permissions)
        if not all(isinstance(p, str) and p for p in names):
            raise ValueError("seamless-auth: permissions must be non-empty strings")
        if self.mode not in ("any", "all"):
            raise ValueError('seamless-auth: permission mode must be "any" or "all"')
        param = self.organization_param
        if param is not None and (not isinstance(param, str) or not param):
            raise ValueError("seamless-auth: organization_param must be a non-empty string")
        object.__setattr__(self, "permissions", names)

    def allows(
        self,
        permissions: Collection[str],
        organization_permissions: Collection[str],
        organization_id: str | None,
        route_params: Mapping[str, Any] | None = None,
    ) -> bool:
        """Whether a holder of these permissions meets the rule."""
        if not self.permissions:
            return False
        if self.organization or self.organization_param is not None:
            if not organization_id or not self._route_matches(organization_id, route_params):
                return False
            held = set(organization_permissions)
        else:
            held = {*permissions, *organization_permissions}
        pick = all if self.mode == "all" else any
        return pick(p in held for p in self.permissions)

    def _route_matches(self, organization_id: str, route_params: Mapping[str, Any] | None) -> bool:
        if self.organization_param is None:
            return True
        # str() because a route converter may have parsed the value, into a UUID say.
        value = (route_params or {}).get(self.organization_param)
        return value is not None and str(value) == organization_id


def required_permissions(
    permissions: Iterable[str] | None,
    *,
    mode: PermissionMode = "any",
    organization: bool = False,
    organization_param: str | None = None,
) -> PermissionRule | None:
    """A guard's permission options as a rule: ``None`` means no permission check.
    The other options without ``permissions`` are refused, because that guard would
    look scoped and check nothing."""
    if permissions is None:
        if mode != "any" or organization or organization_param is not None:
            raise ValueError("seamless-auth: permission options need permissions")
        return None
    if isinstance(permissions, str):
        raise TypeError("seamless-auth: pass a list of permissions, not a string")
    return PermissionRule(tuple(permissions), mode, organization, organization_param)
