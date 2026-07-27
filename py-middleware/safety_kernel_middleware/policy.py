"""Three-tier route policy for the Safety Kernel middleware.

Routes are classified into one of three tiers:

* ``UNRESTRICTED`` — no kernel call (e.g. ``/healthz``, ``/metrics``, static
  assets). Never blocks request flow.
* ``SUPERVISED``  — the kernel is called, but a transport failure fails *open*
  with an audit-only warning. Use sparingly — fail-open is a deliberate
  reduction in the safety guarantee.
* ``GATED``       — the kernel is called fail-closed. Any failure (unreachable,
  deny, signature mismatch) terminates the request with 403 (deny) or 503
  (unavailable). This is the default for any route that mutates state or
  accesses sensitive data.

The default for an unmatched route is ``GATED`` — fail-closed by default.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum


class PolicyTier(str, Enum):
    """Three-tier route classification."""

    UNRESTRICTED = "unrestricted"
    SUPERVISED = "supervised"
    GATED = "gated"


@dataclass(frozen=True)
class PolicyEntry:
    """One rule in a :class:`SafetyPolicy` (first match wins).

    Args:
        route_pattern: Regex matched against the request path.
        method: HTTP method (``"*"`` matches any).
        tier: Tier to apply when this entry matches.
        action: Action name sent to the kernel as the ``action`` field (only
            used for ``SUPERVISED`` / ``GATED``). Should be on the kernel's
            allowlist.
    """

    route_pattern: str
    method: str
    tier: PolicyTier
    action: str = ""


@dataclass
class SafetyPolicy:
    """Ordered list of :class:`PolicyEntry` — first match wins.

    A request with no matching entry defaults to :attr:`default_tier` (which
    itself defaults to ``GATED`` — fail-closed-by-default).
    """

    entries: list[PolicyEntry] = field(default_factory=list)
    default_tier: PolicyTier = PolicyTier.GATED
    default_action: str = "unclassified"

    def __post_init__(self) -> None:
        self._compiled: list[tuple[re.Pattern[str], PolicyEntry]] = [
            (re.compile(e.route_pattern), e) for e in self.entries
        ]

    def classify(self, *, path: str, method: str) -> tuple[PolicyTier, str]:
        """Return the ``(tier, action)`` pair for the given request."""
        for pattern, entry in self._compiled:
            if entry.method not in ("*", method.upper()):
                continue
            if pattern.match(path):
                return entry.tier, entry.action or self.default_action
        return self.default_tier, self.default_action

    def routes_at_tier(self, tier: PolicyTier) -> Iterable[PolicyEntry]:
        """Iterate over policy entries at the given tier (audit helper)."""
        for entry in self.entries:
            if entry.tier == tier:
                yield entry


# A minimal example policy: health/metrics are unrestricted, everything else is
# GATED by default (fail-closed). Real callers compose their own.
DEFAULT_POLICY = SafetyPolicy(
    entries=[
        PolicyEntry(r"^/healthz$", "*", PolicyTier.UNRESTRICTED),
        PolicyEntry(r"^/metrics$", "GET", PolicyTier.UNRESTRICTED),
    ],
    default_tier=PolicyTier.GATED,
)
