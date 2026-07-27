"""Behavioural + adversarial tests for the Safety Kernel middleware.

The adversarial cases (Rule 8) are the fail-closed ones the gate MUST honour:
a GATED route whose kernel call denies or is unreachable must NOT reach the
handler, and an UNCLASSIFIED route must default to GATED (fail-closed), never
pass through.
"""

from __future__ import annotations

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from safety_kernel_middleware import (
    PolicyEntry,
    PolicyTier,
    SafetyKernelMiddleware,
    SafetyPolicy,
)


async def _ok(request):  # noqa: ANN001, ANN201
    return PlainTextResponse("handler-reached")


POLICY = SafetyPolicy(
    entries=[
        PolicyEntry(r"^/healthz$", "*", PolicyTier.UNRESTRICTED),
        PolicyEntry(r"^/deploy$", "POST", PolicyTier.GATED, action="deploy"),
        PolicyEntry(r"^/read$", "GET", PolicyTier.SUPERVISED, action="read"),
    ],
    default_tier=PolicyTier.GATED,  # fail-closed by default
)


def _app(client) -> TestClient:  # noqa: ANN001
    app = Starlette(
        routes=[
            Route("/healthz", _ok),
            Route("/deploy", _ok, methods=["POST"]),
            Route("/read", _ok),
            Route("/unlisted", _ok, methods=["POST"]),
        ]
    )
    app.add_middleware(SafetyKernelMiddleware, client=client, policy=POLICY, subject="api")
    return TestClient(app, raise_server_exceptions=False)


class AllowClient:
    def authorize(self, action, fp, run_id, subject, traceparent=None):  # noqa: ANN001
        return {"decision": "allow", "token": "t"}


class DenyClient:
    def authorize(self, *a, **k):  # noqa: ANN002, ANN003
        raise PermissionError("kernel_denied: not allowlisted")


class UnavailableClient:
    def authorize(self, *a, **k):  # noqa: ANN002, ANN003
        raise ConnectionError("kernel_unavailable: circuit breaker open")


class SpyClient:
    def __init__(self) -> None:
        self.calls = 0

    def authorize(self, *a, **k):  # noqa: ANN002, ANN003
        self.calls += 1
        return {"decision": "allow"}


# --- happy paths -----------------------------------------------------------
def test_unrestricted_route_skips_kernel():
    spy = SpyClient()
    resp = _app(spy).get("/healthz")
    assert resp.status_code == 200
    assert resp.text == "handler-reached"
    assert spy.calls == 0  # no kernel call on UNRESTRICTED


def test_gated_allow_reaches_handler():
    resp = _app(AllowClient()).post("/deploy")
    assert resp.status_code == 200
    assert resp.text == "handler-reached"


# --- adversarial: GATED must fail closed -----------------------------------
def test_gated_deny_returns_403_and_blocks_handler():
    resp = _app(DenyClient()).post("/deploy")
    assert resp.status_code == 403
    assert resp.text != "handler-reached"


def test_gated_unavailable_returns_503_and_blocks_handler():
    resp = _app(UnavailableClient()).post("/deploy")
    assert resp.status_code == 503
    assert resp.text != "handler-reached"


def test_unclassified_route_defaults_to_gated_fail_closed():
    # No policy entry matches /unlisted → default GATED → unavailable → 503.
    resp = _app(UnavailableClient()).post("/unlisted")
    assert resp.status_code == 503
    assert resp.text != "handler-reached"


def test_unclassified_route_denied_is_403():
    resp = _app(DenyClient()).post("/unlisted")
    assert resp.status_code == 403


# --- SUPERVISED fails open (documented, deliberate) ------------------------
def test_supervised_deny_continues():
    resp = _app(DenyClient()).get("/read")
    assert resp.status_code == 200
    assert resp.text == "handler-reached"


def test_supervised_unavailable_continues():
    resp = _app(UnavailableClient()).get("/read")
    assert resp.status_code == 200
    assert resp.text == "handler-reached"


# --- construction guard ----------------------------------------------------
def test_exports_present():
    import safety_kernel_middleware as m

    for name in ("SafetyKernelMiddleware", "SafetyMiddleware", "install_safety_middleware"):
        assert hasattr(m, name)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
