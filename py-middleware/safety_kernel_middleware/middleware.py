"""FastAPI / Starlette Safety Kernel middleware (app-layer enforcement seam).

A drop-in :class:`BaseHTTPMiddleware` that consults the Safety Kernel once per
request via the ``safety-kernel-client`` PyO3 SDK. The policy classifies each
route into one of three tiers; only ``GATED`` and ``SUPERVISED`` routes hit the
kernel.

Failure semantics (fail-closed):

* ``GATED`` + kernel deny        → 403 Forbidden
* ``GATED`` + kernel unreachable → 503 Service Unavailable
* ``GATED`` + signature failed   → 503 Service Unavailable
* ``SUPERVISED`` + any failure   → request continues, audit warning emitted
* ``UNRESTRICTED``               → no kernel call

The client's ``authorize`` is fail-closed at the source: ALLOW returns a dict,
DENY raises ``PermissionError``, and unreachable / breaker-open / bad-signature
raise ``ConnectionError``. This middleware maps those to HTTP status codes.
"""

from __future__ import annotations

import logging
from typing import Any, Protocol, runtime_checkable

from safety_kernel_client import params_fingerprint

from .policy import PolicyTier, SafetyPolicy

logger = logging.getLogger("safety_kernel_middleware")

try:
    from starlette.concurrency import run_in_threadpool
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response

    _HAVE_STARLETTE = True
except ImportError:  # base install without the [fastapi] extra
    _HAVE_STARLETTE = False
    BaseHTTPMiddleware = object  # type: ignore[assignment,misc]


@runtime_checkable
class KernelClient(Protocol):
    """The subset of ``safety_kernel_client.SafetyKernelClient`` this needs.

    ``authorize`` MUST be fail-closed: return a dict on ALLOW, raise
    ``PermissionError`` on DENY, and raise ``ConnectionError`` (or any other
    exception) when the kernel is unavailable / the response cannot be trusted.
    """

    def authorize(
        self,
        action: str,
        params_fingerprint: str,
        run_id: str,
        subject: str,
        traceparent: str | None = ...,
    ) -> dict: ...


class SafetyKernelMiddleware(BaseHTTPMiddleware):
    """Per-request Safety Kernel enforcement middleware.

    Args:
        app: the ASGI app.
        client: a :class:`KernelClient` (typically
            ``safety_kernel_client.SafetyKernelClient``).
        policy: the :class:`SafetyPolicy` classifying routes into tiers.
        subject: caller subject reported to the kernel (default ``"api"``).
        run_id_header: request header carrying the run id (default ``x-run-id``).
    """

    def __init__(
        self,
        app: Any,
        *,
        client: KernelClient,
        policy: SafetyPolicy,
        subject: str = "api",
        run_id_header: str = "x-run-id",
    ) -> None:
        if not _HAVE_STARLETTE:
            raise RuntimeError(
                "SafetyKernelMiddleware requires starlette/fastapi — install "
                "`safety-kernel-middleware[fastapi]`."
            )
        super().__init__(app)
        self._client = client
        self._policy = policy
        self._subject = subject
        self._run_id_header = run_id_header

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        tier, action = self._policy.classify(path=request.url.path, method=request.method)
        if tier == PolicyTier.UNRESTRICTED:
            return await call_next(request)

        params_fp = params_fingerprint(
            {
                "method": request.method,
                "path": request.url.path,
                "query": request.url.query,
            }
        )
        run_id = request.headers.get(self._run_id_header, "-")

        try:
            # The client's authorize() is a blocking (tokio-backed) call; run it
            # off the event loop.
            await run_in_threadpool(
                self._client.authorize, action, params_fp, run_id, self._subject
            )
        except PermissionError as exc:  # authoritative DENY
            if tier == PolicyTier.GATED:
                return JSONResponse(
                    status_code=403,
                    content={"detail": "safety kernel denied", "action": action},
                )
            logger.warning("SUPERVISED route %r denied by kernel (continuing): %s", action, exc)
            return await call_next(request)
        except Exception as exc:  # noqa: BLE001 — unavailable / untrusted → fail-closed
            if tier == PolicyTier.GATED:
                return JSONResponse(
                    status_code=503,
                    content={"detail": "safety kernel unavailable", "action": action},
                )
            logger.warning("SUPERVISED route %r kernel unavailable (continuing): %s", action, exc)
            return await call_next(request)

        return await call_next(request)


def install_safety_middleware(
    app: Any,
    *,
    client: KernelClient,
    policy: SafetyPolicy,
    subject: str = "api",
    run_id_header: str = "x-run-id",
) -> None:
    """Register :class:`SafetyKernelMiddleware` on a FastAPI/Starlette ``app``."""
    app.add_middleware(
        SafetyKernelMiddleware,
        client=client,
        policy=policy,
        subject=subject,
        run_id_header=run_id_header,
    )


# Back-compat alias — the reference examples referred to `SafetyMiddleware`.
SafetyMiddleware = SafetyKernelMiddleware
