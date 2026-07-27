"""safety_kernel_middleware — app-layer Safety Kernel enforcement for Python.

A FastAPI/Starlette middleware that consults the Safety Kernel once per request
through the ``safety-kernel-client`` PyO3 SDK, with a three-tier route policy
and fail-closed failure semantics.

Quickstart::

    from fastapi import FastAPI
    from safety_kernel_client import SafetyKernelClient
    from safety_kernel_middleware import (
        SafetyKernelMiddleware, SafetyPolicy, PolicyEntry, PolicyTier,
        install_safety_middleware,
    )

    app = FastAPI()
    client = SafetyKernelClient("https://kernel:9443", api_key, pinned_pubkey)
    policy = SafetyPolicy(
        entries=[PolicyEntry(r"^/healthz$", "*", PolicyTier.UNRESTRICTED)],
        default_tier=PolicyTier.GATED,  # fail-closed by default
    )
    install_safety_middleware(app, client=client, policy=policy, subject="api")

Install with the framework extra: ``pip install safety-kernel-middleware[fastapi]``.
"""

from __future__ import annotations

from .middleware import (
    KernelClient,
    SafetyKernelMiddleware,
    SafetyMiddleware,
    install_safety_middleware,
)
from .policy import DEFAULT_POLICY, PolicyEntry, PolicyTier, SafetyPolicy

__all__ = [
    "DEFAULT_POLICY",
    "KernelClient",
    "PolicyEntry",
    "PolicyTier",
    "SafetyKernelMiddleware",
    "SafetyMiddleware",
    "SafetyPolicy",
    "install_safety_middleware",
]

__version__ = "0.1.0"
