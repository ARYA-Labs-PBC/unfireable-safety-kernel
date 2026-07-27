# safety-kernel-middleware

App-layer [Unfireable Safety Kernel](https://github.com/ARYA-Labs-Public/unfireable-safety-kernel)
enforcement for Python web apps. A FastAPI/Starlette middleware that consults
the kernel once per request through the
[`safety-kernel-client`](https://pypi.org/project/safety-kernel-client/) PyO3
SDK, with a three-tier route policy and **fail-closed** semantics.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://github.com/ARYA-Labs-Public/unfireable-safety-kernel/blob/main/LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org)

## What this does

Classifies each route into a tier and enforces the kernel decision:

| Tier | Kernel call | On deny | On unreachable |
|---|---|---|---|
| `UNRESTRICTED` | no | — | — |
| `SUPERVISED` | yes | continue + audit warning | continue + audit warning (fail-open) |
| `GATED` | yes | **403** | **503** |

Unmatched routes default to **`GATED`** — fail-closed by default. The decision
comes from `safety_kernel_client.SafetyKernelClient`, which is itself
fail-closed (ALLOW → dict, DENY → `PermissionError`, unreachable/bad-signature →
`ConnectionError`); this middleware maps those to HTTP status codes.

## Install

```bash
pip install safety-kernel-middleware[fastapi]
```

## Quickstart

```python
from fastapi import FastAPI
from safety_kernel_client import SafetyKernelClient
from safety_kernel_middleware import (
    SafetyPolicy, PolicyEntry, PolicyTier, install_safety_middleware,
)

app = FastAPI()
client = SafetyKernelClient("https://kernel.local:9443", api_key, pinned_pubkey_bytes)
policy = SafetyPolicy(
    entries=[
        PolicyEntry(r"^/healthz$", "*", PolicyTier.UNRESTRICTED),
        PolicyEntry(r"^/deploy$", "POST", PolicyTier.GATED, action="deploy"),
    ],
    default_tier=PolicyTier.GATED,  # fail-closed by default
)
install_safety_middleware(app, client=client, policy=policy, subject="api")
```

## Testing

```bash
pip install safety-kernel-middleware[test]
pytest safety_kernel_middleware/tests/
```

The suite drives the middleware with fake clients (allow / deny / unavailable)
and asserts the fail-closed cases: a GATED route whose kernel call denies →
403, is unreachable → 503, and an unclassified route defaults to GATED.

## Security

Report security issues privately to **security@aryalabs.io**. See the upstream
[SECURITY.md](https://github.com/ARYA-Labs-Public/unfireable-safety-kernel/blob/main/SECURITY.md).

## License

Apache-2.0 — see [LICENSE](https://github.com/ARYA-Labs-Public/unfireable-safety-kernel/blob/main/LICENSE).
