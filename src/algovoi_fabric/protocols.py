"""Fail-closed protocol-version front-door for the AlgoVoi bundle.

This is the single source of truth for *which* agentic-commerce protocol
versions the bundle accepts. Every inbound message is gated against the
declared matrix before it can enter a keystone chain: an unknown protocol or
an unsupported version raises ``ProtocolError`` and nothing is emitted. That
is the "all versions" discipline made honest -- the bundle covers the
specific spec versions the estate has proven, and refuses everything else
rather than silently accepting a shape it cannot verify.

Supported matrix (provenance):
  * x402  "1", "2"   - HTTP 402; v1 legacy ``x-payment`` and v2
                       ``PAYMENT-SIGNATURE`` are both present in the estate
                       adapter (x402_adapter.py).
  * ap2   "0.1", "0.2" - SD-JWT+kb IntentMandate / CartMandate.
  * mpp   "2"        - IETF draft payment auth (version 2).
  * a2a   "0.3", "1.0.1" - JSON-RPC agent-to-agent; 0.3 is pack-proven
                       (keystone_4proto_pack.json), 1.0.1 is graph-EVIDENCED.

A accepted message is content-addressed with the estate's one reference
primitive (``algovoi_keystone_connect.keystone_ref`` = sha256 over RFC 8785
JCS) and wrapped as a ``protocol:face`` preimage, so the protocol/version and
the exact message bytes become a tamper-evident link that the real keystone
verifier recomputes offline. Fabric never invents a wire schema: it binds the
caller's message by content address and gates the version.
"""
from __future__ import annotations

import copy
from typing import Any

from algovoi_keystone_connect import keystone_ref

from .compose import FabricError, compose_chain

FACE_ACTION_TYPE = "protocol:face"

# The declared, fail-closed support matrix. Adding a version here is a
# deliberate act that must be backed by a conformance proof, not a default.
SUPPORTED_VERSIONS: dict[str, frozenset[str]] = {
    "x402": frozenset({"1", "2"}),
    "ap2": frozenset({"0.1", "0.2"}),
    "mpp": frozenset({"2"}),
    "a2a": frozenset({"0.3", "1.0.1"}),
}


class ProtocolError(FabricError):
    """Raised when a protocol/version is unsupported or a message is malformed."""


def supported_matrix() -> dict[str, list[str]]:
    """A JSON-friendly copy of the support matrix (sorted versions)."""
    return {p: sorted(v) for p, v in SUPPORTED_VERSIONS.items()}


def check_version(protocol: str, version: str) -> None:
    """Fail-closed gate: raise unless (protocol, version) is supported.

    Unknown protocol and unsupported version are distinct, explicit errors so
    a caller can tell a typo'd protocol from a real-but-uncovered version.
    """
    if not isinstance(protocol, str) or protocol not in SUPPORTED_VERSIONS:
        raise ProtocolError(f"unsupported protocol {protocol!r}")
    if not isinstance(version, str) or version not in SUPPORTED_VERSIONS[protocol]:
        raise ProtocolError(
            f"unsupported version {version!r} for protocol {protocol!r}; "
            f"supported: {sorted(SUPPORTED_VERSIONS[protocol])}"
        )


def protocol_face(protocol: str, version: str, message: dict[str, Any]) -> dict[str, Any]:
    """Gate the version and content-address the message into a face preimage.

    Returns a ``protocol:face`` preimage binding the exact message bytes by
    ``message_ref``. Raises ProtocolError on an unsupported protocol/version
    or a non-dict message; never returns a face for an invalid input.
    """
    check_version(protocol, version)
    if not isinstance(message, dict):
        raise ProtocolError("protocol message must be a dict")
    return {
        "action_type": FACE_ACTION_TYPE,
        "protocol": protocol,
        "version": version,
        "message_ref": keystone_ref(message),
    }


def compose_protocol_chain(
    protocol: str,
    version: str,
    message: dict[str, Any],
    *,
    execution: dict[str, Any] | None = None,
    description: str = "",
) -> dict[str, Any]:
    """Compose a verifiable keystone chain anchored by a gated protocol face.

    The chain has a ``protocol`` link (the gated, content-addressed face) and
    an ``execution`` link that binds it via ``@protocol``. The result is a
    ``compose_chain`` output accepted by the real keystone verifier and ready
    for ``compose_journey`` (AV-RAILS -> AV-PEF -> AV-VCS).

    Fail-closed: an unsupported protocol/version or malformed message raises
    before any chain is emitted.
    """
    face = protocol_face(protocol, version, message)
    exec_pre: dict[str, Any] = {"action_type": "execute", "protocol_ref": "@protocol"}
    if execution is not None:
        if not isinstance(execution, dict):
            raise ProtocolError("execution preimage must be a dict")
        extra = copy.deepcopy(execution)
        # The caller may not override the structural binding to the face.
        extra.pop("protocol_ref", None)
        extra.pop("action_type", None)
        exec_pre.update(extra)
    return compose_chain(
        [("protocol", face), ("execution", exec_pre)],
        description=description or f"{protocol} v{version} journey",
    )
