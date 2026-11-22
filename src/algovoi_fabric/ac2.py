"""Algorand AC2 consent face: proof of *who approved* a settlement.

The fabric journey already proves the decision (AV-RAILS), the payment
evidence (AV-PEF) and the sealed-archive binding (AV-VCS). AC2 adds the
consent seam: ``avm-mesh`` proves *what settled*, AC2 proves *who approved*,
and this face makes the second checkable against the first inside one
tamper-evident journey.

Nothing here re-implements cryptography or canonicalisation. Every consent
check delegates to the published ``avm_ac2.verify_consent`` (which itself
re-verifies the sealed receipt's LEVEL 1 ``content_hash`` before reading any
claim, and verifies a detached Ed25519 signature over the settlement's
canonical payload). The fabric boundary only translates the estate's
``MeshError`` into ``FabricError`` and refuses a journey that *claims* AC2
but carries no verifying consent (fail-closed, trust-boundary Rule K).

What the levels mean is owned by avm-ac2, not restated as a stronger claim
here: ``consent_present`` proves a key signed this settlement, NOT that a
human or a hardware passkey approved; ``sender_bound`` additionally ties that
key to the authenticated transaction sender; ``consensus_bound`` additionally
requires a stake-attested settlement. Fabric never upgrades a level.
"""
from __future__ import annotations

import copy
from typing import Any

from algovoi_keystone_connect import keystone_ref
from avm_ac2 import LEVEL_NONE, verify_consent
from avm_mesh import MeshError

from .compose import FabricError, compose_chain

AC2_BIND_ACTION_TYPE = "ac2:bind"


def ac2_binding_ref(*, content_hash: str, level: str, did: str) -> str:
    """Content-addressed AC2 binding, delegating to the canonical keystone_ref.

    Binds the journey to the sealed receipt's ``content_hash`` (which already
    covers the consent block) at the reached consent ``level`` for the named
    ``did``. Recomputable by anyone offline; raises FabricError on a malformed
    attestation and never returns a reference for an invalid input.
    """
    if not isinstance(content_hash, str) or not content_hash:
        raise FabricError("ac2 content_hash must be a non-empty string")
    if not isinstance(level, str) or not level:
        raise FabricError("ac2 level must be a non-empty string")
    if not isinstance(did, str):
        raise FabricError("ac2 did must be a string")
    return keystone_ref({"action_type": AC2_BIND_ACTION_TYPE,
                         "content_hash": content_hash, "level": level, "did": did})


def verify_ac2_consent(sealed: dict, *, expected_sender: bytes | None = None,
                       require: bool = True) -> dict:
    """Verify the AC2 consent inside a sealed receipt, fail-closed.

    Delegates to ``avm_ac2.verify_consent`` and translates every estate refusal
    (``MeshError``) — and any structural exception a hostile receipt provokes —
    into ``FabricError`` so a caller's ``except FabricError`` always catches it.
    A receipt that carries no verifying consent (``level == none``) is refused:
    a journey may not claim AC2 without an approval that actually checks out.

    Returns {level, reason, did, content_hash, binding_ref}. ``expected_sender``
    (the 32-byte authenticated STIB sender) is passed straight through; supplying
    it is what promotes the result to ``sender_bound``.
    """
    if not isinstance(sealed, dict):
        raise FabricError("ac2 sealed receipt must be a dict")
    try:
        report = verify_consent(sealed, expected_sender=expected_sender, require=require)
    except MeshError as exc:
        raise FabricError(str(exc)) from exc
    except Exception as exc:
        # Uniform contract (Rule K): ANY exception a hostile receipt provokes in
        # the foreign verifier surfaces as a fabric refusal, never as a raw
        # structural exception escaping the boundary. MeshError is handled above
        # for its specific message; this net is deliberately unconditional so a
        # future avm-ac2 change cannot leak a new exception type past it.
        raise FabricError(f"malformed ac2 sealed receipt: {exc}") from exc
    level = report.get("level")
    if level == LEVEL_NONE:
        raise FabricError("journey claims AC2 but the receipt carries no verifying consent")
    content_hash = sealed.get("content_hash")
    did = report.get("did") or ""
    binding = ac2_binding_ref(content_hash=content_hash, level=level, did=did)
    return {"level": level, "reason": report.get("reason"), "did": report.get("did"),
            "content_hash": content_hash, "binding_ref": binding}


def compose_ac2_chain(sealed: dict, *, expected_sender: bytes | None = None,
                      execution: str = "execution", description: str = "") -> dict:
    """Compose a keystone chain whose execution link binds a verifying AC2 consent.

    The consent is verified first (fail-closed); only then is a chain emitted,
    so a forged or absent approval can never be bound. The execution preimage
    carries the content-addressed ``ac2_binding_ref`` and the reached level.
    """
    report = verify_ac2_consent(sealed, expected_sender=expected_sender, require=True)
    preimage = {"action_class": "ac2:consent",
                "ac2_binding_ref": report["binding_ref"],
                "ac2_level": report["level"],
                "ac2_did": report["did"] or ""}
    return compose_chain([(execution, preimage)], description=description)


def ac2_attestation(sealed: dict, *, expected_sender: bytes | None = None) -> dict:
    """The journey-ready AC2 block: the sealed receipt plus its recomputed binding.

    Carrying the sealed receipt makes the block self-verifiable offline (the
    consent signature is re-checked from these bytes, not trusted on the
    issuer's word), exactly as the journey carries the PEF frame.
    """
    report = verify_ac2_consent(sealed, expected_sender=expected_sender, require=True)
    return {"sealed": copy.deepcopy(sealed), "level": report["level"],
            "did": report["did"], "content_hash": report["content_hash"],
            "binding_ref": report["binding_ref"]}


def verify_ac2_attestation(block: Any, *, expected_sender: bytes | None = None) -> dict:
    """Re-verify a journey AC2 block offline, fail-closed at every step.

    ``expected_sender`` must be the same 32-byte authenticated STIB sender used
    at compose time: the binding covers the reached level, so a ``sender_bound``
    block only re-verifies when the sender is supplied again. Without it the
    re-check stays at ``consent_present`` and the binding refuses to recompute
    (fail-closed, never a silent downgrade).
    """
    if not isinstance(block, dict):
        raise FabricError("ac2 attestation must be a dict")
    sealed = block.get("sealed")
    report = verify_ac2_consent(sealed, expected_sender=expected_sender, require=True)
    recomputed = ac2_binding_ref(content_hash=report["content_hash"],
                                 level=report["level"], did=report["did"] or "")
    if recomputed != block.get("binding_ref"):
        raise FabricError("AC2 binding_ref does not recompute")
    if block.get("level") != report["level"]:
        raise FabricError("AC2 attestation level does not match the re-verified consent")
    return report