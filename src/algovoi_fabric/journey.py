"""Full-journey composition: AV-RAILS -> AV-PEF -> AV-VCS.

One envelope binds the agentic-commerce decision (the AV-RAILS keystone
chain), the payment evidence frame (AV-PEF), and the sealed-archive storage
binding (AV-VCS), so the entire journey can be started and finished as a
single tamper-evident artefact. Every reference delegates to a published
estate primitive, so the whole journey recomputes offline with no vendor in
the loop:

  * AV-RAILS - algovoi_keystone.verify.verify_chain
  * AV-PEF   - algovoi_pef.verify_pef
  * AV-VCS   - algovoi_keystone_connect.keystone_ref over the ``archive:bind``
               preimage, identical to the public algovoi-keystone-archive
               bridge that AV-VCS's Compliance Command Center re-verifies.

The post-quantum sealing (Falcon-1024), authenticated encryption
(ML-KEM-1024) and RFC 3161 timestamping of the archive entry are performed by
the customer's licensed AV-VCS engine. Fabric binds the journey to that
sealed entry by its content address and never imports the engine; the
binding is content-addressed and recomputable by anyone offline.
"""
from __future__ import annotations

import copy
from typing import Any

from algovoi_keystone_connect import keystone_ref
from algovoi_pef import verify_pef

from .ac2 import ac2_attestation, verify_ac2_attestation
from .compose import FabricError, verify

JOURNEY_SCHEMA = "algovoi-fabric-journey/v1"
BIND_ACTION_TYPE = "archive:bind"


def _execution_ref(chain: dict, execution: str) -> str:
    for link in chain["chain"]:
        if link["name"] == execution:
            return link["ref"]
    raise FabricError(f"journey needs an execution link named '{execution}'")


def _execution_preimage(chain: dict, execution: str) -> dict:
    for link in chain["chain"]:
        if link["name"] == execution:
            return link["preimage"]
    raise FabricError(f"journey needs an execution link named '{execution}'")


def _validate_chain_shape(chain: Any) -> None:
    """Refuse a malformed journey chain with FabricError (trust-boundary Rule K).

    A journey binds a compose_chain() output; every link must carry a string
    name, a string ref and a dict preimage. Without this guard a hostile chain
    (a string/number ``chain``, a link missing name/ref/preimage) raised
    TypeError/KeyError that escaped a caller's ``except FabricError``, and a
    preimage-less execution link was emitted outright (fail-open).
    """
    if not isinstance(chain, dict):
        raise FabricError("journey needs a composed keystone chain")
    links = chain.get("chain")
    if not isinstance(links, list) or not links:
        raise FabricError("journey chain must contain a non-empty 'chain' array")
    for i, link in enumerate(links):
        if not isinstance(link, dict):
            raise FabricError(f"journey chain link at index {i} must be a dict")
        if not isinstance(link.get("name"), str) or not link["name"]:
            raise FabricError(f"journey chain link at index {i} has no 'name'")
        if not isinstance(link.get("ref"), str) or not link["ref"]:
            raise FabricError(f"journey chain link {link['name']!r} has no 'ref'")
        if not isinstance(link.get("preimage"), dict):
            raise FabricError(f"journey chain link {link['name']!r} has no preimage dict")


def archive_binding_ref(*, execution_ref: str, doc_hash: str,
                        entry_id: str, seq: int) -> str:
    """The AV-VCS storage binding, delegating to the canonical keystone_ref.

    Uses the exact ``archive:bind`` preimage of the public
    algovoi-keystone-archive bridge, so a binding Fabric emits is accepted by
    AV-VCS offline. Raises FabricError on a malformed attestation; never
    returns a reference for an invalid input.
    """
    if not isinstance(execution_ref, str) or not execution_ref:
        raise FabricError("execution_ref must be a non-empty string")
    if not isinstance(doc_hash, str) or not doc_hash:
        raise FabricError("doc_hash must be a non-empty string")
    if not isinstance(entry_id, str) or not entry_id:
        raise FabricError("entry_id must be a non-empty string")
    if not isinstance(seq, int) or isinstance(seq, bool):
        raise FabricError("seq must be an int")
    return keystone_ref({"action_type": BIND_ACTION_TYPE,
                         "execution_ref": execution_ref, "doc_hash": doc_hash,
                         "entry_id": entry_id, "seq": seq})


def compose_journey(chain: dict, *, execution: str = "execution",
                    pef_frame: dict | None = None,
                    archive: dict | None = None,
                    ac2_sealed: dict | None = None,
                    ac2_expected_sender: bytes | None = None,
                    description: str = "") -> dict:
    """Compose the full AV-RAILS -> AV-PEF -> AV-VCS journey envelope.

    chain: a compose_chain() output (the AV-RAILS decision chain).
    execution: name of the execution link whose ref anchors the downstream
        levels.
    pef_frame: optional AV-PEF frame (build_pef output). The execution link
        must structurally bind its frame_id via settlement_frame_id.
    archive: optional AV-VCS attestation {doc_hash, entry_id, seq} from the
        customer's sealed engine; Fabric emits the content-addressed
        binding_ref.

    Fail-closed: a missing execution link, an unbound or invalid PEF frame,
    or a malformed archive attestation raises before any envelope is emitted.
    """
    if not isinstance(chain, dict) or "chain" not in chain:
        raise FabricError("journey needs a composed keystone chain")
    _validate_chain_shape(chain)
    # Refuse a forged or unverifiable chain at compose time, not only at verify:
    # binding must never silently trust a ref the keystone verifier would reject.
    # verify_chain reports (ChainResult.ok) rather than raising on a ref mismatch,
    # so the ok flag must be asserted explicitly to be fail-closed here.
    chain_result = verify(chain)
    if not getattr(chain_result, "ok", False):
        raise FabricError("journey chain does not verify offline")
    exec_ref = _execution_ref(chain, execution)
    out: dict[str, Any] = {
        "schema": JOURNEY_SCHEMA,
        "canon": chain.get("canon", "jcs-rfc8785-v1"),
        "levels": ["av-rails"],
        "chain": copy.deepcopy(chain),
        "execution": execution,
        "execution_ref": exec_ref,
    }
    if pef_frame is not None:
        if not isinstance(pef_frame, dict):
            raise FabricError("pef_frame must be a dict")
        exec_pre = _execution_preimage(chain, execution)
        if exec_pre.get("settlement_frame_id") != pef_frame.get("frame_id"):
            raise FabricError("execution link does not bind the supplied PEF frame_id")
        if verify_pef(pef_frame).get("valid") is not True:
            raise FabricError("PEF frame does not verify offline")
        out["pef_frame"] = copy.deepcopy(pef_frame)
        out["levels"].append("av-pef")
    if archive is not None:
        if not isinstance(archive, dict):
            raise FabricError("archive attestation must be a dict")
        binding = archive_binding_ref(execution_ref=exec_ref,
                                      doc_hash=archive.get("doc_hash"),
                                      entry_id=archive.get("entry_id"),
                                      seq=archive.get("seq"))
        out["archive"] = {"doc_hash": archive["doc_hash"],
                          "entry_id": archive["entry_id"],
                          "seq": archive["seq"], "binding_ref": binding}
        out["levels"].append("av-vcs")
    if ac2_sealed is not None:
        # AC2 consent (Algorand/Voi): proof of who approved the settlement.
        # Verified fail-closed before binding; the block carries the sealed
        # receipt so the consent is re-checkable offline, like the PEF frame.
        out["ac2"] = ac2_attestation(ac2_sealed, expected_sender=ac2_expected_sender)
        out["levels"].append("ac2")
    if description:
        out["description"] = description
    return out


def verify_journey(envelope: dict, *, ac2_expected_sender: bytes | None = None) -> dict:
    """Offline verification of the whole journey, fail-closed at every level.

    Recomputes the AV-RAILS chain, the AV-PEF frame and the AV-VCS storage
    binding, and checks that the downstream levels anchor to the chain's own
    execution link. Any mismatch raises FabricError; a valid journey returns
    {"ok": True, "levels": [...], "execution_ref": ...}.

    ac2_expected_sender: the same 32-byte authenticated STIB sender supplied at
        compose time, needed to re-verify a sender_bound AC2 block (the binding
        covers the reached level). Omitting it keeps the re-check fail-closed.
    """
    if not isinstance(envelope, dict) or envelope.get("schema") != JOURNEY_SCHEMA:
        raise FabricError("not a fabric journey envelope")
    chain = envelope.get("chain")
    _validate_chain_shape(chain)
    res = verify(chain)
    if res.ok is not True:
        raise FabricError("AV-RAILS chain failed offline verification")
    execution = envelope.get("execution")
    exec_ref = _execution_ref(chain, execution)
    if exec_ref != envelope.get("execution_ref"):
        raise FabricError("journey execution_ref does not match the chain's execution link")
    levels = ["av-rails"]
    if "pef_frame" in envelope:
        frame = envelope["pef_frame"]
        if not isinstance(frame, dict):
            raise FabricError("pef_frame must be a dict")
        if verify_pef(frame).get("valid") is not True:
            raise FabricError("AV-PEF frame failed offline verification")
        exec_pre = _execution_preimage(chain, execution)
        if exec_pre.get("settlement_frame_id") != frame.get("frame_id"):
            raise FabricError("execution link does not bind the PEF frame_id")
        levels.append("av-pef")
    if "archive" in envelope:
        a = envelope["archive"]
        if not isinstance(a, dict):
            raise FabricError("archive attestation must be a dict")
        recomputed = archive_binding_ref(execution_ref=exec_ref,
                                         doc_hash=a.get("doc_hash"),
                                         entry_id=a.get("entry_id"),
                                         seq=a.get("seq"))
        if recomputed != a.get("binding_ref"):
            raise FabricError("AV-VCS archive binding_ref does not recompute")
        levels.append("av-vcs")
    if "ac2" in envelope:
        verify_ac2_attestation(envelope["ac2"], expected_sender=ac2_expected_sender)
        levels.append("ac2")
    return {"ok": True, "levels": levels, "execution_ref": exec_ref}
