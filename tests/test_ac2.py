"""AC2 consent face: fail-closed binding of Algorand/Voi settlement consent.

Self-sufficient fixtures: a real Ed25519 keypair signs the settlement's
canonical payload (avm_ac2.consent_payload) and the consent block is sealed
with avm_mesh's own canonicaliser, so the consent_present path needs no
mainnet capture. Every refusal must surface as FabricError (never a raw
MeshError/TypeError/AttributeError), and a journey may not claim AC2 without
a consent that actually verifies.
"""
import base64
import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from avm_ac2 import build_consent, consent_payload
from avm_mesh.sealed import canonical_bytes

from algovoi_fabric import (
    FabricError,
    ac2_attestation,
    ac2_binding_ref,
    compose_ac2_chain,
    compose_chain,
    compose_journey,
    verify_ac2_attestation,
    verify_ac2_consent,
    verify_journey,
)


def _keypair():
    sk = Ed25519PrivateKey.generate()
    return sk, sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _seal(settlement, consent):
    cb = canonical_bytes({"version": 1, "settlement": settlement, "ac2_consent": consent})
    return {"canonical_bytes_b64": base64.b64encode(cb).decode(),
            "content_hash": hashlib.sha256(cb).hexdigest()}


@pytest.fixture()
def valid():
    settlement = {"chain": "mainnet-v1.0", "txid": "TESTTX", "round": 1,
                  "amount": "100", "asset": 0}
    sk, pk = _keypair()
    consent = build_consent(
        did="did:key:zTestController", sig_hint="raw-ed25519",
        public_key_b64=base64.b64encode(pk).decode(),
        signature_b64=base64.b64encode(sk.sign(consent_payload(settlement))).decode(),
        settlement=settlement)
    return _seal(settlement, consent), settlement, pk


# --- verify_ac2_consent: the fail-closed boundary ---------------------------
def test_valid_consent_verifies_and_binds(valid):
    sealed, _, _ = valid
    r = verify_ac2_consent(sealed)
    assert r["level"] == "consent_present"
    assert r["did"] == "did:key:zTestController"
    assert r["binding_ref"].startswith("sha256:") or r["binding_ref"]


def test_sender_binding_promotes_level(valid):
    sealed, _, pk = valid
    r = verify_ac2_consent(sealed, expected_sender=pk)
    assert r["level"] == "sender_bound"


@pytest.mark.parametrize("bad", ["forged", None, 123, []])
def test_non_dict_sealed_is_fabric_error(bad):
    with pytest.raises(FabricError):
        verify_ac2_consent(bad)


def test_absent_consent_refused(valid):
    sealed, settlement, _ = valid
    cb = canonical_bytes({"version": 1, "settlement": settlement})
    no_consent = {"canonical_bytes_b64": base64.b64encode(cb).decode(),
                  "content_hash": hashlib.sha256(cb).hexdigest()}
    with pytest.raises(FabricError):
        verify_ac2_consent(no_consent)


def test_require_false_still_refuses_absent_consent(valid):
    # avm_ac2 with require=False returns level=none WITHOUT raising; the fabric
    # boundary must still refuse it, so a journey can never carry a none-level
    # "consent". This is the test that loads the LEVEL_NONE fail-closed guard.
    sealed, settlement, _ = valid
    cb = canonical_bytes({"version": 1, "settlement": settlement})
    no_consent = {"canonical_bytes_b64": base64.b64encode(cb).decode(),
                  "content_hash": hashlib.sha256(cb).hexdigest()}
    with pytest.raises(FabricError):
        verify_ac2_consent(no_consent, require=False)


def test_tampered_content_hash_refused(valid):
    sealed, _, _ = valid
    bad = dict(sealed, content_hash="0" * 64)
    with pytest.raises(FabricError):
        verify_ac2_consent(bad)


def test_consent_over_different_settlement_refused(valid):
    sealed, settlement, _ = valid
    # Re-seal the SAME consent over a different settlement: the signed payload
    # digest no longer matches, so the consent must be refused.
    other = dict(settlement, amount="999")
    import json
    content = json.loads(base64.b64decode(sealed["canonical_bytes_b64"]))
    consent = content["ac2_consent"]
    with pytest.raises(FabricError):
        verify_ac2_consent(_seal(other, consent))


def test_mesh_error_never_escapes(valid):
    sealed, _, _ = valid
    # A structurally broken receipt must raise FabricError, not MeshError.
    with pytest.raises(FabricError):
        verify_ac2_consent({"canonical_bytes_b64": "!!!not-base64!!!",
                            "content_hash": "x"})


# --- ac2_binding_ref: malformed inputs refused ------------------------------
@pytest.mark.parametrize("kw", [
    {"content_hash": "", "level": "consent_present", "did": "d"},
    {"content_hash": "h", "level": "", "did": "d"},
    {"content_hash": "h", "level": "consent_present", "did": 5},
])
def test_binding_ref_malformed_is_fabric_error(kw):
    with pytest.raises(FabricError):
        ac2_binding_ref(**kw)


# --- compose_ac2_chain: bind only a verifying consent -----------------------
def test_compose_ac2_chain_verifies(valid):
    sealed, _, _ = valid
    chain = compose_ac2_chain(sealed)
    from algovoi_fabric import verify
    assert verify(chain).ok is True
    exec_pre = chain["chain"][0]["preimage"]
    assert exec_pre["ac2_level"] == "consent_present"
    assert exec_pre["ac2_binding_ref"]


def test_compose_ac2_chain_forged_refused(valid):
    sealed, _, _ = valid
    with pytest.raises(FabricError):
        compose_ac2_chain(dict(sealed, content_hash="0" * 64))


# --- journey integration: AC2 as an additional offline-verifiable level -----
def test_journey_with_ac2_composes_and_verifies(valid):
    sealed, _, _ = valid
    chain = compose_chain([("execution", {"action_class": "x"})])
    env = compose_journey(chain, ac2_sealed=sealed)
    assert "ac2" in env["levels"]
    res = verify_journey(env)
    assert res["ok"] is True
    assert "ac2" in res["levels"]


def test_journey_without_ac2_unchanged():
    chain = compose_chain([("execution", {"action_class": "x"})])
    env = compose_journey(chain)
    assert "ac2" not in env["levels"]
    assert verify_journey(env)["ok"] is True


def test_journey_ac2_forged_sealed_refused_at_compose(valid):
    sealed, _, _ = valid
    chain = compose_chain([("execution", {"action_class": "x"})])
    with pytest.raises(FabricError):
        compose_journey(chain, ac2_sealed=dict(sealed, content_hash="0" * 64))


@pytest.mark.parametrize("block", ["forged", None, 123])
def test_verify_journey_non_dict_ac2_is_fabric_error(block):
    chain = compose_chain([("execution", {"action_class": "x"})])
    env = compose_journey(chain)
    env["ac2"] = block
    with pytest.raises(FabricError):
        verify_journey(env)


def test_verify_journey_ac2_swapped_binding_ref_refused(valid):
    sealed, _, _ = valid
    chain = compose_chain([("execution", {"action_class": "x"})])
    env = compose_journey(chain, ac2_sealed=sealed)
    env["ac2"]["binding_ref"] = "sha256:" + "0" * 64
    with pytest.raises(FabricError):
        verify_journey(env)


def test_verify_journey_ac2_level_upgrade_refused(valid):
    sealed, _, _ = valid
    chain = compose_chain([("execution", {"action_class": "x"})])
    env = compose_journey(chain, ac2_sealed=sealed)
    # Claim a stronger level than the bytes earned: must be refused.
    env["ac2"]["level"] = "consensus_bound"
    with pytest.raises(FabricError):
        verify_journey(env)


def test_ac2_attestation_roundtrip(valid):
    sealed, _, _ = valid
    block = ac2_attestation(sealed)
    assert verify_ac2_attestation(block)["level"] == "consent_present"


# --- sender_bound round-trip (Claude finding 2) -----------------------------
def test_sender_bound_journey_round_trips_with_sender(valid):
    # The binding covers the reached level, so a sender_bound block must
    # re-verify when the same authenticated sender is supplied again.
    sealed, _, pk = valid
    chain = compose_chain([("execution", {"action_class": "x"})])
    env = compose_journey(chain, ac2_sealed=sealed, ac2_expected_sender=pk)
    assert env["ac2"]["level"] == "sender_bound"
    res = verify_journey(env, ac2_expected_sender=pk)
    assert res["ok"] is True
    assert "ac2" in res["levels"]
    assert verify_ac2_attestation(env["ac2"], expected_sender=pk)["level"] == "sender_bound"


def test_sender_bound_journey_without_sender_fails_closed(valid):
    # Re-verifying a sender_bound block WITHOUT the sender must refuse, never
    # silently downgrade to consent_present and accept.
    sealed, _, pk = valid
    chain = compose_chain([("execution", {"action_class": "x"})])
    env = compose_journey(chain, ac2_sealed=sealed, ac2_expected_sender=pk)
    with pytest.raises(FabricError):
        verify_journey(env)
    with pytest.raises(FabricError):
        verify_ac2_attestation(env["ac2"])


# --- uniform exception net (Claude finding 1) -------------------------------
def test_uniform_exception_net_catches_non_listed_type(valid, monkeypatch):
    # A foreign-verifier exception OUTSIDE the old enumerated allowlist
    # (IndexError is not a ValueError/TypeError/KeyError/AttributeError) must
    # still surface as FabricError. Loads the unconditional `except Exception`.
    from algovoi_fabric import ac2 as ac2_mod

    def boom(*a, **k):
        raise IndexError("truncated signature slice")

    monkeypatch.setattr(ac2_mod, "verify_consent", boom)
    sealed, _, _ = valid
    with pytest.raises(FabricError):
        verify_ac2_consent(sealed)