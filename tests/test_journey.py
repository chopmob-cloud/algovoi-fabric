"""Full-journey security guarantees: AV-RAILS -> AV-PEF -> AV-VCS.

The journey starts at the AV-RAILS authority/decision and finishes at the
AV-VCS sealed-archive binding, with the AV-PEF evidence frame in between.
Every level is proven green (valid passes) AND red (a planted defect is
caught), and the AV-VCS binding is proven byte-identical to the canonical
keystone_ref primitive that the public algovoi-keystone-archive bridge uses.
"""
import pytest

from algovoi_fabric import (
    compose_chain,
    compose_journey,
    verify_journey,
    archive_binding_ref,
    FabricError,
)
from algovoi_keystone_connect import keystone_ref
from algovoi_pef import build_pef

DOC_HASH = "sha256:" + "ab" * 32
ENTRY_ID = "entry-0001"
SEQ = 7


def _frame():
    return build_pef(
        claim_type="payment_settlement",
        receipt={"settlement_result": "SETTLED",
                 "settled_payment_ref": "sha256:abc",
                 "settlement_chain": "algorand:testnet",
                 "settlement_provider_did": "did:web:api.algovoi.co.uk",
                 "settlement_timestamp_ms": 1748534700000},
        frame_provider_did="did:web:api.algovoi.co.uk",
        frame_timestamp_ms=1748534700000)


def _chain(frame_id):
    return [
        ("passport", {"agent_id": "agent-1",
                      "scope": {"capabilities": ["payments"], "max_amount": 1000,
                                "jurisdictions": ["GB"]}}),
        ("mandate", {"payer": "0x00000000000000000000000000000000DEADBEEF",
                     "cap": "1000", "period": "monthly", "revocation_state": "active"}),
        ("decision", {"agent_ref": "@passport", "mandate_ref": "@mandate",
                      "verdict": "ALLOW"}),
        ("execution", {"decision_ref": "@decision", "action_type": "payment",
                       "scope": "bilateral", "settlement_frame_id": frame_id,
                       "outcome": "COMMITTED", "executed_at_ms": 1716460800000}),
        ("trust_query", {"subject_refs": ["@passport", "@mandate", "@decision",
                                          "@execution"], "trust_outcome": "TRUSTED"}),
    ]


def _journey():
    frame = _frame()
    chain = compose_chain(_chain(frame["frame_id"]))
    return compose_journey(chain, execution="execution", pef_frame=frame,
                           archive={"doc_hash": DOC_HASH, "entry_id": ENTRY_ID, "seq": SEQ})


def test_full_journey_spans_all_three_levels_and_verifies_offline():
    env = _journey()
    assert env["levels"] == ["av-rails", "av-pef", "av-vcs"]
    res = verify_journey(env)
    assert res["ok"] is True
    assert res["levels"] == ["av-rails", "av-pef", "av-vcs"]


def test_avvcs_binding_is_byte_identical_to_canonical_primitive():
    # The public algovoi-keystone-archive bridge computes binding_ref as
    # keystone_ref({action_type:"archive:bind", execution_ref, doc_hash, entry_id, seq}).
    # Fabric must delegate to that exact primitive, not a private reimplementation.
    env = _journey()
    expected = keystone_ref({"action_type": "archive:bind",
                             "execution_ref": env["execution_ref"],
                             "doc_hash": DOC_HASH, "entry_id": ENTRY_ID, "seq": SEQ})
    assert env["archive"]["binding_ref"] == expected
    assert archive_binding_ref(execution_ref=env["execution_ref"], doc_hash=DOC_HASH,
                               entry_id=ENTRY_ID, seq=SEQ) == expected


def test_tampered_archive_doc_hash_is_fail_closed():
    env = _journey()
    env["archive"]["doc_hash"] = "sha256:" + "cd" * 32
    with pytest.raises(FabricError):
        verify_journey(env)


def test_tampered_archive_entry_id_is_fail_closed():
    env = _journey()
    env["archive"]["entry_id"] = "entry-9999"
    with pytest.raises(FabricError):
        verify_journey(env)


def test_tampered_archive_seq_is_fail_closed():
    env = _journey()
    env["archive"]["seq"] = SEQ + 1
    with pytest.raises(FabricError):
        verify_journey(env)


def test_substituted_execution_ref_is_fail_closed():
    # Even if an attacker recomputes a binding for a different execution_ref,
    # the journey must reject it because it no longer matches the chain.
    env = _journey()
    forged = "sha256:" + "ee" * 32
    env["execution_ref"] = forged
    env["archive"]["binding_ref"] = archive_binding_ref(
        execution_ref=forged, doc_hash=DOC_HASH, entry_id=ENTRY_ID, seq=SEQ)
    with pytest.raises(FabricError):
        verify_journey(env)


def test_tampered_rails_chain_breaks_the_journey():
    env = _journey()
    for link in env["chain"]["chain"]:
        if link["name"] == "mandate":
            link["preimage"]["cap"] = "999999"
    with pytest.raises(FabricError):
        verify_journey(env)


def test_tampered_pef_frame_is_fail_closed():
    env = _journey()
    env["pef_frame"]["receipt"]["settlement_result"] = "REFUNDED"
    with pytest.raises(FabricError):
        verify_journey(env)


def test_unbound_pef_frame_is_fail_closed_at_composition():
    frame = _frame()
    chain = compose_chain(_chain("sha256:not-the-frame-id"))
    with pytest.raises(FabricError):
        compose_journey(chain, execution="execution", pef_frame=frame)


def test_missing_execution_link_is_fail_closed():
    frame = _frame()
    chain = compose_chain(_chain(frame["frame_id"]))
    with pytest.raises(FabricError):
        compose_journey(chain, execution="no-such-link")


def test_journey_without_archive_still_verifies():
    frame = _frame()
    chain = compose_chain(_chain(frame["frame_id"]))
    env = compose_journey(chain, execution="execution", pef_frame=frame)
    assert env["levels"] == ["av-rails", "av-pef"]
    assert verify_journey(env)["ok"] is True


def test_invalid_archive_attestation_is_fail_closed():
    frame = _frame()
    chain = compose_chain(_chain(frame["frame_id"]))
    with pytest.raises(FabricError):
        compose_journey(chain, execution="execution",
                        archive={"doc_hash": DOC_HASH, "entry_id": ENTRY_ID, "seq": True})
