"""Security guarantees of the Fabric composition core, proven both directions.

Each protection is tested green (valid passes) AND red (a planted defect is
caught), per the hardening discipline: a test that only proves the happy path
is not evidence of protection.
"""
import copy

import pytest

from algovoi_fabric import compose_chain, verify, FabricError
from algovoi_pef import build_pef, verify_pef

# The published keystone-golden contract (chopmob-cloud/algovoi-keystone,
# examples/keystone-golden.json). The composer must reproduce these declared
# refs byte-for-byte: correctness against the real verifier, by construction.
GOLDEN = [
    ("passport_ref",
     {"agent_id": "agent-001", "issuer": "did:algo:issuer", "scope": "payments",
      "validity_window": "2026-06-21/2026-09-21"},
     "sha256:b3594e33998af01bd1ad208172c5c1ac586daa8c75781379f034d97e50b1a9be"),
    ("mandate_ref",
     {"payer": "0x00000000000000000000000000000000DEADBEEF", "cap": "1000",
      "period": "monthly", "revocation_state": "active"},
     "sha256:a4f8cb5ee09b29478ac1cc2f468d66e16d3d25f7a229a31d22ad521e11d04d35"),
    ("policy_ref",
     {"policy_id": "aml.transfer", "version": 1, "max_amount": 1000,
      "deny_jurisdictions": ["XX"]},
     "sha256:acc943b05fa8e8096e5b313288bc4f919cc2661f167c833770509a53049afa1c"),
    ("policy_bound_ref",
     {"policy_ref": "@policy_ref",
      "subject_ref": "sha256:7dc4a2bf62b3c5eabd10fc875ff7fc10f188666f15838c4a51464cc72e80f6ca"},
     "sha256:aaee2091799f376ee8cac802ea4920feaa4eca52950488a3e047ff82e6959a21"),
    ("decision_ref",
     {"agent_ref": "@passport_ref", "mandate_ref": "@mandate_ref",
      "policy_bound_ref": "@policy_bound_ref", "verdict": "ALLOW"},
     "sha256:2a444c629892f44fde1bd004aba9be01dd6cc7fe251eecdd545b82dca9f0bf97"),
    ("execution_ref",
     {"decision_ref": "@decision_ref", "action_type": "payment", "scope": "bilateral",
      "outcome": "COMMITTED", "executed_at_ms": 1716460800000},
     None),
    ("trust_query_ref",
     {"subject_refs": ["@passport_ref", "@mandate_ref", "@policy_bound_ref",
                       "@decision_ref", "@execution_ref"], "trust_outcome": "TRUSTED"},
     "sha256:18fb601a08c71eb6bed11e1c117f33bdc0ada6d635ea9bb9cca15e8410ce7ebd"),
]


def _golden_links():
    return [(n, copy.deepcopy(p)) for n, p, _ in GOLDEN]


def test_composer_reproduces_published_golden_refs():
    chain = compose_chain(_golden_links(), description="golden reproduction")
    by_name = {link["name"]: link for link in chain["chain"]}
    for name, _pre, expected in GOLDEN:
        if expected is not None:
            assert by_name[name]["ref"] == expected, f"{name} ref drifted from published contract"
    res = verify(chain)
    assert res.ok is True
    assert res.capped is True
    assert res.cap == "trust_query_ref"
    assert len(res.cap_covers) == 5


def test_tampering_any_preimage_breaks_the_chain():
    chain = compose_chain(_golden_links())
    assert verify(chain).ok is True
    # Plant a defect: widen the mandate cap after composition.
    tampered = copy.deepcopy(chain)
    for link in tampered["chain"]:
        if link["name"] == "mandate_ref":
            link["preimage"]["cap"] = "999999"
    res = verify(tampered)
    assert res.ok is False
    assert res.first_broken is not None


def test_tampering_the_cap_breaks_the_chain():
    chain = compose_chain(_golden_links())
    tampered = copy.deepcopy(chain)
    tampered["chain"][-1]["preimage"]["trust_outcome"] = "UNTRUSTED"
    assert verify(tampered).ok is False


def test_forward_reference_is_fail_closed():
    with pytest.raises(FabricError):
        compose_chain([("a", {"x": "@b"}), ("b", {"y": 1})])


def test_unknown_reference_is_fail_closed():
    with pytest.raises(FabricError):
        compose_chain([("a", {"x": "@nonexistent"})])


def test_duplicate_link_name_is_fail_closed():
    with pytest.raises(FabricError):
        compose_chain([("a", {"x": 1}), ("a", {"y": 2})])


def test_empty_chain_is_fail_closed():
    with pytest.raises(FabricError):
        compose_chain([])


def test_escape_marker_is_literal_not_a_binding():
    # '@@handle' must stay the literal '@handle', never resolve.
    chain = compose_chain([("a", {"handle": "@@alice"}), ("b", {"a_ref": "@a"})])
    assert verify(chain).ok is True
    assert chain["chain"][0]["preimage"]["handle"] == "@@alice"


def _scope_chain(decision_scope):
    return [
        ("passport", {"agent_id": "agent-1",
                      "scope": {"capabilities": ["payments"], "max_amount": 1000,
                                "jurisdictions": ["GB"]}}),
        ("decision", {"agent_ref": "@passport", "scope": decision_scope,
                      "verdict": "ALLOW"}),
    ]


def test_scope_subset_within_passes():
    chain = compose_chain(
        _scope_chain({"capabilities": ["payments"], "max_amount": 500, "jurisdictions": ["GB"]}),
        assertions=[{"kind": "scope_subset", "inner": "decision", "outer": "passport"}])
    res = verify(chain)
    assert res.ok is True
    assert res.assertions[0].ok is True


def test_scope_widening_is_rejected():
    chain = compose_chain(
        _scope_chain({"capabilities": ["payments", "refunds"], "max_amount": 5000,
                      "jurisdictions": ["GB", "XX"]}),
        assertions=[{"kind": "scope_subset", "inner": "decision", "outer": "passport"}])
    res = verify(chain)
    assert res.ok is False
    assert res.failed_assertion is not None
    assert res.failed_assertion.kind == "scope_subset"


def test_revocation_cascade_blocks_action_after_revocation():
    links = [
        ("passport", {"agent_id": "a"}),
        ("action", {"agent_ref": "@passport", "executed_at_ms": 2000}),
        ("revocation", {"revoked_ref": "@passport", "revoked_at_ms": 1000}),
    ]
    assertions = [{"kind": "not_revoked", "action": "action",
                   "revocation": "revocation", "time": "action.executed_at_ms"}]
    # action at 2000 >= revoked_at 1000 -> acted under revoked authority -> BROKEN
    res = verify(compose_chain(links, assertions=assertions))
    assert res.ok is False
    # action before revocation -> valid
    links[1] = ("action", {"agent_ref": "@passport", "executed_at_ms": 500})
    res2 = verify(compose_chain(links, assertions=assertions))
    assert res2.ok is True


def test_pef_evidence_frame_binds_and_verifies_offline():
    frame = build_pef(
        claim_type="payment_settlement",
        receipt={"settlement_result": "SETTLED",
                 "settled_payment_ref": "sha256:abc",
                 "settlement_chain": "algorand:testnet",
                 "settlement_provider_did": "did:web:api.algovoi.co.uk",
                 "settlement_timestamp_ms": 1748534700000},
        frame_provider_did="did:web:api.algovoi.co.uk",
        frame_timestamp_ms=1748534700000)
    assert verify_pef(frame)["valid"] is True
    links = [
        ("passport", {"agent_id": "a"}),
        ("decision", {"agent_ref": "@passport", "verdict": "ALLOW"}),
        ("execution", {"decision_ref": "@decision", "action_type": "payment",
                       "settlement_frame_id": frame["frame_id"], "outcome": "COMMITTED"}),
        ("trust_query", {"subject_refs": ["@passport", "@decision", "@execution"],
                         "trust_outcome": "TRUSTED"}),
    ]
    chain = compose_chain(links)
    assert verify(chain).ok is True
    # The execution link structurally binds the exact PEF frame id.
    exec_pre = next(link["preimage"] for link in chain["chain"] if link["name"] == "execution")
    assert exec_pre["settlement_frame_id"] == frame["frame_id"]