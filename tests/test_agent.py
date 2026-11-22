"""AI-protection guarantees: the av-agent governance level.

Fabric composes algovoi-keystone-agent (the agentic behaviour layer) into the
journey as a fail-closed governance seam bound to the execution link. Every
guarantee is proven green (a governed, allowed action binds and re-verifies
offline) AND red (a blocked action, an inert policy, a tampered record or a
substituted binding is refused as FabricError, never a raw estate exception).

Nothing here re-implements crypto: refs delegate to keystone_ref and event
identity to keystone_agent.Event.ref, exactly as the rest of Fabric delegates.
"""
import pytest

from algovoi_keystone_agent import Event
from algovoi_keystone_agent.library import cap_charges, restrict_scope, flag_large_charges

from algovoi_fabric import (
    compose_chain,
    compose_journey,
    verify_journey,
    FabricError,
)
from algovoi_fabric.agent import (
    agent_binding_ref,
    compose_agent_guard,
    verify_agent_guard,
)

EXEC_REF = "sha256:" + "ab" * 32
OTHER_REF = "sha256:" + "cd" * 32


def _event(amount=50, stage="execution"):
    # No execution_ref inside the event, so Event.ref is a content address over
    # the fields (amount included) -- tampering the amount breaks the identity.
    return Event(stage, {"action_type": "charge", "amount": amount})


def _policy(limit=100):
    return [cap_charges(limit, stage="execution")]


def _block(amount=50, limit=100):
    return compose_agent_guard(_event(amount), _policy(limit),
                               execution_ref=EXEC_REF, stage="execution")


# --- green: a governed, allowed action binds and re-verifies offline ---------

def test_allowed_action_binds_and_verifies():
    block = _block(50)
    assert block["verdict"] == "ALLOW"
    assert block["binding_ref"].startswith("sha256:")
    assert block["firings"], "a governance record must exist"
    rep = verify_agent_guard(block, execution_ref=EXEC_REF)
    assert rep["verdict"] == "ALLOW"
    assert rep["execution_ref"] == EXEC_REF


def test_binding_delegates_to_canonical_primitive():
    from algovoi_keystone_connect import keystone_ref
    block = _block(50)
    expected = keystone_ref({"action_type": "agent:guard",
                             "execution_ref": EXEC_REF,
                             "policy_ref": block["policy_ref"],
                             "verdict": block["verdict"],
                             "behaviour_refs": [f["behaviour_ref"] for f in block["firings"]]})
    assert block["binding_ref"] == expected
    assert agent_binding_ref(execution_ref=EXEC_REF, policy_ref=block["policy_ref"],
                             verdict="ALLOW",
                             behaviour_refs=[f["behaviour_ref"] for f in block["firings"]]) == expected


def test_reexecution_with_policy_matches():
    bhvs = _policy(100)
    block = compose_agent_guard(_event(50), bhvs, execution_ref=EXEC_REF)
    rep = verify_agent_guard(block, execution_ref=EXEC_REF, behaviours=bhvs)
    assert rep["verdict"] == "ALLOW"


# --- red: fail-closed at composition -----------------------------------------

def test_blocked_action_is_refused():
    # amount 500 exceeds the cap of 100 -> BLOCK -> never bound as committed.
    with pytest.raises(FabricError):
        _block(500, limit=100)


def test_inert_policy_is_refused():
    # cap_charges defaults to stage 'spend_decision'; a guard dispatching at
    # 'execution' would never fire it -> governance theatre, refused.
    with pytest.raises(FabricError):
        compose_agent_guard(_event(50), [cap_charges(100)],
                            execution_ref=EXEC_REF, stage="execution")


def test_policy_that_never_fires_is_refused():
    # A wildcard-stage behaviour whose wake condition never matches the charge
    # event: coverage passes (wildcard reaches the guard) but nothing fires, so
    # there is no governance record. Match the specific refusal to isolate it.
    from algovoi_keystone_agent import behaviour, trigger, rule
    never = behaviour("never", on=trigger(stage=None,
                                          where=lambda ev: ev.get("action_type") == "withdraw"),
                      rule=rule("always_allow", lambda ev: "ALLOW"))
    with pytest.raises(FabricError, match="no governance record"):
        compose_agent_guard(_event(50), [never], execution_ref=EXEC_REF, stage="execution")


def test_inert_policy_hidden_by_active_one_is_refused():
    # An active behaviour fires (so the no-firing guard passes) while a second
    # behaviour is inert at this stage: only the coverage guard catches the
    # governance theatre of a policy that can never fully fire.
    bhvs = [cap_charges(100, stage="execution"), cap_charges(100)]  # 2nd is spend_decision
    with pytest.raises(FabricError, match="inert"):
        compose_agent_guard(_event(50), bhvs, execution_ref=EXEC_REF, stage="execution")


def test_tampered_firing_timestamp_is_fail_closed():
    # Tamper a field that changes neither verdict nor event identity: only the
    # behaviour_ref recompute catches it (isolates the tamper-evident check).
    block = _block(50)
    block["firings"][0]["executed_at_ms"] += 1
    with pytest.raises(FabricError, match="behaviour_ref does not recompute"):
        verify_agent_guard(block, execution_ref=EXEC_REF)


def test_empty_policy_is_refused():
    with pytest.raises(FabricError):
        compose_agent_guard(_event(50), [], execution_ref=EXEC_REF)


def test_malformed_event_is_refused():
    with pytest.raises(FabricError):
        compose_agent_guard("not-an-event", _policy(), execution_ref=EXEC_REF)


# --- red: fail-closed at offline verification (tamper-evident) ---------------

def test_tampered_firing_verdict_is_fail_closed():
    block = _block(50)
    block["firings"][0]["verdict"] = "BLOCK"
    with pytest.raises(FabricError):
        verify_agent_guard(block, execution_ref=EXEC_REF)


def test_tampered_event_amount_is_fail_closed():
    block = _block(50)
    block["event"]["amount"] = 500
    with pytest.raises(FabricError):
        verify_agent_guard(block, execution_ref=EXEC_REF)


def test_tampered_binding_is_fail_closed():
    block = _block(50)
    block["binding_ref"] = "sha256:" + "00" * 32
    with pytest.raises(FabricError):
        verify_agent_guard(block, execution_ref=EXEC_REF)


def test_tampered_policy_is_fail_closed():
    block = _block(50)
    block["policy"][0]["name"] = "cap_charges<=999999"
    with pytest.raises(FabricError):
        verify_agent_guard(block, execution_ref=EXEC_REF)


def test_substituted_execution_ref_is_fail_closed():
    block = _block(50)
    with pytest.raises(FabricError):
        verify_agent_guard(block, execution_ref=OTHER_REF)


def test_reexecution_catches_event_tamper():
    bhvs = _policy(100)
    block = compose_agent_guard(_event(50), bhvs, execution_ref=EXEC_REF)
    block["event"]["amount"] = 500  # re-running the policy would now BLOCK
    with pytest.raises(FabricError):
        verify_agent_guard(block, execution_ref=EXEC_REF, behaviours=bhvs)


def test_claimed_allow_with_block_firing_is_fail_closed():
    block = _block(50)
    # Forge the top-level verdict to ALLOW while a firing says BLOCK.
    block["firings"][0]["verdict"] = "BLOCK"
    block["verdict"] = "ALLOW"
    with pytest.raises(FabricError):
        verify_agent_guard(block, execution_ref=EXEC_REF)


# --- journey integration: the av-agent level ---------------------------------

def _chain():
    return [
        ("passport", {"agent_id": "agent-1",
                      "scope": {"capabilities": ["payments"], "max_amount": 1000,
                                "jurisdictions": ["GB"]}}),
        ("mandate", {"payer": "0x00000000000000000000000000000000DEADBEEF",
                     "cap": "1000", "period": "monthly", "revocation_state": "active"}),
        ("decision", {"agent_ref": "@passport", "mandate_ref": "@mandate",
                      "verdict": "ALLOW"}),
        ("execution", {"decision_ref": "@decision", "action_type": "payment",
                       "scope": "bilateral", "outcome": "COMMITTED",
                       "executed_at_ms": 1716460800000}),
        ("trust_query", {"subject_refs": ["@passport", "@mandate", "@decision",
                                          "@execution"], "trust_outcome": "TRUSTED"}),
    ]


def test_journey_carries_av_agent_level_and_verifies():
    chain = compose_chain(_chain())
    env = compose_journey(chain, execution="execution",
                          agent_event=_event(50), agent_behaviours=_policy(100))
    assert env["levels"] == ["av-rails", "av-agent"]
    res = verify_journey(env)
    assert res["ok"] is True
    assert "av-agent" in res["levels"]


def test_journey_blocked_agent_action_is_fail_closed():
    chain = compose_chain(_chain())
    with pytest.raises(FabricError):
        compose_journey(chain, execution="execution",
                        agent_event=_event(500), agent_behaviours=_policy(100))


def test_journey_tampered_agent_block_is_fail_closed():
    chain = compose_chain(_chain())
    env = compose_journey(chain, execution="execution",
                          agent_event=_event(50), agent_behaviours=_policy(100))
    env["agent"]["event"]["amount"] = 500
    with pytest.raises(FabricError):
        verify_journey(env)


# --- isolating tests for checks masked by earlier guards ---------------------

def test_verdict_downgrade_is_fail_closed():
    # A FLAG firing intact, but the claimed verdict downgraded to ALLOW and the
    # binding recomputed: only the verdict==strongest check catches this.
    from algovoi_fabric.agent import agent_binding_ref
    bhvs = [flag_large_charges(100, stage="execution")]
    block = compose_agent_guard(_event(500), bhvs, execution_ref=EXEC_REF)
    assert block["verdict"] == "FLAG"
    block["verdict"] = "ALLOW"
    block["binding_ref"] = agent_binding_ref(
        execution_ref=EXEC_REF, policy_ref=block["policy_ref"], verdict="ALLOW",
        behaviour_refs=[f["behaviour_ref"] for f in block["firings"]])
    with pytest.raises(FabricError):
        verify_agent_guard(block, execution_ref=EXEC_REF)


def test_reexecution_catches_forged_allow_firings():
    # A fully self-consistent forgery: over-cap event with fabricated ALLOW
    # firings whose refs all recompute. Static checks pass; only re-running the
    # policy reveals it would BLOCK. This isolates the re-execution verdict check.
    from algovoi_keystone_connect import keystone_ref
    from algovoi_fabric.agent import (agent_binding_ref, _policy_ref,
                                      _policy_descriptor)
    bhvs = _policy(100)
    event = {"action_type": "charge", "amount": 500}
    stage = "execution"
    evref = Event(stage, dict(event)).ref
    descriptor = _policy_descriptor(bhvs)
    polref = _policy_ref(descriptor)
    firing = {"decision_ref": EXEC_REF, "behaviour": bhvs[0].name,
              "rule": bhvs[0].rule.name, "stage": stage, "event_ref": evref,
              "verdict": "ALLOW", "executed_at_ms": 1000}
    firing["behaviour_ref"] = keystone_ref(
        {k: v for k, v in firing.items() if k != "behaviour_ref"})
    binding = agent_binding_ref(execution_ref=EXEC_REF, policy_ref=polref,
                                verdict="ALLOW", behaviour_refs=[firing["behaviour_ref"]])
    forged = {"execution_ref": EXEC_REF, "stage": stage, "event": event,
              "policy": descriptor, "policy_ref": polref, "verdict": "ALLOW",
              "firings": [firing], "binding_ref": binding}
    # Without the policy, the static recompute checks accept the consistent forgery.
    assert verify_agent_guard(forged, execution_ref=EXEC_REF)["verdict"] == "ALLOW"
    # With the policy, re-execution catches that the action would actually BLOCK.
    with pytest.raises(FabricError):
        verify_agent_guard(forged, execution_ref=EXEC_REF, behaviours=bhvs)