"""AI-protection face: proof that an agent's action was *governed*.

The fabric journey proves the decision (AV-RAILS), the payment evidence
(AV-PEF), the sealed-archive binding (AV-VCS) and who approved (AC2). The
av-agent level adds the governance seam: it composes the published
``algovoi-keystone-agent`` behaviour layer so an AI agent's spend/write is
dispatched against a deployed policy *before* it is bound, a BLOCK is refused
fail-closed, and every governance firing becomes a content-addressed
``behaviour_ref`` bound to the journey's execution link.

Nothing here re-implements cryptography, canonicalisation or the guardrail
engine. Refs delegate to ``keystone_ref`` (sha256 over RFC 8785 JCS), event
identity to ``keystone_agent.Event.ref``, verdict ordering to
``keystone_agent.VERDICTS``, and policy evaluation to ``keystone_agent.Engine``.
The fabric boundary only translates the estate's refusals (``Denied`` and any
structural exception a hostile event provokes) into ``FabricError`` so a
caller's ``except FabricError`` always catches it (trust-boundary Rule K).

What the level means is owned by keystone-agent, not restated as a stronger
claim here: a binding proves a deployed policy fired on this event and reached
ALLOW/FLAG, NOT that the agent is benign. Fabric never upgrades a verdict and
never binds a BLOCKed action as a committed journey.
"""
from __future__ import annotations

import copy
from typing import Any

from algovoi_keystone_connect import keystone_ref
from algovoi_keystone_agent import (
    VERDICTS,
    Denied,
    Engine,
    Event,
    check_guard_coverage,
)

from .compose import FabricError

AGENT_BIND_ACTION_TYPE = "agent:guard"
AGENT_POLICY_ACTION_TYPE = "agent:policy"


def _strongest(verdicts) -> str:
    """Strongest verdict using the estate's own ordering (BLOCK > FLAG > ALLOW)."""
    return max(verdicts, key=VERDICTS.index)


def _policy_descriptor(behaviours) -> list:
    return [{"name": b.name, "behaviour_id": b.behaviour_id, "rule": b.rule.name}
            for b in behaviours]


def _policy_ref(descriptor: list) -> str:
    return keystone_ref({"action_type": AGENT_POLICY_ACTION_TYPE,
                         "behaviours": descriptor})


def _event_ref(stage: str, event: dict) -> str:
    """Delegate event identity to keystone_agent.Event.ref (no reimplementation)."""
    return Event(stage, dict(event)).ref


def _firing_identity(rec: dict) -> tuple:
    """The governance substance of a firing, excluding the wall-clock fields.

    behaviour_ref covers executed_at_ms, so a re-run can never reproduce the exact
    ref; re-execution compares what was governed (behaviour, rule, event identity,
    decision binding, verdict), while the recorded bytes are checked separately by
    recomputing behaviour_ref.
    """
    return (rec.get("behaviour"), rec.get("rule"), rec.get("stage"),
            rec.get("event_ref"), rec.get("decision_ref"), rec.get("verdict"))


def agent_binding_ref(*, execution_ref: str, policy_ref: str, verdict: str,
                      behaviour_refs: list) -> str:
    """Content-addressed AI-protection binding, delegating to keystone_ref.

    Binds the journey's execution link to the deployed policy (``policy_ref``),
    the reached ``verdict`` and the ordered list of governance ``behaviour_refs``.
    Recomputable by anyone offline; raises FabricError on a malformed attestation
    and never returns a reference for an invalid input.
    """
    if not isinstance(execution_ref, str) or not execution_ref:
        raise FabricError("agent execution_ref must be a non-empty string")
    if not isinstance(policy_ref, str) or not policy_ref:
        raise FabricError("agent policy_ref must be a non-empty string")
    if verdict not in VERDICTS:
        raise FabricError(f"agent verdict must be one of {VERDICTS}")
    if not isinstance(behaviour_refs, (list, tuple)) or not behaviour_refs:
        raise FabricError("agent behaviour_refs must be a non-empty list")
    if not all(isinstance(r, str) and r for r in behaviour_refs):
        raise FabricError("agent behaviour_refs must be non-empty strings")
    return keystone_ref({"action_type": AGENT_BIND_ACTION_TYPE,
                         "execution_ref": execution_ref, "policy_ref": policy_ref,
                         "verdict": verdict, "behaviour_refs": list(behaviour_refs)})


def compose_agent_guard(event: Any, behaviours: Any, *, execution_ref: str,
                        stage: str = "execution") -> dict:
    """Govern an agent action and emit the journey-ready av-agent block.

    Deploys ``behaviours`` (keystone-agent Behaviour objects) in an Engine bound
    to ``execution_ref``, dispatches ``event`` and records every firing. Fail-
    closed: an inert policy (a trigger that can never fire at ``stage``), a
    policy that produces no governance record, or a BLOCK verdict raises before
    any block is emitted, so a denied action can never be bound as committed.

    Returns {execution_ref, stage, event, policy, policy_ref, verdict, firings,
    binding_ref}. The firings are plain content-addressed dicts, so the block
    re-verifies offline with no vendor in the loop.
    """
    if not isinstance(execution_ref, str) or not execution_ref:
        raise FabricError("agent execution_ref must be a non-empty string")
    if isinstance(event, Event):
        ev = event
    elif isinstance(event, dict):
        ev = Event(stage, dict(event))
    else:
        raise FabricError("agent event must be an Event or a dict")
    bhvs = list(behaviours) if isinstance(behaviours, (list, tuple)) else []
    if not bhvs:
        raise FabricError("agent guard needs at least one behaviour")
    try:
        coverage = check_guard_coverage(bhvs, stage=stage)
        if not coverage.ok:
            raise FabricError("agent policy cannot fire at this stage (inert guard)")
        engine = Engine(bhvs, decision_ref=execution_ref)
        verdict = engine.verdict(ev)
    except FabricError:
        raise
    except Denied as exc:
        raise FabricError(str(exc)) from exc
    except Exception as exc:
        # Uniform contract (Rule K): any exception a hostile event provokes in
        # the foreign engine surfaces as a fabric refusal, never a raw escape.
        raise FabricError(f"malformed agent guard input: {exc}") from exc
    firings = engine.log
    if not firings:
        raise FabricError("agent guard produced no governance record (policy never fired)")
    if verdict == "BLOCK":
        raise FabricError(f"agent action BLOCKED by policy; refused (verdict={verdict})")
    descriptor = _policy_descriptor(bhvs)
    policy_ref = _policy_ref(descriptor)
    behaviour_refs = [f["behaviour_ref"] for f in firings]
    binding = agent_binding_ref(execution_ref=execution_ref, policy_ref=policy_ref,
                                verdict=verdict, behaviour_refs=behaviour_refs)
    return {"execution_ref": execution_ref, "stage": stage,
            "event": copy.deepcopy(dict(ev)), "policy": descriptor,
            "policy_ref": policy_ref, "verdict": verdict,
            "firings": copy.deepcopy(firings), "binding_ref": binding}


def verify_agent_guard(block: Any, *, execution_ref: str | None = None,
                       behaviours: Any = None) -> dict:
    """Re-verify an av-agent block offline, fail-closed at every step.

    Recomputes every firing's ``behaviour_ref`` (tamper-evident), checks each is
    bound to the execution link and to the event's own content address, refuses
    a BLOCK or a verdict that does not match the strongest firing, and recomputes
    the policy and binding refs. When ``behaviours`` is supplied the policy is
    re-run against the event (re-execution proof), so a tampered event that would
    now BLOCK is caught even if its recorded firings were left intact.

    ``execution_ref`` (the journey's own execution link) must match the block's;
    a substituted binding is refused. Returns {verdict, execution_ref, policy_ref,
    firings}.
    """
    if not isinstance(block, dict):
        raise FabricError("agent attestation must be a dict")
    needed = ("execution_ref", "stage", "event", "policy", "policy_ref",
              "verdict", "firings", "binding_ref")
    if not all(k in block for k in needed):
        raise FabricError("agent attestation is missing required fields")
    block_exec = block["execution_ref"]
    if execution_ref is not None and block_exec != execution_ref:
        raise FabricError("agent guard execution_ref does not match the journey")
    stage = block["stage"]
    event = block["event"]
    if not isinstance(event, dict):
        raise FabricError("agent event must be a dict")
    firings = block["firings"]
    if not isinstance(firings, list) or not firings:
        raise FabricError("agent attestation carries no governance record")
    try:
        expected_event_ref = _event_ref(stage, event)
        for f in firings:
            if not isinstance(f, dict):
                raise FabricError("agent firing must be a dict")
            body = {k: v for k, v in f.items() if k != "behaviour_ref"}
            if keystone_ref(body) != f.get("behaviour_ref"):
                raise FabricError("agent behaviour_ref does not recompute (tampered)")
            if f.get("decision_ref") != block_exec:
                raise FabricError("agent firing is not bound to the execution_ref")
            if f.get("event_ref") != expected_event_ref:
                raise FabricError("agent firing event_ref does not match the event (tampered)")
            if f.get("stage") != stage:
                raise FabricError("agent firing stage does not match the block")
            if f.get("verdict") not in VERDICTS:
                raise FabricError("agent firing carries an unknown verdict")
        strongest = _strongest(f["verdict"] for f in firings)
        verdict = block["verdict"]
        if verdict not in VERDICTS:
            raise FabricError("agent attestation carries an unknown verdict")
        if verdict == "BLOCK":
            raise FabricError("a BLOCKed agent action cannot be a committed journey")
        if verdict != strongest:
            raise FabricError("agent verdict does not match the strongest firing")
        if _policy_ref(block["policy"]) != block.get("policy_ref"):
            raise FabricError("agent policy_ref does not recompute (tampered)")
        recomputed = agent_binding_ref(execution_ref=block_exec,
                                       policy_ref=block["policy_ref"], verdict=verdict,
                                       behaviour_refs=[f["behaviour_ref"] for f in firings])
        if recomputed != block.get("binding_ref"):
            raise FabricError("agent binding_ref does not recompute")
        if behaviours is not None:
            bhvs = list(behaviours)
            if not check_guard_coverage(bhvs, stage=stage).ok:
                raise FabricError("agent policy cannot fire at this stage (inert guard)")
            engine = Engine(bhvs, decision_ref=block_exec)
            engine.verdict(Event(stage, dict(event)))
            if [_firing_identity(r) for r in engine.log] != [_firing_identity(f) for f in firings]:
                raise FabricError("re-executed governance records do not match the block")
    except FabricError:
        raise
    except Denied as exc:
        raise FabricError(str(exc)) from exc
    except Exception as exc:
        raise FabricError(f"malformed agent attestation: {exc}") from exc
    return {"verdict": verdict, "execution_ref": block_exec,
            "policy_ref": block["policy_ref"], "firings": len(firings)}


# Journey-ready aliases, mirroring the AC2 face.
agent_attestation = compose_agent_guard
verify_agent_attestation = verify_agent_guard