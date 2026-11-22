#!/usr/bin/env python3
"""AlgoVoi Fabric — the Keystone spine, proven both directions.

One command re-proves every fail-closed guarantee of the Fabric composition
core against the *published* estate packages (algovoi-keystone, algovoi-pef,
algovoi-keystone-connect, avm-ac2, avm-mesh) — not a private fork. Each
property is exercised twice:

  * GREEN  — a valid input is accepted / verifies offline;
  * RED    — a planted defect (tamper, forgery, widening, malformed input)
             is refused, and the refusal surfaces as ``FabricError`` at the
             Fabric boundary (trust-boundary Rule K), never a raw estate
             exception.

A property that fails to go red is a fail-open hole; a property that fails to
go green is a broken guarantee. Either makes this script exit non-zero, so it
is usable as a gate. Run it from a clean install of the wheel:

    python -m proofs.spine_proof        # or: python proofs/spine_proof.py

Nothing here re-implements cryptography or canonicalisation: every reference
is the estate's ``keystone_ref`` / ``_ref`` (sha256 over RFC 8785 JCS) and every
verification delegates to the published verifier. See ARCHITECTURE.md.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import sys

from algovoi_fabric import (
    FabricError,
    ProtocolError,
    ac2_attestation,
    ac2_binding_ref,
    agent_binding_ref,
    archive_binding_ref,
    compose_ac2_chain,
    compose_agent_guard,
    compose_chain,
    compose_journey,
    compose_protocol_chain,
    supported_matrix,
    verify,
    verify_ac2_attestation,
    verify_ac2_consent,
    verify_agent_guard,
    verify_journey,
)
from algovoi_keystone.verify import KeystoneError
from algovoi_keystone_agent import Event
from algovoi_keystone_agent.library import cap_charges, flag_large_charges
from algovoi_keystone_connect import keystone_ref
from algovoi_pef import build_pef
from avm_ac2 import build_consent, consent_payload
from avm_mesh.sealed import canonical_bytes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

_RESULTS: list[tuple[str, bool, str]] = []


def record(pid: str, ok: bool, detail: str = "") -> None:
    _RESULTS.append((pid, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {pid}" + (f" — {detail}" if detail else ""))


def green(pid: str, fn, detail: str = "") -> None:
    """The valid path must succeed."""
    try:
        fn()
        record(pid, True, detail or "valid input accepted")
    except Exception as exc:  # noqa: BLE001 - report, do not mask
        record(pid, False, f"valid path raised {type(exc).__name__}: {exc}")


def red(pid: str, fn, detail: str = "") -> None:
    """The planted defect must be refused as FabricError at the boundary."""
    try:
        fn()
    except FabricError as exc:
        record(pid, True, detail or f"refused as FabricError ({exc})")
    except Exception as exc:  # noqa: BLE001
        record(pid, False, f"leaked {type(exc).__name__} past the boundary: {exc}")
    else:
        record(pid, False, "FAIL-OPEN: planted defect was accepted")


def red_verify(pid: str, chain, detail: str = "") -> None:
    """A tampered chain must verify offline as not-ok (no exception needed)."""
    try:
        res = verify(chain)
    except FabricError as exc:
        record(pid, True, detail or f"refused as FabricError ({exc})")
        return
    except Exception as exc:  # noqa: BLE001
        record(pid, False, f"leaked {type(exc).__name__}: {exc}")
        return
    record(pid, not res.ok, detail or ("tampered chain rejected" if not res.ok else "FAIL-OPEN: tamper accepted"))


# --- fixtures (self-sufficient; no mainnet capture, no private fork) ---------
DOC_HASH = "sha256:" + "ab" * 32
ENTRY_ID = "entry-0001"
SEQ = 7


def _passport_scope(amount=1000):
    return {"capabilities": ["payments"], "max_amount": amount, "jurisdictions": ["GB"]}


def _core_chain(decision_amount=500):
    return compose_chain(
        [
            ("passport", {"agent_id": "agent-1", "scope": _passport_scope(1000)}),
            ("decision", {"agent_ref": "@passport", "verdict": "ALLOW",
                          "scope": _passport_scope(decision_amount)}),
            ("execution", {"decision_ref": "@decision", "action_type": "payment",
                           "outcome": "COMMITTED"}),
            ("trust_query", {"subject_refs": ["@passport", "@decision", "@execution"],
                             "trust_outcome": "TRUSTED"}),
        ],
        assertions=[{"kind": "scope_subset", "inner": "decision", "outer": "passport"}],
    )


def _pef_frame():
    return build_pef(
        claim_type="payment_settlement",
        receipt={"settlement_result": "SETTLED", "settled_payment_ref": "sha256:abc",
                 "settlement_chain": "algorand:testnet",
                 "settlement_provider_did": "did:web:api.algovoi.co.uk",
                 "settlement_timestamp_ms": 1748534700000},
        frame_provider_did="did:web:api.algovoi.co.uk",
        frame_timestamp_ms=1748534700000)


def _journey_chain(frame_id):
    return [
        ("passport", {"agent_id": "agent-1", "scope": _passport_scope(1000)}),
        ("mandate", {"payer": "0x00000000000000000000000000000000DEADBEEF",
                     "cap": "1000", "period": "monthly", "revocation_state": "active"}),
        ("decision", {"agent_ref": "@passport", "mandate_ref": "@mandate", "verdict": "ALLOW"}),
        ("execution", {"decision_ref": "@decision", "action_type": "payment",
                       "scope": "bilateral", "settlement_frame_id": frame_id,
                       "outcome": "COMMITTED", "executed_at_ms": 1716460800000}),
        ("trust_query", {"subject_refs": ["@passport", "@mandate", "@decision", "@execution"],
                         "trust_outcome": "TRUSTED"}),
    ]


def _journey():
    frame = _pef_frame()
    chain = compose_chain(_journey_chain(frame["frame_id"]))
    return compose_journey(chain, execution="execution", pef_frame=frame,
                           archive={"doc_hash": DOC_HASH, "entry_id": ENTRY_ID, "seq": SEQ})


def _ac2_sealed():
    settlement = {"chain": "mainnet-v1.0", "txid": "TESTTX", "round": 1,
                  "amount": "100", "asset": 0}
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    consent = build_consent(
        did="did:key:zTestController", sig_hint="raw-ed25519",
        public_key_b64=base64.b64encode(pk).decode(),
        signature_b64=base64.b64encode(sk.sign(consent_payload(settlement))).decode(),
        settlement=settlement)
    cb = canonical_bytes({"version": 1, "settlement": settlement, "ac2_consent": consent})
    sealed = {"canonical_bytes_b64": base64.b64encode(cb).decode(),
              "content_hash": hashlib.sha256(cb).hexdigest()}
    return sealed, settlement, pk


def main() -> int:
    print("AlgoVoi Fabric — Keystone spine proof (published packages, both directions)\n")

    # == 1. Chain core: integrity + fail-closed composition ===================
    green("C01 chain verifies offline", lambda: _assert(_core_chain_ok()))
    tampered = copy.deepcopy(_core_chain())
    tampered["chain"][1]["preimage"]["verdict"] = "DENY"
    red_verify("C02 tampered preimage breaks chain", tampered)

    red("C03 forward/unknown @ref refused", lambda: compose_chain([("a", {"x": 1}), ("b", {"y": "@nope"})]))
    red("C04 duplicate link name refused", lambda: compose_chain([("a", {"x": 1}), ("a", {"y": 2})]))
    red("C05 empty chain refused", lambda: compose_chain([]))
    red("C06 non-dict preimage refused (Rule K)", lambda: compose_chain([("a", "not-a-dict")]))  # type: ignore[arg-type]  # hostile input
    red("C07 non-pair link refused (Rule K)", lambda: compose_chain(["not-a-pair"]))  # type: ignore[arg-type]  # hostile input

    # scope widening: decision asks for more than the passport grants
    widened = _core_chain(decision_amount=2000)
    red_verify("C08 scope widening rejected (scope_subset)", widened)

    # the boundary translates KeystoneError -> FabricError (Rule K)
    def _boundary():
        try:
            compose_chain([("a", {"x": 1}), ("b", {"y": "@nope"})])
        except FabricError as exc:
            assert not isinstance(exc, KeystoneError), "FabricError must not be a KeystoneError"
            return
        raise AssertionError("expected FabricError")
    green("C09 Rule K: refusal is FabricError, not KeystoneError", _boundary)

    # == 2. Protocol front-door: fail-closed version gate =====================
    green("P01 supported matrix is the declared set",
          lambda: _assert(supported_matrix() == {"x402": ["1", "2"], "ap2": ["0.1"],
                                                 "mpp": ["2"], "a2a": ["0.3", "1.0.1"]}))
    for proto, ver in [("x402", "1"), ("x402", "2"), ("ap2", "0.1"), ("mpp", "2"),
                       ("a2a", "0.3"), ("a2a", "1.0.1")]:
        green(f"P02 {proto} v{ver} composes+verifies",
              lambda p=proto, v=ver: _assert(verify(compose_protocol_chain(p, v, {"amount": 250})).ok))
    red("P03 unknown protocol refused", lambda: compose_protocol_chain("nope", "1", {}), )
    red("P04 unsupported version refused", lambda: compose_protocol_chain("x402", "99", {}))
    red("P05 non-dict message refused", lambda: compose_protocol_chain("x402", "2", "not-a-dict"))  # type: ignore[arg-type]  # hostile input
    # the face binds the exact message bytes: tamper the message_ref -> chain breaks
    pchain = compose_protocol_chain("x402", "2", {"amount": 250, "currency": "USD"})
    pchain["chain"][0]["preimage"]["message_ref"] = "sha256:" + "00" * 32
    red_verify("P06 tampered protocol message_ref breaks chain", pchain)
    # caller cannot override the structural binding to the face
    def _no_override():
        c = compose_protocol_chain("x402", "2", {"amount": 1},
                                   execution={"protocol_ref": "@forged", "action_type": "evil"})
        exe = next(l for l in c["chain"] if l["name"] == "execution")["preimage"]
        assert exe["protocol_ref"] == "@protocol" and exe["action_type"] == "execute"
    green("P07 caller cannot override face binding", _no_override)

    # == 3. Full journey: AV-RAILS -> AV-PEF -> AV-VCS ========================
    green("J01 journey spans 3 levels, verifies offline",
          lambda: _assert(_journey_ok(_journey())))
    green("J02 archive binding byte-identical to canonical keystone_ref", _binding_identical)

    for field, mutant in [("doc_hash", "sha256:" + "cd" * 32), ("entry_id", "entry-9999"), ("seq", SEQ + 1)]:
        env = _journey()
        env["archive"][field] = mutant
        red(f"J03 tampered archive {field} refused", lambda e=env: verify_journey(e))

    env = _journey()
    forged = "sha256:" + "ee" * 32
    env["execution_ref"] = forged
    env["archive"]["binding_ref"] = archive_binding_ref(
        execution_ref=forged, doc_hash=DOC_HASH, entry_id=ENTRY_ID, seq=SEQ)
    red("J04 substituted execution_ref refused (even recomputed)", lambda: verify_journey(env))

    env = _journey()
    for link in env["chain"]["chain"]:
        if link["name"] == "mandate":
            link["preimage"]["cap"] = "999999"
    red("J05 tampered AV-RAILS chain breaks journey", lambda: verify_journey(env))

    env = _journey()
    env["pef_frame"]["receipt"]["settlement_result"] = "REFUNDED"
    red("J06 tampered AV-PEF frame refused", lambda: verify_journey(env))

    red("J07 unbound PEF frame refused at composition",
        lambda: compose_journey(compose_chain(_journey_chain("sha256:not-the-frame-id")),
                                execution="execution", pef_frame=_pef_frame()))
    red("J08 missing execution link refused",
        lambda: compose_journey(compose_chain(_journey_chain(_pef_frame()["frame_id"])),
                                execution="no-such-link"))
    red("J09 invalid archive attestation (bool seq) refused",
        lambda: compose_journey(compose_chain(_journey_chain(_pef_frame()["frame_id"])),
                                execution="execution",
                                archive={"doc_hash": DOC_HASH, "entry_id": ENTRY_ID, "seq": True}))

    # == 4. AC2 consent: who approved, fail-closed, never upgraded ============
    sealed, settlement, pk = _ac2_sealed()
    green("A01 valid consent verifies (consent_present)",
          lambda: _assert(verify_ac2_consent(sealed)["level"] == "consent_present"))
    green("A02 sender binding promotes to sender_bound",
          lambda: _assert(verify_ac2_consent(sealed, expected_sender=pk)["level"] == "sender_bound"))
    green("A03 compose_ac2_chain binds verifying consent",
          lambda: _assert(verify(compose_ac2_chain(sealed)).ok))

    cb = canonical_bytes({"version": 1, "settlement": settlement})
    no_consent = {"canonical_bytes_b64": base64.b64encode(cb).decode(),
                  "content_hash": hashlib.sha256(cb).hexdigest()}
    red("A04 absent consent refused", lambda: verify_ac2_consent(no_consent))
    red("A05 absent consent refused even require=False", lambda: verify_ac2_consent(no_consent, require=False))
    red("A06 tampered content_hash refused", lambda: verify_ac2_consent(dict(sealed, content_hash="0" * 64)))
    red("A07 consent over different settlement refused",
        lambda: verify_ac2_consent(_reseal(settlement, sealed, amount="999")))
    red("A08 malformed receipt -> FabricError not MeshError (Rule K)",
        lambda: verify_ac2_consent({"canonical_bytes_b64": "!!!not-base64!!!", "content_hash": "x"}))
    red("A09 non-dict sealed refused", lambda: verify_ac2_consent("forged"))  # type: ignore[arg-type]  # hostile input
    red("A10 malformed binding inputs refused", lambda: ac2_binding_ref(content_hash="", level="x", did="d"))

    # journey-level AC2: no silent upgrade, no silent downgrade
    chain = compose_chain([("execution", {"action_class": "x"})])
    env = compose_journey(chain, ac2_sealed=sealed)
    green("A11 journey with AC2 verifies offline", lambda: _assert("ac2" in verify_journey(env)["levels"]))
    env_up = compose_journey(chain, ac2_sealed=sealed)
    env_up["ac2"]["level"] = "consensus_bound"
    red("A12 claimed level upgrade refused", lambda: verify_journey(env_up))
    env_sw = compose_journey(chain, ac2_sealed=sealed)
    env_sw["ac2"]["binding_ref"] = "sha256:" + "0" * 64
    red("A13 swapped AC2 binding_ref refused", lambda: verify_journey(env_sw))
    env_sb = compose_journey(chain, ac2_sealed=sealed, ac2_expected_sender=pk)
    red("A14 sender_bound without sender fails closed (no downgrade)", lambda: verify_journey(env_sb))
    green("A15 sender_bound round-trips with sender",
          lambda: _assert(verify_journey(env_sb, ac2_expected_sender=pk)["ok"]))
    green("A16 attestation round-trips offline",
          lambda: _assert(verify_ac2_attestation(ac2_attestation(sealed))["level"] == "consent_present"))

    # == av-agent: AI protection (composes algovoi-keystone-agent) =============
    ag_chain = _core_chain()
    ag_exec = [l["ref"] for l in ag_chain["chain"] if l["name"] == "execution"][0]
    ag_ev = Event("execution", {"action_type": "charge", "amount": 50})
    ag_bhvs = [cap_charges(100, stage="execution")]

    def _ag_block(amount=50, bhvs=None):
        return compose_agent_guard(Event("execution", {"action_type": "charge", "amount": amount}),
                                   bhvs if bhvs is not None else ag_bhvs, execution_ref=ag_exec)

    green("G01 governed ALLOW action binds and re-verifies offline",
          lambda: _assert(verify_agent_guard(_ag_block(), execution_ref=ag_exec)["verdict"] == "ALLOW"))

    def _canonical():
        b = _ag_block()
        expected = keystone_ref({"action_type": "agent:guard", "execution_ref": ag_exec,
                                 "policy_ref": b["policy_ref"], "verdict": b["verdict"],
                                 "behaviour_refs": [f["behaviour_ref"] for f in b["firings"]]})
        _assert(b["binding_ref"] == expected)

    green("G02 agent binding delegates to the canonical keystone_ref", _canonical)
    red("G03 over-cap action BLOCKED and refused", lambda: _ag_block(500))
    red("G04 inert policy (wrong trigger stage) refused",
        lambda: compose_agent_guard(ag_ev, [cap_charges(100)], execution_ref=ag_exec, stage="execution"))
    red("G05 policy that never fires refused", lambda: compose_agent_guard(
        ag_ev, [__import__("algovoi_keystone_agent").behaviour(
            "never", on=__import__("algovoi_keystone_agent").trigger(
                stage=None, where=lambda ev: ev.get("action_type") == "withdraw"),
            rule=__import__("algovoi_keystone_agent").rule("allow", lambda ev: "ALLOW"))],
        execution_ref=ag_exec))

    def _tamper_ts():
        b = _ag_block()
        b["firings"][0]["executed_at_ms"] += 1
        return verify_agent_guard(b, execution_ref=ag_exec)

    red("G06 tampered firing timestamp breaks behaviour_ref", _tamper_ts)

    def _tamper_event():
        b = _ag_block()
        b["event"]["amount"] = 500
        return verify_agent_guard(b, execution_ref=ag_exec)

    red("G07 tampered event amount breaks event identity", _tamper_event)
    red("G08 substituted execution_ref refused",
        lambda: verify_agent_guard(_ag_block(), execution_ref="sha256:" + "cd" * 32))

    def _tamper_binding():
        b = _ag_block()
        b["binding_ref"] = "sha256:" + "0" * 64
        return verify_agent_guard(b, execution_ref=ag_exec)

    red("G09 swapped agent binding_ref refused", _tamper_binding)

    def _downgrade():
        b = compose_agent_guard(Event("execution", {"action_type": "charge", "amount": 500}),
                                [flag_large_charges(100, stage="execution")], execution_ref=ag_exec)
        b["verdict"] = "ALLOW"
        b["binding_ref"] = agent_binding_ref(
            execution_ref=ag_exec, policy_ref=b["policy_ref"], verdict="ALLOW",
            behaviour_refs=[f["behaviour_ref"] for f in b["firings"]])
        return verify_agent_guard(b, execution_ref=ag_exec)

    red("G10 verdict downgrade (FLAG->ALLOW) refused", _downgrade)
    ag_env = compose_journey(ag_chain, agent_event=ag_ev, agent_behaviours=ag_bhvs)
    green("G11 journey carries av-agent and verifies offline",
          lambda: _assert("av-agent" in verify_journey(ag_env)["levels"]))

    def _journey_tamper():
        env = compose_journey(ag_chain, agent_event=ag_ev, agent_behaviours=ag_bhvs)
        env["agent"]["event"]["amount"] = 500
        return verify_journey(env)

    red("G12 journey with tampered agent block refused", _journey_tamper)

    def _forged():
        from algovoi_fabric.agent import _policy_descriptor, _policy_ref
        event = {"action_type": "charge", "amount": 500}
        evref = Event("execution", dict(event)).ref
        desc = _policy_descriptor(ag_bhvs)
        polref = _policy_ref(desc)
        firing = {"decision_ref": ag_exec, "behaviour": ag_bhvs[0].name,
                  "rule": ag_bhvs[0].rule.name, "stage": "execution", "event_ref": evref,
                  "verdict": "ALLOW", "executed_at_ms": 1000}
        firing["behaviour_ref"] = keystone_ref({k: v for k, v in firing.items() if k != "behaviour_ref"})
        binding = agent_binding_ref(execution_ref=ag_exec, policy_ref=polref, verdict="ALLOW",
                                    behaviour_refs=[firing["behaviour_ref"]])
        forged = {"execution_ref": ag_exec, "stage": "execution", "event": event, "policy": desc,
                  "policy_ref": polref, "verdict": "ALLOW", "firings": [firing], "binding_ref": binding}
        return verify_agent_guard(forged, execution_ref=ag_exec, behaviours=ag_bhvs)

    red("G13 re-execution catches a self-consistent forged ALLOW", _forged)

    # == ledger ===============================================================
    failed = [r for r in _RESULTS if not r[1]]
    print(f"\n{len(_RESULTS) - len(failed)}/{len(_RESULTS)} properties proven both directions.")
    if failed:
        print("FAILURES:")
        for pid, _, detail in failed:
            print(f"  {pid}: {detail}")
        return 1
    print("SPINE PROOF: every guarantee green on valid input and red on its planted defect.")
    return 0


# --- small assert helpers ----------------------------------------------------
def _assert(cond):
    if not cond:
        raise AssertionError("condition false")


def _core_chain_ok():
    return verify(_core_chain()).ok


def _journey_ok(env):
    res = verify_journey(env)
    return res["ok"] and res["levels"] == ["av-rails", "av-pef", "av-vcs"]


def _binding_identical():
    env = _journey()
    expected = keystone_ref({"action_type": "archive:bind", "execution_ref": env["execution_ref"],
                             "doc_hash": DOC_HASH, "entry_id": ENTRY_ID, "seq": SEQ})
    _assert(env["archive"]["binding_ref"] == expected)
    _assert(archive_binding_ref(execution_ref=env["execution_ref"], doc_hash=DOC_HASH,
                                entry_id=ENTRY_ID, seq=SEQ) == expected)


def _reseal(settlement, sealed, **changes):
    import json
    other = dict(settlement, **changes)
    content = json.loads(base64.b64decode(sealed["canonical_bytes_b64"]))
    cb = canonical_bytes({"version": 1, "settlement": other, "ac2_consent": content["ac2_consent"]})
    return {"canonical_bytes_b64": base64.b64encode(cb).decode(),
            "content_hash": hashlib.sha256(cb).hexdigest()}


if __name__ == "__main__":
    sys.exit(main())