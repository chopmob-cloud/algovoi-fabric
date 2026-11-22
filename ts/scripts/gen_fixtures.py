"""Produce golden parity fixtures from the REAL Python keystone verifier.

Run with the gate venv (has rfc8785 + algovoi_keystone + algovoi_substrate):
    .venv-gate/Scripts/python.exe ts/scripts/gen_fixtures.py

Writes ts/fixtures/golden.json. The TypeScript port must reproduce every
canonical byte string and every ref in this file, byte-for-byte. This is the
estate's 'golden py==node' parity gate: one producer (Python), one consumer (TS).
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys

import rfc8785
from algovoi_keystone.verify import _ref, _resolve, verify_chain, _canonicalize
from algovoi_fabric.compose import compose_chain
from algovoi_fabric.protocols import (
    compose_protocol_chain, supported_matrix, protocol_face, check_version,
)
from algovoi_fabric.journey import compose_journey, verify_journey, archive_binding_ref
from algovoi_pef import build_pef

OUT = pathlib.Path(__file__).resolve().parent.parent / "fixtures" / "golden.json"

# Preimages chosen to exercise the parity traps the Python verifier documents:
# nested objects, arrays, unicode, integer-valued floats, JS-safe integers,
# booleans/null, and key ordering (JCS sorts keys).
JCS_VECTORS = [
    {},
    {"b": 2, "a": 1},
    {"z": [3, 1, 2], "a": {"y": True, "x": None}},
    {"amount_minor": 500, "currency": "USD"},
    {"amount_minor": 500.0},                      # integer-valued float -> 500
    {"n": 9007199254740991},                     # MAX_SAFE_INTEGER
    {"unicode": "café — 日本語 — 😀", "s": "a/b\\c\"d"},
    {"nested": {"deep": {"list": [{"k": "v"}, 1, 2.5, False]}}},
    {"esc": "@@literal", "ref": "@earlier"},     # markers are data here, not resolved
    [1, "two", {"three": 3}, None, True],
    {"neg": -42, "frac": 3.14159, "exp": 1e20},
]

def jcs_hex(obj):
    return _canonicalize(obj).hex()

def main():
    vectors = []
    for i, obj in enumerate(JCS_VECTORS):
        vectors.append({
            "id": f"jcs_{i:02d}",
            "preimage": obj,
            "jcs_hex": jcs_hex(obj),
            "ref": _ref(obj),
        })

    # A resolved chain: downstream links bind upstream via @name.
    links = [
        ("passport", {"action_type": "passport", "agent": "agent:a", "scope": {"max_amount": 1000, "resource": "/pay"}}),
        ("mandate", {"action_type": "mandate", "passport_ref": "@passport", "scope": {"max_amount": 500, "resource": "/pay/tx"}}),
        ("execution", {"action_type": "execute", "mandate_ref": "@mandate", "amount_minor": 500, "executed_at_ms": 1700000000000}),
    ]
    chain = compose_chain(links, description="golden parity chain")
    vr = verify_chain(chain)
    chain_case = {
        "id": "chain_basic",
        "links": [[n, p] for n, p in links],
        "chain": chain,
        "verify_ok": vr.ok,
        "refs": {l.name: l.computed for l in vr.links},
    }

    # A protocol chain (x402 v2) through the real gated face.
    pchain = compose_protocol_chain("x402", "2", {"amount": "500", "currency": "USD", "pay_to": "0xabc"})
    pvr = verify_chain(pchain)
    proto_case = {
        "id": "protocol_x402_v2",
        "protocol": "x402", "version": "2",
        "message": {"amount": "500", "currency": "USD", "pay_to": "0xabc"},
        "chain": pchain,
        "verify_ok": pvr.ok,
    }

    # Every supported protocol/version: face + composed chain through the gate.
    proto_cases = []
    for proto, vers in supported_matrix().items():
        for ver in vers:
            msg = {"amount": "500", "currency": "USD"}
            face = protocol_face(proto, ver, msg)
            pc = compose_protocol_chain(proto, ver, msg, execution={"action_type": "execute", "amount_minor": 500})
            pvr = verify_chain(pc)
            proto_cases.append({
                "id": f"proto_{proto}_{ver}", "protocol": proto, "version": ver,
                "message": msg, "face": face, "chain": pc, "verify_ok": pvr.ok,
            })

    # Version-gate refusals (record the exact error text for parity).
    proto_errors = []
    for proto, ver in [("nope", "1"), ("x402", "9")]:
        try:
            check_version(proto, ver)
            proto_errors.append({"protocol": proto, "version": ver, "error": None})
        except Exception as e:
            proto_errors.append({"protocol": proto, "version": ver, "error": str(e)})

    # A full AV-RAILS -> AV-PEF -> AV-VCS journey with a real PEF frame.
    frame = build_pef(
        claim_type="payment_settlement",
        receipt={"amount_minor": 500, "currency": "USD", "pay_to": "0xabc"},
        frame_provider_did="did:algovoi:provider",
        frame_timestamp_ms=1700000000000,
    )
    jlinks = [
        ("policy", {"action_type": "policy", "max_amount": 1000}),
        ("execution", {"action_type": "execute", "settlement_frame_id": frame["frame_id"],
                       "amount_minor": 500, "executed_at_ms": 1700000000000}),
    ]
    jchain = compose_chain(jlinks, description="golden journey chain")
    archive = {"doc_hash": "sha256:" + "ee" * 32, "entry_id": "entry-1", "seq": 7}
    env = compose_journey(jchain, pef_frame=frame, archive=archive, description="golden journey")
    vj = verify_journey(env)
    binding = archive_binding_ref(execution_ref=env["execution_ref"],
                                  doc_hash=archive["doc_hash"],
                                  entry_id=archive["entry_id"], seq=archive["seq"])
    journey_case = {
        "id": "journey_full",
        "chain_links": [[n, p] for n, p in jlinks],
        "pef_frame": frame,
        "archive": archive,
        "envelope": env,
        "verify": vj,
        "binding_ref": binding,
        "execution_ref": env["execution_ref"],
    }

    # A journey whose execution link binds an upstream link via @ref. The
    # execution ref must be the chain's STORED (resolved) link ref, not a hash
    # of the raw @ref-bearing preimage — otherwise the journey anchors to a
    # content address the verifier never computes, and cross-edition journeys
    # fail mutual verification. Python returns link["ref"]; the TS twin must too.
    jlinks_ref = [
        ("policy", {"action_type": "policy", "max_amount": 1000}),
        ("execution", {"action_type": "execute", "policy_ref": "@policy",
                       "amount_minor": 500, "executed_at_ms": 1700000000000}),
    ]
    jchain_ref = compose_chain(jlinks_ref, description="golden journey @ref execution chain")
    exec_link_ref = [l for l in jchain_ref["chain"] if l["name"] == "execution"][0]
    archive_ref = {"doc_hash": "sha256:" + "ff" * 32, "entry_id": "entry-ref-1", "seq": 9}
    env_ref = compose_journey(jchain_ref, archive=archive_ref,
                              description="golden journey @ref execution")
    vj_ref = verify_journey(env_ref)
    binding_ref = archive_binding_ref(execution_ref=env_ref["execution_ref"],
                                      doc_hash=archive_ref["doc_hash"],
                                      entry_id=archive_ref["entry_id"], seq=archive_ref["seq"])
    journey_ref_case = {
        "id": "journey_ref_execution",
        "chain_links": [[n, p] for n, p in jlinks_ref],
        "archive": archive_ref,
        "envelope": env_ref,
        "verify": vj_ref,
        "binding_ref": binding_ref,
        "execution_ref": env_ref["execution_ref"],
        "exec_stored_ref": exec_link_ref["ref"],
        "exec_raw_preimage": exec_link_ref["preimage"],
    }

    # _resolve behaviour: escape + forward-ref refusal (record the error text).
    resolve_cases = []
    r = _resolve({"a": "@x", "b": "@@x", "c": ["@x", 1]}, {"x": "sha256:" + "ab"*32}, "self")
    resolve_cases.append({"id": "resolve_ok", "refs": {"x": "sha256:" + "ab"*32},
                          "value": {"a": "@x", "b": "@@x", "c": ["@x", 1]}, "resolved": r})
    try:
        _resolve({"a": "@missing"}, {}, "self")
        resolve_cases.append({"id": "resolve_forward", "error": None})
    except Exception as e:
        resolve_cases.append({"id": "resolve_forward", "value": {"a": "@missing"},
                              "refs": {}, "link_name": "self", "error": str(e)})

    doc = {
        "producer": "algovoi-fabric Python (real keystone verifier)",
        "canon": "jcs-rfc8785-v1",
        "jcs_vectors": vectors,
        "chains": [chain_case, proto_case],
        "protocol_cases": proto_cases,
        "protocol_errors": proto_errors,
        "journey": journey_case,
        "journey_ref": journey_ref_case,
        "resolve": resolve_cases,
        "supported_matrix": supported_matrix(),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    # Write bytes so the fixture is LF on every platform (text mode would emit
    # CRLF on Windows and break byte-for-byte cross-platform reproducibility).
    OUT.write_bytes((json.dumps(doc, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
    print(f"wrote {OUT} ({len(vectors)} jcs vectors, {len(doc['chains'])} chains, "
          f"{len(proto_cases)} protocol cases, {len(resolve_cases)} resolve cases, journey={journey_case['verify']['ok']})")
    print("substrate cross-check present:", end=" ")
    try:
        import algovoi_substrate
        print("yes")
    except Exception:
        print("no")

if __name__ == "__main__":
    sys.exit(main())