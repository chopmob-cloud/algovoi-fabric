#!/usr/bin/env python3
"""Throughput benchmark for the algovoi-fabric public surface.

Measures every callable export against the *installed* wheel (no source tree on
sys.path), using genuinely valid fixtures so the numbers reflect the success
path, not the fail-fast refusal path:

  * a real Ed25519 keypair signs the settlement's canonical payload (avm_ac2),
    sealed with avm_mesh's own canonicaliser -> consent_present / sender_bound;
  * a real algovoi_pef.build_pef frame bound into a 5-link AV-RAILS chain;
  * a full AV-RAILS -> AV-PEF -> AV-VCS -> AC2 journey envelope.

For each operation it reports sustained single-thread ops/sec and latency
percentiles (p50/p95/p99). For the two verify-heavy paths it also reports a
multi-process peak (ProcessPoolExecutor saturating the available cores) so the
"maximum throughput" figure is an observed aggregate, not an extrapolation.

Run inside the VM2 clean room against the installed wheel:

    python bench_fabric.py --json results.json [--scale 1.0] [--workers N]

Every numeral written to the JSON comes from this run's own perf_counter
samples; nothing is estimated. The environment block records the host, CPU,
core count, interpreter and package versions the numbers were produced on.
"""
from __future__ import annotations

import argparse
import base64
import gc
import hashlib
import json
import os
import platform
import statistics
import sys
import time
from concurrent.futures import ProcessPoolExecutor

import algovoi_fabric as F
from algovoi_fabric import (
    ac2_attestation,
    ac2_binding_ref,
    archive_binding_ref,
    check_version,
    compose_ac2_chain,
    compose_chain,
    compose_journey,
    compose_protocol_chain,
    protocol_face,
    supported_matrix,
    verify,
    verify_ac2_attestation,
    verify_ac2_consent,
    verify_journey,
)
from algovoi_pef import build_pef
from avm_ac2 import build_consent, consent_payload
from avm_mesh.sealed import canonical_bytes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

DOC_HASH = "sha256:" + "ab" * 32
ENTRY_ID = "entry-0001"
SEQ = 7


def _pef_frame():
    return build_pef(
        claim_type="payment_settlement",
        receipt={"settlement_result": "SETTLED",
                 "settled_payment_ref": "sha256:abc",
                 "settlement_chain": "algorand:testnet",
                 "settlement_provider_did": "did:web:api.algovoi.co.uk",
                 "settlement_timestamp_ms": 1748534700000},
        frame_provider_did="did:web:api.algovoi.co.uk",
        frame_timestamp_ms=1748534700000)


def _rails_links(frame_id):
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
    return sealed, pk


def build_fixtures():
    frame = _pef_frame()
    rails = compose_chain(_rails_links(frame["frame_id"]))
    sealed, pk = _ac2_sealed()
    full = compose_journey(rails, execution="execution", pef_frame=frame,
                           archive={"doc_hash": DOC_HASH, "entry_id": ENTRY_ID, "seq": SEQ},
                           ac2_sealed=sealed)
    full_sender = compose_journey(rails, execution="execution", pef_frame=frame,
                                  archive={"doc_hash": DOC_HASH, "entry_id": ENTRY_ID, "seq": SEQ},
                                  ac2_sealed=sealed, ac2_expected_sender=pk)
    block = ac2_attestation(sealed)
    block_sender = ac2_attestation(sealed, expected_sender=pk)
    message = {"payment": {"amount": "100", "asset": 0, "to": "0xdeadbeef"},
               "nonce": "bench-0001"}
    return {
        "rails": rails, "frame": frame, "sealed": sealed, "pk": pk,
        "full": full, "full_sender": full_sender,
        "block": block, "block_sender": block_sender, "message": message,
        "exec_ref": full["execution_ref"],
    }


def bench(fn, n, warmup=200):
    for _ in range(warmup):
        fn()
    gc.collect()
    samples = []
    start = time.perf_counter_ns()
    for _ in range(n):
        s = time.perf_counter_ns()
        fn()
        samples.append(time.perf_counter_ns() - s)
    total_s = (time.perf_counter_ns() - start) / 1e9
    samples.sort()
    m = len(samples)

    def pct(p):
        return samples[min(m - 1, int(p * m))] / 1e3  # microseconds

    return {
        "n": n,
        "ops_per_s": round(n / total_s, 1),
        "mean_us": round(statistics.fmean(samples) / 1e3, 3),
        "p50_us": round(pct(0.50), 3),
        "p95_us": round(pct(0.95), 3),
        "p99_us": round(pct(0.99), 3),
    }


def _worker_verify_journey(args):
    env, batch = args
    for _ in range(batch):
        verify_journey(env)
    return batch


def _worker_verify_ac2(args):
    sealed, batch = args
    for _ in range(batch):
        verify_ac2_consent(sealed)
    return batch


def parallel_peak(worker, payload, workers, batch):
    jobs = [(payload, batch)] * workers
    gc.collect()
    start = time.perf_counter_ns()
    with ProcessPoolExecutor(max_workers=workers) as ex:
        done = sum(ex.map(worker, jobs))
    wall_s = (time.perf_counter_ns() - start) / 1e9
    return {"workers": workers, "total_ops": done,
            "wall_s": round(wall_s, 3),
            "aggregate_ops_per_s": round(done / wall_s, 1)}


def cpu_model():
    try:
        with open("/proc/cpuinfo") as fh:
            for line in fh:
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default=None)
    ap.add_argument("--scale", type=float, default=1.0,
                    help="multiply the per-op iteration counts")
    ap.add_argument("--workers", type=int, default=os.cpu_count() or 1)
    ap.add_argument("--batch", type=int, default=2000,
                    help="ops per worker for the parallel peak")
    args = ap.parse_args()

    fx = build_fixtures()
    rails, sealed, pk = fx["rails"], fx["sealed"], fx["pk"]
    full, full_sender = fx["full"], fx["full_sender"]
    block, block_sender = fx["block"], fx["block_sender"]
    msg, exec_ref = fx["message"], fx["exec_ref"]

    def n(base):
        return max(200, int(base * args.scale))

    ops = [
        ("compose_chain (5-link AV-RAILS)", lambda: compose_chain(_rails_links("sha256:x")), n(20000)),
        ("verify (AV-RAILS chain)", lambda: verify(rails), n(20000)),
        ("compose_protocol_chain (x402 v2)", lambda: compose_protocol_chain("x402", "2", msg), n(20000)),
        ("protocol_face (x402 v2)", lambda: protocol_face("x402", "2", msg), n(50000)),
        ("check_version (x402 v2)", lambda: check_version("x402", "2"), n(200000)),
        ("supported_matrix", lambda: supported_matrix(), n(200000)),
        ("archive_binding_ref (AV-VCS)", lambda: archive_binding_ref(execution_ref=exec_ref, doc_hash=DOC_HASH, entry_id=ENTRY_ID, seq=SEQ), n(100000)),
        ("ac2_binding_ref", lambda: ac2_binding_ref(content_hash=sealed["content_hash"], level="consent_present", did="did:key:zTestController"), n(100000)),
        ("verify_ac2_consent (consent_present)", lambda: verify_ac2_consent(sealed), n(10000)),
        ("verify_ac2_consent (sender_bound)", lambda: verify_ac2_consent(sealed, expected_sender=pk), n(10000)),
        ("compose_ac2_chain", lambda: compose_ac2_chain(sealed), n(10000)),
        ("ac2_attestation", lambda: ac2_attestation(sealed), n(10000)),
        ("verify_ac2_attestation", lambda: verify_ac2_attestation(block), n(10000)),
        ("verify_ac2_attestation (sender_bound)", lambda: verify_ac2_attestation(block_sender, expected_sender=pk), n(10000)),
        ("compose_journey (rails+pef+vcs+ac2)", lambda: compose_journey(rails, execution="execution", pef_frame=fx["frame"], archive={"doc_hash": DOC_HASH, "entry_id": ENTRY_ID, "seq": SEQ}, ac2_sealed=sealed), n(3000)),
        ("verify_journey (rails+pef+vcs+ac2)", lambda: verify_journey(full), n(3000)),
        ("verify_journey (sender_bound ac2)", lambda: verify_journey(full_sender, ac2_expected_sender=pk), n(3000)),
    ]

    results = {}
    print(f"{'operation':42s} {'ops/s':>12s} {'p50 us':>10s} {'p95 us':>10s} {'p99 us':>10s} {'n':>8s}")
    print("-" * 96)
    for name, fn, count in ops:
        r = bench(fn, count)
        results[name] = r
        print(f"{name:42s} {r['ops_per_s']:12.1f} {r['p50_us']:10.3f} {r['p95_us']:10.3f} {r['p99_us']:10.3f} {r['n']:8d}")

    print("\nParallel peak (ProcessPoolExecutor, observed aggregate):")
    peak = {}
    single_j = results["verify_journey (rails+pef+vcs+ac2)"]["ops_per_s"]
    single_a = results["verify_ac2_consent (consent_present)"]["ops_per_s"]
    pj = parallel_peak(_worker_verify_journey, full, args.workers, args.batch)
    pj["single_thread_ops_per_s"] = single_j
    pj["speedup_vs_single"] = round(pj["aggregate_ops_per_s"] / single_j, 2)
    peak["verify_journey (full)"] = pj
    pa = parallel_peak(_worker_verify_ac2, sealed, args.workers, args.batch)
    pa["single_thread_ops_per_s"] = single_a
    pa["speedup_vs_single"] = round(pa["aggregate_ops_per_s"] / single_a, 2)
    peak["verify_ac2_consent"] = pa
    for name, p in peak.items():
        print(f"  {name:34s} workers={p['workers']:2d} "
              f"aggregate={p['aggregate_ops_per_s']:12.1f} ops/s "
              f"speedup={p['speedup_vs_single']}x")

    import avm_ac2
    import avm_mesh
    env = {
        "host": platform.node(),
        "system": f"{platform.system()} {platform.release()}",
        "machine": platform.machine(),
        "cpu_model": cpu_model(),
        "cpu_count": os.cpu_count(),
        "python": sys.version.split()[0],
        "algovoi_fabric": F.__version__,
        "avm_ac2": getattr(avm_ac2, "__version__", "unknown"),
        "avm_mesh": getattr(avm_mesh, "__version__", "unknown"),
        "fabric_module_file": F.__file__,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scale": args.scale,
    }
    out = {"environment": env, "single_thread": results, "parallel_peak": peak}
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(out, fh, indent=2)
        print(f"\nwrote {args.json}")
    print(json.dumps(env, indent=2))


if __name__ == "__main__":
    main()
