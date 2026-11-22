# algovoi-fabric — throughput benchmarks (VM2 clean-room evidence)

Every public callable in `algovoi_fabric` 0.3.1, measured against the **installed
wheel** inside a fresh `python:3.12-slim` clean room on VM2, with genuinely valid
fixtures (a real Ed25519-signed AC2 consent, a real `algovoi_pef` frame, a full
AV-RAILS → AV-PEF → AV-VCS → AC2 journey). The numbers reflect the **success
path**, not the fail-fast refusal path.

## How to reproduce

```bash
# on VM2, inside the clean-room container, against the installed wheel:
python bench_fabric.py --json results.json --workers "$(nproc)" --batch 2000
```

`bench_fabric.py` imports only the installed package and its runtime deps
(`algovoi_pef`, `avm_ac2`, `avm_mesh`, `cryptography`); no source tree is on
`sys.path`. Each operation is warmed up (200 calls), then timed with
`time.perf_counter_ns` over N calls; ops/sec = N / wall-seconds, latency
percentiles come from the per-call samples. The parallel peak uses
`ProcessPoolExecutor` saturating the visible cores and reports the **observed
aggregate**, not an extrapolation. Every numeral in `results/` comes from that
run's own samples.

## Environment (this run)

| field | value |
|---|---|
| host | VM2 clean-room container `3af25c2063cf` |
| OS | Linux 6.8.0-136-generic, x86_64 |
| CPU | AMD EPYC-Milan Processor |
| cores visible | 2 |
| Python | 3.12.16 |
| algovoi-fabric | 0.3.1 (installed wheel) |
| avm-ac2 | 0.1.0 |
| avm-mesh | 0.13.6 |
| timestamp (UTC) | 2026-11-22T16:16:58Z |

Raw data: [`results/vm2-cleanroom-2026-11-22.json`](results/vm2-cleanroom-2026-11-22.json)
(console log: [`results/vm2-bench.log`](results/vm2-bench.log)).

## Single-thread throughput

| operation | ops/s | p50 µs | p95 µs | p99 µs | n |
|---|--:|--:|--:|--:|--:|
| compose_chain (5-link AV-RAILS) | 4,493.8 | 197.2 | 349.8 | 437.6 | 20,000 |
| verify (AV-RAILS chain) | 4,715.1 | 191.8 | 323.1 | 425.8 | 20,000 |
| compose_protocol_chain (x402 v2) | 12,602.7 | 67.2 | 132.5 | 173.4 | 20,000 |
| protocol_face (x402 v2) | 64,867.0 | 12.7 | 27.5 | 45.6 | 50,000 |
| check_version (x402 v2) | 2,366,928.6 | 0.23 | 0.38 | 0.45 | 200,000 |
| supported_matrix | 576,533.2 | 1.39 | 2.27 | 3.19 | 200,000 |
| archive_binding_ref (AV-VCS) | 61,083.2 | 13.3 | 32.5 | 44.6 | 100,000 |
| ac2_binding_ref | 80,746.8 | 11.0 | 19.8 | 37.3 | 100,000 |
| verify_ac2_consent (consent_present) | 4,479.1 | 214.9 | 299.3 | 359.3 | 10,000 |
| verify_ac2_consent (sender_bound) | 4,387.0 | 219.5 | 288.0 | 342.2 | 10,000 |
| compose_ac2_chain | 3,777.5 | 253.5 | 344.6 | 408.6 | 10,000 |
| ac2_attestation | 4,600.1 | 205.3 | 267.0 | 351.3 | 10,000 |
| verify_ac2_attestation | 4,200.0 | 225.4 | 340.7 | 378.4 | 10,000 |
| verify_ac2_attestation (sender_bound) | 4,322.5 | 223.5 | 301.1 | 372.7 | 10,000 |
| compose_journey (rails+pef+vcs+ac2) | 1,606.4 | 591.6 | 922.5 | 1,085.6 | 3,000 |
| verify_journey (rails+pef+vcs+ac2) | 1,773.6 | 537.6 | 785.2 | 952.3 | 3,000 |
| verify_journey (sender_bound ac2) | 1,710.6 | 560.6 | 764.5 | 957.8 | 3,000 |

## Maximum throughput (multi-process peak, 2 workers)

| operation | aggregate ops/s | speedup vs single |
|---|--:|--:|
| verify_journey (full journey) | 2,845.7 | 1.60× |
| verify_ac2_consent | 7,473.1 | 1.67× |

The peak is bounded by the **2 cores visible to the container**; it is an
observed aggregate on this box, not a per-core extrapolation. The crypto-heavy
paths (AC2 consent verify ≈ 4.4k ops/s single-thread; full-journey verify ≈
1.8k ops/s) are dominated by Ed25519 verification and RFC-8785 canonicalisation
delegated to `avm_ac2` / `avm_mesh`; the pure binding-hash and matrix operations
reach 10⁴–10⁶ ops/s.

## Functional gate + negative control (same clean room)

The benchmark ran against the same installed wheel that passed the functional
gate, so the throughput figures and the correctness gate share one artefact.

- **Build:** wheel built on VM2 from the committed tree
  (`git archive HEAD`, tree `be9f695e21ba9f34aac31f37dead3b47780c3f2b`,
  commit `916a130`), `python -m build --wheel`.
- **Closure:** 21 wheels downloaded as linux/manylinux py3.12, installed
  **offline** (`pip install --no-index --find-links artefacts`), exit 0;
  `import algovoi_fabric` → 0.3.1, AC2 face present, `avm_ac2` 0.1.0.
- **Gate:** `pytest` against the installed wheel (tests staged separately, no
  `src` on path) → **117 collected, 113 passed, 4 skipped, exit 0**
  ([`results/vm2-gate.log`](results/vm2-gate.log)). The 4 skips are the four
  *supported* protocols (x402/ap2/mpp/a2a) correctly skipped inside
  `test_unknown_protocol_fails_closed` — intentional, not missing dependencies.
- **Negative control (both directions):** disabling the `LEVEL_NONE` guard in a
  throwaway install (`if level == LEVEL_NONE:` → `if level == "consent_absent":`,
  ac2.py:83) makes `test_require_false_still_refuses_absent_consent` **FAIL**
  (exit 1); the real wheel **passes** it (exit 0). The gate discriminates.

## Honesty limits

- These are clean-room figures on a 2-vCPU AMD EPYC-Milan container, Python
  3.12.16, against the 0.3.1 wheel. They are not a production SLA and will differ
  on other hardware/core counts.
- AC2 fixtures use a synthetic Ed25519 keypair, so `consent_present` /
  `sender_bound` are exercised; `consensus_bound` (state-proof + stake-attested
  trust root) is **not** benchmarked here — it needs live mainnet captures.
- `consent_present` proves a key signed the settlement, not human/passkey
  approval; the benchmark measures verification cost, not approval semantics.
