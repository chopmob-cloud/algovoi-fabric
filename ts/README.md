# @algovoi/fabric — TypeScript edition (Phase 1)

The TypeScript twin of the Python [`algovoi-fabric`](../README.md) composition
spine. It binds an agent's payment journey into one tamper-evident, fail-closed
keystone chain that the customer recomputes **offline** — nothing trusted on our
word. Apache-2.0.

Phase 1 ports the security spine and the protocol/journey composition:

| Module | Port of | What it does |
|---|---|---|
| `src/keystone/verify.ts` | `algovoi_keystone.verify` | RFC 8785 JCS + SHA-256 references, `@name` resolution, the six assertion kinds, pins-first chain verification |
| `src/compose.ts` | `algovoi_fabric.compose` | `composeChain` / `verify` — one definition of "recomputes" |
| `src/protocols.ts` | `algovoi_fabric.protocols` | x402 / AP2 / MPP / A2A version gate, protocol faces, protocol→execution chains |
| `src/journey.ts` | `algovoi_fabric.journey` | AV-RAILS → AV-PEF → AV-VCS envelope, archive binding, offline verdict |
| `src/index.ts` | `algovoi_fabric.__init__` | public surface |

**Phase 2 (not yet ported):** AC2 consent (`ac2.py`) and the av-agent guard
(`agent.py`). Passing `ac2` or `agent` to `composeJourney` fails closed with an
explicit `FabricError` rather than silently dropping a level. PQC (Falcon-1024),
ML-KEM-1024 and RFC 3161 remain in the customer's licensed AV-VCS engine, exactly
as in the Python edition.

## The parity gate

There is **one producer and one consumer** of the reference values:

- `scripts/gen_fixtures.py` runs the **real Python verifier** (gate venv,
  `PYTHONPATH=src`) and emits `fixtures/golden.json` — JCS byte vectors, composed
  chains, every supported protocol version, version-gate error texts, and a full
  journey built from a real `algovoi_pef` frame.
- The vitest suites consume that file and assert the TypeScript port reproduces
  it byte-for-byte. No expected hash is hand-written.

Canonicalisation is **dual-witness**: `@algovoi/substrate` is primary and the
independent `canonicalize` library is the witness; any divergence throws
`KeystoneError` (fail closed), mirroring the Python `rfc8785`-vs-substrate check.

```bash
cd ts
npm install
npm run build      # tsc -p tsconfig.json (strict, NodeNext)
npm test           # 50 parity tests across 4 suites
npm run parity     # the golden-driven gate explicitly
```

Regenerate the golden corpus after any change to the Python spine:

```bash
PYTHONPATH=src ../.venv-gate/Scripts/python.exe scripts/gen_fixtures.py   # Windows
PYTHONPATH=src ../.venv-gate/bin/python scripts/gen_fixtures.py           # POSIX
```

### Mutation discipline

A passing suite only proves the code agrees with its author's belief. The gate is
proven real by mutation: swapping the reference hash from SHA-256 to MD5 makes
**32 of 50** tests fail (exit 1); restoring SHA-256 returns **50/50** (exit 0).
Run this check before trusting any "green".

## Dependencies

- `@algovoi/substrate@0.5.1` — estate JCS canonicalisation (published npm twin).
- `@algovoi/pef@0.1.2` — structural PEF frame verification (published npm twin).
- `canonicalize@^3` (transitive) — independent JCS witness.

The keystone verify core is ported in-repo because `@algovoi/keystone`,
`@algovoi/keystone-connect`, `@algovoi/keystone-agent` and `@algovoi/ac2` have no
npm edition (registry 404). Hardening rule 12 requires exactly one definition of
"recomputes", so `compose`/`protocols`/`journey` all import the same `ref`.

## Status

Phase 1 is built and parity-proven locally (50/50 TS, 135 passed / 4 skipped
Python, strict `tsc` clean, mutation check both directions). **Not yet committed
or published.** An independent model review and the VM2 clean-room gate are
required before any commit, per the estate's ship-with-proof flow.