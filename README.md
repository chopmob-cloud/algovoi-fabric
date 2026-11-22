# AlgoVoi Fabric

**The security composition core for agentic commerce.** Fabric turns an agent's
payment action into a single, tamper-evident, fail-closed, **offline-verifiable**
keystone chain that binds authority, policy, decision, execution and settlement
evidence into one recomputable sequence.

The defining guarantee: **every protection is recomputable offline by the
customer: nothing is trusted on AlgoVoi's word.** A plain receipt checker
recomputes one digest; Fabric proves the *whole chain binds in order* and that
one verdict covers it.

> The security composition core is built and proven (see *Proof* below).
> The wider protection tiers (post-quantum signing, RFC 3161 time, KMS/HSM
> custody) compose existing AlgoVoi primitives and are being wired in. Fabric is
> a composition layer, not a new protocol.

## Why security is the spine

Companies adopting autonomous agents need assurance they can *verify themselves*,
not a vendor promise. Fabric's chain is content-addressed (`sha256` over RFC 8785
JCS), so tampering any link breaks that link and every link that binds it, and a
customer can recompute the entire chain with no AlgoVoi software in the trust
base and no network contact.

## Protection layers

| Layer | Guarantee | Primitive |
|---|---|---|
| Authority | no permission widening | keystone `scope_subset`, fail-closed |
| Policy | deny-by-default verdicts | compliance gate (ALLOW / REFER / DENY) |
| Integrity | tamper any link → chain breaks | `sha256(JCS)` content addressing |
| Time & revocation | post-revocation actions blocked | `not_revoked` cascade, RFC 3161 |
| Evidence | settlement bound to the decision | PEF frame (`draft-hopley-x402-payment-evidence-frame`) |
| Assurance | recomputable offline by the customer | independent `rfc8785` canonicalisation |

Post-quantum signing (Falcon-1024 / ML-DSA-65 / ML-KEM-1024), RFC 9421
authentication and BYO-key/KMS/HSM custody compose the estate's existing,
independently validated primitives in the tiers above the core.

## Proof

The core is proven against the **published** packages (`algovoi-keystone` 0.6.0,
`algovoi-pef` 0.1.2, `algovoi-substrate` 0.5.1), not a private fork:

- **12 security tests, both directions**: each protection passes green on valid
  input and goes red on a planted defect.
- **Byte-exact contract**: the composer reproduces the published
  `keystone-golden.json` references exactly, so the emitted chain is accepted by
  the real `verify_chain` by construction.
- **Mutation self-test**: planting a fail-open in the composer (dropping ref
  anchoring) turns 3 tests red; restoring returns 12 green, bytes identical.

Proven properties: tamper-evidence; fail-closed on forward/unknown references,
duplicate names and empty chains; scope-widening rejected; revocation cascade
blocks actions after revocation; a PEF settlement frame binds and verifies
offline.

## Quickstart

```python
from algovoi_fabric import compose_chain, verify

chain = compose_chain([
    ("passport", {"agent_id": "agent-1", "scope": {"capabilities": ["payments"],
                                                    "max_amount": 1000}}),
    ("decision", {"agent_ref": "@passport", "verdict": "ALLOW",
                  "scope": {"capabilities": ["payments"], "max_amount": 500}}),
    ("execution", {"decision_ref": "@decision", "action_type": "payment",
                   "outcome": "COMMITTED"}),
    ("trust_query", {"subject_refs": ["@passport", "@decision", "@execution"],
                     "trust_outcome": "TRUSTED"}),
], assertions=[{"kind": "scope_subset", "inner": "decision", "outer": "passport"}])

result = verify(chain)   # offline; no issuer contact
assert result.ok and result.capped
```

`@name` binds an earlier link by its computed reference; `@@name` is a literal
escape. A forward or unknown reference raises `KeystoneError` (fail-closed).

## Links

- Verifier: [algovoi-keystone](https://github.com/chopmob-cloud/algovoi-keystone)
- Evidence frame: [algovoi-pef](https://github.com/chopmob-cloud/algovoi-pef)
- AV-VCS: [algovoi-vcs](https://github.com/chopmob-cloud/algovoi-vcs)
- AV-RAILS ↔ AV-VCS bridge: [AlgoVoi-Keystone-Connectors](https://github.com/chopmob-cloud/AlgoVoi-Keystone-Connectors)

## Licence

Apache-2.0. Canonicalisation follows RFC 8785 (JCS); attribution per NOTICE.