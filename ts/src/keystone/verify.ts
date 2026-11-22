// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Christopher Hopley / AlgoVoi (chopmob-cloud)
/**
 * Keystone chain verification core — TypeScript port of algovoi_keystone.verify.
 *
 * A keystone chain is an ordered list of content-addressed links. Each link's
 * reference is `"sha256:" + SHA-256(RFC 8785 JCS(preimage))`. Composition is
 * structural: a downstream preimage refers to an upstream link by `@name`, so
 * the downstream reference cannot be computed without the exact upstream
 * reference. Tamper any link and that link, and every link that binds it, diverge.
 *
 * PARITY CONTRACT: this port must reproduce the Python verifier byte-for-byte.
 * The independent witness is the Python `rfc8785` implementation, exercised by
 * the golden fixtures in ts/fixtures/golden.json (produced by the real Python
 * verifier). In-process, the substrate canonicaliser is cross-checked against
 * the `canonicalize` library; a divergence fails closed rather than silently
 * choosing one — mirroring the Python `_canonicalize` discipline.
 */
import { canonicalizeBytes as substrateBytes } from '@algovoi/substrate';
import canonicalizeLib from 'canonicalize';
import { createHash } from 'node:crypto';

export const SCHEMA = 'algovoi-keystone-chain/v1';
export const CANON = 'jcs-rfc8785-v1';
const REF_RE = /^sha256:[0-9a-f]{64}$/;
const MAX_SAFE_INT = Number.MAX_SAFE_INTEGER; // 2**53 - 1
const hasOwn = (o: object, k: PropertyKey): boolean => Object.prototype.hasOwnProperty.call(o, k);

/** Raised when a chain is structurally invalid (not when a link simply mismatches). */
export class KeystoneError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KeystoneError';
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * RFC 8785 JCS bytes for `obj`. The substrate is the canonicaliser under test;
 * the independent `canonicalize` library is the in-process witness. The two must
 * agree byte-for-byte or the chain is refused. Cross-language independence is
 * proven separately against Python rfc8785 by the golden parity suite.
 */
export function canonicalize(obj: unknown): Uint8Array {
  const primary = substrateBytes(obj);
  const witnessStr = canonicalizeLib(obj);
  if (witnessStr === undefined) {
    throw new KeystoneError('object is not JCS-canonicalisable (canonicalize returned undefined)');
  }
  const witness = new TextEncoder().encode(witnessStr);
  if (!bytesEqual(primary, witness)) {
    throw new KeystoneError('canonicalisation divergence: substrate and canonicalize disagree');
  }
  return primary;
}

/** Content-address reference: "sha256:" + SHA-256(JCS(obj)). */
export function ref(obj: unknown): string {
  return 'sha256:' + createHash('sha256').update(canonicalize(obj)).digest('hex');
}

/**
 * Replace every '@name' marker with the already-computed reference of link `name`.
 * A leading '@@' is an escape: '@@name' is the literal string '@name' and never
 * resolves. Fail-closed on a forward or unknown reference.
 */
export function resolve(value: unknown, refs: Record<string, string>, linkName: string): unknown {
  if (typeof value === 'string' && value.startsWith('@')) {
    if (value.startsWith('@@')) return value.slice(1);
    const target = value.slice(1);
    if (!hasOwn(refs, target)) {
      throw new KeystoneError(`link '${linkName}' references @${target}, which is not an earlier link`);
    }
    return refs[target];
  }
  if (Array.isArray(value)) return value.map((v) => resolve(v, refs, linkName));
  if (value !== null && typeof value === 'object') {
    // Object.fromEntries defines own data properties (even a '__proto__' key),
    // matching Python dict semantics and avoiding prototype assignment via out[k]=v.
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([k, v]) => [k, resolve(v, refs, linkName)]),
    );
  }
  return value;
}

/** Deep structural equality (Python `==` on JSON values). */
export function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (a === null || b === null || typeof a !== 'object') return false;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((v, i) => deepEqual(v, b[i]));
  }
  const ao = a as Record<string, unknown>;
  const bo = b as Record<string, unknown>;
  const ak = Object.keys(ao);
  const bk = Object.keys(bo);
  if (ak.length !== bk.length) return false;
  return ak.every((k) => Object.prototype.hasOwnProperty.call(bo, k) && deepEqual(ao[k], bo[k]));
}

// --- result shapes (mirror the Python dataclasses) ---
export interface LinkResult {
  name: string;
  computed: string;
  expected: string | null;
  ok: boolean;
  binds: string[];
  detail: string;
}
export interface AssertionResult {
  kind: string;
  ok: boolean;
  detail: string;
}
export interface ChainResult {
  links: LinkResult[];
  assertions: AssertionResult[];
  cap: string | null;
  cap_covers: string[];
  capped: boolean;
  ok: boolean;
  first_broken: LinkResult | null;
  failed_assertion: AssertionResult | null;
}

function isDict(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

/** Python repr()-alike for the detail strings (strings quoted, JSON otherwise). */
function repr(v: unknown): string {
  if (typeof v === 'string') return `'${v}'`;
  if (v === undefined || v === null) return 'None';
  if (Array.isArray(v) || isDict(v)) return JSON.stringify(v);
  return String(v);
}

/** True iff `inner` is wholly within `outer` (the inner widened nothing). */
export function scopeContains(outer: unknown, inner: unknown): [boolean, string] {
  if (!isDict(outer) || !isDict(inner)) {
    const eq = deepEqual(outer, inner);
    return [eq, eq ? '' : 'non-dict scopes differ'];
  }
  if (hasOwn(outer, 'resource')) {
    const o = String(outer['resource']).replace(/^\/+|\/+$/g, '').split('/').filter((s) => s !== '');
    const i = String(inner['resource'] ?? '').replace(/^\/+|\/+$/g, '').split('/').filter((s) => s !== '');
    const prefix = i.slice(0, o.length);
    if (prefix.length !== o.length || !prefix.every((s, idx) => s === o[idx])) {
      return [false, `resource ${repr(inner['resource'])} not within ${repr(outer['resource'])}`];
    }
  }
  if (hasOwn(outer, 'max_amount')) {
    const iv = inner['max_amount'];
    if (iv === undefined || iv === null || (iv as number) > (outer['max_amount'] as number)) {
      return [false, `max_amount ${iv} exceeds ${outer['max_amount']}`];
    }
  }
  for (const dim of ['capabilities', 'jurisdictions'] as const) {
    if (hasOwn(outer, dim)) {
      const outerSet = new Set(outer[dim] as unknown[]);
      const innerArr = (inner[dim] ?? []) as unknown[];
      if (!innerArr.every((x) => outerSet.has(x))) {
        return [false, `${dim} ${repr(inner[dim])} not a subset of ${repr(outer[dim])}`];
      }
    }
  }
  return [true, ''];
}

function binds(value: unknown, acc: string[]): void {
  if (typeof value === 'string' && value.startsWith('@')) {
    if (!value.startsWith('@@')) acc.push(value.slice(1));
  } else if (Array.isArray(value)) {
    for (const v of value) binds(v, acc);
  } else if (isDict(value)) {
    for (const v of Object.values(value)) binds(v, acc);
  }
}

function getPath(path: string, preimages: Record<string, Record<string, unknown>>): unknown {
  if (!path.includes('.')) throw new KeystoneError(`assertion path '${path}' must be 'link.field'`);
  const idx = path.indexOf('.');
  const link = path.slice(0, idx);
  const fld = path.slice(idx + 1);
  if (!hasOwn(preimages, link)) {
    throw new KeystoneError(`assertion references link '${link}', which is not in the chain`);
  }
  if (!hasOwn(preimages[link]!, fld)) {
    throw new KeystoneError(`assertion path '${path}' names no field on link '${link}'`);
  }
  return preimages[link]![fld];
}

/** Positive, integer-valued JSON number within the JS-safe range (bool excluded). */
function posIntish(v: unknown): boolean {
  if (typeof v !== 'number') return false;
  return Number.isInteger(v) && v > 0 && v <= MAX_SAFE_INT;
}

function isInt(v: unknown): v is number {
  return typeof v === 'number' && Number.isInteger(v);
}

function assertOne(a: Record<string, unknown>, preimages: Record<string, Record<string, unknown>>): AssertionResult {
  const kind = a['kind'];
  if (kind === 'scope_subset') {
    const inner = a['inner'] as string;
    const outer = a['outer'] as string;
    for (const nm of [inner, outer]) {
      if (!hasOwn(preimages, nm)) throw new KeystoneError(`scope_subset references link '${nm}', not in the chain`);
    }
    const [ok, why] = scopeContains(preimages[outer]!['scope'], preimages[inner]!['scope']);
    return { kind: 'scope_subset', ok, detail: ok ? '' : `${inner}.scope widens ${outer}.scope: ${why}` };
  }
  if (kind === 'field_equals') {
    const av = getPath(a['a'] as string, preimages);
    const bv = getPath(a['b'] as string, preimages);
    const ok = deepEqual(av, bv);
    return { kind: 'field_equals', ok, detail: ok ? '' : `${a['a']} (${repr(av)}) != ${a['b']} (${repr(bv)})` };
  }
  if (kind === 'time_within') {
    const win = a['window'] as string;
    if (!hasOwn(preimages, win)) throw new KeystoneError(`time_within references window '${win}', not in the chain`);
    const t = getPath(a['time'] as string, preimages);
    const nb = preimages[win]!['not_before_ms'];
    const na = preimages[win]!['not_after_ms'];
    const ok = isInt(t) && isInt(nb) && isInt(na) && nb <= t && t <= na;
    return { kind: 'time_within', ok, detail: ok ? '' : `${a['time']} (${t}) not within ${win} [${nb}, ${na}]` };
  }
  if (kind === 'not_revoked') {
    const action = a['action'] as string;
    const rev = a['revocation'] as string;
    for (const nm of [action, rev]) {
      if (!hasOwn(preimages, nm)) throw new KeystoneError(`not_revoked references link '${nm}', not in the chain`);
    }
    const t = getPath(a['time'] as string, preimages);
    const revokedAt = preimages[rev]!['revoked_at_ms'];
    const ok = isInt(t) && isInt(revokedAt) && t < revokedAt;
    return {
      kind: 'not_revoked', ok,
      detail: ok ? '' : `${action} acted at ${t} >= ${rev}.revoked_at_ms (${revokedAt}): authority revoked`,
    };
  }
  if (kind === 'journey') {
    const refName = a['ref'] as string;
    const hops = (a['hops'] ?? []) as string[];
    if (!hasOwn(preimages, refName)) throw new KeystoneError(`journey references link '${refName}', not in the chain`);
    const covered: string[] = [];
    binds(preimages[refName], covered);
    const missing = hops.filter((h) => !covered.includes(h) || !hasOwn(preimages, h));
    const ok = hops.length > 0 && missing.length === 0;
    return { kind: 'journey', ok, detail: ok ? '' : `journey '${refName}' does not cover hops ${JSON.stringify(missing)}` };
  }
  if (kind === 'recurring_cap') {
    const auth = a['authority'] as string;
    const policy = a['policy'] as string;
    const execs = (a['executions'] ?? []) as string[];
    const amountField = (a['amount_field'] ?? 'amount_minor') as string;
    const timeField = (a['time_field'] ?? 'executed_at_ms') as string;
    for (const nm of [auth, policy, ...execs]) {
      if (!hasOwn(preimages, nm)) throw new KeystoneError(`recurring_cap references link '${nm}', not in the chain`);
    }
    const A = preimages[auth]!;
    const P = preimages[policy]!;
    const perCycleRaw = A['per_cycle_amount_minor'];
    const capAmtRaw = A['cap_amount_minor'];
    const pmaxRaw = P['max_amount'];
    if (![perCycleRaw, capAmtRaw, pmaxRaw].every(posIntish)) {
      return { kind: 'recurring_cap', ok: false, detail: 'authority per_cycle/cap or policy max_amount must be a positive integer' };
    }
    const perCycle = perCycleRaw as number;
    const capAmt = capAmtRaw as number;
    const pmax = pmaxRaw as number;
    const expiresStr = String(A['expires_at'] ?? '');
    // Must be timezone-aware (Z or ±HH:MM), else Python (local tz) and JS disagree.
    const tzAware = /(?:Z|[+-]\d{2}:\d{2})$/.test(expiresStr);
    const expMs = Date.parse(expiresStr.replace('Z', '+00:00'));
    if (Number.isNaN(expMs)) {
      return { kind: 'recurring_cap', ok: false, detail: `authority.expires_at not ISO-8601: ${repr(A['expires_at'])}` };
    }
    if (!tzAware) {
      return { kind: 'recurring_cap', ok: false, detail: 'authority.expires_at must be timezone-aware ISO-8601 (got naive)' };
    }
    if (perCycle > pmax) {
      return { kind: 'recurring_cap', ok: false, detail: `per_cycle_amount_minor ${perCycle} exceeds policy max_amount ${pmax}` };
    }
    let total = 0;
    for (const e of execs) {
      const E = preimages[e]!;
      const amt = E[amountField];
      const t = E[timeField];
      if (!(posIntish(amt) && posIntish(t))) {
        return { kind: 'recurring_cap', ok: false, detail: `${e}.${amountField}/${timeField} must be positive integers` };
      }
      const amtN = amt as number;
      const tN = t as number;
      if (amtN > perCycle) {
        return { kind: 'recurring_cap', ok: false, detail: `${e}.${amountField} ${amtN} exceeds per_cycle cap ${perCycle}` };
      }
      if (tN > expMs) {
        return { kind: 'recurring_cap', ok: false, detail: `${e} executed at ${tN} after authority expiry ${expMs}` };
      }
      total += amtN;
    }
    if (total > capAmt) {
      return { kind: 'recurring_cap', ok: false, detail: `cumulative ${total} exceeds cap_amount_minor ${capAmt}` };
    }
    return { kind: 'recurring_cap', ok: true, detail: '' };
  }
  throw new KeystoneError(`unknown assertion kind '${kind}'`);
}

function pinResults(refs: Record<string, string>, expect: Record<string, string> | null | undefined): AssertionResult[] {
  if (!expect || Object.keys(expect).length === 0) return [];
  const out: AssertionResult[] = [];
  for (const [name, want] of Object.entries(expect)) {
    if (typeof name !== 'string' || !name) throw new KeystoneError('expect keys must be non-empty link names');
    if (typeof want !== 'string' || !REF_RE.test(want)) {
      throw new KeystoneError(`expected ref for '${name}' must be 'sha256:' + 64 lowercase hex, got ${repr(want)}`);
    }
    if (!hasOwn(refs, name)) {
      out.push({ kind: 'ref_pinned', ok: false, detail: `pinned link '${name}' is not in the chain` });
    } else if (refs[name] !== want) {
      out.push({ kind: 'ref_pinned', ok: false, detail: `${name} recomputed ${refs[name]} != pinned ${want}` });
    } else {
      out.push({ kind: 'ref_pinned', ok: true, detail: '' });
    }
  }
  return out;
}

/**
 * Recompute every link in order, enforcing structural composition via @name refs.
 * `chain` = {"chain": [ {"name", "preimage", "ref"?}, ... ], "assertions"?: [...]}.
 * `expect` optionally pins link name -> the reference independently trusted.
 */
export function verifyChain(chain: Record<string, unknown>, expect?: Record<string, string> | null): ChainResult {
  const links = chain['chain'];
  if (!Array.isArray(links) || links.length === 0) {
    throw new KeystoneError("chain must contain a non-empty 'chain' array");
  }
  // Null-prototype maps: a link literally named '__proto__' is a normal own key
  // (Python dict parity), and no inherited key can ever satisfy a membership test.
  const refs: Record<string, string> = Object.create(null);
  const preimages: Record<string, Record<string, unknown>> = Object.create(null);
  const linkResults: LinkResult[] = [];
  const assertions: AssertionResult[] = [];

  for (let i = 0; i < links.length; i++) {
    const link = links[i];
    if (!isDict(link)) throw new KeystoneError(`link at index ${i} is not an object`);
    const name = link['name'];
    if (!name) throw new KeystoneError(`link at index ${i} has no 'name'`);
    const nameStr = name as string;
    if (hasOwn(refs, nameStr)) throw new KeystoneError(`duplicate link name '${nameStr}'`);
    if (!hasOwn(link, 'preimage')) throw new KeystoneError(`link '${nameStr}' has no 'preimage'`);
    const preimage = link['preimage'];
    const b: string[] = [];
    binds(preimage, b);
    const resolved = resolve(preimage, refs, nameStr);
    const computed = ref(resolved);
    const expected = (link['ref'] ?? null) as string | null;
    const ok = expected === null || computed === expected;
    const detail = ok ? '' : `recomputed ${computed} != declared ${expected}`;
    refs[nameStr] = computed;
    preimages[nameStr] = preimage as Record<string, unknown>;
    linkResults.push({ name: nameStr, computed, expected, ok, binds: b, detail });
  }

  assertions.push(...pinResults(refs, expect ?? null));
  for (const a of (chain['assertions'] ?? []) as Record<string, unknown>[]) {
    assertions.push(assertOne(a, preimages));
  }

  const final = links[links.length - 1] as Record<string, unknown>;
  const finalBinds: string[] = [];
  binds(final['preimage'] ?? {}, finalBinds);
  let cap: string | null = null;
  let capCovers: string[] = [];
  let capped = false;
  if (finalBinds.length >= 2 && finalBinds.every((x) => hasOwn(refs, x))) {
    cap = final['name'] as string;
    capCovers = finalBinds;
    capped = linkResults[linkResults.length - 1]!.ok;
  }

  const ok = linkResults.length > 0 && linkResults.every((l) => l.ok) && assertions.every((a) => a.ok);
  return {
    links: linkResults,
    assertions,
    cap,
    cap_covers: capCovers,
    capped,
    ok,
    first_broken: linkResults.find((l) => !l.ok) ?? null,
    failed_assertion: assertions.find((a) => !a.ok) ?? null,
  };
}