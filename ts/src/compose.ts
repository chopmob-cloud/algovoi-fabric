// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Christopher Hopley / AlgoVoi (chopmob-cloud)
/**
 * AV-RAILS composition — TypeScript port of algovoi_fabric.compose.
 *
 * Turns an ordered list of named preimages into a content-addressed keystone
 * chain that the real verifier recomputes offline. Each link may bind an earlier
 * link by the string "@name"; "@@name" is the literal "@name". Fail-closed on a
 * forward or unknown reference, a duplicate name, or a malformed input.
 *
 * Reference computation delegates to the same keystone primitives (ref/resolve)
 * the verifier uses, so there is exactly one definition of "recomputes": the
 * chain emitted here is accepted by verifyChain by construction and cannot drift.
 */
import {
  SCHEMA,
  CANON,
  ref,
  resolve,
  verifyChain,
  KeystoneError,
  type ChainResult,
} from './keystone/verify.js';
const hasOwn = (o: object, k: PropertyKey): boolean => Object.prototype.hasOwnProperty.call(o, k);

/** Raised when a composition request is structurally invalid (fail-closed). */
export class FabricError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FabricError';
  }
}

function isDict(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

export interface ComposeOptions {
  description?: string;
  assertions?: Record<string, unknown>[] | null;
}

/**
 * Compose a keystone chain from (name, preimage) pairs.
 * Fail-closed: a non-iterable, a malformed pair, a non-string/empty name, a
 * non-dict preimage, a duplicate name, or a forward/unknown @ref raises
 * FabricError before any chain is emitted.
 */
export function composeChain(links: Iterable<unknown>, opts: ComposeOptions = {}): Record<string, unknown> {
  let items: unknown[];
  try {
    items = Array.from(links as Iterable<unknown>);
  } catch {
    throw new FabricError('links must be an iterable of (name, preimage) pairs');
  }
  const chain: Record<string, unknown>[] = [];
  const refs: Record<string, string> = Object.create(null);
  for (const item of items) {
    if (!Array.isArray(item) || item.length !== 2) {
      throw new FabricError('each link must be a (name, preimage) pair');
    }
    const [name, preimage] = item as [unknown, unknown];
    if (typeof name !== 'string' || !name) {
      throw new FabricError('each link needs a non-empty string name');
    }
    if (!isDict(preimage)) {
      throw new FabricError(`link '${name}' preimage must be a dict`);
    }
    if (hasOwn(refs, name)) {
      throw new FabricError(`duplicate link name '${name}'`);
    }
    let r: string;
    try {
      const resolved = resolve(preimage, refs, name);
      r = ref(resolved);
    } catch (exc) {
      if (exc instanceof KeystoneError) throw new FabricError(exc.message);
      throw exc;
    }
    refs[name] = r;
    chain.push({ name, preimage: structuredClone(preimage), ref: r });
  }
  if (chain.length === 0) {
    throw new FabricError('chain must contain at least one link');
  }
  const out: Record<string, unknown> = { schema: SCHEMA, canon: CANON, chain };
  if (opts.description) out['description'] = opts.description;
  if (opts.assertions !== undefined && opts.assertions !== null) {
    out['assertions'] = structuredClone(opts.assertions);
  }
  return out;
}

/**
 * Offline verification of a composed chain via the real keystone verifier.
 * A structurally malformed chain raises FabricError (Rule K: no KeystoneError
 * escapes the fabric boundary); a broken-but-well-formed chain returns a
 * ChainResult with ok === false.
 */
export function verify(chain: Record<string, unknown>): ChainResult {
  try {
    return verifyChain(chain);
  } catch (exc) {
    if (exc instanceof KeystoneError) throw new FabricError(exc.message);
    throw exc;
  }
}