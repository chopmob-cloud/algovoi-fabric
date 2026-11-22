// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Christopher Hopley / AlgoVoi (chopmob-cloud)
/**
 * Fabric journey — TypeScript port of algovoi_fabric.journey (Phase 1 levels).
 *
 * Binds a composed AV-RAILS chain to the downstream AV-PEF frame and AV-VCS
 * archive attestation, each anchored to the chain's own execution link by
 * content address. Every level is re-checkable offline and fail-closed.
 *
 * Phase 1 covers av-rails / av-pef / av-vcs. The AC2 consent and av-agent guard
 * branches are Phase 2: passing them here raises a clear FabricError rather than
 * silently dropping a level. PQC sealing (Falcon-1024), ML-KEM-1024 and RFC 3161
 * stay in the customer's licensed AV-VCS engine; Fabric only binds by content
 * address (doc_hash / entry_id / seq -> binding_ref).
 */
import { verify, FabricError } from './compose.js';
import { ref } from './keystone/verify.js';
import { verifyPef } from '@algovoi/pef';
const hasOwn = (o: object, k: PropertyKey): boolean => Object.prototype.hasOwnProperty.call(o, k);

export const JOURNEY_SCHEMA = 'algovoi-fabric-journey/v1';
export const BIND_ACTION_TYPE = 'archive:bind';

function isDict(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

/** Rule K: every link must carry name + ref + a preimage dict, or raise. */
function validateChainShape(chain: unknown): void {
  if (!isDict(chain) || !hasOwn(chain, 'chain')) {
    throw new FabricError('journey needs a composed keystone chain');
  }
  const links = chain['chain'];
  if (!Array.isArray(links) || links.length === 0) {
    throw new FabricError("journey chain must contain a non-empty 'chain' array");
  }
  for (let i = 0; i < links.length; i++) {
    const link = links[i];
    if (!isDict(link)) {
      throw new FabricError(`journey chain link at index ${i} must be a dict`);
    }
    if (!hasOwn(link, 'name') || !link['name']) {
      throw new FabricError(`journey chain link at index ${i} has no 'name'`);
    }
    const name = link['name'] as string;
    if (!hasOwn(link, 'ref') || !link['ref']) {
      throw new FabricError(`journey chain link '${name}' has no 'ref'`);
    }
    if (!isDict(link['preimage'])) {
      throw new FabricError(`journey chain link '${name}' has no preimage dict`);
    }
  }
}

function executionPreimage(chain: unknown, execution: unknown): Record<string, unknown> {
  if (!isDict(chain)) {
    throw new FabricError('journey needs a composed keystone chain');
  }
  const links = (chain['chain'] ?? []) as Record<string, unknown>[];
  const link = links.find((l) => isDict(l) && l['name'] === execution);
  if (typeof execution !== 'string' || !execution || !link || !isDict(link['preimage'])) {
    throw new FabricError(`journey needs an execution link named '${execution}'`);
  }
  return link['preimage'] as Record<string, unknown>;
}

function executionRef(chain: unknown, execution: unknown): string {
  // Anchor to the chain's STORED (resolved) execution-link ref — the content
  // address the keystone verifier recomputes — exactly as Python _execution_ref
  // returns link["ref"]. Hashing the raw preimage here would diverge for any
  // @ref-bearing execution link (the protocol-chain default) and break
  // cross-edition journey verification.
  if (!isDict(chain)) {
    throw new FabricError('journey needs a composed keystone chain');
  }
  const links = (chain['chain'] ?? []) as Record<string, unknown>[];
  const link = links.find((l) => isDict(l) && l['name'] === execution);
  if (typeof execution !== 'string' || !execution || !link) {
    throw new FabricError(`journey needs an execution link named '${execution}'`);
  }
  return link['ref'] as string;
}

export interface ArchiveBindingInput {
  execution_ref: unknown;
  doc_hash: unknown;
  entry_id: unknown;
  seq: unknown;
}

/**
 * Content-addressed AV-VCS binding: keystone_ref over an archive:bind preimage.
 * Fail-closed on a malformed attestation; never returns a reference for invalid
 * input. seq must be an integer (a boolean is not an int).
 */
export function archiveBindingRef(input: ArchiveBindingInput): string {
  const { execution_ref, doc_hash, entry_id, seq } = input;
  if (typeof execution_ref !== 'string' || !execution_ref) {
    throw new FabricError('execution_ref must be a non-empty string');
  }
  if (typeof doc_hash !== 'string' || !doc_hash) {
    throw new FabricError('doc_hash must be a non-empty string');
  }
  if (typeof entry_id !== 'string' || !entry_id) {
    throw new FabricError('entry_id must be a non-empty string');
  }
  if (typeof seq !== 'number' || !Number.isInteger(seq)) {
    throw new FabricError('seq must be an int');
  }
  return ref({ action_type: BIND_ACTION_TYPE, execution_ref, doc_hash, entry_id, seq });
}

export interface ComposeJourneyOptions {
  execution?: string;
  pef_frame?: Record<string, unknown> | null;
  archive?: Record<string, unknown> | null;
  description?: string;
}

/** Compose the AV-RAILS -> AV-PEF -> AV-VCS journey envelope (Phase 1). */
export function composeJourney(chain: Record<string, unknown>, opts: ComposeJourneyOptions = {}): Record<string, unknown> {
  const execution = opts.execution ?? 'execution';
  if (!isDict(chain) || !hasOwn(chain, 'chain')) {
    throw new FabricError('journey needs a composed keystone chain');
  }
  validateChainShape(chain);
  // Refuse a forged/unverifiable chain at compose time, not only at verify.
  const chainResult = verify(chain);
  if (chainResult.ok !== true) {
    throw new FabricError('journey chain does not verify offline');
  }
  const execRef = executionRef(chain, execution);
  const out: Record<string, unknown> = {
    schema: JOURNEY_SCHEMA,
    canon: (chain['canon'] as string) ?? 'jcs-rfc8785-v1',
    levels: ['av-rails'],
    chain: structuredClone(chain),
    execution,
    execution_ref: execRef,
  };
  if (opts.pef_frame !== undefined && opts.pef_frame !== null) {
    const frame = opts.pef_frame;
    if (!isDict(frame)) {
      throw new FabricError('pef_frame must be a dict');
    }
    const execPre = executionPreimage(chain, execution);
    if (execPre['settlement_frame_id'] !== frame['frame_id']) {
      throw new FabricError('execution link does not bind the supplied PEF frame_id');
    }
    if (verifyPef(frame).valid !== true) {
      throw new FabricError('PEF frame does not verify offline');
    }
    out['pef_frame'] = structuredClone(frame);
    (out['levels'] as string[]).push('av-pef');
  }
  if (opts.archive !== undefined && opts.archive !== null) {
    const archive = opts.archive;
    if (!isDict(archive)) {
      throw new FabricError('archive attestation must be a dict');
    }
    const binding = archiveBindingRef({
      execution_ref: execRef,
      doc_hash: archive['doc_hash'],
      entry_id: archive['entry_id'],
      seq: archive['seq'],
    });
    out['archive'] = {
      doc_hash: archive['doc_hash'],
      entry_id: archive['entry_id'],
      seq: archive['seq'],
      binding_ref: binding,
    };
    (out['levels'] as string[]).push('av-vcs');
  }
  if (opts.description) {
    out['description'] = opts.description;
  }
  return out;
}

/** Offline verification of the whole journey, fail-closed at every level. */
export function verifyJourney(envelope: Record<string, unknown>): { ok: boolean; levels: string[]; execution_ref: string } {
  if (!isDict(envelope) || envelope['schema'] !== JOURNEY_SCHEMA) {
    throw new FabricError('not a fabric journey envelope');
  }
  const chain = envelope['chain'];
  validateChainShape(chain);
  const res = verify(chain as Record<string, unknown>);
  if (res.ok !== true) {
    throw new FabricError('AV-RAILS chain failed offline verification');
  }
  const execution = envelope['execution'];
  const execRef = executionRef(chain, execution);
  if (execRef !== envelope['execution_ref']) {
    throw new FabricError('journey execution_ref does not match the chain\'s execution link');
  }
  const levels = ['av-rails'];
  if (hasOwn(envelope, 'pef_frame')) {
    const frame = envelope['pef_frame'];
    if (!isDict(frame)) {
      throw new FabricError('pef_frame must be a dict');
    }
    if (verifyPef(frame).valid !== true) {
      throw new FabricError('AV-PEF frame failed offline verification');
    }
    const execPre = executionPreimage(chain, execution);
    if (execPre['settlement_frame_id'] !== frame['frame_id']) {
      throw new FabricError('execution link does not bind the PEF frame_id');
    }
    levels.push('av-pef');
  }
  if (hasOwn(envelope, 'archive')) {
    const a = envelope['archive'];
    if (!isDict(a)) {
      throw new FabricError('archive attestation must be a dict');
    }
    const recomputed = archiveBindingRef({
      execution_ref: execRef,
      doc_hash: a['doc_hash'],
      entry_id: a['entry_id'],
      seq: a['seq'],
    });
    if (recomputed !== a['binding_ref']) {
      throw new FabricError('AV-VCS archive binding_ref does not recompute');
    }
    levels.push('av-vcs');
  }
  if (hasOwn(envelope, 'ac2')) {
    throw new FabricError('AC2 consent verification is Phase 2 of the TypeScript edition');
  }
  if (hasOwn(envelope, 'agent')) {
    throw new FabricError('av-agent guard verification is Phase 2 of the TypeScript edition');
  }
  return { ok: true, levels, execution_ref: execRef };
}