// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Christopher Hopley / AlgoVoi (chopmob-cloud)
/**
 * Protocol journey spine — TypeScript port of algovoi_fabric.protocols.
 *
 * Binds a protocol message (x402 / AP2 / MPP / A2A) to its execution as a
 * keystone chain: a `protocol:face` link content-addresses the message, and the
 * execution link structurally binds that face via "@protocol". The version gate
 * is fail-closed — an unsupported protocol or version raises before any chain.
 */
import { composeChain, FabricError } from './compose.js';
import { ref } from './keystone/verify.js';
const hasOwn = (o: object, k: PropertyKey): boolean => Object.prototype.hasOwnProperty.call(o, k);

/** A protocol request is structurally invalid (fail-closed). */
export class ProtocolError extends FabricError {
  constructor(message: string) {
    super(message);
    this.name = 'ProtocolError';
  }
}

export const FACE_ACTION_TYPE = 'protocol:face';

/** The protocol/version matrix this edition binds. */
export const SUPPORTED_VERSIONS: Record<string, Set<string>> = {
  x402: new Set(['1', '2']),
  ap2: new Set(['0.1']),
  mpp: new Set(['2']),
  a2a: new Set(['0.3', '1.0.1']),
};

function isDict(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

/** The supported matrix as sorted arrays (stable, JSON-friendly). */
export function supportedMatrix(): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const [p, vs] of Object.entries(SUPPORTED_VERSIONS)) {
    out[p] = [...vs].sort();
  }
  return out;
}

/** Fail-closed version gate. */
export function checkVersion(protocol: string, version: string): void {
  if (!hasOwn(SUPPORTED_VERSIONS, protocol)) {
    throw new ProtocolError(`unsupported protocol '${protocol}'`);
  }
  if (!SUPPORTED_VERSIONS[protocol]!.has(version)) {
    const supported = [...SUPPORTED_VERSIONS[protocol]!].sort();
    throw new ProtocolError(
      `unsupported version '${version}' for protocol '${protocol}'; supported: [${supported.map((v) => `'${v}'`).join(', ')}]`,
    );
  }
}

/** Content-addressed face for a protocol message. */
export function protocolFace(protocol: string, version: string, message: Record<string, unknown>): Record<string, unknown> {
  checkVersion(protocol, version);
  if (!isDict(message)) {
    throw new ProtocolError('protocol message must be a dict');
  }
  return { action_type: FACE_ACTION_TYPE, protocol, version, message_ref: ref(message) };
}

export interface ProtocolChainOptions {
  execution?: Record<string, unknown> | null;
  description?: string;
}

/**
 * Compose a protocol->execution keystone chain. The execution link binds the
 * face structurally ("@protocol"). With no execution preimage the link is the
 * bare {action_type, protocol_ref}; caller extras are deep-copied and cannot
 * override the structural binding (protocol_ref / action_type are popped first).
 */
export function composeProtocolChain(
  protocol: string,
  version: string,
  message: Record<string, unknown>,
  opts: ProtocolChainOptions = {},
): Record<string, unknown> {
  const face = protocolFace(protocol, version, message);
  const execPre: Record<string, unknown> = { action_type: 'execute', protocol_ref: '@protocol' };
  if (opts.execution !== undefined && opts.execution !== null) {
    if (!isDict(opts.execution)) {
      throw new ProtocolError('execution preimage must be a dict');
    }
    const extra = structuredClone(opts.execution) as Record<string, unknown>;
    delete extra['protocol_ref'];
    delete extra['action_type'];
    Object.assign(execPre, extra);
  }
  return composeChain(
    [
      ['protocol', face],
      ['execution', execPre],
    ],
    { description: opts.description || `${protocol} v${version} journey` },
  );
}