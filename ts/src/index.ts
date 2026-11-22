// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Christopher Hopley / AlgoVoi (chopmob-cloud)
/**
 * @algovoi/fabric — TypeScript edition (Phase 1).
 *
 * The AV-RAILS -> AV-PEF -> AV-VCS composition spine, plus the protocol journey
 * spine (x402 / AP2 / MPP / A2A), ported from the Python algovoi-fabric with
 * byte-for-byte reference parity proven against the real Python verifier.
 *
 * Phase 2 (AC2 consent + av-agent guard) is not yet ported; those journey
 * branches fail closed with an explicit error.
 */
export const VERSION = '0.1.0';

export {
  SCHEMA,
  CANON,
  KeystoneError,
  canonicalize,
  ref,
  resolve,
  deepEqual,
  scopeContains,
  verifyChain,
  type LinkResult,
  type AssertionResult,
  type ChainResult,
} from './keystone/verify.js';

export { FabricError, composeChain, verify, type ComposeOptions } from './compose.js';

export {
  ProtocolError,
  FACE_ACTION_TYPE,
  SUPPORTED_VERSIONS,
  supportedMatrix,
  checkVersion,
  protocolFace,
  composeProtocolChain,
  type ProtocolChainOptions,
} from './protocols.js';

export {
  JOURNEY_SCHEMA,
  BIND_ACTION_TYPE,
  archiveBindingRef,
  composeJourney,
  verifyJourney,
  type ArchiveBindingInput,
  type ComposeJourneyOptions,
} from './journey.js';