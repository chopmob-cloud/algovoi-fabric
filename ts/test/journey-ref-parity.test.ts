// SPDX-License-Identifier: Apache-2.0
/**
 * Journey @ref execution-link parity (golden, Python-produced).
 *
 * Regression for the cross-edition defect: the journey's execution_ref must be
 * the chain's STORED (resolved) execution-link ref — the content address the
 * keystone verifier actually recomputes — not a hash of the raw @ref-bearing
 * preimage. The golden journey_full preimage has no @refs, so it could not catch
 * this; this fixture's execution link binds @policy, where raw != resolved.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { composeChain } from '../src/compose.js';
import { ref } from '../src/keystone/verify.js';
import { archiveBindingRef, composeJourney, verifyJourney } from '../src/journey.js';

const here = dirname(fileURLToPath(import.meta.url));
const golden = JSON.parse(readFileSync(join(here, '..', 'fixtures', 'golden.json'), 'utf-8'));
const j = golden.journey_ref;
const DESC = 'golden journey @ref execution';

describe('journey @ref execution-link parity (golden)', () => {
  it('fixture invariant: Python execution_ref is the stored resolved ref, not ref(raw)', () => {
    expect(j.execution_ref).toBe(j.exec_stored_ref);
    expect(ref(j.exec_raw_preimage)).not.toBe(j.exec_stored_ref);
  });

  it('composeJourney anchors execution_ref to the stored execution-link ref', () => {
    const chain = composeChain(j.chain_links, { description: 'golden journey @ref execution chain' });
    const env = composeJourney(chain, { archive: j.archive, description: DESC });
    const exec = (chain.chain as Record<string, unknown>[]).find((l) => l['name'] === 'execution');
    expect(env.execution_ref).toBe(exec?.ref);
    expect(env.execution_ref).toBe(j.exec_stored_ref);
  });

  it('composeJourney reproduces the Python envelope for an @ref execution link', () => {
    const chain = composeChain(j.chain_links, { description: 'golden journey @ref execution chain' });
    const env = composeJourney(chain, { archive: j.archive, description: DESC });
    expect(env).toEqual(j.envelope);
  });

  it('archive binding_ref recomputes identically (anchors to the stored ref)', () => {
    const r = archiveBindingRef({
      execution_ref: j.execution_ref,
      doc_hash: j.archive.doc_hash,
      entry_id: j.archive.entry_id,
      seq: j.archive.seq,
    });
    expect(r).toBe(j.binding_ref);
  });

  it('verifyJourney reaches the Python verdict', () => {
    expect(verifyJourney(j.envelope)).toEqual(j.verify);
    expect(verifyJourney(j.envelope).levels).toEqual(['av-rails', 'av-vcs']);
  });

  it('cross-edition: TS verifies the Python-composed @ref journey', () => {
    expect(verifyJourney(j.envelope).ok).toBe(true);
  });
});

describe('journey execution_ref refusal + missing-link guards (regression locks)', () => {
  // The cross-edition fail-open the executionRef fix prevents: an envelope
  // anchored to ref(RAW @ref preimage) with its archive binding recomputed over
  // that same wrong anchor is internally self-consistent, so a TS-only round
  // trip accepts it — but the keystone verifier never computes that address.
  // This is exactly the envelope the pre-fix code produced. verifyJourney MUST
  // refuse it (execution_ref !== the chain's stored resolved execution-link ref).
  it('verifyJourney refuses an envelope anchored to the raw-preimage hash', () => {
    const rawHash = ref(j.exec_raw_preimage);
    expect(rawHash).not.toBe(j.exec_stored_ref); // raw != resolved for this @ref link
    const tampered = {
      ...j.envelope,
      execution_ref: rawHash,
      archive: {
        ...j.envelope.archive,
        binding_ref: archiveBindingRef({
          execution_ref: rawHash,
          doc_hash: j.archive.doc_hash,
          entry_id: j.archive.entry_id,
          seq: j.archive.seq,
        }),
      },
    };
    expect(() => verifyJourney(tampered)).toThrow(
      /execution_ref does not match the chain's execution link/,
    );
  });

  it('composeJourney raises the Python-identical error for a missing execution link', () => {
    const chain = composeChain(j.chain_links, { description: 'golden journey @ref execution chain' });
    expect(() =>
      composeJourney(chain, { execution: 'nonexistent', archive: j.archive, description: DESC }),
    ).toThrow(/journey needs an execution link named 'nonexistent'/);
  });

  it('verifyJourney raises the Python-identical error when the execution link is absent', () => {
    // verifyJourney anchors to envelope['execution']; point it at a name the
    // chain does not contain and the guard must raise (Python-identical message).
    const chain = composeChain(j.chain_links, { description: 'golden journey @ref execution chain' });
    const env = composeJourney(chain, { archive: j.archive, description: DESC });
    const tampered = { ...env, execution: 'nonexistent' };
    expect(() => verifyJourney(tampered)).toThrow(
      /journey needs an execution link named 'nonexistent'/,
    );
  });
});
