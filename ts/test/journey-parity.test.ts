// SPDX-License-Identifier: Apache-2.0
/**
 * Journey Python==Node parity: the AV-RAILS -> AV-PEF -> AV-VCS envelope, the
 * archive binding ref, and the offline verdict must match the real Python.
 * Also proves the @algovoi/pef npm twin accepts the Python-built frame.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { verifyPef } from '@algovoi/pef';
import { composeChain, FabricError } from '../src/compose.js';
import { archiveBindingRef, composeJourney, verifyJourney } from '../src/journey.js';

const here = dirname(fileURLToPath(import.meta.url));
const golden = JSON.parse(readFileSync(join(here, '..', 'fixtures', 'golden.json'), 'utf-8'));
const j = golden.journey;

describe('journey parity (golden)', () => {
  it('npm PEF twin accepts the Python-built frame', () => {
    expect(verifyPef(j.pef_frame).valid).toBe(true);
  });

  it('archive binding_ref recomputes identically', () => {
    const r = archiveBindingRef({
      execution_ref: j.execution_ref,
      doc_hash: j.archive.doc_hash,
      entry_id: j.archive.entry_id,
      seq: j.archive.seq,
    });
    expect(r).toBe(j.binding_ref);
  });

  it('composeJourney reproduces the Python envelope', () => {
    const chain = composeChain(j.chain_links, { description: 'golden journey chain' });
    const env = composeJourney(chain, {
      pef_frame: j.pef_frame,
      archive: j.archive,
      description: 'golden journey',
    });
    expect(env).toEqual(j.envelope);
  });

  it('verifyJourney reaches the Python verdict', () => {
    expect(verifyJourney(j.envelope)).toEqual(j.verify);
    expect(verifyJourney(j.envelope).levels).toEqual(['av-rails', 'av-pef', 'av-vcs']);
  });

  it('a tampered archive binding_ref fails closed', () => {
    const bad = structuredClone(j.envelope);
    bad.archive.binding_ref = 'sha256:' + '00'.repeat(32);
    expect(() => verifyJourney(bad)).toThrow(FabricError);
    expect(() => verifyJourney(bad)).toThrow('AV-VCS archive binding_ref does not recompute');
  });

  it('an unbound PEF frame is refused at compose time', () => {
    const chain = composeChain(j.chain_links, { description: 'golden journey chain' });
    const wrongFrame = structuredClone(j.pef_frame);
    wrongFrame.frame_id = 'sha256:' + '11'.repeat(32);
    expect(() => composeJourney(chain, { pef_frame: wrongFrame, archive: j.archive }))
      .toThrow('execution link does not bind the supplied PEF frame_id');
  });
});