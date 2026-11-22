// SPDX-License-Identifier: Apache-2.0
/**
 * Chain-level Python==Node parity: the TypeScript composer must reproduce the
 * Python compose_chain output, and the TypeScript verifier must reach the same
 * verdict and the same recomputed refs on the golden chains.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { composeChain, verify } from '../src/compose.js';
import { verifyChain } from '../src/keystone/verify.js';

const here = dirname(fileURLToPath(import.meta.url));
const golden = JSON.parse(readFileSync(join(here, '..', 'fixtures', 'golden.json'), 'utf-8'));

describe('chain parity (golden)', () => {
  for (const c of golden.chains) {
    it(`${c.id}: verifier reaches the Python verdict`, () => {
      expect(verify(c.chain).ok).toBe(c.verify_ok);
    });
    it(`${c.id}: every declared ref recomputes identically`, () => {
      const res = verifyChain(c.chain);
      for (const link of res.links) {
        const declared = c.chain.chain.find((l: { name: string }) => l.name === link.name);
        expect(link.computed).toBe(declared.ref);
      }
      if (c.refs) {
        for (const [name, r] of Object.entries(c.refs)) {
          expect(res.links.find((l) => l.name === name)?.computed).toBe(r);
        }
      }
    });
  }

  it('chain_basic: TS composeChain reproduces the Python chain structure', () => {
    const c = golden.chains.find((x: { id: string }) => x.id === 'chain_basic');
    const composed = composeChain(c.links, { description: c.chain.description });
    expect(composed).toEqual(c.chain);
  });
});