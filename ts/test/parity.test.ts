// SPDX-License-Identifier: Apache-2.0
/**
 * Golden Python==Node parity gate (the linchpin).
 *
 * Every canonical byte string and every ref here was produced by the REAL
 * Python keystone verifier (ts/scripts/gen_fixtures.py). The TypeScript port
 * must reproduce them byte-for-byte. If substrate's JCS diverges from Python
 * rfc8785 on any vector, this fails — and that divergence is the whole risk of
 * a TypeScript Fabric, so it is the first thing proven.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { canonicalize, ref, resolve, KeystoneError } from '../src/keystone/verify.js';

const here = dirname(fileURLToPath(import.meta.url));
const golden = JSON.parse(readFileSync(join(here, '..', 'fixtures', 'golden.json'), 'utf-8'));

function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

describe('JCS linchpin: TS substrate == Python rfc8785 (golden)', () => {
  for (const v of golden.jcs_vectors) {
    it(`${v.id}: canonical bytes match`, () => {
      expect(toHex(canonicalize(v.preimage))).toBe(v.jcs_hex);
    });
    it(`${v.id}: ref matches`, () => {
      expect(ref(v.preimage)).toBe(v.ref);
    });
  }
});

describe('resolve: marker substitution + escape + fail-closed (golden)', () => {
  for (const c of golden.resolve) {
    if (c.error === null || c.error === undefined) {
      if (c.resolved !== undefined) {
        it(`${c.id}: resolves identically`, () => {
          expect(resolve(c.value, c.refs, 'self')).toEqual(c.resolved);
        });
      }
    } else {
      it(`${c.id}: refuses with identical error text`, () => {
        expect(() => resolve(c.value, c.refs, c.link_name)).toThrow(KeystoneError);
        expect(() => resolve(c.value, c.refs, c.link_name)).toThrow(c.error);
      });
    }
  }
});