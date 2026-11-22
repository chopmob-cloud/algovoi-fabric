// SPDX-License-Identifier: Apache-2.0
/** Protocol-spine Python==Node parity: matrix, faces, composed chains, gate errors. */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  supportedMatrix, protocolFace, composeProtocolChain, checkVersion, ProtocolError,
} from '../src/protocols.js';
import { verify } from '../src/compose.js';

const here = dirname(fileURLToPath(import.meta.url));
const golden = JSON.parse(readFileSync(join(here, '..', 'fixtures', 'golden.json'), 'utf-8'));

describe('protocol parity (golden)', () => {
  it('supported matrix matches Python', () => {
    expect(supportedMatrix()).toEqual(golden.supported_matrix);
  });

  for (const c of golden.protocol_cases) {
    it(`${c.id}: face matches Python`, () => {
      expect(protocolFace(c.protocol, c.version, c.message)).toEqual(c.face);
    });
    it(`${c.id}: composed chain matches Python and verifies`, () => {
      const composed = composeProtocolChain(c.protocol, c.version, c.message, {
        execution: { action_type: 'execute', amount_minor: 500 },
      });
      expect(composed).toEqual(c.chain);
      expect(verify(c.chain).ok).toBe(c.verify_ok);
    });
  }

  for (const e of golden.protocol_errors) {
    it(`gate refuses ${e.protocol} v${e.version} with the Python error text`, () => {
      expect(() => checkVersion(e.protocol, e.version)).toThrow(ProtocolError);
      expect(() => checkVersion(e.protocol, e.version)).toThrow(e.error);
    });
  }
});