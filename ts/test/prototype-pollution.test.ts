// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Christopher Hopley / AlgoVoi (chopmob-cloud)
/**
 * Regression: prototype-chain membership must be fail-closed.
 *
 * The independent Claude gate review (2026-11-22) executed a BLOCKER on the
 * pre-fix bytes: `key in obj` on the plain-object refs/preimages maps walks the
 * prototype chain, so an unknown `@__proto__` reference silently resolved to
 * Object.prototype and verifyChain returned ok=true; checkVersion('constructor')
 * threw TypeError instead of ProtocolError; and a first link named 'constructor'
 * was falsely rejected as a duplicate. These tests fail on the pre-fix code and
 * pass once membership uses own-property checks (hasOwn) over null-proto maps.
 */
import { describe, it, expect } from 'vitest';
import {
  resolve,
  verifyChain,
  composeChain,
  checkVersion,
  KeystoneError,
  ProtocolError,
} from '../src/index.js';

describe('prototype-chain membership is fail-closed', () => {
  it.each(['__proto__', 'constructor', 'toString', 'hasOwnProperty'])(
    'resolve @%s fails closed with KeystoneError',
    (name) => {
      expect(() => resolve({ x: '@' + name }, {}, 'L')).toThrow(KeystoneError);
    },
  );

  it('verifyChain fails closed on an unknown @__proto__ ref (throws, not ok=true)', () => {
    expect(() =>
      verifyChain({ chain: [{ name: 'a', preimage: { x: '@__proto__' } }] }),
    ).toThrow(KeystoneError);
  });

  it.each(['constructor', 'toString', '__proto__', 'hasOwnProperty'])(
    'checkVersion(%s) raises ProtocolError, not TypeError',
    (p) => {
      expect(() => checkVersion(p, '1')).toThrow(ProtocolError);
    },
  );

  it('a first link named constructor is not a false duplicate', () => {
    const chain = composeChain([['constructor', { a: 1 }]]);
    expect(verifyChain(chain).ok).toBe(true);
  });

  it('a link named __proto__ stores and binds (Python dict parity)', () => {
    const chain = composeChain([
      ['__proto__', { a: 1 }],
      ['exec', { binds: ['@__proto__'] }],
    ]);
    expect(verifyChain(chain).ok).toBe(true);
  });

  it('journey hop __proto__ (not a real link) fails the assertion', () => {
    const r = verifyChain({
      chain: [
        { name: 'a', preimage: { z: 1 } },
        { name: 'r', preimage: { binds: ['@a'] } },
      ],
      assertions: [{ kind: 'journey', ref: 'r', hops: ['__proto__'] }],
    });
    expect(r.ok).toBe(false);
    expect(r.failed_assertion?.kind).toBe('journey');
  });

  it('field_equals on a non-existent constructor link fails closed', () => {
    expect(() =>
      verifyChain({
        chain: [{ name: 'a', preimage: { z: 1 } }],
        assertions: [{ kind: 'field_equals', a: 'constructor.prototype', b: 'a.z' }],
      }),
    ).toThrow(KeystoneError);
  });

  it('scope_subset on a non-existent constructor link fails closed', () => {
    expect(() =>
      verifyChain({
        chain: [{ name: 'a', preimage: { z: 1 } }],
        assertions: [{ kind: 'scope_subset', outer: 'constructor', inner: 'a' }],
      }),
    ).toThrow(KeystoneError);
  });
});