/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
import { describe, it, expect } from 'vitest'

import { X25519KeyAgreementKey2020 } from '../../src/index.js'
import { base58btc } from '../../src/baseX.js'
import * as nobleBackend from '../../src/crypto-react-native.js'

// multicodec x25519-pub header as varint
const MULTICODEC_X25519_PUB_HEADER = new Uint8Array([0xec, 0x01])
// multicodec x25519-priv header as varint
const MULTICODEC_X25519_PRIV_HEADER = new Uint8Array([0x82, 0x26])

function fromHex(hex: string): Uint8Array {
  return Uint8Array.from(
    (hex.match(/../g) as string[]).map(byte => parseInt(byte, 16))
  )
}

function toHex(bytes: Uint8Array): string {
  return [...bytes].map(byte => byte.toString(16).padStart(2, '0')).join('')
}

function multibaseEncode(header: Uint8Array, bytes: Uint8Array): string {
  const mcBytes = new Uint8Array(header.length + bytes.length)
  mcBytes.set(header)
  mcBytes.set(bytes, header.length)
  return 'z' + base58btc.encode(mcBytes)
}

/**
 * RFC 7748 (Elliptic Curves for Security) X25519 test vectors.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7748#section-5.2 (scalar mult)
 * @see https://www.rfc-editor.org/rfc/rfc7748#section-6.1 (Diffie-Hellman)
 *
 * These pin the library's ECDH output to the canonical spec values, exercised
 * through both backends: the native Node `crypto.diffieHellman` path (default
 * in Node) and the `@noble/curves` fallback path (used in React Native / the
 * browser).
 */

// RFC 7748 Section 6.1
const ALICE_PRIVATE_HEX =
  '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'
const ALICE_PUBLIC_HEX =
  '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a'
const BOB_PRIVATE_HEX =
  '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb'
const BOB_PUBLIC_HEX =
  'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f'
const SHARED_SECRET_HEX =
  '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742'

// RFC 7748 Section 5.2 (X25519(scalar, u-coordinate) single computations)
const SCALAR_MULT_VECTORS = [
  {
    scalar: 'a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4',
    u: 'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c',
    output: 'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552'
  },
  {
    scalar: '4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d',
    u: 'e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493',
    output: '95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957'
  }
]

describe('RFC 7748 test vectors', () => {
  describe('Section 6.1 Diffie-Hellman (via public API, native backend)', () => {
    it('derives the spec shared secret (alice -> bob)', async () => {
      const alice = await X25519KeyAgreementKey2020.from({
        publicKeyMultibase: multibaseEncode(
          MULTICODEC_X25519_PUB_HEADER,
          fromHex(ALICE_PUBLIC_HEX)
        ),
        privateKeyMultibase: multibaseEncode(
          MULTICODEC_X25519_PRIV_HEADER,
          fromHex(ALICE_PRIVATE_HEX)
        )
      })
      const bob = await X25519KeyAgreementKey2020.from({
        publicKeyMultibase: multibaseEncode(
          MULTICODEC_X25519_PUB_HEADER,
          fromHex(BOB_PUBLIC_HEX)
        )
      })

      const secret = await alice.deriveSecret({ publicKey: bob })
      expect(toHex(secret)).toBe(SHARED_SECRET_HEX)
    })

    it('is symmetric (alice·bob === bob·alice)', async () => {
      const alice = await X25519KeyAgreementKey2020.from({
        publicKeyMultibase: multibaseEncode(
          MULTICODEC_X25519_PUB_HEADER,
          fromHex(ALICE_PUBLIC_HEX)
        ),
        privateKeyMultibase: multibaseEncode(
          MULTICODEC_X25519_PRIV_HEADER,
          fromHex(ALICE_PRIVATE_HEX)
        )
      })
      const bob = await X25519KeyAgreementKey2020.from({
        publicKeyMultibase: multibaseEncode(
          MULTICODEC_X25519_PUB_HEADER,
          fromHex(BOB_PUBLIC_HEX)
        ),
        privateKeyMultibase: multibaseEncode(
          MULTICODEC_X25519_PRIV_HEADER,
          fromHex(BOB_PRIVATE_HEX)
        )
      })

      const secretAB = await alice.deriveSecret({ publicKey: bob })
      const secretBA = await bob.deriveSecret({ publicKey: alice })
      expect(toHex(secretAB)).toBe(SHARED_SECRET_HEX)
      expect(toHex(secretBA)).toBe(SHARED_SECRET_HEX)
    })
  })

  describe('Section 6.1 Diffie-Hellman (noble fallback backend)', () => {
    it('derives the spec shared secret', async () => {
      const secret = await nobleBackend.deriveSecret({
        privateKey: fromHex(ALICE_PRIVATE_HEX),
        remotePublicKey: fromHex(BOB_PUBLIC_HEX)
      })
      expect(toHex(secret)).toBe(SHARED_SECRET_HEX)
    })

    it('generateKeyPair returns 32-byte keys that agree round trip', async () => {
      const aliceKeys = await nobleBackend.generateKeyPair()
      const bobKeys = await nobleBackend.generateKeyPair()

      expect(aliceKeys.publicKey).toHaveLength(32)
      expect(aliceKeys.privateKey).toHaveLength(32)

      const secretAB = await nobleBackend.deriveSecret({
        privateKey: aliceKeys.privateKey,
        remotePublicKey: bobKeys.publicKey
      })
      const secretBA = await nobleBackend.deriveSecret({
        privateKey: bobKeys.privateKey,
        remotePublicKey: aliceKeys.publicKey
      })
      expect(toHex(secretAB)).toBe(toHex(secretBA))
    })
  })

  describe('Section 5.2 scalar multiplication (noble fallback backend)', () => {
    for (const { scalar, u, output } of SCALAR_MULT_VECTORS) {
      it(`X25519(${scalar.slice(0, 8)}…, ${u.slice(0, 8)}…)`, async () => {
        const result = await nobleBackend.deriveSecret({
          privateKey: fromHex(scalar),
          remotePublicKey: fromHex(u)
        })
        expect(toHex(result)).toBe(output)
      })
    }
  })

  describe('cross-backend agreement', () => {
    it('native and noble backends derive the same secret', async () => {
      const alice = await X25519KeyAgreementKey2020.from({
        publicKeyMultibase: multibaseEncode(
          MULTICODEC_X25519_PUB_HEADER,
          fromHex(ALICE_PUBLIC_HEX)
        ),
        privateKeyMultibase: multibaseEncode(
          MULTICODEC_X25519_PRIV_HEADER,
          fromHex(ALICE_PRIVATE_HEX)
        )
      })
      const bob = await X25519KeyAgreementKey2020.from({
        publicKeyMultibase: multibaseEncode(
          MULTICODEC_X25519_PUB_HEADER,
          fromHex(BOB_PUBLIC_HEX)
        )
      })

      const nativeSecret = await alice.deriveSecret({ publicKey: bob })
      const nobleSecret = await nobleBackend.deriveSecret({
        privateKey: fromHex(ALICE_PRIVATE_HEX),
        remotePublicKey: fromHex(BOB_PUBLIC_HEX)
      })
      expect(toHex(nativeSecret)).toBe(toHex(nobleSecret))
    })
  })
})
