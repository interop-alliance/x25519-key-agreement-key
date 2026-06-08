/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
import { describe, it, expect } from 'vitest'

import { X25519KeyAgreementKey2020 } from '../../src/index.js'
import { base58btc } from '../../src/baseX.js'

// A valid X25519 (2020) public/private key pair, for use as fixtures.
const validKey = {
  publicKeyMultibase: 'z6LSeRSE5Em5oJpwdk3NBaLVERBS332ULC7EQq5EtMsmXhsM',
  privateKeyMultibase: 'z3weeMD56C1T347EmB6kYNS7trpQwjvtQCpCYRpqGz6mcemT'
}

// An Ed25519 verification key (2020), whose multicodec headers differ from the
// X25519 headers the constructor expects.
const edPublicKeyMultibase = 'z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T'
const edPrivateKeyMultibase =
  'zrv2EET2WWZ8T1Jbg4fEH5cQxhbUS22XxdweypUbjWVzv1Y' +
  'D6VqYuW6LH7heQCNYQCuoKaDwvv2qCWz3uBzG2xesqmf'

// multicodec ed25519-pub header as varint
const MULTICODEC_ED25519_PUB_HEADER = new Uint8Array([0xed, 0x01])

function multibaseEncode(header: Uint8Array, bytes: Uint8Array): string {
  const mcBytes = new Uint8Array(header.length + bytes.length)
  mcBytes.set(header)
  mcBytes.set(bytes, header.length)
  return 'z' + base58btc.encode(mcBytes)
}

describe('X25519KeyAgreementKey2020 error paths', () => {
  describe('constructor', () => {
    it('throws on invalid public key header bytes', () => {
      // An Ed25519 public key has the wrong multicodec header for X25519.
      expect(
        () =>
          new X25519KeyAgreementKey2020({
            publicKeyMultibase: edPublicKeyMultibase
          })
      ).toThrow(/has invalid header bytes/)
    })

    it('throws on invalid private key header bytes', () => {
      expect(
        () =>
          new X25519KeyAgreementKey2020({
            publicKeyMultibase: validKey.publicKeyMultibase,
            privateKeyMultibase: edPrivateKeyMultibase
          })
      ).toThrow('"privateKeyMultibase" has invalid header bytes.')
    })
  })

  describe('from', () => {
    it('dispatches to the 2019 importer when publicKeyBase58 is present', async () => {
      // A raw 32-byte X25519 public key, base58btc encoded (no multicodec
      // header), as produced by X25519KeyAgreementKey2019.
      const rawPublicKey = new Uint8Array(32).fill(7)
      const key = await X25519KeyAgreementKey2020.from({
        publicKeyBase58: base58btc.encode(rawPublicKey)
      })

      expect(key.type).toBe('X25519KeyAgreementKey2020')
      // Re-encoded with the X25519 multibase/multicodec header.
      expect(key.publicKeyMultibase.startsWith('z6LS')).toBe(true)
    })
  })

  describe('fromEd25519VerificationKey2020', () => {
    it('throws if source public key is missing', () => {
      expect(() =>
        X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({
          keyPair: {}
        })
      ).toThrow('Source public key is required to convert.')
    })

    it('throws if public key is not multibase base58btc encoded', () => {
      expect(() =>
        X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({
          keyPair: { publicKeyMultibase: 'not-base58btc' }
        })
      ).toThrow(/must start with "z"/)
    })

    it('throws if private key is not multibase base58btc encoded', () => {
      expect(() =>
        X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({
          keyPair: {
            publicKeyMultibase: edPublicKeyMultibase,
            privateKeyMultibase: 'not-base58btc'
          }
        })
      ).toThrow(/must start with "z"/)
    })

    it('converts a public-key-only source key', () => {
      const xKey = X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({
        keyPair: { publicKeyMultibase: edPublicKeyMultibase }
      })

      expect(xKey.publicKeyMultibase).toBe(
        'z6LSotGbgPCJD2Y6TSvvgxERLTfVZxCh9KSrez3WNrNp7vKW'
      )
      expect(xKey.privateKeyMultibase).toBeUndefined()
    })
  })

  describe('convertFromEdPublicKey', () => {
    it('throws if source public key is missing', () => {
      expect(() =>
        X25519KeyAgreementKey2020.convertFromEdPublicKey({})
      ).toThrow('Source public key is required to convert.')
    })

    it('throws on an invalid Ed25519 public key', () => {
      // Correct ed25519-pub header, but the 32 key bytes are not a valid point.
      const invalid = multibaseEncode(
        MULTICODEC_ED25519_PUB_HEADER,
        new Uint8Array(32).fill(2)
      )
      expect(() =>
        X25519KeyAgreementKey2020.convertFromEdPublicKey({
          publicKeyMultibase: invalid
        })
      ).toThrow('Error converting to X25519; Invalid Ed25519 public key.')
    })
  })

  describe('convertFromEdPrivateKey', () => {
    it('throws if source private key is missing', () => {
      expect(() =>
        X25519KeyAgreementKey2020.convertFromEdPrivateKey({})
      ).toThrow('Source private key is required to convert.')
    })
  })

  describe('fingerprintFromPublicKey', () => {
    it('returns the public key multibase as the fingerprint', () => {
      expect(
        X25519KeyAgreementKey2020.fingerprintFromPublicKey({
          publicKeyMultibase: validKey.publicKeyMultibase
        })
      ).toBe(validKey.publicKeyMultibase)
    })

    it('throws if source public key is missing', () => {
      expect(() =>
        X25519KeyAgreementKey2020.fingerprintFromPublicKey({})
      ).toThrow('Source public key is required.')
    })
  })

  describe('fromFingerprint', () => {
    it('builds a public-only key from a fingerprint', () => {
      const key = X25519KeyAgreementKey2020.fromFingerprint({
        fingerprint: validKey.publicKeyMultibase
      })
      expect(key.publicKeyMultibase).toBe(validKey.publicKeyMultibase)
      expect(key.privateKeyMultibase).toBeUndefined()
    })
  })

  describe('verifyFingerprint', () => {
    it('throws on a fingerprint with invalid header bytes', () => {
      const key = X25519KeyAgreementKey2020.fromFingerprint({
        fingerprint: validKey.publicKeyMultibase
      })
      expect(() =>
        key.verifyFingerprint({ fingerprint: edPublicKeyMultibase })
      ).toThrow(/has invalid header bytes/)
    })
  })

  describe('deriveSecret', () => {
    it('throws when the remote public key has the wrong header', async () => {
      const key = await X25519KeyAgreementKey2020.from(validKey)
      await expect(
        key.deriveSecret({
          publicKey: { publicKeyMultibase: edPublicKeyMultibase }
        })
      ).rejects.toThrow('Multibase value does not have expected header.')
    })
  })

  describe('export', () => {
    it('throws when neither publicKey nor privateKey is requested', async () => {
      const key = await X25519KeyAgreementKey2020.from(validKey)
      expect(() => key.export()).toThrow(
        'Export requires specifying either "publicKey" or "privateKey".'
      )
    })
  })

  describe('signer / verifier', () => {
    it('signer() throws (key agreement keys cannot sign)', async () => {
      const key = await X25519KeyAgreementKey2020.from(validKey)
      expect(() => key.signer()).toThrow('cannot sign')
    })

    it('verifier() throws (key agreement keys cannot verify)', async () => {
      const key = await X25519KeyAgreementKey2020.from(validKey)
      expect(() => key.verifier()).toThrow('cannot verify')
    })
  })
})
