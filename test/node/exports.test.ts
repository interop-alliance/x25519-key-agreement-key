/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
import { describe, it, expect } from 'vitest'

import {
  X25519KeyAgreementKey2020,
  multibaseEncode,
  multibaseDecode,
  MULTICODEC_X25519_PUB_HEADER,
  MULTICODEC_X25519_PRIV_HEADER
} from '../../src/index.js'

describe('multibase framing helpers', () => {
  it('should expose the X25519 multicodec headers', () => {
    expect(Array.from(MULTICODEC_X25519_PUB_HEADER)).toEqual([0xec, 0x01])
    expect(Array.from(MULTICODEC_X25519_PRIV_HEADER)).toEqual([0x82, 0x26])
  })

  it('should round-trip bytes with the public key header', () => {
    const bytes = new Uint8Array(32).fill(7)
    const encoded = multibaseEncode(MULTICODEC_X25519_PUB_HEADER, bytes)
    expect(encoded[0]).toBe('z')
    const decoded = multibaseDecode(MULTICODEC_X25519_PUB_HEADER, encoded)
    expect(Array.from(decoded)).toEqual(Array.from(bytes))
  })

  it('should round-trip bytes with the private key header', () => {
    const bytes = new Uint8Array(32).fill(9)
    const encoded = multibaseEncode(MULTICODEC_X25519_PRIV_HEADER, bytes)
    const decoded = multibaseDecode(MULTICODEC_X25519_PRIV_HEADER, encoded)
    expect(Array.from(decoded)).toEqual(Array.from(bytes))
  })

  it('should throw when decoding with the wrong header', () => {
    const bytes = new Uint8Array(32).fill(1)
    const encoded = multibaseEncode(MULTICODEC_X25519_PUB_HEADER, bytes)
    expect(() =>
      multibaseDecode(MULTICODEC_X25519_PRIV_HEADER, encoded)
    ).toThrow('Multibase value does not have expected header.')
  })
})

describe('X25519KeyAgreementKey2020 raw-secret API', () => {
  it('should construct from a raw secret and round-trip via rawSecret', () => {
    const secret = new Uint8Array(32).fill(3)
    const keyPair = X25519KeyAgreementKey2020.fromRawSecret({ secret })

    expect(keyPair.privateKeyMultibase).toBeDefined()
    expect(keyPair.publicKeyMultibase[0]).toBe('z')
    expect(Array.from(keyPair.rawSecret)).toEqual(Array.from(secret))
  })

  it('should derive a public key matching generate()/fromRawSecret', async () => {
    const generated = await X25519KeyAgreementKey2020.generate()
    const rebuilt = X25519KeyAgreementKey2020.fromRawSecret({
      secret: generated.rawSecret
    })
    expect(rebuilt.publicKeyMultibase).toBe(generated.publicKeyMultibase)
    expect(rebuilt.privateKeyMultibase).toBe(generated.privateKeyMultibase)
  })

  it('should accept a controller and derive an id', () => {
    const secret = new Uint8Array(32).fill(5)
    const keyPair = X25519KeyAgreementKey2020.fromRawSecret({
      secret,
      controller: 'did:example:1234'
    })
    expect(keyPair.id).toBe('did:example:1234#' + keyPair.publicKeyMultibase)
  })

  it('should give a did:key identity when didKey is true', () => {
    const secret = new Uint8Array(32).fill(6)
    const keyPair = X25519KeyAgreementKey2020.fromRawSecret({
      secret,
      didKey: true
    })
    expect(keyPair.controller).toBe(`did:key:${keyPair.publicKeyMultibase}`)
  })

  it('should throw on a wrong-length secret', () => {
    expect(() =>
      X25519KeyAgreementKey2020.fromRawSecret({
        secret: new Uint8Array(31)
      })
    ).toThrow('"secret" must be a 32-byte Uint8Array.')
  })

  it('should throw reading rawSecret on a public-key-only instance', () => {
    const secret = new Uint8Array(32).fill(4)
    const publicOnly = X25519KeyAgreementKey2020.fromFingerprint({
      fingerprint: X25519KeyAgreementKey2020.fromRawSecret({ secret })
        .publicKeyMultibase
    })
    expect(() => publicOnly.rawSecret).toThrow(
      'This key pair has no private key material.'
    )
  })

  it('should expose public fromFingerprint / verifyFingerprint', () => {
    const secret = new Uint8Array(32).fill(2)
    const { publicKeyMultibase } = X25519KeyAgreementKey2020.fromRawSecret({
      secret
    })
    const key = X25519KeyAgreementKey2020.fromFingerprint({
      fingerprint: publicKeyMultibase
    })
    expect(key.verifyFingerprint({ fingerprint: publicKeyMultibase })).toEqual({
      verified: true
    })
  })
})
