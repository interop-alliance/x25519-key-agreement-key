/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
import { describe, it, expect } from 'vitest'

import { X25519KeyAgreementKey2019 } from '@digitalbazaar/x25519-key-agreement-key-2019'
import { Ed25519VerificationKey2020 } from '@digitalcredentials/ed25519-verification-key-2020'
import { X25519KeyAgreementKey2020 } from '../../src/index.js'
import { base58btc } from '../../src/baseX.js'

const mockKey = {
  publicKeyMultibase: 'z6LSeRSE5Em5oJpwdk3NBaLVERBS332ULC7EQq5EtMsmXhsM',
  privateKeyMultibase: 'z3weeMD56C1T347EmB6kYNS7trpQwjvtQCpCYRpqGz6mcemT'
}

describe('X25519KeyAgreementKey2020', () => {
  describe('class vars', () => {
    it('should expose suite and context for crypto-ld usage', async () => {
      expect(X25519KeyAgreementKey2020.suite).toBe('X25519KeyAgreementKey2020')
      expect(X25519KeyAgreementKey2020.SUITE_CONTEXT).toBe(
        'https://w3id.org/security/suites/x25519-2020/v1'
      )
    })
  })

  describe('constructor', () => {
    it('should auto-set key.id based on controller, if present', async () => {
      const { publicKeyMultibase } = mockKey
      const controller = 'did:example:1234'

      const keyPair = new X25519KeyAgreementKey2020({
        controller,
        publicKeyMultibase
      })
      expect(keyPair.id).toBe('did:example:1234#' + keyPair.fingerprint())
    })

    it('should error if publicKeyMultibase property is missing', async () => {
      let error: any
      try {
        // @ts-expect-error - intentionally constructing without required args
        new X25519KeyAgreementKey2020()
      } catch (e) {
        error = e
      }
      expect(error.message).toBe(
        'The "publicKeyMultibase" property is required.'
      )
    })
  })

  describe('fromEd25519VerificationKey2020', () => {
    it('should convert both public and private key (2020)', async () => {
      const edKeyPair = await Ed25519VerificationKey2020.from({
        controller: 'did:example:123',
        publicKeyMultibase: 'z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX',
        privateKeyMultibase:
          'zruzf4Y29hDp7vLoV3NWzuymGMTtJcQfttAWzESod4wV2fb' +
          'PvEp4XtzGp2VWwQSQAXMxDyqrnVurYg2sBiqiu1FHDDM'
      })

      const xKeyPair = X25519KeyAgreementKey2020.fromEd25519VerificationKey2020(
        {
          keyPair: edKeyPair
        }
      )

      expect(xKeyPair.type).toBe('X25519KeyAgreementKey2020')
      expect(xKeyPair.controller).toBe('did:example:123')
      expect(xKeyPair.publicKeyMultibase).toBe(
        'z6LSdVzMmB67tKXYmkjiKRAQgbxgjnjdfiajqUvx7C9fxTNv'
      )
      expect(xKeyPair.privateKeyMultibase).toBe(
        'z3wecm2zNYbRorUz8ZfuV1tGbKr41xS2GzZM2jFfvyXytE9K'
      )

      // Check to make sure export works after conversion
      const exported = await xKeyPair.export({ publicKey: true })

      expect(exported).toHaveProperty('publicKeyMultibase')
      expect(exported).not.toHaveProperty('privateKeyMultibase')
    })
  })

  describe('deriveSecret', () => {
    it('should produce a secret from a remote key', async () => {
      const localKey = await X25519KeyAgreementKey2020.from({
        publicKeyMultibase: 'z6LSdVzMmB67tKXYmkjiKRAQgbxgjnjdfiajqUvx7C9fxTNv',
        privateKeyMultibase: 'z3wecm2zNYbRorUz8ZfuV1tGbKr41xS2GzZM2jFfvyXytE9K'
      })

      const edKeyPair = await Ed25519VerificationKey2020.from({
        controller: 'did:example:123',
        publicKeyMultibase: 'z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T',
        privateKeyMultibase:
          'zrv2EET2WWZ8T1Jbg4fEH5cQxhbUS22XxdweypUbjWVzv1Y' +
          'D6VqYuW6LH7heQCNYQCuoKaDwvv2qCWz3uBzG2xesqmf'
      })
      const remoteKey =
        X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({
          keyPair: edKeyPair
        })

      const secret = await localKey.deriveSecret({ publicKey: remoteKey })
      const secretString = base58btc.encode(secret)

      expect(secretString).toBe('4jK2aXkz6pspNahm7yvMS9Z8S1ghtDm22Q1HjE3p1cNJ')
    })
  })

  describe(`export`, () => {
    it('should export only the public key', async () => {
      const key = await X25519KeyAgreementKey2020.generate({
        controller: 'did:ex:1234'
      })

      const exported = await key.export({ publicKey: true })
      expect(exported).toHaveProperty('publicKeyMultibase')
      expect(exported).not.toHaveProperty('privateKeyMultibase')
    })

    it('should export only the private key', async () => {
      const key = await X25519KeyAgreementKey2020.generate()

      const exported = await key.export({ privateKey: true })
      expect(exported).not.toHaveProperty('publicKeyMultibase')
      expect(exported).toHaveProperty('privateKeyMultibase')
    })

    it('should include the JSON-LD context when requested', async () => {
      const key = await X25519KeyAgreementKey2020.generate()

      const exported = await key.export({
        publicKey: true,
        includeContext: true
      })
      expect(exported['@context']).toBe(X25519KeyAgreementKey2020.SUITE_CONTEXT)
    })

    it('should export both public and private key', async () => {
      const key = await X25519KeyAgreementKey2020.generate({
        controller: 'did:example:1234'
      })
      const pastDate = new Date(2020, 11, 17)
        .toISOString()
        .replace(/\.[0-9]{3}/, '')
      key.revoked = pastDate

      const exported = await key.export({ publicKey: true, privateKey: true })
      expect(Object.keys(exported).sort()).toEqual(
        [
          'id',
          'type',
          'controller',
          'publicKeyMultibase',
          'privateKeyMultibase',
          'revoked'
        ].sort()
      )
      expect(exported.controller).toBe('did:example:1234')
      expect(exported.type).toBe('X25519KeyAgreementKey2020')
      expect(exported).toHaveProperty('revoked', pastDate)
    })
  })

  describe('fingerprint', () => {
    it('should round trip convert to and from public key', async () => {
      const key = await X25519KeyAgreementKey2020.generate()
      const fingerprint = key.fingerprint()
      const newKey = X25519KeyAgreementKey2020.fromFingerprint({ fingerprint })

      expect(key.publicKeyMultibase).toBe(newKey.publicKeyMultibase)
    })

    it('should leave id/controller unset by default', async () => {
      const key = await X25519KeyAgreementKey2020.generate()
      const newKey = X25519KeyAgreementKey2020.fromFingerprint({
        fingerprint: key.fingerprint()
      })

      expect(newKey.controller).toBeUndefined()
      expect(newKey.id).toBeUndefined()
    })

    it('should set a did:key identity when didKey is true', async () => {
      const key = await X25519KeyAgreementKey2020.generate()
      const fingerprint = key.fingerprint()
      const newKey = X25519KeyAgreementKey2020.fromFingerprint({
        fingerprint,
        didKey: true
      })

      expect(newKey.controller).toBe(`did:key:${fingerprint}`)
      expect(newKey.id).toBe(`did:key:${fingerprint}#${fingerprint}`)
    })

    it('should verify via verifyFingerprint()', async () => {
      const key = await X25519KeyAgreementKey2020.generate()
      const fingerprint = key.fingerprint()

      const result = key.verifyFingerprint({ fingerprint })
      expect(result.verified).toBe(true)
      expect(result.error).toBeUndefined()
    })
  })

  describe('from', () => {
    it('should default a did:key controller/id when didKey is true', async () => {
      const { publicKeyMultibase, privateKeyMultibase } = mockKey
      const key = await X25519KeyAgreementKey2020.from({
        publicKeyMultibase,
        privateKeyMultibase,
        didKey: true
      })

      expect(key.controller).toBe(`did:key:${publicKeyMultibase}`)
      expect(key.id).toBe(`did:key:${publicKeyMultibase}#${publicKeyMultibase}`)
    })

    it('should not override an explicit controller when didKey is true', async () => {
      const { publicKeyMultibase } = mockKey
      const key = await X25519KeyAgreementKey2020.from({
        controller: 'did:example:1234',
        publicKeyMultibase,
        didKey: true
      })

      expect(key.controller).toBe('did:example:1234')
      expect(key.id).toBe(`did:example:1234#${publicKeyMultibase}`)
    })

    it('should leave id/controller unset when didKey is omitted', async () => {
      const { publicKeyMultibase } = mockKey
      const key = await X25519KeyAgreementKey2020.from({ publicKeyMultibase })

      expect(key.controller).toBeUndefined()
      expect(key.id).toBeUndefined()
    })
  })

  describe('Multikey', () => {
    const MULTIKEY_CONTEXT = 'https://w3id.org/security/multikey/v1'

    it('toMultikey() emits a public Multikey by default', async () => {
      const key = new X25519KeyAgreementKey2020({
        controller: 'did:example:1234',
        ...mockKey
      })
      const multikey = key.toMultikey()

      expect(multikey.type).toBe('Multikey')
      expect(multikey['@context']).toBe(MULTIKEY_CONTEXT)
      expect(multikey.controller).toBe('did:example:1234')
      expect(multikey.id).toBe(`did:example:1234#${mockKey.publicKeyMultibase}`)
      expect(multikey.publicKeyMultibase).toBe(mockKey.publicKeyMultibase)
      expect(multikey).not.toHaveProperty('secretKeyMultibase')
    })

    it('toMultikey() emits secretKeyMultibase when requested', async () => {
      const key = new X25519KeyAgreementKey2020({ ...mockKey })
      const multikey = key.toMultikey({ secretKey: true })

      // X25519 secret carries the same header in both serializations.
      expect(multikey.secretKeyMultibase).toBe(mockKey.privateKeyMultibase)
    })

    it('toMultikey() omits the context when includeContext is false', async () => {
      const key = new X25519KeyAgreementKey2020({ ...mockKey })
      const multikey = key.toMultikey({ includeContext: false })

      expect(multikey).not.toHaveProperty('@context')
    })

    it('fromMultikey() round-trips public and secret key material', async () => {
      const original = new X25519KeyAgreementKey2020({
        controller: 'did:example:1234',
        ...mockKey
      })
      const imported = X25519KeyAgreementKey2020.fromMultikey(
        original.toMultikey({ secretKey: true })
      )

      expect(imported.type).toBe('X25519KeyAgreementKey2020')
      expect(imported.id).toBe(`did:example:1234#${mockKey.publicKeyMultibase}`)
      expect(imported.controller).toBe('did:example:1234')
      expect(imported.publicKeyMultibase).toBe(mockKey.publicKeyMultibase)
      expect(imported.privateKeyMultibase).toBe(mockKey.privateKeyMultibase)
    })

    it('from() dispatches a Multikey-typed document to fromMultikey()', async () => {
      const key = await X25519KeyAgreementKey2020.from({
        type: 'Multikey',
        controller: 'did:example:1234',
        publicKeyMultibase: mockKey.publicKeyMultibase
      })

      expect(key.type).toBe('X25519KeyAgreementKey2020')
      expect(key.publicKeyMultibase).toBe(mockKey.publicKeyMultibase)
    })

    it('round-trips through Multikey and still derives the shared secret', async () => {
      const alice = await X25519KeyAgreementKey2020.generate()
      const bob = await X25519KeyAgreementKey2020.generate()
      const aliceReimported = X25519KeyAgreementKey2020.fromMultikey(
        alice.toMultikey({ secretKey: true })
      )

      const secret = await alice.deriveSecret({ publicKey: bob })
      const reimportedSecret = await aliceReimported.deriveSecret({
        publicKey: bob
      })
      expect(reimportedSecret).toEqual(secret)
    })

    it('fromMultikey() rejects an invalid public key header', async () => {
      let error: any
      try {
        X25519KeyAgreementKey2020.fromMultikey({
          type: 'Multikey',
          publicKeyMultibase: 'zNotAnX25519Key'
        })
      } catch (e) {
        error = e
      }
      expect(error.message).toContain('invalid header bytes')
    })
  })

  describe('Backwards compat with X25519KeyAgreementKey2019', () => {
    it('2020 key should import from 2019', async () => {
      const keyPair2019 = await X25519KeyAgreementKey2019.generate({
        controller: 'did:example:1234'
      })

      const keyPair2020 =
        await X25519KeyAgreementKey2020.fromX25519KeyAgreementKey2019(
          keyPair2019
        )

      // Both should have the same fingerprint
      expect(keyPair2019.fingerprint()).toBe(keyPair2020.fingerprint())
    })
  })
})
