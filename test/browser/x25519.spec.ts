import { test, expect } from '@playwright/test'

/**
 * Isomorphic smoke test: proves the library loads in a real browser (using the
 * tweetnacl-backed `crypto-browser` path, since Node's `crypto` is unavailable)
 * and that a core key-agreement round trip works end to end.
 */
test('X25519KeyAgreementKey2020 derives an agreeing secret in-browser', async ({
  page
}) => {
  await page.goto('/test/index.html')

  const result = await page.evaluate(async () => {
    const { X25519KeyAgreementKey2020 } = await import('/src/index.ts')

    const alice = await X25519KeyAgreementKey2020.generate({
      controller: 'did:example:alice'
    })
    const bob = await X25519KeyAgreementKey2020.generate({
      controller: 'did:example:bob'
    })

    const secretA = await alice.deriveSecret({ publicKey: bob })
    const secretB = await bob.deriveSecret({ publicKey: alice })

    return {
      type: alice.type,
      fingerprintIsMultibase: alice.fingerprint().startsWith('z'),
      secretLength: secretA.length,
      // X25519 ECDH must be symmetric: alice·bob === bob·alice
      secretsAgree:
        secretA.length === secretB.length &&
        secretA.every((byte, i) => byte === secretB[i])
    }
  })

  expect(result.type).toBe('X25519KeyAgreementKey2020')
  expect(result.fingerprintIsMultibase).toBe(true)
  expect(result.secretLength).toBe(32)
  expect(result.secretsAgree).toBe(true)
})
