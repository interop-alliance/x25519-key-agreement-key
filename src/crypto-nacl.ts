/*!
 * Copyright (c) 2021-2022 Digital Bazaar, Inc. All rights reserved.
 */
import { x25519, ed25519 } from '@noble/curves/ed25519.js'

/**
 * Note: The following two functions are async to match the signature of
 * their native Node.js counterparts (see './crypto.js').
 */

export async function deriveSecret({
  privateKey,
  remotePublicKey
}: {
  privateKey: Uint8Array
  remotePublicKey: Uint8Array
}): Promise<Uint8Array> {
  return x25519.getSharedSecret(privateKey, remotePublicKey)
}

export async function generateKeyPair(): Promise<{
  publicKey: Uint8Array
  privateKey: Uint8Array
}> {
  // Each is a Uint8Array with 32-byte key
  const { secretKey: privateKey, publicKey } = x25519.keygen()
  return { publicKey, privateKey }
}

export function ed25519SecretKeyToX25519(secretKey: Uint8Array): Uint8Array {
  // `toMontgomerySecret` hashes and clamps the 32-byte Ed25519 secret seed.
  // The historical input here is a 64-byte Ed25519 secret key of which only
  // the first 32 bytes (the seed) are used; noble throws on a 64-byte input,
  // so slice to the seed to preserve existing behavior.
  return ed25519.utils.toMontgomerySecret(secretKey.slice(0, 32))
}
