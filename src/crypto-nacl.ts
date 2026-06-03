/*!
 * Copyright (c) 2021-2022 Digital Bazaar, Inc. All rights reserved.
 */
import nacl from 'tweetnacl'

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
  return nacl.scalarMult(privateKey, remotePublicKey)
}

export async function generateKeyPair(): Promise<{
  publicKey: Uint8Array
  privateKey: Uint8Array
}> {
  // Each is a Uint8Array with 32-byte key
  const { publicKey, secretKey: privateKey } = nacl.box.keyPair()
  return { publicKey, privateKey }
}

export function ed25519SecretKeyToX25519(secretKey: Uint8Array): Uint8Array {
  const hash = new Uint8Array(64)
  // X25519 secret key is the first 32 bytes of the hash with clamped values.
  // `nacl.lowlevel` is not covered by tweetnacl's published type definitions.
  const { lowlevel } = nacl as unknown as {
    lowlevel: {
      crypto_hash(out: Uint8Array, m: Uint8Array, n: number): number
    }
  }
  lowlevel.crypto_hash(hash, secretKey, 32)
  hash[0] &= 248
  hash[31] &= 127
  hash[31] |= 64
  const x25519SecretKey = hash.slice(0, 32)
  // zero-fill remainder of hash before returning
  hash.fill(0, 32)
  return x25519SecretKey
}
