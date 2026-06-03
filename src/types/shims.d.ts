// Ambient type shims for runtime deps that ship no TypeScript declarations.

declare module '@noble/ed25519' {
  /**
   * Minimal surface of the noble-ed25519 v1 `Point` used by this library:
   * decoding an Ed25519 public key and converting it to a Montgomery
   * (X25519) public key.
   */
  export class Point {
    static fromHex(hex: Uint8Array | string): Point
    toX25519(): Uint8Array
  }
}
