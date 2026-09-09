/*!
 * Copyright (c) 2021-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {
  AbstractKeyPair,
  type GenerateKeyPairOptions,
  type IKeyAgreementKeyPair2020,
  type IMultikeyDocument,
  type IMultikeyPair,
  type IPublicMultikey,
  type ISigner,
  type IVerificationKeyPair2020,
  type IVerificationResult,
  type IVerifier
} from '@interop/data-integrity-core'
import {
  decodeMultikey,
  MultikeyCodec
} from '@interop/data-integrity-core/multihash'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'

import { base58btc } from './baseX.js'
import {
  deriveSecret,
  ed25519SecretKeyToX25519,
  generateKeyPair
} from './crypto.js'

const SUITE_ID = 'X25519KeyAgreementKey2020'
// multibase base58-btc header
const MULTIBASE_BASE58BTC_HEADER = 'z'
// multicodec x25519-pub header as varint
export const MULTICODEC_X25519_PUB_HEADER = new Uint8Array([0xec, 0x01])
// multicodec x25519-priv header as varint
export const MULTICODEC_X25519_PRIV_HEADER = new Uint8Array([0x82, 0x26])
const MULTIKEY_CONTEXT_V1_URL = 'https://w3id.org/security/multikey/v1'

/**
 * A source Ed25519 key shape, used by the `fromEd25519` conversion method.
 * Any object carrying multicodec-prefixed base58btc Ed25519 multibase fields
 * satisfies it: a VerificationKey2020 descriptor, a Multikey document, or a
 * live `Ed25519VerificationKey` instance.
 */
interface Ed25519KeyLike {
  controller?: string
  publicKeyMultibase?: string
  privateKeyMultibase?: string
}

export class X25519KeyAgreementKey2020 extends AbstractKeyPair {
  // Used by CryptoLD harness for dispatching.
  static suite: string = SUITE_ID
  // Used by CryptoLD harness's fromKeyId() method.
  static SUITE_CONTEXT: string =
    'https://w3id.org/security/suites/x25519-2020/v1'

  publicKeyMultibase: string
  privateKeyMultibase?: string

  /**
   * @param {object} options - Options hashmap.
   * @param {string} options.controller - Controller DID or document url.
   * @param {string} [options.id] - Key ID, typically composed of controller
   *   URL and key fingerprint as hash fragment.
   * @param {string} options.publicKeyMultibase - Multibase encoded public key.
   * @param {string} [options.privateKeyMultibase] - Multibase private key.
   * @param {string} [options.revoked] - Timestamp of when the key has been
   *   revoked, in RFC3339 format. If not present, the key itself is considered
   *   not revoked. Note that this mechanism is slightly different than DID
   *   Document key revocation, where a DID controller can revoke a key from
   *   that DID by removing it from the DID Document.
   */
  constructor(options: IKeyAgreementKeyPair2020 = {}) {
    super(options)
    this.type = SUITE_ID
    const { publicKeyMultibase, privateKeyMultibase } = options

    if (!publicKeyMultibase) {
      throw new TypeError('The "publicKeyMultibase" property is required.')
    }

    if (
      !publicKeyMultibase ||
      !_isValidKeyHeader(publicKeyMultibase, MultikeyCodec.X25519_PUB)
    ) {
      throw new Error(
        '"publicKeyMultibase" has invalid header bytes: ' +
          `"${publicKeyMultibase}".`
      )
    }

    if (
      privateKeyMultibase &&
      !_isValidKeyHeader(privateKeyMultibase, MultikeyCodec.X25519_PRIV)
    ) {
      throw new Error('"privateKeyMultibase" has invalid header bytes.')
    }

    // assign valid key values
    this.publicKeyMultibase = publicKeyMultibase
    this.privateKeyMultibase = privateKeyMultibase

    if (this.controller && !this.id) {
      this.id = `${this.controller}#${this.fingerprint()}`
    }
  }

  /**
   * Generates a new public/private X25519 Key Pair.
   *
   * @param {object} [options={}] - Keypair options (see controller docstring).
   *
   * @returns {Promise<X25519KeyAgreementKey2020>} Generated key pair.
   */
  static async generate(
    options: GenerateKeyPairOptions = {}
  ): Promise<X25519KeyAgreementKey2020> {
    const { publicKey, privateKey } = await generateKeyPair()

    return new X25519KeyAgreementKey2020({
      publicKeyMultibase: multibaseEncode(
        MULTICODEC_X25519_PUB_HEADER,
        publicKey
      ),
      privateKeyMultibase: multibaseEncode(
        MULTICODEC_X25519_PRIV_HEADER,
        privateKey
      ),
      ...options
    })
  }

  /**
   * Creates an X25519KeyAgreementKey2020 Key Pair from a raw 32-byte X25519
   * secret (constructor method). The public key and the multibase encodings are
   * derived internally, so callers that hold only the raw secret bytes (e.g. a
   * secret unwrapped from a JWE recipient) do not have to multibase-encode them
   * by hand.
   *
   * @param {object} options - Options hashmap.
   * @param {Uint8Array} options.secret - The raw 32-byte X25519 secret.
   * @param {string} [options.controller] - Controller DID or document url.
   * @param {string} [options.id] - Key ID.
   * @param {boolean} [options.didKey=false] - When no `controller`/`id` is
   *   given, default the `controller` to the key's own `did:key` form (see
   *   {@link from}).
   *
   * @returns {X25519KeyAgreementKey2020} An X25519 Key Pair.
   */
  static fromRawSecret({
    secret,
    controller,
    id,
    didKey = false
  }: {
    secret: Uint8Array
    controller?: string
    id?: string
    didKey?: boolean
  }): X25519KeyAgreementKey2020 {
    if (!(secret instanceof Uint8Array) || secret.length !== 32) {
      throw new Error('"secret" must be a 32-byte Uint8Array.')
    }
    const publicKey = x25519.getPublicKey(secret)
    const publicKeyMultibase = multibaseEncode(
      MULTICODEC_X25519_PUB_HEADER,
      publicKey
    )
    const privateKeyMultibase = multibaseEncode(
      MULTICODEC_X25519_PRIV_HEADER,
      secret
    )
    if (didKey && !controller && !id) {
      controller = `did:key:${publicKeyMultibase}`
    }
    return new X25519KeyAgreementKey2020({
      controller,
      id,
      publicKeyMultibase,
      privateKeyMultibase
    })
  }

  /**
   * Creates an X25519KeyAgreementKey2020 Key Pair from an existing key
   * (constructor method).
   *
   * @param {object} [options={}] - Keypair options (see controller docstring).
   * @param {boolean} [options.didKey=false] - When the source has neither a
   *   `controller` nor an `id`, default its `controller` to the key's own
   *   `did:key` form (`did:key:<publicKeyMultibase>`), so the constructor
   *   derives a self-contained `did:key:<mb>#<mb>` `id`. Ignored when a
   *   `controller` or `id` is already present.
   *
   * @returns {X25519KeyAgreementKey2020} An X25519 Key Pair.
   */
  static async from(
    options: (IKeyAgreementKeyPair2020 | IMultikeyDocument) & {
      publicKeyBase58?: string
      privateKeyBase58?: string
      didKey?: boolean
    } = {}
  ): Promise<X25519KeyAgreementKey2020> {
    const { didKey = false, ...keyPairOptions } = options
    // A Multikey-typed verification method (e.g. from a did:key/did:web doc).
    if (keyPairOptions.type === 'Multikey') {
      return this.fromMultikey(keyPairOptions as IMultikeyDocument)
    }
    // Check to see if this is an X25519KeyAgreementKey2019
    if (keyPairOptions.publicKeyBase58) {
      // Convert it to a 2020 key pair instance
      return this.fromX25519KeyAgreementKey2019(keyPairOptions)
    }
    if (didKey && !keyPairOptions.controller && !keyPairOptions.id) {
      keyPairOptions.controller = `did:key:${keyPairOptions.publicKeyMultibase}`
    }
    return new X25519KeyAgreementKey2020(keyPairOptions)
  }

  /**
   * Creates a key pair instance from a Multikey verification method. For X25519
   * the Multikey `publicKeyMultibase`/`secretKeyMultibase` use the same
   * multicodec headers as this suite's `publicKeyMultibase`/
   * `privateKeyMultibase` (x25519-pub / x25519-priv), and an X25519 secret is
   * always 32 bytes, so the mapping is a field rename -- there is no
   * key-length reconstruction step (unlike Ed25519). The returned instance is
   * an `X25519KeyAgreementKey2020`; use {@link toMultikey} to round-trip back.
   *
   * @see https://www.w3.org/TR/cid-1.0/#Multikey
   *
   * @param {object} options - A Multikey-typed key document.
   * @param {string} [options.id] - Verification method id.
   * @param {string} [options.controller] - Controller DID or document url.
   * @param {string} options.publicKeyMultibase - Multibase encoded public key.
   * @param {string} [options.secretKeyMultibase] - Multibase encoded secret key.
   * @param {string} [options.revoked] - Revocation timestamp (RFC3339).
   *
   * @returns {X25519KeyAgreementKey2020} An X25519 Key Pair.
   */
  static fromMultikey(options: IMultikeyDocument): X25519KeyAgreementKey2020 {
    const { id, controller, publicKeyMultibase, revoked } = options
    if (!_isValidKeyHeader(publicKeyMultibase, MultikeyCodec.X25519_PUB)) {
      throw new TypeError(
        '"publicKeyMultibase" has invalid header bytes: ' +
          `"${publicKeyMultibase}".`
      )
    }

    let privateKeyMultibase: string | undefined
    if ('secretKeyMultibase' in options) {
      const { secretKeyMultibase } = options
      if (!_isValidKeyHeader(secretKeyMultibase, MultikeyCodec.X25519_PRIV)) {
        throw new Error('"secretKeyMultibase" has invalid header bytes.')
      }
      // Same multicodec header and 32-byte length in both serializations, so
      // the Multikey secret is this suite's private key verbatim.
      privateKeyMultibase = secretKeyMultibase
    }

    return new X25519KeyAgreementKey2020({
      id,
      controller,
      revoked,
      publicKeyMultibase,
      privateKeyMultibase
    })
  }

  /**
   * Creates an X25519KeyAgreementKey2020 Key Pair from an existing 2019 key
   * (backwards compatibility method).
   *
   * @param {object} [options={}] - Options hashmap.
   * @param {string} options.publicKeyBase58 - Base58btc encoded public key.
   * @param {string} [options.privateKeyBase58] - Base58btc encoded private key.
   * @param {object} [options.keyPairOptions] - Other options.
   *
   * @returns {Promise<X25519KeyAgreementKey2020>} 2020 Crypto suite key pair.
   */
  static async fromX25519KeyAgreementKey2019({
    publicKeyBase58,
    privateKeyBase58,
    ...keyPairOptions
  }: IKeyAgreementKeyPair2020 & {
    publicKeyBase58?: string
    privateKeyBase58?: string
  } = {}): Promise<X25519KeyAgreementKey2020> {
    let publicKeyMultibase: string | undefined
    let privateKeyMultibase: string | undefined

    if (publicKeyBase58) {
      // prefix with `z` to indicate multi-base base58btc encoding
      publicKeyMultibase = multibaseEncode(
        MULTICODEC_X25519_PUB_HEADER,
        base58btc.decode(publicKeyBase58)
      )
    }
    if (privateKeyBase58) {
      // prefix with `z` to indicate multi-base base58btc encoding
      privateKeyMultibase = multibaseEncode(
        MULTICODEC_X25519_PRIV_HEADER,
        base58btc.decode(privateKeyBase58)
      )
    }
    return new X25519KeyAgreementKey2020({
      publicKeyMultibase,
      privateKeyMultibase,
      ...keyPairOptions
    })
  }

  /**
   * Derives an X25519 key agreement key from an Ed25519 key, converting the
   * Edwards public key (and private key, when present) to Montgomery form.
   * The source is any object carrying Ed25519 multibase fields; the same
   * multicodec-prefixed base58btc encoding is shared by VerificationKey2020
   * descriptors, Multikey documents, and `Ed25519VerificationKey` instances.
   *
   * @param options {object}
   * @param [options.controller] {string} Carried over to the derived key.
   * @param options.publicKeyMultibase {string} Multibase Ed25519 public key.
   * @param [options.privateKeyMultibase] {string} Multibase Ed25519 private
   *   key.
   *
   * @returns {X25519KeyAgreementKey2020} The derived key agreement key.
   */
  static fromEd25519({
    controller,
    publicKeyMultibase,
    privateKeyMultibase
  }: Ed25519KeyLike): X25519KeyAgreementKey2020 {
    if (!publicKeyMultibase) {
      throw new Error('Source public key is required to convert.')
    }

    if (!publicKeyMultibase.startsWith(MULTIBASE_BASE58BTC_HEADER)) {
      throw new TypeError(
        'Expecting "publicKeyMultibase" value to be multibase base58btc ' +
          'encoded (must start with "z").'
      )
    }

    const xKey = new X25519KeyAgreementKey2020({
      controller,
      publicKeyMultibase: X25519KeyAgreementKey2020.convertFromEdPublicKey({
        publicKeyMultibase
      })
    })

    if (privateKeyMultibase) {
      if (!privateKeyMultibase.startsWith(MULTIBASE_BASE58BTC_HEADER)) {
        throw new TypeError(
          'Expecting "privateKeyMultibase" value to be multibase base58btc ' +
            'encoded (must start with "z").'
        )
      }

      xKey.privateKeyMultibase =
        X25519KeyAgreementKey2020.convertFromEdPrivateKey({
          privateKeyMultibase
        })
    }

    return xKey
  }

  /**
   * Older name for `fromEd25519()`, which takes the source key fields
   * directly. The conversion never depended on the 2020 serialization.
   *
   * @param options {object}
   * @param options.keyPair {Ed25519KeyLike} Source key.
   *
   * @returns {X25519KeyAgreementKey2020} The derived key agreement key.
   */
  static fromEd25519VerificationKey2020({
    keyPair
  }: {
    keyPair: Ed25519KeyLike
  }): X25519KeyAgreementKey2020 {
    return X25519KeyAgreementKey2020.fromEd25519(keyPair)
  }

  /**
   * @param {object} [options={}] - Options hashmap.
   * @param {string} options.publicKeyMultibase - Multibase encoded Ed25519
   *   public key.
   *
   * @returns {string} Multibase encoded converted X25519 Public key.
   */
  static convertFromEdPublicKey({
    publicKeyMultibase
  }: { publicKeyMultibase?: string } = {}): string {
    if (!publicKeyMultibase) {
      throw new Error('Source public key is required to convert.')
    }

    const edPubkeyBytes = _decodeKeyBytes(
      publicKeyMultibase,
      MultikeyCodec.ED25519_PUB
    )

    // Converts a 32-byte Ed25519 public key into a 32-byte Curve25519 key.
    // Throws if the given public key is not a valid Ed25519 public key.
    let dhPubkeyBytes: Uint8Array
    try {
      dhPubkeyBytes = ed25519.utils.toMontgomery(edPubkeyBytes)
    } catch {
      throw new Error('Error converting to X25519; Invalid Ed25519 public key.')
    }
    return multibaseEncode(MULTICODEC_X25519_PUB_HEADER, dhPubkeyBytes)
  }

  /**
   * @param {object} [options={}] - Options hashmap.
   * @param {string} options.privateKeyMultibase - Multibase encoded Ed25519
   *   private key.
   *
   * @returns {string} Multibase encoded converted X25519 Private key.
   */
  static convertFromEdPrivateKey({
    privateKeyMultibase
  }: { privateKeyMultibase?: string } = {}): string {
    if (!privateKeyMultibase) {
      throw new Error('Source private key is required to convert.')
    }

    const edPrivkeyBytes = _decodeKeyBytes(
      privateKeyMultibase,
      MultikeyCodec.ED25519_PRIV
    )
    // Converts a 64-byte Ed25519 secret key (or just the first 32-byte part of
    // it, which is the secret value) into a 32-byte Curve25519 secret key
    const dhPrivkeyBytes = ed25519SecretKeyToX25519(edPrivkeyBytes)
    if (!dhPrivkeyBytes) {
      throw new Error(
        'Error converting to X25519; Invalid Ed25519 private key.'
      )
    }
    return multibaseEncode(MULTICODEC_X25519_PRIV_HEADER, dhPrivkeyBytes)
  }

  /**
   * Exports the serialized representation of the KeyPair.
   *
   * @param {object} [options={}] - Options hashmap.
   * @param {boolean} [options.publicKey] - Export public key material?
   * @param {boolean} [options.privateKey] - Export private key material?
   * @param {boolean} [options.includeContext] - Include JSON-LD context?
   *
   * @returns {Promise<object>} A plain js object that's ready for serialization
   *   (to JSON, etc), for use in DIDs etc.
   */
  async export({
    publicKey = false,
    privateKey = false,
    includeContext = false
  }: {
    publicKey?: boolean
    privateKey?: boolean
    includeContext?: boolean
  } = {}): Promise<IVerificationKeyPair2020> {
    if (!(publicKey || privateKey)) {
      throw new TypeError(
        'Export requires specifying either "publicKey" or "privateKey".'
      )
    }
    const exportedKey: IVerificationKeyPair2020 = {
      id: this.id,
      type: this.type
    }
    if (includeContext) {
      exportedKey['@context'] = X25519KeyAgreementKey2020.SUITE_CONTEXT
    }
    if (this.controller) {
      exportedKey.controller = this.controller
    }
    if (publicKey) {
      exportedKey.publicKeyMultibase = this.publicKeyMultibase
    }
    if (privateKey) {
      exportedKey.privateKeyMultibase = this.privateKeyMultibase
    }
    if (this.revoked) {
      exportedKey.revoked = this.revoked
    }
    return exportedKey
  }

  /**
   * Serializes this key pair as a Multikey verification method (opt-in;
   * `export()` remains the default `X25519KeyAgreementKey2020` serialization).
   * `publicKeyMultibase` is always emitted; the X25519 secret carries the same
   * multicodec header in both forms, so `secretKeyMultibase` is the suite
   * `privateKeyMultibase` verbatim.
   *
   * @see https://www.w3.org/TR/cid-1.0/#Multikey
   *
   * @param {object} [options={}] - Options hashmap.
   * @param {boolean} [options.secretKey=false] - Export secret key material too?
   * @param {boolean} [options.includeContext=true] - Include the Multikey
   *   JSON-LD context?
   *
   * @returns {IMultikeyDocument} `IPublicMultikey` (default) or `IMultikeyPair`
   *   (when `secretKey: true`).
   */
  toMultikey(options: {
    secretKey: true
    includeContext?: boolean
  }): IMultikeyPair
  toMultikey(options?: {
    secretKey?: false
    includeContext?: boolean
  }): IPublicMultikey
  toMultikey({
    secretKey = false,
    includeContext = true
  }: {
    secretKey?: boolean
    includeContext?: boolean
  } = {}): IMultikeyDocument {
    const publicShape: IPublicMultikey = {
      type: 'Multikey',
      publicKeyMultibase: this.publicKeyMultibase
    }
    if (this.id != null) {
      publicShape.id = this.id
    }
    if (includeContext) {
      publicShape['@context'] = MULTIKEY_CONTEXT_V1_URL
    }
    if (this.controller) {
      publicShape.controller = this.controller
    }
    if (this.revoked) {
      publicShape.revoked = this.revoked
    }

    if (secretKey && this.privateKeyMultibase) {
      return {
        ...publicShape,
        secretKeyMultibase: this.privateKeyMultibase
      } satisfies IMultikeyPair
    }
    return publicShape
  }

  /**
   * Generates and returns a base58btc multibase encoded value of a multicodec
   * X25519 public key fingerprint (for use with cryptonyms, for example).
   *
   * @see https://github.com/multiformats/multicodec
   * @see https://github.com/multiformats/multibase
   *
   * @param {object} [options={}] - Options hashmap.
   * @param {string} options.publicKeyMultibase - Multibase encoded public key.
   *
   * @returns {string} The fingerprint.
   */
  static fingerprintFromPublicKey({
    publicKeyMultibase
  }: { publicKeyMultibase?: string } = {}): string {
    if (!publicKeyMultibase) {
      throw new Error('Source public key is required.')
    }

    return publicKeyMultibase
  }

  /**
   * Creates an instance of X25519KeyAgreementKey2020 from a key fingerprint.
   *
   * @param {object} [options={}] - Options hashmap.
   * @param {string} options.fingerprint - Public key fingerprint.
   * @param {boolean} [options.didKey=false] - Give the resulting key a
   *   `did:key` identity: set its `controller` to `did:key:<fingerprint>`, so
   *   its `id` is the self-contained `did:key:<fingerprint>#<fingerprint>`. Off
   *   by default, so the key has no `controller`/`id` unless requested.
   *
   * @returns {X25519KeyAgreementKey2020} Key pair instance (public key material
   *   only) created from the fingerprint.
   */
  static fromFingerprint({
    fingerprint,
    didKey = false
  }: {
    fingerprint?: string
    didKey?: boolean
  } = {}): X25519KeyAgreementKey2020 {
    return new X25519KeyAgreementKey2020({
      controller: didKey ? `did:key:${fingerprint}` : undefined,
      publicKeyMultibase: fingerprint
    })
  }

  /**
   * Derives a shared secret via a given public key, typically for use
   * as one parameter for computing a shared key. It should not be used as
   * a shared key itself, but rather as an input into a key derivation function
   * (KDF) to produce a shared key.
   *
   * @param {object} [options={}] - Options hashmap.
   * @param {LDKeyPair} options.publicKey - Remote key pair.
   *
   * @returns {Promise<Uint8Array>} Derived secret.
   */
  async deriveSecret({
    publicKey
  }: {
    publicKey: { publicKeyMultibase?: string }
  }): Promise<Uint8Array> {
    const remotePublicKey = _decodeKeyBytes(
      publicKey.publicKeyMultibase as string,
      MultikeyCodec.X25519_PUB
    )
    const privateKey = _decodeKeyBytes(
      this.privateKeyMultibase as string,
      MultikeyCodec.X25519_PRIV
    )

    return deriveSecret({ privateKey, remotePublicKey })
  }

  /**
   * The raw 32-byte X25519 secret, decoded from `privateKeyMultibase` (the
   * inverse of {@link fromRawSecret}). Useful for callers that must wrap the
   * secret to a recipient or hand it to a lower-level cipher. Throws if this is
   * a public-key-only instance.
   *
   * @returns {Uint8Array} The raw 32-byte secret.
   */
  get rawSecret(): Uint8Array {
    if (!this.privateKeyMultibase) {
      throw new Error('This key pair has no private key material.')
    }
    return _decodeKeyBytes(this.privateKeyMultibase, MultikeyCodec.X25519_PRIV)
  }

  /**
   * Generates and returns a multiformats encoded
   * X25519 public key fingerprint (for use with cryptonyms, for example).
   *
   * @see https://github.com/multiformats/multicodec
   *
   * @returns {string} The fingerprint.
   */
  fingerprint(): string {
    return this.publicKeyMultibase
  }

  /**
   * Tests whether the fingerprint was generated from a given key pair.
   *
   * @example
   * xKeyPair.verifyFingerprint('...');
   * // {valid: true};
   *
   * @param {object} [options={}] - Options hashmap.
   * @param {string} options.fingerprint - An x25519 key fingerprint (typically
   *   from a key id).
   *
   * @returns {IVerificationResult} An object indicating whether the fingerprint
   *   was verified.
   */
  verifyFingerprint({
    fingerprint
  }: { fingerprint?: string } = {}): IVerificationResult {
    // fingerprint should have `z` prefix indicating
    // that it's base58btc multibase encoded
    if (!_isValidKeyHeader(fingerprint, MultikeyCodec.X25519_PUB)) {
      throw new Error(
        `"fingerprint" has invalid header bytes: "${fingerprint}".`
      )
    }

    return { verified: true }
  }

  /**
   * Key agreement keys are used for ECDH (see {@link deriveSecret}), not for
   * producing signatures.
   *
   * @returns {ISigner} Never returns; always throws.
   */
  signer(): ISigner {
    throw new Error(
      'X25519KeyAgreementKey2020 is a key agreement key and cannot sign.'
    )
  }

  /**
   * Key agreement keys are used for ECDH (see {@link deriveSecret}), not for
   * verifying signatures.
   *
   * @returns {IVerifier} Never returns; always throws.
   */
  verifier(): IVerifier {
    throw new Error(
      'X25519KeyAgreementKey2020 is a key agreement key and cannot verify ' +
        'signatures.'
    )
  }
}

/**
 * Checks to see if the given value is a valid multibase encoded key of the
 * expected multikey codec. Delegates to `decodeMultikey`, so this also
 * catches a missing `z` multibase prefix and a wrong key length, neither of
 * which the previous header-byte comparison checked.
 *
 * @param {unknown} multibaseKey - The multibase-encoded key value.
 * @param {MultikeyCodec} expectedCodec - The expected multikey codec.
 * @returns {boolean} Returns true if the key decodes as that codec, false
 *   otherwise.
 */
function _isValidKeyHeader(
  multibaseKey: unknown,
  expectedCodec: MultikeyCodec
): boolean {
  if (typeof multibaseKey !== 'string') {
    return false
  }
  try {
    decodeMultikey({ multikey: multibaseKey, expectedCodec })
    return true
  } catch {
    return false
  }
}

/**
 * Decodes a multibase-encoded multikey of the expected codec, mapping any
 * `decodeMultikey` failure (a missing `z` prefix, malformed base58, a
 * mismatched codec, or a wrong key length) to this suite's historical
 * "invalid header" wording, so existing callers keep seeing the same error
 * shape they always have rather than a library-internal message.
 *
 * @param {string} multibaseKey - The multibase-encoded key value.
 * @param {MultikeyCodec} expectedCodec - The expected multikey codec.
 * @returns {Uint8Array} The decoded raw key bytes.
 */
function _decodeKeyBytes(
  multibaseKey: string,
  expectedCodec: MultikeyCodec
): Uint8Array {
  try {
    return decodeMultikey({ multikey: multibaseKey, expectedCodec }).keyBytes
  } catch (err) {
    throw new Error('Multibase value does not have expected header.', {
      cause: err
    })
  }
}

/**
 * Encodes a given Uint8Array to multibase-encoded string.
 *
 * @param {Uint8Array} header - Multicodec header to prepend to the bytes.
 * @param {Uint8Array} bytes - Bytes to encode.
 * @returns {string} Multibase-encoded string.
 */
export function multibaseEncode(header: Uint8Array, bytes: Uint8Array): string {
  const mcBytes = new Uint8Array(header.length + bytes.length)

  mcBytes.set(header)
  mcBytes.set(bytes, header.length)

  return MULTIBASE_BASE58BTC_HEADER + base58btc.encode(mcBytes)
}

/**
 * Decodes a given string as a multibase-encoded multicodec value.
 *
 * @param {Uint8Array} header - Expected header bytes for the multicodec value.
 * @param {string} text - Multibase encoded string to decode.
 * @returns {Uint8Array} Decoded bytes.
 */
export function multibaseDecode(header: Uint8Array, text: string): Uint8Array {
  const mcValue = base58btc.decode(text.substr(1))

  if (!header.every((val, i) => mcValue[i] === val)) {
    throw new Error('Multibase value does not have expected header.')
  }

  return mcValue.slice(header.length)
}
