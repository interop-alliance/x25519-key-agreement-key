# X25519KeyAgreementKey2020 _(@interop/x25519-key-agreement-key)_

[![CI](https://github.com/interop-alliance/x25519-key-agreement-key/workflows/CI/badge.svg)](https://github.com/interop-alliance/x25519-key-agreement-key/actions?query=workflow%3ACI)
[![NPM Version](https://img.shields.io/npm/v/@interop/x25519-key-agreement-key)](https://www.npmjs.com/package/@interop/x25519-key-agreement-key)

> An X25519 (Curve25519) DH (Diffie-Hellman) key implementation to work with the
> X25519 2020 Crypto suite for JS/TypeScript, for Node.js, browser and React
> Native.

## Table of Contents

- [Background](#background)
- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [Commercial Support](#commercial-support)
- [License](#license)

## Background

(Forked from
[`digitalcredentials/x25519-key-agreement-key-2020`](https://github.com/digitalcredentials/x25519-key-agreement-key-2020),
which was in turn forked from
[`digitalbazaar/x25519-key-agreement-key-2020` v2.0.0](https://github.com/digitalbazaar/x25519-key-agreement-key-2020)
to provide TypeScript compatibility.)

For use with
[`@interop/data-integrity-core`](https://www.npmjs.com/package/@interop/data-integrity-core).

To actually perform encryption with those keys, we recommend you use the
[`minimal-cipher`](https://github.com/digitalbazaar/minimal-cipher) library.

This is a low-level level library to generate and serialize X25519 (Curve25519)
key pairs (uses [`@noble/curves`](https://github.com/paulmillr/noble-curves)
under the hood).

See also (related specs):

- [Linked Data Proofs](https://w3c-ccg.github.io/ld-proofs/)
- [Linked Data Cryptographic Suite Registry](https://w3c-ccg.github.io/ld-cryptosuite-registry/)

## Install

Requires Node.js 24+

This is an ESM-only package (`"type": "module"`).

To install as a dependency:

```
npm install @interop/x25519-key-agreement-key
```

To install locally (for development):

```
git clone https://github.com/interop-alliance/x25519-key-agreement-key.git
cd x25519-key-agreement-key
pnpm install
```

## Usage

Importing:

```js
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
```

Generating:

```js
const keyPair = await X25519KeyAgreementKey2020.generate({
  controller: 'did:example:1234'
});
// ->
{
  "id": "did:example:1234#z6LSeRSE5Em5oJpwdk3NBaLVERBS332ULC7EQq5EtMsmXhsM",
  "controller": "did:example:1234",
  "type": "X25519KeyAgreementKey2020",
  "publicKeyMultibase": "z6LSeRSE5Em5oJpwdk3NBaLVERBS332ULC7EQq5EtMsmXhsM",
  "privateKeyMultibase": "z3weeMD56C1T347EmB6kYNS7trpQwjvtQCpCYRpqGz6mcemT"
}

```

Serializing just the public key:

```js
await keyPair.export({publicKey: true});
// ->
{
  "id": "did:example:1234#z6LSeRSE5Em5oJpwdk3NBaLVERBS332ULC7EQq5EtMsmXhsM",
  "controller": "did:example:1234",
  "type": "X25519KeyAgreementKey2020",
  "publicKeyMultibase": "z6LSeRSE5Em5oJpwdk3NBaLVERBS332ULC7EQq5EtMsmXhsM"
}
```

Serializing both the private and public key:

```js
// a different key pair than the previous example
await keyPair.export({publicKey: true, privateKey: true})
// ->
{
  "id": "did:example:1234#z6LSeRSE5Em5oJpwdk3NBaLVERBS332ULC7EQq5EtMsmXhsM",
  "controller": "did:example:1234",
  "type": "X25519KeyAgreementKey2020",
  "publicKeyMultibase": "z6LSeRSE5Em5oJpwdk3NBaLVERBS332ULC7EQq5EtMsmXhsM",
  "privateKeyMultibase": "z3weeMD56C1T347EmB6kYNS7trpQwjvtQCpCYRpqGz6mcemT"
}
```

Deserializing:

```js
// Loading public key only
const keyPair = await X25519KeyAgreementKey2020.from({
  id: 'did:example:1234#z6LSeRSE5Em5oJpwdk3NBaLVERBS332ULC7EQq5EtMsmXhsM',
  controller: 'did:example:1234',
  type: 'X25519KeyAgreementKey2020',
  publicKeyMultibase: 'z6LSeRSE5Em5oJpwdk3NBaLVERBS332ULC7EQq5EtMsmXhsM'
})
```

Giving a key a self-contained `did:key` identity (when it has no controller of
its own, e.g. a bare recipient public key) -- pass `didKey: true` to `from()` or
`fromFingerprint()`:

```js
const recipient = X25519KeyAgreementKey2020.fromFingerprint({
  fingerprint: 'z6LSeRSE5Em5oJpwdk3NBaLVERBS332ULC7EQq5EtMsmXhsM',
  didKey: true
})
// recipient.controller ->
//   'did:key:z6LSeRSE5Em5oJpwdk3NBaLVERBS332ULC7EQq5EtMsmXhsM'
// recipient.id ->
//   'did:key:z6LSeRSE5Em5oJpwdk3NBaLVERBS332ULC7EQq5EtMsmXhsM#z6LSeRSE5Em5oJpwdk3NBaLVERBS332ULC7EQq5EtMsmXhsM'
```

Multikey interop. `export()` is the default `X25519KeyAgreementKey2020`
serialization; `toMultikey()` is the opt-in Multikey form, and `from()` /
`fromMultikey()` import a Multikey-typed verification method (e.g. a
`keyAgreement` key from a DID document that uses Multikey):

```js
const multikey = keyPair.toMultikey({ secretKey: true });
// ->
{
  "@context": "https://w3id.org/security/multikey/v1",
  "id": "did:example:1234#z6LSeRSE5Em5oJpwdk3NBaLVERBS332ULC7EQq5EtMsmXhsM",
  "controller": "did:example:1234",
  "type": "Multikey",
  "publicKeyMultibase": "z6LSeRSE5Em5oJpwdk3NBaLVERBS332ULC7EQq5EtMsmXhsM",
  "secretKeyMultibase": "z3weeMD56C1T347EmB6kYNS7trpQwjvtQCpCYRpqGz6mcemT"
}

const keyPair = await X25519KeyAgreementKey2020.from(multikey);
```

Working with a raw 32-byte secret. `fromRawSecret()` builds a key pair from raw
secret bytes (deriving the public key and multibase encodings for you), and the
`rawSecret` getter is its inverse:

```js
const keyPair = X25519KeyAgreementKey2020.fromRawSecret({ secret })
// keyPair.rawSecret -> the same 32-byte Uint8Array

// pass `didKey: true` for a self-contained did:key identity
const recipient = X25519KeyAgreementKey2020.fromRawSecret({
  secret,
  didKey: true
})
```

The multibase framing helpers used internally are also exported, so consumers
can reuse the suite's exact base58btc multibase encoding:

```js
import {
  multibaseEncode,
  multibaseDecode,
  MULTICODEC_X25519_PUB_HEADER,
  MULTICODEC_X25519_PRIV_HEADER
} from '@interop/x25519-key-agreement-key'

const publicKeyMultibase = multibaseEncode(MULTICODEC_X25519_PUB_HEADER, bytes)
const bytes = multibaseDecode(MULTICODEC_X25519_PUB_HEADER, publicKeyMultibase)
```

## Contribute

See
[the contribute file](https://github.com/digitalbazaar/bedrock/blob/master/CONTRIBUTING.md)!

PRs accepted.

If editing the Readme, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## License

- New BSD License (3-clause) © 2020-2026 Digital Bazaar - Initial
  implementation.
- Copyright 2026 Interop Alliance - TypeScript conversion.
