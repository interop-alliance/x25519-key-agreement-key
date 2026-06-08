# @interop/x25519-key-agreement-key Changelog

## 4.0.2 - 2026-06-07

### Added

- Expanded the test suite (statement coverage 78% -- 96%): RFC 7748 X25519 test
  vectors (Section 6.1 Diffie-Hellman and Section 5.2 scalar multiplication) run
  through both the native Node and `@noble/curves` backends, a cross-backend
  agreement check, and error-path coverage for constructor/header validation,
  key conversion, fingerprint, `deriveSecret`, `export`, `signer`, and
  `verifier`. No library behavior change.

### Changed

- Replaced `tweetnacl` with `@noble/curves` for X25519 Diffie-Hellman, key
  generation, and Ed25519-to-X25519 secret-key conversion; removed the
  `tweetnacl` dependency. No public API change.

## 4.0.0-4.0.1 - 2026-06-03

### Changed

- **BREAKING**: Forked to
  [`interop-alliance/x25519-key-agreement-key`](https://github.com/interop-alliance/x25519-key-agreement-key)
  and renamed the published package from
  `@digitalcredentials/x25519-key-agreement-key-2020` to
  `@interop/x25519-key-agreement-key`.
- **BREAKING**: Converted the source to TypeScript and the published package to
  ESM-only (`"type": "module"`). The compiled output now ships type declarations
  (`.d.ts`).
- **BREAKING**: `verifyFingerprint()` now returns an `IVerificationResult`
  (`{ verified: boolean }`) instead of `{ valid: boolean }`, to match
  `@interop/data-integrity-core`.
- **BREAKING**: Replaced the `crypto-ld` `LDKeyPair` base class with
  `AbstractKeyPair` from
  [`@interop/data-integrity-core`](https://www.npmjs.com/package/@interop/data-integrity-core).
  Key agreement keys now expose `signer()`/`verifier()` methods (which throw, as
  key agreement keys cannot sign).
- **BREAKING**: Raised the minimum Node.js version to 24.
- Replaced `@digitalcredentials/base58-universal` with
  [`@scure/base`](https://www.npmjs.com/package/@scure/base) for base58btc
  encoding.
- Replaced `@noble/ed25519` (v1) with
  [`@noble/curves`](https://www.npmjs.com/package/@noble/curves) for the Ed25519
  public key to X25519 conversion, using `ed25519.utils.toMontgomery()`.
  `@noble/ed25519` v2+ removed the Edwards-to-Montgomery conversion this library
  relied on.
- Migrated tooling to the isomorphic-lib-template infrastructure: pnpm, a `tsc`
  build, ESLint flat config, Prettier 3, vitest (Node tests), and Playwright
  (browser tests).

## 3.0.0 - 2022-09-08

### Changed

- Replace internal ed25519 => x25519 conversion implementation such that only
  tweetnacl is used, allowing for `ed2curve` dependency to be removed.

## 2.1.0 - 2022-05-xx

### Changed

- Use `@noble/ed25519` to convert public ed25519 keys to x25519.

## 2.0.0 - 2021-06-19

### Changed

- **BREAKING**: Upgrade to @digitalbazaar/ed25519-verification-key-2020@3 which
  changes the key format to multicodec.

## 1.2.1 - 2021-05-06

### Fixed

- Fix `package.json` browser section alias for `crypto.js` (was causing
  downstream webpack errors).

## 1.2.0 - 2021-04-02

### Added

- Add `includeContext` flag to `export()`.

## 1.1.0 - 2021-04-02

### Added

- Add `revoked` export tests, `SUITE_CONTEXT` class property. (To support
  `CryptoLD`'s new `fromKeyId()` method.)

## 1.0.0 - 2021-03-30

### Added

- Initial commit.
