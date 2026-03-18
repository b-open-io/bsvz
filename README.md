# bsvz

`bsvz` is a BSV foundation library for Zig.

Initial focus:

- primitives
- crypto
- script
- transaction
- SPV
- broadcast

Non-goals for the first milestone:

- full node functionality
- full wallet product APIs
- broad application-layer protocol coverage
- HD wallet derivation (`bip32`, `bip39`, `bip44`)
- SegWit, Taproot, and other post-fork BTC transaction formats

## Zig Version

- Zig `0.15.2`

## Module Layout

- `bsvz.primitives`
- `bsvz.crypto`
- `bsvz.script`
- `bsvz.transaction`
- `bsvz.spv`
- `bsvz.broadcast`
- `bsvz.compat`

## Status

This repository is a standalone BSV library under active development.

Current implemented areas:

- primitives: hex, varint, base58, base58check, network/version-byte helpers
- crypto: sha256, hash256, ripemd160, hash160, secp256k1 private/public keys, DER signatures, tx-signature helpers
- compat: legacy P2PKH address and WIF encode/decode
- transaction: legacy transaction parse/serialize, txid, replay-protected sighash/preimage helpers, P2PKH spend helpers
- script: ScriptNum, byte helpers, script parser/chunks, broad opcode set, general execution engine, transaction-aware CHECKSIG/CHECKMULTISIG, P2PKH and OP_RETURN templates

Current construction zones:

- SPV is not yet real beyond placeholders and type stubs
- broadcast is not yet real beyond namespace scaffolding
- the script interpreter is now general enough for real progress, but it is not yet at full Go/TS SDK parity
- native execution coverage for compiled Runar contracts is still in progress

Project direction:

- BSV-only, not BTC-compatible
- no SegWit or Taproot support
- no HD wallet derivation in core scope
- prioritize script execution and downstream Runar integration before broadening into secondary areas
