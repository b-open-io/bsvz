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
- script: ScriptNum, byte helpers, script parser/chunks, broad opcode set, general execution engine, transaction-aware CHECKSIG/CHECKMULTISIG, Go-shaped policy enforcement, P2PKH and OP_RETURN templates

Current construction zones:

- SPV is not yet real beyond placeholders and type stubs
- broadcast is not yet real beyond namespace scaffolding
- the script interpreter is materially closer to Go parity, but the full Go reference corpus is not yet imported
- native execution coverage for compiled Runar contracts is broad and growing, but not complete

## Script Interpreter Coverage

This is the current interpreter map for `bsvz.script`.

| Area | Coverage | Notes |
| --- | --- | --- |
| Script bytes, chunks, parser, serializer | implemented | direct pushes, `PUSHDATA1/2/4`, chunk roundtrip, malformed pushdata rejection |
| Push-only and script inspection helpers | implemented | `isPushOnly`, `hasCodeSeparator`, top-level `OP_RETURN` tail handling, and push-only seam behavior |
| Execution core | implemented | stack, altstack, condition stack, truthiness, op counting, stack limits |
| Control flow | implemented | `IF`, `NOTIF`, `ELSE`, `ENDIF`, `VERIFY`, legacy vs post-Genesis multi-`ELSE` behavior, post-Genesis `OP_RETURN`, `CODESEPARATOR` |
| Stack ops | broad coverage | includes `DUP`, `DROP`, `SWAP`, `ROT`, `ROLL`, `PICK`, `2DUP`, `2DROP`, `2OVER`, `2ROT`, `2SWAP`, `3DUP`, `IFDUP`, `TOALTSTACK`, `FROMALTSTACK` |
| Byte/splice ops | broad coverage | `CAT`, `SPLIT`, `NUM2BIN`, `BIN2NUM`, `SIZE` |
| Bitwise ops | implemented | `INVERT`, `AND`, `OR`, `XOR`, `LSHIFT`, `RSHIFT` |
| Numeric and boolean ops | broad coverage | `ADD`, `SUB`, `MUL`, `DIV`, `MOD`, comparisons, min/max, within, boolean logic |
| Hash ops | implemented | `RIPEMD160`, `SHA1`, `SHA256`, `HASH160`, `HASH256` |
| `ScriptNum` | implemented | small-or-big numeric core using Zig stdlib bigint for promoted values |
| `CHECKSIG` | implemented | transaction-aware, BSV-only, legacy and ForkID paths, `CODESEPARATOR` handling, scriptCode normalization |
| `CHECKMULTISIG` | implemented | transaction-aware, post-Genesis behavior, early-exit behavior, `NULLDUMMY` / `NULLFAIL` / ForkID policy coverage |
| Policy flags | broad coverage | `strict_encoding`, `der_signatures`, `low_s`, `strict_pubkey_encoding`, `null_dummy`, `null_fail`, `sig_push_only`, `clean_stack`, `minimal_data`, `minimal_if` |
| Numeric minimal-encoding parity | implemented | minimal push and minimal numeric decoding are both enforced where Go applies `MINIMALDATA` |
| `CODESEPARATOR` parity | broad coverage | legacy and ForkID scriptCode behavior, chained separator result-shape tests, parser/scanner coverage |
| Go parity vectors | broad but incomplete | many direct parser, policy, script-pair seam, multisig, `CODESEPARATOR`, and BIP66-style reference/result-shape vectors are in place, but not the full Go corpus |
| Runar local acceptance | broad but incomplete | real local acceptance covers stateless, stateful, covenant, NFT, fungible-token, and math/crypto-heavy contracts, but the full Runar corpus is not yet green |
| SPV / script-adjacent proof tooling | construction zone | not part of the interpreter core yet |

BSV-specific scope rules:

- supported: modern BSV script execution and post-Genesis behavior
- not supported: SegWit, Taproot, and BTC witness semantics
- not supported: P2SH as a modern BSV feature
- not supported: BCH-specific script or transaction semantics

Project direction:

- BSV-only, not BTC-compatible
- no SegWit or Taproot support
- no HD wallet derivation in core scope
- prioritize script execution and downstream Runar integration before broadening into secondary areas
