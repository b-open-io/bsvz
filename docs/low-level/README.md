# Low-Level Notes

## Module reference

For the authoritative module index, use the root [README](../../README.md#module-layout).

## Core low-level surfaces

- `bsvz.primitives`
  - hex, varint, base58, chainhash, BIP32, BIP39, AES, DRBG, Shamir shares
- `bsvz.crypto`
  - hash helpers, secp256k1, DER signatures, compact signatures, ECIES
- `bsvz.script`
  - parser, builder, ASM, type detection, engine, policy flags
- `bsvz.transaction`
  - raw format, extended format, sighash, builder, BEEF
- `bsvz.spv`
  - MerklePath, header shape, SPV verification
- `bsvz.broadcast`
  - WhatsOnChain, TAAL, ARC HTTP clients

## Testing and corpus coverage

Run:

```bash
zig build test
```

Optional external-corpus visibility is printed during the test run. The filtered Go corpus lane executes all dynamic rows; remaining skips are meta rows only.
