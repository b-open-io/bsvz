# BRC ↔ bsvz module map

Authoritative table: [README.md § Standards Coverage](../README.md#standards-coverage). This file exists so searches for “BRC matrix” or “docs” land in-repo.

| Area | Module(s) |
| --- | --- |
| Key derivation (BRC-32, 42, 43, 75) | `primitives.bip32`, `primitives.bip39`, `primitives.brc43` (invoice = go `computeInvoiceNumber`), `primitives.ec` |
| Transactions (BRC-8, 12, 30, 36, 62, 95, 96) | `transaction`, `transaction.beef` |
| Scripts (BRC-14–19, 48, …) | `script`, `script.templates.*` |
| SPV / Merkle (BRC-9, 61, 67, 74) | `spv` (`verify`, `verifyBeef`, `MerklePath`, …) |
| Messages / encryption (BRC-2, 77, 78) | `message.signed`, `message.encrypted`, `primitives.symmetric` (AES-GCM), `primitives.aescbc`, `compat.bsm` (legacy BSM), `crypto.ecies`, `compat.ecies` (compat ECIES) |

Run `zig build test` for corpus-backed verification.
