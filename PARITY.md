# Go SDK parity matrix

This is a living checklist that maps Go SDK packages to current `bsvz` modules.

## Active parallel work (in progress)

- Reference thread: the transaction/SPV 10x hardening pass against Go `transaction/*` and `spv/*`.
- In scope:
  - ownership and clone/deinit rules for parsed transaction data
  - BEEF/BUMP parsing, atomic BEEF, dependency hydration, validation, and verification
  - MerklePath helpers and hardening
  - fee-model and SPV verification surface
  - parity-first test corpus for tx/SPV behavior
- Out of scope:
  - broadcast work
  - ECDH / Type-42 / compact recovery
  - BSM / ECIES / BIP32 / BIP39
  - script builder / broader script surface
  - unrelated primitive and wallet layers
- Coordination:
  - do not duplicate the tx/SPV hardening thread while `parallel-tx-spv-hardening` is active
  - refresh the matrix rows below when that work lands
  - `tier1-tx-hex` has been absorbed by the tx/BEEF hardening surface
  - overlapping Cursor todos were intentionally cancelled in favor of the umbrella tracker
    - cancelled: `tier2-tx-surface`, `tier3-merkle-api`, `merkle-spv`
    - active umbrella: `parallel-tx-spv-hardening`

Legend:

- **done**: feature parity + tests
- **partial**: some APIs or behavior missing
- **missing**: not implemented
- **out-of-scope**: intentionally excluded (for now)

## Test harness notes

- `zig build test` now emits an explicit external-coverage notice for optional sibling inputs such as `../go-sdk/script/interpreter/data/script_tests.json` and `../runar/packages/runar-compiler/dist/index.js`.
- Set `BSVZ_REQUIRE_EXTERNAL_CORPORA=1` to make the default test run fail if those optional external inputs are missing.
- The filtered Go corpus lanes are intentionally partial:
  - `go_corpus_filtered_vectors.zig` excludes unsupported checksig/checkmultisig/CSV rows, raw pushdata-prefix rows, and unsafe legacy `P2SH HASH160 EQUAL` cases.
  - `go_sigcheck_reference_vectors.zig` and `go_multisig_reference_vectors.zig` exercise mapped subsets only and print executed/skipped counts in stderr.
- `zig build test-runar-acceptance` remains separate from the default `test` step.

| Go SDK path | bsvz module | Status | Tests / notes |
| --- | --- | --- | --- |
| `chainhash/*` | `crypto/hash.zig` + `primitives/*` | partial | No dedicated `chainhash.Hash` type or display byte-order helpers |
| `primitives/hash/*` | `crypto/hash.zig` | partial | Missing some Go surface + compat callers |
| `primitives/ec/*` | `crypto/secp256k1.zig` | partial | Key/point APIs differ; no shared surface |
| `primitives/ecdsa/*` | `crypto/signature.zig` | partial | DER + sighash integration gaps |
| `primitives/schnorr/*` | `primitives/schnorr.zig` | partial | Vectors; align all Go surface |
| `primitives/ec/shamir.go` | `primitives/keyshares.zig` (polynomial) | partial | See Tier 1–2 gaps for full Shamir API |
| `primitives/keyshares/*` | `primitives/keyshares.zig` | partial | Backup format + Lagrange; see roadmap |
| `primitives/ec/symmetric.go` | `primitives/symmetric.zig` | partial | Align KDF/encryption with Go |
| `primitives/aescbc/*` | `primitives/aescbc.zig` | partial | |
| `primitives/aesgcm/*` | `primitives/aesgcm.zig` | partial | |
| `primitives/drbg/*` | `primitives/drbg.zig` | partial | |
| `script/interpreter/*` | `script/*` + `script/thread.zig` | done | `tests/go_*_vectors.zig` |
| `script/address.go` | `compat/address.zig` | partial | Address kinds + parity rules missing |
| `script/addressvalidation.go` | (none) | missing | Validation rules |
| `script/bip276.go` | (none) | missing | BIP276 format |
| `transaction/*` core | `transaction/*` | partial | Parsed txs now own script data, support `clone`/`shallowClone`, can derive prevouts from non-owning ancestry links, and expose a first builder/signing surface (`Builder`, P2PKH-first) |
| `transaction/beef*.go` | `transaction/beef.zig` | partial | BEEF v1/v2 + AtomicBEEF parse/serialize, clone-safe ownership, ParsedBeef deinit, V2 source-output/source-transaction hydration, duplicate/trailing-input rejection, structural validation + root verification |
| `transaction/merklepath.go` | `spv/merkle_path.zig` | partial | `clone`, `verify`, `findLeafByOffset`, `addLeaf`, `computeMissingHashes`, hardened `combine` |
| `transaction/merkletreeparent.go` | `spv/merkle_tree_parent.zig` | done | Helper exported and used by MerklePath |
| `transaction/fee_model/*` | `transaction/fee_model/*` | partial | Sats-per-kb model implemented and tested |
| `transaction/fees.go` | `transaction/fees.zig` | partial | Deterministic remainder handling and change-output recomputation added |
| `transaction/template/pushdrop` | (none) | missing | Pushdrop template |
| `transaction/broadcaster/*` | `broadcast/woc.zig`, `broadcast/taal.zig`, `broadcast/arc.zig`, `broadcast/http_post.zig` | done | WhatsOnChain / TAAL / Arc HTTP clients aligned with Go; `zig build test` |
| `spv/*` | `spv/*` | partial | Merkle path + root transaction verification entrypoint; `verify`/`verifyBeef` can traverse available ancestor links, but the graph is still non-owning and not yet full Go parity |
| `compat/base58/*` | `primitives/base58.zig` | partial | Alphabet + checksum parity |
| `compat/bip32/*` | (none) | missing | HD keys |
| `compat/bip39/*` | (none) | missing | Mnemonic + wordlists |
| `compat/bsm/*` | (none) | missing | Bitcoin Signed Message |
| `compat/ecies/*` | (none) | missing | ECIES |

## Detailed gap backlog (priority tiers)

Roadmap derived from Go SDK parity review. Use this section for planning; the matrix above stays high-level.

### Tier 1 — high value, enables real usage

| Area | Go-style API | bsvz status |
| --- | --- | --- |
| Transaction | `AddInput` / `AddOutput` / `PayToAddress` / `Sign` / `Fee` / totals | Partial — `Builder` now supports input/output append, `PayToAddress`, `addInputFromTx`, and P2PKH signing; fee orchestration and broader template/signer parity still missing |
| Keys | `PrivateKey.DeriveSharedSecret`, `PublicKey.DeriveSharedSecret` | Missing — ECDH |
| Keys | `PrivateKey.DeriveChild` / `PublicKey.DeriveChild` (Type-42 / BRC-42) | Missing |
| Compat | `compat/bsm` sign / verify / recover | Missing |
| Signatures | `SignCompact` / `RecoverCompact` | Missing |

### Tier 2 — ecosystem compat

| Area | Notes |
| --- | --- |
| `compat/ecies` | Single / shared / electrum-style |
| Script | `IsP2PKH` / `IsP2PK` / `IsData` / `IsMultiSigOut`, `PublicKeyHash`, `Addresses` |
| Script | `AppendPushData` / `AppendOpcodes`, `NewFromHex` / `NewFromASM`, `ToASM()` |
| Transaction | `Hex()` variants for EF; BEEF helpers on `Transaction` type; `IsCoinbase`, input/output totals, `Fee()` — align with Go surface |
| MerklePath | `FromHex` / `Hex()` (serialization exists as `bytes`; hex wrappers missing) |

Note: `Transaction.clone` / `serializeExtended` exist in `transaction.zig`; matrix “Clone” gap is mostly API discoverability / Go naming parity.

### Tier 3 — compat layer / lower priority

| Area | Notes |
| --- | --- |
| `compat/bip32` | xpriv/xpub, paths, child derivation |
| `compat/bip39` | Entropy, word lists, seed |
| MerklePath | `Verify` (chain tracker), `FindLeafByOffset`, `AddLeaf`, `ComputeMissingHashes` |
| Keys | JSON marshaling on keys/sigs (low priority in Zig) |

### PrivateKey / PublicKey method checklist

| Go SDK | bsvz (`primitives/ec.zig`) |
| --- | --- |
| `PrivateKey.DeriveSharedSecret(pub)` | `PrivateKey.deriveSharedSecret` → `PublicKey` point |
| `PrivateKey.DeriveChild(pub, invoiceNumber)` | `PrivateKey.deriveChild` (BRC-42) |
| `PublicKey.DeriveChild(priv, invoiceNumber)` | `PublicKey.deriveChild` |
| `PublicKey.DeriveSharedSecret(priv)` | `PublicKey.deriveSharedSecret` |
| `PublicKey.Hash()` (hash160 compressed) | `PublicKey.hash160` |
| `PublicKey.ToDER` / `ToDERHex` | `toDer` / `toDerHex` (Go uses compressed SEC1, not ASN.1 SPKI) |
| `PublicKey.Validate()` | `validate` |
| `PublicKey.Addresses()` | Use `hash160` + `compat/address.encodeP2pkh` (avoid circular import on `ec`) |
| `SignCompact` / `RecoverCompact` | Still missing |

## Out-of-scope (current)

These Go SDK areas are not targeted yet:

- `wallet/*`
- `auth/*`
- `identity/*`
- `overlay/*`
- `message/*`
- `storage/*`
- `kvstore/*`
- `registry/*`
