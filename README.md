![bsvz](assets/banner.png)

# bsvz

BSV foundation library for Zig. Full Go SDK parity: keys, scripts, transactions, SPV, BEEF, and broadcast.

## Table of Contents

- [Status](#status)
- [Getting Started](#getting-started)
- [Module Layout](#module-layout)
- [Documentation](#documentation)
- [Standards Coverage](#standards-coverage)
- [Script Verification APIs](#script-verification-apis)
- [Interpreter Coverage](#interpreter-coverage)
- [Benchmarks](#benchmarks)

## Status

Go SDK feature parity across crypto, keys, script, transactions, SPV, BEEF, and broadcast. 27 BRC standards covered.

<details>
<summary>Details</summary>

**Implemented:**

- `primitives`: hex, varint, base58, base58check, network/version-byte helpers, chainhash (display-order hash type), EC curve wrapper with ECDH and Type-42 key derivation, ECDSA signatures with low-S normalization, Schnorr proofs, AES-CBC, AES-GCM, symmetric key encryption, Shamir secret sharing (key shares, backup format), HMAC-DRBG, BIP32 HD keys (xpriv/xpub, child derivation), BIP39 mnemonics (English wordlist, PBKDF2 seed), BRC-43 invoice strings
- `crypto`: sha256, sha512, hash256, ripemd160, hash160, hmacSha256, hmacSha512, secp256k1 private/public keys, secp256k1 point API, DER signatures, compact signatures with recovery, ECIES (Electrum + Bitcore), tx-signature helpers
- `compat`: P2PKH address, WIF encode/decode, Bitcoin Signed Message (sign/verify/recover), ECIES
- `transaction`: parse/serialize (standard + extended format), txid, sighash/preimage, P2PKH spend helpers, BEEF V1/V2/Atomic, transaction builder (addInput/addOutput/payToAddress/sign), fee calculation with pluggable models, change distribution
- `script`: ScriptNum, parser/chunks, broad opcode set, execution engine, transaction-aware CHECKSIG/CHECKMULTISIG, Go-shaped policy enforcement, ASM encode/decode, script builder (appendPushData/appendOpcodes), type detection (isP2PKH/isP2PK/isData/isMultiSigOut), templates (P2PKH, OP_RETURN, PushDrop, R-puzzle, OP_TRUE, Push TX), script clone/ownership
- `spv`: MerklePath parse/serialize/computeRoot/combine/verify, MerkleTreeParent, ancestor traversal, BEEF verification, pluggable chain tracker interface
- `message`: BRC-77 signed messages (sign/verify) and BRC-78 encrypted messages (encrypt/decrypt)
- `broadcast`: WhatsOnChain, TAAL, and Arc HTTP broadcast clients

**Go corpus accounting:**

- All 1,499 rows in Go's `script_tests.json` are accounted for
- 1,435 executable rows passing in the filtered corpus lane
- 64 rows tracked as meta/non-executable

</details>

## Getting Started

**Requirements:** Zig `0.15.2`

Add `bsvz` to your `build.zig.zon`:

```zig
.dependencies = .{
    .bsvz = .{
        .url = "https://github.com/bsv-blockchain/bsvz/archive/<commit>.tar.gz",
        .hash = "<hash>",
    },
},
```

Then add it to your `build.zig`:

```zig
const bsvz = b.dependency("bsvz", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("bsvz", bsvz.module("bsvz"));
```

Run tests:

```bash
zig build test
```

## Module Layout

| Module | Description |
| --- | --- |
| `bsvz.primitives` | Hex, varint, base58, base58check, version-byte helpers |
| `bsvz.primitives.chainhash` | Display-order (reverse hex) hash type, single/double hash helpers |
| `bsvz.primitives.ec` | EC curve wrapper, PrivateKey, PublicKey, key generation, ECDH, Type-42 derivation |
| `bsvz.primitives.ecdsa` | ECDSA signature type with DER encoding and low-S normalization |
| `bsvz.primitives.schnorr` | Schnorr DLEQ proof generation and verification |
| `bsvz.primitives.keyshares` | Shamir secret sharing: polynomial, key shares, backup format |
| `bsvz.primitives.aescbc` | AES-CBC encrypt/decrypt with PKCS7 padding (128/256-bit keys) |
| `bsvz.primitives.aesgcm` | AES-GCM encrypt/decrypt with authentication tags (128/256-bit keys) |
| `bsvz.primitives.symmetric` | Symmetric key wrapper with encrypt/decrypt |
| `bsvz.primitives.drbg` | HMAC-DRBG deterministic random bit generator |
| `bsvz.primitives.bip32` | HD key derivation: ExtendedKey, xpriv/xpub, child paths, mainnet/testnet, `masterFromMnemonic` |
| `bsvz.primitives.bip39` | Mnemonic generation, English wordlist, entropy, PBKDF2 seed derivation |
| `bsvz.primitives.brc43` | BRC-43 protocol ID normalization and `<level>-<protocol>-<key>` invoice strings |
| `bsvz.crypto` | SHA256, SHA512, RIPEMD160, HASH160, HASH256, HMAC-SHA256, HMAC-SHA512, secp256k1 keys and point API, DER and compact signatures, ECIES |
| `bsvz.script` | Script parser, opcode set, execution engine, policy flags, ASM encode/decode, script builder, type detection |
| `bsvz.transaction` | Parse, serialize (standard + extended format), sighash, P2PKH spend helpers |
| `bsvz.transaction.builder` | Transaction builder: addInput, addOutput, payToAddress, sign, applyFee |
| `bsvz.transaction.beef` | BEEF V1/V2/Atomic parse, serialize, and transaction extraction |
| `bsvz.transaction.fees` | Fee calculation, change distribution, total input/output satoshis |
| `bsvz.transaction.fee_model` | Pluggable fee models (satoshis-per-kilobyte) |
| `bsvz.message` | BRC-77 portable signed messages (`signed`); BRC-78 portable encrypted messages (`encrypted`) |
| `bsvz.compat` | P2PKH address, WIF encode/decode, Bitcoin Signed Message, ECIES |
| `bsvz.spv` | MerklePath, MerkleTreeParent, BlockHeader, SPV and BEEF verification |
| `bsvz.broadcast` | WhatsOnChain, TAAL, Arc HTTP broadcast clients |

## Documentation

- [docs/README.md](./docs/README.md)
- [docs/examples/README.md](./docs/examples/README.md)
- [docs/concepts/README.md](./docs/concepts/README.md)
- [docs/low-level/README.md](./docs/low-level/README.md)

## Standards Coverage

<details>
<summary>27 BRC standards covered — full spec index at bsv.brc.dev</summary>

| Standard | Title | Module |
| --- | --- | --- |
| BRC&#8209;2 | [Data Encryption and Decryption](https://bsv.brc.dev/wallet/0002) | `primitives.aescbc`, `primitives.aesgcm`, `primitives.symmetric` |
| BRC&#8209;3 | [Digital Signature Creation and Verification](https://bsv.brc.dev/wallet/0003) | `primitives.ec`, `primitives.ecdsa`, `crypto.secp256k1` |
| BRC&#8209;8 | [Everett-style Transaction Envelopes](https://bsv.brc.dev/transactions/0008) | `transaction` |
| BRC&#8209;9 | [Simplified Payment Verification](https://bsv.brc.dev/transactions/0009) | `spv.verify`, `spv.verifyBeef` |
| BRC&#8209;12 | [Raw Transaction Format](https://bsv.brc.dev/transactions/0012) | `transaction` |
| BRC&#8209;14 | [Script Binary, Hex, and ASM Formats](https://bsv.brc.dev/scripts/0014) | `script`, `script.asm` |
| BRC&#8209;16 | [Pay to Public Key Hash](https://bsv.brc.dev/scripts/0016) | `script.templates.p2pkh`, `compat.address` |
| BRC&#8209;17 | [Pay to R Puzzle Hash](https://bsv.brc.dev/scripts/0017) | `script.templates.r_puzzle` |
| BRC&#8209;18 | [Pay to False Return](https://bsv.brc.dev/scripts/0018) | `script.templates.op_return` |
| BRC&#8209;19 | [Pay to True Return](https://bsv.brc.dev/scripts/0019) | `script.templates.op_true` |
| BRC&#8209;30 | [Transaction Extended Format (EF)](https://bsv.brc.dev/transactions/0030) | `transaction` |
| BRC&#8209;32 | [BIP32 Key Derivation](https://bsv.brc.dev/key-derivation/0032) | `primitives.bip32` |
| BRC&#8209;36 | [Format for Bitcoin Outpoints](https://bsv.brc.dev/outpoints/0036) | `transaction.OutPoint` |
| BRC&#8209;42 | [BSV Key Derivation Scheme (Type&#8209;42)](https://bsv.brc.dev/key-derivation/0042) | `primitives.ec` (`deriveChild`, `deriveSharedSecret`) |
| BRC&#8209;43 | [Security Levels, Protocol IDs, Key IDs](https://bsv.brc.dev/key-derivation/0043) | `primitives.brc43` (parity with go-sdk `wallet/key_deriver.go` / ts-sdk `KeyDeriver`), `primitives.ec` (`deriveChild`) |
| BRC&#8209;47 | [Bare Multi-Signature](https://bsv.brc.dev/scripts/0047) | `script` |
| BRC&#8209;48 | [Pay to Push Drop](https://bsv.brc.dev/scripts/0048) | `script.templates.pushdrop` |
| BRC&#8209;61 | [Compound Merkle Path Format](https://bsv.brc.dev/transactions/0061) | `spv.MerklePath` |
| BRC&#8209;62 | [BEEF Transactions](https://bsv.brc.dev/transactions/0062) | `transaction.beef` |
| BRC&#8209;67 | [Simplified Payment Verification](https://bsv.brc.dev/transactions/0067) | `spv` |
| BRC&#8209;74 | [BSV Unified Merkle Path (BUMP)](https://bsv.brc.dev/transactions/0074) | `spv.MerklePath` |
| BRC&#8209;75 | [Mnemonic for Master Private Key](https://bsv.brc.dev/key-derivation/0075) | `primitives.bip39` |
| BRC&#8209;77 | [Message Signature Creation and Verification](https://bsv.brc.dev/peer-to-peer/0077) | `message.signed` (portable wire); legacy BSM: `compat.bsm`, `crypto.compact` |
| BRC&#8209;78 | [Portable Encrypted Messages](https://bsv.brc.dev/peer-to-peer/0078) | `message.encrypted` (BRC-78 wire); Electrum/Bitcore ECIES: `crypto.ecies`, `compat.ecies` |
| BRC&#8209;94 | [Schnorr Shared Secret Revelation](https://bsv.brc.dev/key-derivation/0094) | `primitives.schnorr` |
| BRC&#8209;95 | [Atomic BEEF Transactions](https://bsv.brc.dev/transactions/0095) | `transaction.beef` |
| BRC&#8209;96 | [BEEF V2 Txid Only Extension](https://bsv.brc.dev/transactions/0096) | `transaction.beef` |

</details>

## Script Verification APIs

The verification surface covers plain script pairs, full prevout spends, detailed results, and step traces.

<details>
<summary>API reference and examples</summary>

### Entry points

| Function | Description |
| --- | --- |
| `bsvz.script.thread.verifyScripts(...)` | Verify a plain unlocking/locking script pair |
| `bsvz.script.thread.ScriptThread.verifyPair(...)` | Same, on a reusable thread |
| `bsvz.script.thread.verifyExecutableScripts(...)` | Verify an executable/full-locking-script pair |
| `bsvz.script.thread.verifyPrevoutSpend(...)` | Verify a spend against a previous output |
| `bsvz.script.thread.verifyPrevoutSpendDetailed(...)` | Same, with structured result |
| `bsvz.script.thread.verifyPrevoutSpendTraced(...)` | Same, with step trace |
| `bsvz.script.interpreter.verify(...)` | Small wrapper for simple verification |
| `bsvz.script.interpreter.verifyPrevout(...)` | Small wrapper for prevout verification |
| `bsvz.script.interpreter.verifyDetailed(...)` | Detailed result variant |
| `bsvz.script.interpreter.verifyTraced(...)` | Traced variant |

**Return shapes:**

- `true` / `false`: script evaluated cleanly, result is the final truthiness
- `error.*`: policy, parsing, encoding, or transaction-context failure; `result.terminal` gives `.success`, `.false_result`, or `.script_error`

**Detailed result fields:** `result.phase`, `result.script_error`

**Trace step fields:** phase, opcode offset, opcode byte, pre-step stack/altstack/condition-stack snapshots, `ops_executed`, `last_code_separator`

Both `VerificationResult` and traced results have `writeDebug(...)` helpers.

### Minimal pair verification

```zig
var thread = bsvz.script.thread.ScriptThread.init(.{ .allocator = allocator });
defer thread.deinit();

const ok = try thread.verifyPair(
    bsvz.script.Script.init(unlocking_bytes),
    bsvz.script.Script.init(locking_bytes),
);
```

### Prevout spend verification

```zig
const previous_output = previous_tx.outputs[previous_output_index];

var result = bsvz.script.interpreter.verifyPrevoutDetailed(.{
    .allocator = allocator,
    .tx = &spend_tx,
    .input_index = spend_input_index,
    .previous_output = previous_output,
    .unlocking_script = spend_tx.inputs[spend_input_index].unlocking_script,
});
defer result.deinit(allocator);

if (result.terminal == .script_error) return result.script_error.?;
const ok = result.success;
```

### Step trace

```zig
var traced = bsvz.script.thread.verifyScriptsTraced(.{
    .allocator = allocator,
}, bsvz.script.Script.init(&[_]u8{}), bsvz.script.Script.init(&[_]u8{
    @intFromEnum(bsvz.script.opcode.Opcode.OP_1),
    @intFromEnum(bsvz.script.opcode.Opcode.OP_FROMALTSTACK),
}));
defer traced.deinit(allocator);

try traced.writeDebug(std.io.getStdOut().writer());
```

### Output serialization

```zig
const output = bsvz.transaction.Output{
    .satoshis = 42,
    .locking_script = bsvz.script.Script.init(&[_]u8{0x6a}),
};

var raw = try allocator.alloc(u8, output.serializedLen());
defer allocator.free(raw);
_ = output.writeInto(raw);

const parsed = try bsvz.transaction.Output.parse(raw);
const hash_all = try bsvz.transaction.Output.hashAll(allocator, &[_]bsvz.transaction.Output{output});
```

### Examples

- Plain script trace: [./examples/script_trace_demo.zig](./examples/script_trace_demo.zig)
- Prevout spend trace: [./examples/prevout_trace_demo.zig](./examples/prevout_trace_demo.zig)
- Hash demo: [./examples/hash_demo.zig](./examples/hash_demo.zig)
- GorillaPool ARC broadcast: [./examples/gorillapool_arc_demo.zig](./examples/gorillapool_arc_demo.zig)

### secp256k1 point API

`bsvz.crypto.Point`: `fromCompressedSec1`, `fromRaw64`, `toCompressedSec1`, `toRaw64`, `xBytes32`, `yBytes32`, `add`, `mul`, `negate`

</details>

## Interpreter Coverage

<details>
<summary>Coverage map</summary>

| Area | Status | Notes |
| --- | --- | --- |
| Script bytes, chunks, parser, serializer | implemented | direct pushes, `PUSHDATA1/2/4`, chunk roundtrip, malformed pushdata rejection |
| Script thread / seam orchestration | implemented | separates seam behavior from the opcode loop; owns the "full previous locking script for sighash, executable prefix for execution" split |
| Push-only and script inspection helpers | implemented | `isPushOnly`, `hasCodeSeparator`, top-level `OP_RETURN` tail handling |
| Execution core | implemented | stack, altstack, condition stack, truthiness, op counting, stack limits |
| Control flow | implemented | `IF`, `NOTIF`, `ELSE`, `ENDIF`, `VERIFY`, legacy vs post-Genesis multi-`ELSE`, post-Genesis `OP_RETURN`, `CODESEPARATOR` |
| Stack ops | complete | `DUP`, `DROP`, `SWAP`, `ROT`, `ROLL`, `PICK`, `2DUP`, `2DROP`, `2OVER`, `2ROT`, `2SWAP`, `3DUP`, `IFDUP`, `TOALTSTACK`, `FROMALTSTACK`, `TUCK` |
| Byte/splice ops | broad | `CAT`, `SPLIT`, `NUM2BIN`, `BIN2NUM`, `SIZE` |
| Bitwise ops | implemented | `INVERT`, `AND`, `OR`, `XOR`, `LSHIFT`, `RSHIFT` |
| Numeric and boolean ops | broad | `ADD`, `SUB`, `MUL`, `DIV`, `MOD`, comparisons, min/max, within, boolean logic |
| Hash ops | implemented | `RIPEMD160`, `SHA1`, `SHA256`, `HASH160`, `HASH256` |
| `ScriptNum` | implemented | small-or-big numeric core using Zig stdlib bigint for promoted values |
| `CHECKSIG` | implemented | transaction-aware, legacy and ForkID paths, `CODESEPARATOR` handling, scriptCode normalization |
| `CHECKMULTISIG` | implemented | transaction-aware, post-Genesis behavior, early-exit, `NULLDUMMY`/`NULLFAIL`/ForkID policy |
| Policy flags | broad | `strict_encoding`, `der_signatures`, `low_s`, `strict_pubkey_encoding`, `null_dummy`, `null_fail`, `sig_push_only`, `clean_stack`, `minimal_data`, `minimal_if`, `discourage_upgradable_nops`, `verify_check_locktime`, `verify_check_sequence` |
| CLTV / CSV / upgradable NOPs | partial | tx-aware legacy/reference semantics behind explicit flags; modern BSV profile treats them as inert unless policy enables them |
| Numeric minimal-encoding parity | implemented | minimal push and minimal numeric decoding enforced where Go applies `MINIMALDATA` |
| `CODESEPARATOR` parity | broad | legacy and ForkID scriptCode behavior, chained separator tests, parser/scanner coverage |
| Go parity vectors | full | all 1,499 rows in Go's `script_tests.json` accounted for; 1,435 executable rows passing; 64 meta/non-executable rows tracked |
| Runar conformance | smoke lane | `zig build test` runs `tests/runar_conformance.zig`; full acceptance suite is `zig build test-runar-acceptance` |
| SPV / proof tooling | implemented | MerklePath parse/serialize/computeRoot/combine/verify, ancestor traversal, BEEF verification, pluggable chain tracker |

**Scope:**

- Modern BSV script execution and post-Genesis behavior

</details>

## Benchmarks

<details>
<summary>Harnesses and results (Apple M3 Max)</summary>

**Harnesses:**

```bash
# bsvz interpreter
zig build bench

# Go SDK comparison
cd benchmarks/go_sdk && GOCACHE=/tmp/go-build-bsvz go test -run '^$' -bench . -benchmem

# Live corpus pipeline (requires sibling bsvz-autotrainer repo)
cd ../bsvz-autotrainer && bun bench:pipe
```

Source: [./benchmarks/script_engine.zig](./benchmarks/script_engine.zig), [./benchmarks/go_sdk/script_engine_bench_test.go](./benchmarks/go_sdk/script_engine_bench_test.go)

Benchmarks use prebuilt fixtures. Key generation and per-iteration signing are excluded from the hot loop.

**Script engine (Apple M3 Max):**

| Workload | `bsvz` | `go-sdk` |
| --- | --- | --- |
| arithmetic verify | ~0.11 us/op | ~3.7 us/op |
| branching verify | ~0.10 us/op | ~4.6 us/op |
| SHA256 verify | ~0.11 us/op | ~3.9 us/op |
| HASH160 verify | ~0.28 us/op | ~4.0 us/op |
| stack ops verify | ~0.30 us/op | ~12.7 us/op |
| P2PKH verify (Go reference tx) | ~476.1 us/op | ~227.4 us/op |

**bsvz diagnostics:**

| Workload | `bsvz` |
| --- | --- |
| P2PKH sighash only | ~0.35 us/op |
| P2PKH secp verify only | ~433.8 us/op |
| P2PKH verify (synthetic fixture) | ~456.5 us/op |
| Runar arithmetic verify | ~0.57 us/op |

**Live corpus pipeline (JungleBus-style, via bsvz-autotrainer):**

| Workload | `bsvz` | `go-sdk` |
| --- | --- | --- |
| wall clock | ~1720 ms | ~1851 ms |
| tx throughput | ~1907 tx/s | ~1772 tx/s |
| parse+spend throughput | ~13121 ops/s | ~12194 ops/s |

Phase split:

| Phase | `bsvz` | `go-sdk` |
| --- | --- | --- |
| JSON DOM | ~492 ms | ~517 ms |
| tx hex decode | ~38 ms | ~59 ms |
| spend verify | ~1146 ms | ~1224 ms |

The remaining cost sits in secp verification. `bsvz` now uses Zig stdlib prehashed verification directly rather than a custom secp256k1 fast path.

These numbers are a local baseline on one machine; your results will vary with allocator configuration, CPU microarchitecture, and corpus mix.

</details>
