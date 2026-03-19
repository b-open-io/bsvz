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
- crypto: sha256, hash256, ripemd160, hash160, secp256k1 private/public keys, public secp256k1 point API backed by Zig stdlib primitives, DER signatures, tx-signature helpers
- compat: legacy P2PKH address and WIF encode/decode
- transaction: legacy transaction parse/serialize, txid, replay-protected sighash/preimage helpers, P2PKH spend helpers
- script: ScriptNum, byte helpers, script parser/chunks, broad opcode set, general execution engine, transaction-aware CHECKSIG/CHECKMULTISIG, Go-shaped policy enforcement, P2PKH and OP_RETURN templates

Current construction zones:

- SPV is not yet real beyond placeholders and type stubs
- broadcast is not yet real beyond namespace scaffolding
- a small local downstream Runar conformance lane remains in the default test suite, but the broader Runar example-contract world belongs in the `runar` repo, not in `bsvz`

Current interpreter target:

- drive `bsvz.script` to full BSV consensus compliance
- keep using Go parity vectors and real Runar execution as the main regression oracles while closing the remaining gaps

Current script-interpreter status:

- Go corpus accounting is complete: all 1,499 rows in Go's `script_tests.json` are now accounted for
- executable Go-row coverage is complete: 1,438 executable exact-row references are in the suite, with the remaining 61 rows explicitly tracked as non-executable header/comment/meta rows
- the suite also keeps a 1,099-row filtered bulk-corpus lane plus focused filtered sigcheck and multisig reference lanes for mixed policy/result-shape coverage
- that does not mean the entire repository is “done”: SPV and broadcast are still construction zones, Runar local acceptance is broad but not complete, and the project still treats full BSV consensus confidence as the long-term script target

## Script Verification APIs

`bsvz` does not ship a framework-specific adapter layer, but the current public verification and tracing surface is already usable from downstream consumers such as `runar-zig` and local fixture-driven flows.

- plain script pair: `bsvz.script.thread.verifyScripts(...)` or `ScriptThread.verifyPair(...)`
- executable/full-locking-script pair: `bsvz.script.thread.verifyExecutableScripts(...)`
- spend directly against a previous output: `bsvz.script.thread.verifyPrevoutSpend(...)`, `verifyPrevoutSpendDetailed(...)`, `verifyPrevoutSpendTraced(...)`
- direct compact outcomes: `verifyScriptsOutcome(...)`, `verifyExecutableScriptsOutcome(...)`, `verifyPrevoutSpendOutcome(...)`, `bsvz.script.interpreter.verifyOutcome(...)`, and `verifyPrevoutOutcome(...)`
- small spend wrappers: `bsvz.script.interpreter.verify(...)` and `verifyPrevout(...)`
- detailed verification result: `bsvz.script.thread.verifyScriptsDetailed(...)`, `verifyExecutableScriptsDetailed(...)`, and `bsvz.script.interpreter.verifyDetailed(...)`
- opt-in execution traces: `bsvz.script.thread.verifyScriptsTraced(...)`, `verifyExecutableScriptsTraced(...)`, and `bsvz.script.interpreter.verifyTraced(...)`

That means:

- `true`: script pair verified
- `false`: the script evaluated cleanly but failed its final truthiness / `VERIFY` outcome
- `error.*`: policy, parsing, encoding, or transaction-context failure

If you want the non-collapsed Zig-native shape, use the detailed result:

- `result.terminal == .success`
- `result.terminal == .false_result`
- `result.terminal == .script_error`, with `result.phase` and `result.script_error`

If you need negative-path debugging, the traced APIs also return a step trace with:

- phase
- opcode offset / opcode byte
- pre-step stack and altstack snapshots
- condition stack snapshot
- `ops_executed` and `last_code_separator` before the step

Both `VerificationResult` and traced results now have `writeDebug(...)` helpers for direct Zig-side debugging.

Minimal pair verification:

```zig
var thread = bsvz.script.thread.ScriptThread.init(.{ .allocator = allocator });
defer thread.deinit();

const ok = try thread.verifyPair(
    bsvz.script.Script.init(unlocking_bytes),
    bsvz.script.Script.init(locking_bytes),
);
```

Spend verification against a previous output:

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

The lower-level `verifyExecutableScripts(...)` entry point still trims any state suffix from the locking script for execution while preserving the full previous locking script in the spend context for sighash checks, but `bsvz.script.interpreter.verifyPrevout*` is now the smaller Runar-facing seam.

Tiny trace example:

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

There is also a tiny standalone example in [examples/script_trace_demo.zig](/Users/satchmo/code/bsvz/examples/script_trace_demo.zig).
For prevout-shaped spends, there is a matching traced example in [examples/prevout_trace_demo.zig](/Users/satchmo/code/bsvz/examples/prevout_trace_demo.zig).

Runar-adjacent helpers already present in the library:

- secp256k1 point API: `bsvz.crypto.Point.fromCompressedSec1`, `fromRaw64`, `toCompressedSec1`, `toRaw64`, `xBytes32`, `yBytes32`, `add`, `mul`, `negate`
- output serialization and hashing: `bsvz.transaction.Output.serialize(...)`, `writeInto(...)`, `parse(...)`, `hash256(...)`, `hashAll(...)`
- transaction serialization and txid: `bsvz.transaction.Transaction.serialize(...)` and `tx.txid(...)`

Tiny serialization example:

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

std.debug.print("{s} {x}\n", .{ std.fmt.fmtSliceHexLower(raw), hash_all });
_ = parsed;
```

## Script Interpreter Coverage

This is the current interpreter map for `bsvz.script`.

| Area | Coverage | Notes |
| --- | --- | --- |
| Script bytes, chunks, parser, serializer | implemented | direct pushes, `PUSHDATA1/2/4`, chunk roundtrip, malformed pushdata rejection |
| Script thread / seam orchestration | implemented | dedicated script-pair orchestration module separates verification seam behavior from the opcode loop and owns the “full previous locking script for sighash, executable prefix for execution” split |
| Push-only and script inspection helpers | implemented | `isPushOnly`, `hasCodeSeparator`, top-level `OP_RETURN` tail handling, and push-only seam behavior |
| Execution core | implemented | stack, altstack, condition stack, truthiness, op counting, stack limits |
| Control flow | implemented | `IF`, `NOTIF`, `ELSE`, `ENDIF`, `VERIFY`, legacy vs post-Genesis multi-`ELSE` behavior, post-Genesis `OP_RETURN`, `CODESEPARATOR` |
| Stack ops | complete | exact stack-shape, underflow, altstack, pair-rotation, and stack-index lanes cover `DUP`, `DROP`, `SWAP`, `ROT`, `ROLL`, `PICK`, `2DUP`, `2DROP`, `2OVER`, `2ROT`, `2SWAP`, `3DUP`, `IFDUP`, `TOALTSTACK`, `FROMALTSTACK`, and `TUCK` |
| Byte/splice ops | broad coverage | `CAT`, `SPLIT`, `NUM2BIN`, `BIN2NUM`, `SIZE` |
| Bitwise ops | implemented | `INVERT`, `AND`, `OR`, `XOR`, `LSHIFT`, `RSHIFT` |
| Numeric and boolean ops | broad coverage | `ADD`, `SUB`, `MUL`, `DIV`, `MOD`, comparisons, min/max, within, boolean logic |
| Hash ops | implemented | `RIPEMD160`, `SHA1`, `SHA256`, `HASH160`, `HASH256` |
| `ScriptNum` | implemented | small-or-big numeric core using Zig stdlib bigint for promoted values |
| `CHECKSIG` | implemented | transaction-aware, BSV-only, legacy and ForkID paths, `CODESEPARATOR` handling, scriptCode normalization |
| `CHECKMULTISIG` | implemented | transaction-aware, post-Genesis behavior, early-exit behavior, `NULLDUMMY` / `NULLFAIL` / ForkID policy coverage |
| Policy flags | broad coverage | `strict_encoding`, `der_signatures`, `low_s`, `strict_pubkey_encoding`, `null_dummy`, `null_fail`, `sig_push_only`, `clean_stack`, `minimal_data`, `minimal_if`, `discourage_upgradable_nops`, `verify_check_locktime`, `verify_check_sequence` |
| CLTV / CSV / upgradable NOP surface | partial but real | `CLTV` and `CSV` now have tx-aware legacy/reference semantics behind explicit flags; the modern BSV profile still treats them as inert unless policy says otherwise |
| Numeric minimal-encoding parity | implemented | minimal push and minimal numeric decoding are both enforced where Go applies `MINIMALDATA`, with a dedicated minimaldata vector lane |
| `CODESEPARATOR` parity | broad coverage | legacy and ForkID scriptCode behavior, chained separator result-shape tests, parser/scanner coverage |
| Go parity vectors | full corpus accounting, full executable-row coverage | All 1,499 rows in Go's `script_tests.json` corpus are now accounted for. That includes 1,438 executable exact-row references spanning the dedicated lanes: control-flow, seam, parser, reserved/NOP, sigcheck, multisig, minimaldata, numeric, boolean/numeric, bitwise, bytes/hash, stack-shape, stack-index, disabled-opcode, bin2num, and the direct exact-corpus lane sourced from `script_tests.json`, plus 61 explicitly audited non-executable header/comment/meta rows. A filtered bulk-corpus lane still executes 1,099 safe Go rows, and focused filtered sigcheck/multisig reference lanes keep mixed policy/result-shape coverage in the suite |
| Downstream Runar coverage | optional smoke + acceptance lane | default `zig build test` keeps a small downstream smoke lane via `tests/runar_conformance.zig`; the broader fixture-heavy acceptance suite in `tests/local_runar_acceptance.zig` is intentionally demoted to the optional `zig build test-runar-acceptance` path so `bsvz` stays centered on Go SDK parity rather than owning the full Runar example world |
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
- target full BSV consensus compliance for script execution
- prioritize script execution and downstream Runar integration before broadening into secondary areas

## Benchmarking

The repo now includes two interpreter benchmark harnesses:

- `zig build bench`
  - runs [benchmarks/script_engine.zig](/Users/satchmo/code/bsvz/benchmarks/script_engine.zig)
  - measures `bsvz` interpreter hot paths on prebuilt workloads
- `cd benchmarks/go_sdk && GOCACHE=/tmp/go-build-bsvz go test -run '^$' -bench . -benchmem`
  - runs [benchmarks/go_sdk/script_engine_bench_test.go](/Users/satchmo/code/bsvz/benchmarks/go_sdk/script_engine_bench_test.go)
  - measures the local `go-sdk` interpreter against comparable workload families
- `cd ../bsvz-autotrainer && bun bench:pipe`
  - runs the live-corpus transaction pipeline benchmark against the sibling `bsvz-autotrainer` harness
  - measures end-to-end NDJSON ingest, tx decoding/parsing, script validation, and prevout spend verification against the local Go comparison binary

Current benchmark shape:

- arithmetic verification
- branching verification
- `SHA256` verification
- `HASH160` verification
- stack-operation verification
- synthetic P2PKH verification
- Go-reference P2PKH verification

The benchmark harnesses intentionally use prebuilt script/transaction fixtures for verification workloads. They do not include key generation or per-iteration signing overhead in the hot loop.

Important benchmark nuance:

- the simple script-only workloads are closely comparable across the Zig and Go harnesses
- the synthetic P2PKH row is still a local diagnostic
- the `Go reference tx` P2PKH row uses the same transaction fixture as the Go benchmark and is the honest cross-language comparison point
- the Zig `sighash only` and `secp verify only` diagnostics are useful for local profiling, but they are not mirrored by identical Go sub-benchmarks yet

Current local baseline on Apple M3 Max:

| Workload | `bsvz` | `go-sdk` |
| --- | --- | --- |
| arithmetic verify | ~0.11 us/op | ~3.7 us/op |
| branching verify | ~0.10 us/op | ~4.6 us/op |
| `SHA256` verify | ~0.11 us/op | ~3.9 us/op |
| `HASH160` verify | ~0.28 us/op | ~4.0 us/op |
| stack ops verify | ~0.30 us/op | ~12.7 us/op |
| P2PKH verify (Go reference tx) | ~219.0 us/op | ~227.4 us/op |

Useful local diagnostics for `bsvz` on the same machine:

- P2PKH sighash only: ~0.30 us/op
- P2PKH secp verify only: ~179.9 us/op
- P2PKH verify (synthetic fixture): ~208.7 us/op
- downstream compiled-script workload (`runar arithmetic verify`): ~0.55 us/op in `bsvz` vs ~19.7 us/op in `go-sdk`

Live corpus baseline from `bsvz-autotrainer` on the same machine:

| Workload | `bsvz` | `go-sdk` |
| --- | --- | --- |
| JungleBus-style corpus wall clock | ~1720 ms | ~1851 ms |
| tx throughput | ~1907 tx/s | ~1772 tx/s |
| parse+spend throughput | ~13121 ops/s | ~12194 ops/s |

Final measured phase split on that corpus:

- `json_dom_ms`: `bsvz` ~492 ms vs `go-sdk` ~517 ms
- `tx_hex_ms`: `bsvz` ~38 ms vs `go-sdk` ~59 ms
- `spend_verify_ms`: `bsvz` ~1146 ms vs `go-sdk` ~1224 ms

That split matters because it shows the remaining cost is concentrated in secp verification, not the script engine or sighash path. `bsvz` now uses a secp256k1 double-base verification fast path built on Zig stdlib curve primitives, which is what moved full P2PKH verification from roughly ~433 us/op down to ~199 us/op.

These numbers are a local baseline, not a universal claim. The important point is that `bsvz` now has a repeatable local benchmark story against the Go SDK, and the benchmark picture is no longer dominated by allocator noise or avoidable verifier overhead.
