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
- the script interpreter now combines 1,263 unique exact Go row references across the dedicated lanes, including a new direct exact-corpus lane sourced from `script_tests.json`, with a 1,099-row filtered bulk-corpus lane and two conservative exact reference lanes for sigcheck and multisig mixed policy/result-shape rows (30 and 24 rows respectively); exact Go-row coverage is now 84.3% of the 1,499-row corpus, but the full corpus is still not green end-to-end
- native execution coverage for compiled Runar contracts is broad and growing, including pure conformance contracts like `if-else`, `if-without-else`, `bounded-loop`, and `multi-method`, plus auction lifecycle, escrow, tic-tac-toe terminal flows, fungible-token merge/transfer, NFT, SHA-256/BLAKE3 crypto paths, `P2Blake3PKH`, and negative covenant checks, but not complete

Current interpreter target:

- drive `bsvz.script` to full BSV consensus compliance
- keep using Go parity vectors and real Runar execution as the main regression oracles while closing the remaining gaps

## Runar-Facing Ergonomics

`bsvz` does not ship a dedicated Runar adapter yet, but the current public surface is already usable from `runar-zig` and local fixture-driven flows.

- plain executable pair: `bsvz.script.thread.verifyScripts(...)` or `ScriptThread.verifyPair(...)`
- spend with transaction context: `bsvz.script.thread.verifyExecutableScripts(...)`
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
| Stack ops | broad coverage | includes `DUP`, `DROP`, `SWAP`, `ROT`, `ROLL`, `PICK`, `2DUP`, `2DROP`, `2OVER`, `2ROT`, `2SWAP`, `3DUP`, `IFDUP`, `TOALTSTACK`, `FROMALTSTACK` |
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
| Go parity vectors | broad and still comfortably past the 75% local-corpus milestone | 1,263 unique exact Go row references now span the dedicated lanes: control-flow, seam, parser, reserved/NOP, sigcheck, multisig, minimaldata, numeric, boolean/numeric, bitwise, bytes/hash, stack-shape, stack-index, disabled-opcode, bin2num, and a direct exact-corpus lane sourced from `script_tests.json`. A filtered bulk-corpus lane still executes 1,099 more safe Go rows, and conservative sigcheck/multisig reference lanes add 30 and 24 mixed policy/result-shape rows respectively. Exact Go-row coverage is now 84.3% of the 1,499-row corpus; the full corpus is still not green end-to-end |
| Runar local acceptance | broad but incomplete | real local acceptance now covers pure conformance contracts like `if-else`, `if-without-else`, `bounded-loop`, and `multi-method`, plus stateless, stateful, covenant, auction, escrow, tic-tac-toe terminal flows, NFT, fungible-token merge/transfer, SHA-256/BLAKE3 crypto paths, and `P2Blake3PKH`, including negative covenant checks, but the full Runar corpus is not yet green |
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
