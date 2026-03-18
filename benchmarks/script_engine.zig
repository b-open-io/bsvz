const std = @import("std");
const bsvz = @import("bsvz");

const Script = bsvz.script.Script;
const engine = bsvz.script.engine;

// Script engine benchmarks.
//
// Run with: zig build bench
//
// Measures throughput of the bsvz script engine across representative
// Bitcoin Script workloads — from trivial arithmetic to real P2PKH
// CHECKSIG verification with transaction context.

const iterations = 10_000;

fn bench(comptime name: []const u8, comptime run_fn: fn (std.mem.Allocator) void) void {
    const allocator = std.heap.page_allocator;

    // Warmup
    for (0..100) |_| run_fn(allocator);

    const start = std.time.nanoTimestamp();
    for (0..iterations) |_| run_fn(allocator);
    const end = std.time.nanoTimestamp();

    const elapsed_ns: u64 = @intCast(end - start);
    const per_iter_ns = elapsed_ns / iterations;
    const per_iter_us = per_iter_ns / 1_000;
    const ops_per_sec = if (per_iter_ns > 0) 1_000_000_000 / per_iter_ns else 0;

    std.debug.print("{s:<50} {d:>8} ns/op  ({d:>6} us/op)  {d:>10} ops/sec\n", .{
        name,
        per_iter_ns,
        per_iter_us,
        ops_per_sec,
    });
}

// ---------------------------------------------------------------------------
// Benchmark cases
// ---------------------------------------------------------------------------

// OP_2 OP_3 OP_ADD OP_5 OP_NUMEQUAL
const arithmetic_script = [_]u8{ 0x52, 0x53, 0x93, 0x55, 0x9c };

fn benchArithmetic(allocator: std.mem.Allocator) void {
    var result = engine.executeScript(.{ .allocator = allocator }, Script.init(&arithmetic_script)) catch return;
    result.deinit(allocator);
}

// OP_1 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF OP_2 OP_NUMEQUAL
const branching_script = [_]u8{ 0x51, 0x63, 0x52, 0x67, 0x53, 0x68, 0x52, 0x9c };

fn benchBranching(allocator: std.mem.Allocator) void {
    var result = engine.executeScript(.{ .allocator = allocator }, Script.init(&branching_script)) catch return;
    result.deinit(allocator);
}

// SHA256: push 32 bytes, OP_SHA256, OP_SHA256, OP_SIZE, OP_1 OP_NUMEQUAL
// (just verify the hash produces a 32-byte result, avoids comptime hash)
const sha256_script = [_]u8{
    0x20, // push 32 bytes
} ++ [_]u8{0xab} ** 32 ++ [_]u8{
    0xa8, // OP_SHA256
    0x82, // OP_SIZE
    0x75, // OP_DROP (drop the hash, keep size)
    0x01, 0x20, // push 32
    0x9c, // OP_NUMEQUAL
};

fn benchSha256(allocator: std.mem.Allocator) void {
    var result = engine.executeScript(.{ .allocator = allocator }, Script.init(&sha256_script)) catch return;
    result.deinit(allocator);
}

// HASH160: push 20 bytes, OP_HASH160, OP_SIZE, push 20, OP_NUMEQUAL
const hash160_script = [_]u8{
    0x14, // push 20 bytes
} ++ [_]u8{0xcd} ** 20 ++ [_]u8{
    0xa9, // OP_HASH160
    0x82, // OP_SIZE
    0x75, // OP_DROP
    0x01, 0x14, // push 20
    0x9c, // OP_NUMEQUAL
};

fn benchHash160(allocator: std.mem.Allocator) void {
    var result = engine.executeScript(.{ .allocator = allocator }, Script.init(&hash160_script)) catch return;
    result.deinit(allocator);
}

// Deep stack ops: push 10 items, various DUPs/SWAPs/ROTs, then verify
fn buildStackOpsScript() [30]u8 {
    return [_]u8{
        0x51, 0x52, 0x53, 0x54, 0x55, // OP_1..OP_5
        0x56, 0x57, 0x58, 0x59, 0x5a, // OP_6..OP_10
        0x76, // OP_DUP
        0x7c, // OP_SWAP
        0x7a, // OP_ROT
        0x75, // OP_DROP
        0x75, // OP_DROP
        0x75, // OP_DROP
        0x75, // OP_DROP
        0x75, // OP_DROP
        0x75, // OP_DROP
        0x75, // OP_DROP
        0x75, // OP_DROP
        0x75, // OP_DROP
        0x93, // OP_ADD
        0x54, // OP_4
        0x9c, // OP_NUMEQUAL
        0x00, 0x00, 0x00, 0x00, 0x00, // padding to fill array
    };
}

const stack_ops_script = buildStackOpsScript();

fn benchStackOps(allocator: std.mem.Allocator) void {
    // Only use the meaningful portion (first 25 bytes)
    var result = engine.executeScript(.{ .allocator = allocator }, Script.init(stack_ops_script[0..25])) catch return;
    result.deinit(allocator);
}

// Runar-compiled arithmetic conformance script
// (compiled from: target=27, verify(a=3, b=7) → sum+diff+prod == 27)
const runar_arithmetic_hex = "6e9352795279945379537995547a547a96537a537a937b937c93011b9c";

fn decodeHexComptime(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

const runar_arithmetic_locking = decodeHexComptime(runar_arithmetic_hex);

fn buildRunarArithmeticUnlocking() [4]u8 {
    // Push 3, push 7
    return [_]u8{ 0x01, 0x03, 0x01, 0x07 };
}

const runar_arithmetic_unlocking = buildRunarArithmeticUnlocking();

fn benchRunarArithmetic(allocator: std.mem.Allocator) void {
    const success = engine.verifyScripts(.{
        .allocator = allocator,
    }, Script.init(&runar_arithmetic_unlocking), Script.init(&runar_arithmetic_locking)) catch return;
    _ = success;
}

// P2PKH locking script (standard 25 bytes)
const p2pkh_locking_hex = "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac";
const p2pkh_locking = decodeHexComptime(p2pkh_locking_hex);

fn benchP2PKHVerify(allocator: std.mem.Allocator) void {
    // Build a real transaction and sign it
    const key_one_private = [_]u8{0} ** 31 ++ [_]u8{1};
    const private_key = bsvz.crypto.PrivateKey.fromBytes(key_one_private) catch return;
    const locking_script = Script.init(&p2pkh_locking);
    const previous_satoshis: i64 = 100_000;

    var inputs = [_]bsvz.transaction.Input{.{
        .previous_outpoint = .{ .txid = .{ .bytes = [_]u8{0xaa} ** 32 }, .index = 0 },
        .unlocking_script = Script.init(""),
        .sequence = 0xffff_ffff,
    }};
    var outputs = [_]bsvz.transaction.Output{.{
        .satoshis = 99_000,
        .locking_script = Script.init(&[_]u8{0x6a}),
    }};
    var tx = bsvz.transaction.Transaction{
        .version = 2,
        .inputs = &inputs,
        .outputs = &outputs,
        .lock_time = 0,
    };

    const tx_signature = bsvz.transaction.templates.p2pkh_spend.signInput(
        allocator,
        &tx,
        0,
        locking_script,
        previous_satoshis,
        private_key,
        bsvz.transaction.templates.p2pkh_spend.default_scope,
    ) catch return;
    const sig_bytes = tx_signature.toChecksigFormat(allocator) catch return;
    defer allocator.free(sig_bytes);

    const pubkey = private_key.publicKey() catch return;
    var unlock_buf: [128]u8 = undefined;
    var upos: usize = 0;
    unlock_buf[upos] = @intCast(sig_bytes.len);
    upos += 1;
    @memcpy(unlock_buf[upos..][0..sig_bytes.len], sig_bytes);
    upos += sig_bytes.len;
    unlock_buf[upos] = @intCast(pubkey.bytes.len);
    upos += 1;
    @memcpy(unlock_buf[upos..][0..pubkey.bytes.len], &pubkey.bytes);
    upos += pubkey.bytes.len;

    const success = engine.verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = locking_script,
        .previous_satoshis = previous_satoshis,
    }, Script.init(unlock_buf[0..upos]), locking_script) catch return;
    _ = success;
}

pub fn main() !void {
    std.debug.print("\nbsvz script engine benchmarks ({d} iterations each)\n", .{iterations});
    std.debug.print("{s}\n", .{"=" ** 90});

    bench("arithmetic (2+3==5)", benchArithmetic);
    bench("branching (if/else)", benchBranching);
    bench("OP_SHA256 (32-byte input)", benchSha256);
    bench("OP_HASH160 (20-byte input)", benchHash160);
    bench("stack ops (10 pushes + DUP/SWAP/ROT/DROP)", benchStackOps);
    bench("runar arithmetic (compiled, verifyScripts)", benchRunarArithmetic);
    bench("P2PKH full verify (sign + CHECKSIG)", benchP2PKHVerify);

    std.debug.print("{s}\n", .{"=" ** 90});
}
