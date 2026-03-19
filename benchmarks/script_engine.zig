const std = @import("std");
const bsvz = @import("bsvz");

const Script = bsvz.script.Script;
const engine = bsvz.script.engine;

const iterations = 10_000;
const allocator = std.heap.page_allocator;

fn bench(comptime name: []const u8, comptime run_fn: fn () void) void {
    for (0..100) |_| run_fn();

    const start = std.time.nanoTimestamp();
    for (0..iterations) |_| run_fn();
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

const arithmetic_locking = [_]u8{ 0x52, 0x53, 0x93, 0x55, 0x9c };
const branching_locking = [_]u8{ 0x51, 0x63, 0x52, 0x67, 0x53, 0x68, 0x52, 0x9c };

const sha256_locking = [_]u8{
    0x20,
} ++ [_]u8{0xab} ** 32 ++ [_]u8{
    0xa8,
    0x82,
    0x01, 0x20,
    0x9c,
};

const hash160_locking = [_]u8{
    0x14,
} ++ [_]u8{0xcd} ** 20 ++ [_]u8{
    0xa9,
    0x82,
    0x01, 0x14,
    0x9c,
};

fn buildStackOpsScript() [25]u8 {
    return [_]u8{
        0x51, 0x52, 0x53, 0x54, 0x55,
        0x56, 0x57, 0x58, 0x59, 0x5a,
        0x76,
        0x7c,
        0x7b,
        0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75,
        0x93,
        0x54,
        0x9c,
        0x51,
    };
}

const stack_ops_locking = buildStackOpsScript();

fn decodeHexComptime(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

const runar_arithmetic_locking = decodeHexComptime("6e9352795279945379537995547a547a96537a537a937b937c93011b9c");
const runar_arithmetic_unlocking = [_]u8{ 0x01, 0x03, 0x01, 0x07 };
const p2pkh_locking = decodeHexComptime("76a914751e76e8199196d454941c45d1b3a323f1433bd688ac");

const ScriptPair = struct {
    unlocking: []const u8,
    locking: []const u8,
};

const PrevoutFixture = struct {
    tx: bsvz.transaction.Transaction,
    unlocking: []const u8,
    locking: Script,
    prev_satoshis: i64,
};

fn verifyPair(pair: ScriptPair) void {
    const ok = engine.verifyScripts(.{
        .allocator = allocator,
    }, Script.init(pair.unlocking), Script.init(pair.locking)) catch return;
    if (!ok) unreachable;
}

fn pairArithmetic() ScriptPair {
    return .{ .unlocking = &.{}, .locking = &arithmetic_locking };
}

fn pairBranching() ScriptPair {
    return .{ .unlocking = &.{}, .locking = &branching_locking };
}

fn pairSha256() ScriptPair {
    return .{ .unlocking = &.{}, .locking = &sha256_locking };
}

fn pairHash160() ScriptPair {
    return .{ .unlocking = &.{}, .locking = &hash160_locking };
}

fn pairStackOps() ScriptPair {
    return .{ .unlocking = &.{}, .locking = &stack_ops_locking };
}

fn pairRunarArithmetic() ScriptPair {
    return .{ .unlocking = &runar_arithmetic_unlocking, .locking = &runar_arithmetic_locking };
}

var p2pkh_fixture_once = std.once(initP2PKHFixture);
var p2pkh_fixture: PrevoutFixture = undefined;

fn initP2PKHFixture() void {
    const key_bytes = [_]u8{0} ** 31 ++ [_]u8{1};
    const private_key = bsvz.crypto.PrivateKey.fromBytes(key_bytes) catch unreachable;
    const locking_script = Script.init(&p2pkh_locking);
    const previous_satoshis: i64 = 100_000;

    var inputs = allocator.alloc(bsvz.transaction.Input, 1) catch unreachable;
    var outputs = allocator.alloc(bsvz.transaction.Output, 1) catch unreachable;

    inputs[0] = .{
        .previous_outpoint = .{ .txid = .{ .bytes = [_]u8{0xaa} ** 32 }, .index = 0 },
        .unlocking_script = Script.init(""),
        .sequence = 0xffff_ffff,
    };
    outputs[0] = .{
        .satoshis = 99_000,
        .locking_script = Script.init(&[_]u8{0x6a}),
    };

    var tx = bsvz.transaction.Transaction{
        .version = 2,
        .inputs = inputs,
        .outputs = outputs,
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
    ) catch unreachable;

    const sig_bytes = tx_signature.toChecksigFormat(allocator) catch unreachable;
    const pubkey = private_key.publicKey() catch unreachable;
    const unlock_len = 1 + sig_bytes.len + 1 + pubkey.bytes.len;
    const unlock = allocator.alloc(u8, unlock_len) catch unreachable;

    var pos: usize = 0;
    unlock[pos] = @intCast(sig_bytes.len);
    pos += 1;
    @memcpy(unlock[pos..][0..sig_bytes.len], sig_bytes);
    pos += sig_bytes.len;
    unlock[pos] = @intCast(pubkey.bytes.len);
    pos += 1;
    @memcpy(unlock[pos..][0..pubkey.bytes.len], &pubkey.bytes);

    allocator.free(sig_bytes);
    inputs[0].unlocking_script = Script.init(unlock);

    p2pkh_fixture = .{
        .tx = tx,
        .unlocking = unlock,
        .locking = locking_script,
        .prev_satoshis = previous_satoshis,
    };
}

fn getP2PKHFixture() *const PrevoutFixture {
    p2pkh_fixture_once.call();
    return &p2pkh_fixture;
}

fn benchArithmetic() void {
    verifyPair(pairArithmetic());
}

fn benchBranching() void {
    verifyPair(pairBranching());
}

fn benchSha256() void {
    verifyPair(pairSha256());
}

fn benchHash160() void {
    verifyPair(pairHash160());
}

fn benchStackOps() void {
    verifyPair(pairStackOps());
}

fn benchRunarArithmetic() void {
    verifyPair(pairRunarArithmetic());
}

fn benchP2PKHVerify() void {
    const fixture = getP2PKHFixture();
    const ok = engine.verifyScripts(.{
        .allocator = allocator,
        .tx = &fixture.tx,
        .input_index = 0,
        .previous_locking_script = fixture.locking,
        .previous_satoshis = fixture.prev_satoshis,
    }, Script.init(fixture.unlocking), fixture.locking) catch return;
    if (!ok) unreachable;
}

pub fn main() !void {
    _ = getP2PKHFixture();

    std.debug.print("\nbsvz script engine benchmarks ({d} iterations each)\n", .{iterations});
    std.debug.print("{s}\n", .{"=" ** 90});

    bench("arithmetic verify (2+3==5)", benchArithmetic);
    bench("branching verify (if/else)", benchBranching);
    bench("OP_SHA256 verify (32-byte input)", benchSha256);
    bench("OP_HASH160 verify (20-byte input)", benchHash160);
    bench("stack ops verify", benchStackOps);
    bench("runar arithmetic verify", benchRunarArithmetic);
    bench("P2PKH verify (prebuilt tx + CHECKSIG)", benchP2PKHVerify);

    std.debug.print("{s}\n", .{"=" ** 90});
}
