const std = @import("std");
const crypto = @import("../crypto/lib.zig");
const Script = @import("../script/script.zig").Script;
const primitives = @import("../primitives/lib.zig");
const Transaction = @import("transaction.zig").Transaction;
const Output = @import("output.zig").Output;

pub const Error = error{
    ForkIdRequired,
    InputIndexOutOfRange,
    OutputIndexOutOfRange,
    EndOfStream,
};

pub const SigHashType = struct {
    pub const all: u32 = 0x01;
    pub const none: u32 = 0x02;
    pub const single: u32 = 0x03;
    pub const forkid: u32 = 0x40;
    pub const anyone_can_pay: u32 = 0x80;
    pub const output_mask: u32 = 0x1f;

    pub fn baseType(scope: u32) u32 {
        return scope & output_mask;
    }

    pub fn hasForkId(scope: u32) bool {
        return (scope & forkid) != 0;
    }

    pub fn hasAnyoneCanPay(scope: u32) bool {
        return (scope & anyone_can_pay) != 0;
    }
};

pub fn formatPreimage(
    allocator: std.mem.Allocator,
    tx: *const Transaction,
    input_index: usize,
    subscript: Script,
    satoshis: primitives.money.Satoshis,
    scope: u32,
) ![]u8 {
    if (!SigHashType.hasForkId(scope)) return error.ForkIdRequired;
    if (input_index >= tx.inputs.len) return error.InputIndexOutOfRange;

    const hash_prevouts = try hashPrevouts(allocator, tx, scope);
    const hash_sequence = try hashSequence(allocator, tx, scope);
    const hash_outputs = try hashOutputs(allocator, tx, input_index, scope);

    const script_len = subscript.bytes.len;
    const preimage_len = 4 + 32 + 32 + 36 + primitives.varint.VarInt.encodedLen(script_len) + script_len + 8 + 4 + 32 + 4 + 4;
    var out = try allocator.alloc(u8, preimage_len);
    errdefer allocator.free(out);

    var cursor: usize = 0;
    std.mem.writeInt(i32, out[cursor..][0..4], tx.version, .little);
    cursor += 4;

    @memcpy(out[cursor..][0..32], &hash_prevouts.bytes);
    cursor += 32;
    @memcpy(out[cursor..][0..32], &hash_sequence.bytes);
    cursor += 32;

    const input = tx.inputs[input_index];
    @memcpy(out[cursor..][0..32], &input.previous_outpoint.txid.bytes);
    cursor += 32;
    std.mem.writeInt(u32, out[cursor..][0..4], input.previous_outpoint.index, .little);
    cursor += 4;

    cursor += try primitives.varint.VarInt.encodeInto(out[cursor..], script_len);
    @memcpy(out[cursor..][0..script_len], subscript.bytes);
    cursor += script_len;

    std.mem.writeInt(i64, out[cursor..][0..8], satoshis, .little);
    cursor += 8;
    std.mem.writeInt(u32, out[cursor..][0..4], input.sequence, .little);
    cursor += 4;

    @memcpy(out[cursor..][0..32], &hash_outputs.bytes);
    cursor += 32;
    std.mem.writeInt(u32, out[cursor..][0..4], tx.lock_time, .little);
    cursor += 4;
    std.mem.writeInt(u32, out[cursor..][0..4], scope, .little);
    cursor += 4;

    std.debug.assert(cursor == preimage_len);
    return out;
}

pub fn digest(
    allocator: std.mem.Allocator,
    tx: *const Transaction,
    input_index: usize,
    subscript: Script,
    satoshis: primitives.money.Satoshis,
    scope: u32,
) !crypto.Hash256 {
    const preimage = try formatPreimage(allocator, tx, input_index, subscript, satoshis, scope);
    defer allocator.free(preimage);
    return crypto.hash.hash256(preimage);
}

pub fn hashPrevouts(allocator: std.mem.Allocator, tx: *const Transaction, scope: u32) !crypto.Hash256 {
    if (SigHashType.hasAnyoneCanPay(scope)) return crypto.Hash256.zero();

    const len = tx.inputs.len * 36;
    var buf = try allocator.alloc(u8, len);
    defer allocator.free(buf);

    var cursor: usize = 0;
    for (tx.inputs) |input| {
        @memcpy(buf[cursor..][0..32], &input.previous_outpoint.txid.bytes);
        cursor += 32;
        std.mem.writeInt(u32, buf[cursor..][0..4], input.previous_outpoint.index, .little);
        cursor += 4;
    }

    return crypto.hash.hash256(buf);
}

pub fn hashSequence(allocator: std.mem.Allocator, tx: *const Transaction, scope: u32) !crypto.Hash256 {
    const base_type = SigHashType.baseType(scope);
    if (SigHashType.hasAnyoneCanPay(scope) or base_type == SigHashType.single or base_type == SigHashType.none) {
        return crypto.Hash256.zero();
    }

    const len = tx.inputs.len * 4;
    var buf = try allocator.alloc(u8, len);
    defer allocator.free(buf);

    var cursor: usize = 0;
    for (tx.inputs) |input| {
        std.mem.writeInt(u32, buf[cursor..][0..4], input.sequence, .little);
        cursor += 4;
    }

    return crypto.hash.hash256(buf);
}

pub fn hashOutputs(allocator: std.mem.Allocator, tx: *const Transaction, input_index: usize, scope: u32) !crypto.Hash256 {
    const base_type = SigHashType.baseType(scope);
    if (base_type == SigHashType.none) return crypto.Hash256.zero();

    if (base_type == SigHashType.single) {
        if (input_index >= tx.outputs.len) return crypto.Hash256.zero();

        const output = tx.outputs[input_index];
        const buf = try serializeOutput(allocator, output);
        defer allocator.free(buf);
        return crypto.hash.hash256(buf);
    }

    var total_len: usize = 0;
    for (tx.outputs) |output| total_len += serializedOutputLen(output);
    var buf = try allocator.alloc(u8, total_len);
    defer allocator.free(buf);

    var cursor: usize = 0;
    for (tx.outputs) |output| {
        cursor += writeOutput(buf[cursor..], output);
    }

    return crypto.hash.hash256(buf);
}

fn serializedOutputLen(output: Output) usize {
    return 8 + primitives.varint.VarInt.encodedLen(output.locking_script.bytes.len) + output.locking_script.bytes.len;
}

fn serializeOutput(allocator: std.mem.Allocator, output: Output) ![]u8 {
    const len = serializedOutputLen(output);
    const buf = try allocator.alloc(u8, len);
    _ = writeOutput(buf, output);
    return buf;
}

fn writeOutput(out: []u8, output: Output) usize {
    var cursor: usize = 0;
    std.mem.writeInt(i64, out[cursor..][0..8], output.satoshis, .little);
    cursor += 8;
    cursor += primitives.varint.VarInt.encodeInto(out[cursor..], output.locking_script.bytes.len) catch unreachable;
    @memcpy(out[cursor..][0..output.locking_script.bytes.len], output.locking_script.bytes);
    cursor += output.locking_script.bytes.len;
    return cursor;
}

test "forkid sighash preimage matches the parser layout" {
    const allocator = std.testing.allocator;
    const tx = Transaction{
        .version = 2,
        .inputs = &[_]@import("input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x11} ** 32 },
                    .index = 7,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 0xffff_fffe,
            },
        },
        .outputs = &[_]Output{
            .{
                .satoshis = 5_000,
                .locking_script = .{ .bytes = &[_]u8{ 0x51, 0x21 } },
            },
        },
        .lock_time = 123,
    };

    const subscript = Script.init(&[_]u8{ 0x76, 0xa9, 0x14, 0x88, 0xac });
    const scope = SigHashType.forkid | SigHashType.all;
    const preimage = try formatPreimage(allocator, &tx, 0, subscript, 9_999, scope);
    defer allocator.free(preimage);

    const parsed = try @import("preimage.zig").Preimage.parse(preimage);
    try std.testing.expectEqual(tx.version, parsed.version);
    try std.testing.expectEqual(@as(u32, 7), parsed.outpoint.index);
    try std.testing.expectEqual(@as(i64, 9_999), parsed.satoshis);
    try std.testing.expectEqual(tx.lock_time, parsed.lockTime());
    try std.testing.expectEqual(scope, parsed.sighash_type);
}

test "sighash helper hashes respond to scope flags" {
    const allocator = std.testing.allocator;
    const tx = Transaction{
        .version = 1,
        .inputs = &[_]@import("input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x01} ** 32 },
                    .index = 0,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 11,
            },
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x02} ** 32 },
                    .index = 1,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 22,
            },
        },
        .outputs = &[_]Output{
            .{ .satoshis = 1, .locking_script = .{ .bytes = &[_]u8{0x51} } },
            .{ .satoshis = 2, .locking_script = .{ .bytes = &[_]u8{0x52} } },
        },
        .lock_time = 0,
    };

    try std.testing.expect(!(try hashPrevouts(allocator, &tx, SigHashType.forkid | SigHashType.all)).eql(crypto.Hash256.zero()));
    try std.testing.expect((try hashPrevouts(allocator, &tx, SigHashType.forkid | SigHashType.all | SigHashType.anyone_can_pay)).eql(crypto.Hash256.zero()));
    try std.testing.expect((try hashSequence(allocator, &tx, SigHashType.forkid | SigHashType.none)).eql(crypto.Hash256.zero()));
    try std.testing.expect((try hashOutputs(allocator, &tx, 1, SigHashType.forkid | SigHashType.none)).eql(crypto.Hash256.zero()));
    try std.testing.expect(!(try hashOutputs(allocator, &tx, 1, SigHashType.forkid | SigHashType.single)).eql(crypto.Hash256.zero()));
}

test "forkid sighash matches the replay-protected single anyone-can-pay vector" {
    const allocator = std.testing.allocator;
    const raw_tx = try primitives.hex.decode(
        allocator,
        "0100000002e9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc0010000000000ffffffff80e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b0000000000ffffffff0280969800000000001976a914de4b231626ef508c9a74a8517e6783c0546d6b2888ac80969800000000001976a9146648a8cd4531e1ec47f35916de8e259237294d1e88ac00000000",
    );
    defer allocator.free(raw_tx);

    const tx = try Transaction.parse(allocator, raw_tx);
    defer tx.deinit(allocator);

    const subscript_bytes = try primitives.hex.decode(
        allocator,
        "0063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac",
    );
    defer allocator.free(subscript_bytes);
    const subscript = Script.init(subscript_bytes);

    const preimage = try formatPreimage(
        allocator,
        &tx,
        0,
        subscript,
        16_777_215,
        SigHashType.forkid | SigHashType.single | SigHashType.anyone_can_pay,
    );
    defer allocator.free(preimage);

    const expected_hash_outputs = try primitives.hex.decode(
        allocator,
        "b258eaf08c39fbe9fbac97c15c7e7adeb8df142b0df6f83e017f349c2b6fe3d2",
    );
    defer allocator.free(expected_hash_outputs);
    const expected_preimage = try primitives.hex.decode(
        allocator,
        "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc00100000000270063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98acffffff0000000000ffffffffb258eaf08c39fbe9fbac97c15c7e7adeb8df142b0df6f83e017f349c2b6fe3d200000000c3000000",
    );
    defer allocator.free(expected_preimage);
    const expected_digest = try primitives.hex.decode(
        allocator,
        "7dc5b40f14d8e45a9f301969573beb318c4cae1feffb35577a6523564439a19b",
    );
    defer allocator.free(expected_digest);

    try std.testing.expect((try hashPrevouts(allocator, &tx, SigHashType.forkid | SigHashType.single | SigHashType.anyone_can_pay)).eql(crypto.Hash256.zero()));
    try std.testing.expect((try hashSequence(allocator, &tx, SigHashType.forkid | SigHashType.single | SigHashType.anyone_can_pay)).eql(crypto.Hash256.zero()));
    try std.testing.expectEqualSlices(u8, expected_hash_outputs, &(try hashOutputs(allocator, &tx, 0, SigHashType.forkid | SigHashType.single | SigHashType.anyone_can_pay)).bytes);
    try std.testing.expectEqualSlices(u8, expected_preimage, preimage);
    try std.testing.expectEqualSlices(u8, expected_digest, &crypto.hash.hash256(preimage).bytes);
}
