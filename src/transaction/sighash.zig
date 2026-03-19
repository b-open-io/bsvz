const std = @import("std");
const crypto = @import("../crypto/lib.zig");
const Script = @import("../script/script.zig").Script;
const primitives = @import("../primitives/lib.zig");
const Transaction = @import("transaction.zig").Transaction;
const Output = @import("output.zig").Output;

pub const Error = error{
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
    if (input_index >= tx.inputs.len) return error.InputIndexOutOfRange;

    if (SigHashType.hasForkId(scope)) {
        return formatForkIdPreimage(allocator, tx, input_index, subscript, satoshis, scope);
    }

    return formatLegacyPreimage(allocator, tx, input_index, subscript, scope);
}

fn formatForkIdPreimage(
    allocator: std.mem.Allocator,
    tx: *const Transaction,
    input_index: usize,
    subscript: Script,
    satoshis: primitives.money.Satoshis,
    scope: u32,
) ![]u8 {
    std.debug.assert(SigHashType.hasForkId(scope));

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

fn formatLegacyPreimage(
    allocator: std.mem.Allocator,
    tx: *const Transaction,
    input_index: usize,
    subscript: Script,
    scope: u32,
) ![]u8 {
    const base_type = SigHashType.baseType(scope);
    if (base_type == SigHashType.single and input_index >= tx.outputs.len) {
        return allocator.dupe(u8, &legacySingleBugBytes());
    }

    const normalized_subscript = try stripCodeSeparators(allocator, subscript.bytes);
    defer allocator.free(normalized_subscript);

    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(allocator);

    var int_buf_4: [4]u8 = undefined;
    std.mem.writeInt(i32, &int_buf_4, tx.version, .little);
    try out.appendSlice(allocator, &int_buf_4);

    if (SigHashType.hasAnyoneCanPay(scope)) {
        try appendVarInt(&out, 1, allocator);
        try appendLegacyInput(&out, allocator, tx.inputs[input_index], normalized_subscript, tx.inputs[input_index].sequence);
    } else {
        try appendVarInt(&out, tx.inputs.len, allocator);
        for (tx.inputs, 0..) |input, index| {
            const input_script = if (index == input_index) normalized_subscript else "";
            const sequence = if (index == input_index or (base_type != SigHashType.none and base_type != SigHashType.single))
                input.sequence
            else
                0;
            try appendLegacyInput(&out, allocator, input, input_script, sequence);
        }
    }

    switch (base_type) {
        SigHashType.none => try appendVarInt(&out, 0, allocator),
        SigHashType.single => {
            try appendVarInt(&out, input_index + 1, allocator);
            for (0..input_index) |_| try appendLegacySinglePlaceholderOutput(&out, allocator);
            try appendLegacyOutput(&out, allocator, tx.outputs[input_index]);
        },
        else => {
            try appendVarInt(&out, tx.outputs.len, allocator);
            for (tx.outputs) |output| try appendLegacyOutput(&out, allocator, output);
        },
    }

    std.mem.writeInt(u32, &int_buf_4, tx.lock_time, .little);
    try out.appendSlice(allocator, &int_buf_4);
    std.mem.writeInt(u32, &int_buf_4, scope, .little);
    try out.appendSlice(allocator, &int_buf_4);

    return out.toOwnedSlice(allocator);
}

pub fn digest(
    allocator: std.mem.Allocator,
    tx: *const Transaction,
    input_index: usize,
    subscript: Script,
    satoshis: primitives.money.Satoshis,
    scope: u32,
) !crypto.Hash256 {
    if (!SigHashType.hasForkId(scope) and SigHashType.baseType(scope) == SigHashType.single and input_index >= tx.outputs.len) {
        return .{ .bytes = legacySingleBugBytes() };
    }

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
        const buf = try output.serialize(allocator);
        defer allocator.free(buf);
        return crypto.hash.hash256(buf);
    }

    return Output.hashAll(allocator, tx.outputs);
}

fn legacySingleBugBytes() [32]u8 {
    var bytes = [_]u8{0} ** 32;
    bytes[0] = 0x01;
    return bytes;
}

fn appendVarInt(list: *std.ArrayListUnmanaged(u8), value: usize, allocator: std.mem.Allocator) !void {
    var buf: [9]u8 = undefined;
    const len = try primitives.varint.VarInt.encodeInto(&buf, value);
    try list.appendSlice(allocator, buf[0..len]);
}

fn appendLegacyInput(list: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, input: @import("input.zig").Input, script_bytes: []const u8, sequence: u32) !void {
    try list.appendSlice(allocator, &input.previous_outpoint.txid.bytes);

    var int_buf_4: [4]u8 = undefined;
    std.mem.writeInt(u32, &int_buf_4, input.previous_outpoint.index, .little);
    try list.appendSlice(allocator, &int_buf_4);

    try appendVarInt(list, script_bytes.len, allocator);
    try list.appendSlice(allocator, script_bytes);

    std.mem.writeInt(u32, &int_buf_4, sequence, .little);
    try list.appendSlice(allocator, &int_buf_4);
}

fn appendLegacyOutput(list: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, output: Output) !void {
    var int_buf_8: [8]u8 = undefined;
    std.mem.writeInt(i64, &int_buf_8, output.satoshis, .little);
    try list.appendSlice(allocator, &int_buf_8);
    try appendVarInt(list, output.locking_script.bytes.len, allocator);
    try list.appendSlice(allocator, output.locking_script.bytes);
}

fn appendLegacySinglePlaceholderOutput(list: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator) !void {
    const satoshis = [_]u8{0xff} ** 8;
    try list.appendSlice(allocator, &satoshis);
    try list.append(allocator, 0x00);
}

fn stripCodeSeparators(allocator: std.mem.Allocator, script_bytes: []const u8) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(allocator);

    var cursor: usize = 0;
    while (cursor < script_bytes.len) {
        const byte = script_bytes[cursor];
        cursor += 1;

        if (byte >= 0x01 and byte <= 0x4b) {
            if (script_bytes.len < cursor + byte) return error.EndOfStream;
            try out.append(allocator, byte);
            try out.appendSlice(allocator, script_bytes[cursor .. cursor + byte]);
            cursor += byte;
            continue;
        }

        if (byte == @intFromEnum(@import("../script/opcode.zig").Opcode.OP_PUSHDATA1)) {
            if (script_bytes.len < cursor + 1) return error.EndOfStream;
            const len = script_bytes[cursor];
            if (script_bytes.len < cursor + 1 + len) return error.EndOfStream;
            try out.append(allocator, byte);
            try out.append(allocator, script_bytes[cursor]);
            try out.appendSlice(allocator, script_bytes[cursor + 1 .. cursor + 1 + len]);
            cursor += 1 + len;
            continue;
        }

        if (byte == @intFromEnum(@import("../script/opcode.zig").Opcode.OP_PUSHDATA2)) {
            if (script_bytes.len < cursor + 2) return error.EndOfStream;
            const len = std.mem.readInt(u16, script_bytes[cursor..][0..2], .little);
            if (script_bytes.len < cursor + 2 + len) return error.EndOfStream;
            try out.append(allocator, byte);
            try out.appendSlice(allocator, script_bytes[cursor..][0..2]);
            try out.appendSlice(allocator, script_bytes[cursor + 2 .. cursor + 2 + len]);
            cursor += 2 + len;
            continue;
        }

        if (byte == @intFromEnum(@import("../script/opcode.zig").Opcode.OP_PUSHDATA4)) {
            if (script_bytes.len < cursor + 4) return error.EndOfStream;
            const len = std.mem.readInt(u32, script_bytes[cursor..][0..4], .little);
            if (script_bytes.len < cursor + 4 + len) return error.EndOfStream;
            try out.append(allocator, byte);
            try out.appendSlice(allocator, script_bytes[cursor..][0..4]);
            try out.appendSlice(allocator, script_bytes[cursor + 4 .. cursor + 4 + len]);
            cursor += 4 + len;
            continue;
        }

        if (byte != @intFromEnum(@import("../script/opcode.zig").Opcode.OP_CODESEPARATOR)) {
            try out.append(allocator, byte);
        }
    }

    return out.toOwnedSlice(allocator);
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

test "legacy sighash preimage matches the Go SDK single-input all vector" {
    const allocator = std.testing.allocator;
    const raw_tx = try primitives.hex.decode(
        allocator,
        "010000000193a35408b6068499e0d5abd799d3e827d9bfe70c9b75ebe209c91d25072326510000000000ffffffff02404b4c00000000001976a91404ff367be719efa79d76e4416ffb072cd53b208888acde94a905000000001976a91404d03f746652cfcb6cb55119ab473a045137d26588ac00000000",
    );
    defer allocator.free(raw_tx);

    const expected_preimage = try primitives.hex.decode(
        allocator,
        "010000000193a35408b6068499e0d5abd799d3e827d9bfe70c9b75ebe209c91d2507232651000000001976a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88acffffffff02404b4c00000000001976a91404ff367be719efa79d76e4416ffb072cd53b208888acde94a905000000001976a91404d03f746652cfcb6cb55119ab473a045137d26588ac0000000001000000",
    );
    defer allocator.free(expected_preimage);

    const tx = try Transaction.parse(allocator, raw_tx);
    defer tx.deinit(allocator);

    const subscript = Script.init(try primitives.hex.decode(
        allocator,
        "76a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac",
    ));
    defer allocator.free(subscript.bytes);

    const preimage = try formatPreimage(allocator, &tx, 0, subscript, 100_000_000, SigHashType.all);
    defer allocator.free(preimage);

    try std.testing.expectEqualSlices(u8, expected_preimage, preimage);
}

test "legacy sighash digest matches the Go SDK two-input all vector" {
    const allocator = std.testing.allocator;
    const raw_tx = try primitives.hex.decode(
        allocator,
        "01000000027e2705da59f7112c7337d79840b56fff582b8f3a0e9df8eb19e282377bebb1bc0100000000ffffffffdebe6fe5ad8e9220a10fcf6340f7fca660d87aeedf0f74a142fba6de1f68d8490000000000ffffffff0300e1f505000000001976a9142987362cf0d21193ce7e7055824baac1ee245d0d88ac00e1f505000000001976a9143ca26faa390248b7a7ac45be53b0e4004ad7952688ac34657fe2000000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788ac00000000",
    );
    defer allocator.free(raw_tx);
    const expected_digest = try primitives.hex.decode(
        allocator,
        "4c8ee5be8b0b4a822284248e3854bda603e6eca5e2db73498759cd3f7c25d329",
    );
    defer allocator.free(expected_digest);

    const tx = try Transaction.parse(allocator, raw_tx);
    defer tx.deinit(allocator);

    const subscript = Script.init(try primitives.hex.decode(
        allocator,
        "76a914eb0bd5edba389198e73f8efabddfc61666969ff788ac",
    ));
    defer allocator.free(subscript.bytes);

    const actual = try digest(allocator, &tx, 1, subscript, 2_000_000_000, SigHashType.all);
    try std.testing.expectEqualSlices(u8, expected_digest, &actual.bytes);
}

test "legacy sighash returns the consensus single out-of-range sentinel" {
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
                .sequence = 0xffff_fffe,
            },
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x02} ** 32 },
                    .index = 1,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 0xffff_fffd,
            },
        },
        .outputs = &[_]Output{
            .{
                .satoshis = 5_000,
                .locking_script = .{ .bytes = &[_]u8{0x51} },
            },
        },
        .lock_time = 0,
    };

    const subscript = Script.init(&[_]u8{0x51});
    const expected = legacySingleBugBytes();
    const preimage = try formatPreimage(allocator, &tx, 1, subscript, 0, SigHashType.single);
    defer allocator.free(preimage);
    const actual = try digest(allocator, &tx, 1, subscript, 0, SigHashType.single);

    try std.testing.expectEqualSlices(u8, &expected, preimage);
    try std.testing.expectEqualSlices(u8, &expected, &actual.bytes);
}

test "legacy sighash strips OP_CODESEPARATOR from the subscript" {
    const allocator = std.testing.allocator;
    const tx = Transaction{
        .version = 1,
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
                .satoshis = 123,
                .locking_script = .{ .bytes = &[_]u8{0x51} },
            },
        },
        .lock_time = 9,
    };

    const preimage = try formatPreimage(allocator, &tx, 0, Script.init(&[_]u8{ 0x51, 0xab, 0x52 }), 0, SigHashType.all);
    defer allocator.free(preimage);

    try std.testing.expect(std.mem.indexOf(u8, preimage, &[_]u8{ 0x02, 0x51, 0x52 }) != null);
    try std.testing.expect(std.mem.indexOf(u8, preimage, &[_]u8{0xab}) == null);
}
