const std = @import("std");
const crypto = @import("../crypto/lib.zig");
const primitives = @import("../primitives/lib.zig");
pub const Input = @import("input.zig").Input;
pub const Output = @import("output.zig").Output;
const MerklePath = @import("../spv/merkle_path.zig").MerklePath;
const PathElement = @import("../spv/merkle_path.zig").PathElement;

pub const Transaction = struct {
    version: i32,
    inputs: []const Input,
    outputs: []const Output,
    lock_time: u32,
    merkle_path: ?@import("../spv/merkle_path.zig").MerklePath = null,
    /// When true, `deinit` frees `merkle_path` inner allocations.
    owns_merkle_path: bool = false,

    pub fn serializedLen(self: *const Transaction) usize {
        var len: usize = 4;
        len += primitives.varint.VarInt.encodedLen(self.inputs.len);
        for (self.inputs) |input| {
            len += 32 + 4;
            len += primitives.varint.VarInt.encodedLen(input.unlocking_script.bytes.len);
            len += input.unlocking_script.bytes.len;
            len += 4;
        }

        len += primitives.varint.VarInt.encodedLen(self.outputs.len);
        for (self.outputs) |output| {
            len += 8;
            len += primitives.varint.VarInt.encodedLen(output.locking_script.bytes.len);
            len += output.locking_script.bytes.len;
        }

        len += 4;
        return len;
    }

    pub fn serialize(self: *const Transaction, allocator: std.mem.Allocator) ![]u8 {
        const len = self.serializedLen();
        var out = try allocator.alloc(u8, len);
        errdefer allocator.free(out);

        var cursor: usize = 0;
        std.mem.writeInt(i32, out[cursor..][0..4], self.version, .little);
        cursor += 4;

        cursor += try primitives.varint.VarInt.encodeInto(out[cursor..], self.inputs.len);
        for (self.inputs) |input| {
            @memcpy(out[cursor..][0..32], &input.previous_outpoint.txid.bytes);
            cursor += 32;
            std.mem.writeInt(u32, out[cursor..][0..4], input.previous_outpoint.index, .little);
            cursor += 4;
            cursor += try primitives.varint.VarInt.encodeInto(out[cursor..], input.unlocking_script.bytes.len);
            @memcpy(out[cursor..][0..input.unlocking_script.bytes.len], input.unlocking_script.bytes);
            cursor += input.unlocking_script.bytes.len;
            std.mem.writeInt(u32, out[cursor..][0..4], input.sequence, .little);
            cursor += 4;
        }

        cursor += try primitives.varint.VarInt.encodeInto(out[cursor..], self.outputs.len);
        for (self.outputs) |output| {
            std.mem.writeInt(i64, out[cursor..][0..8], output.satoshis, .little);
            cursor += 8;
            cursor += try primitives.varint.VarInt.encodeInto(out[cursor..], output.locking_script.bytes.len);
            @memcpy(out[cursor..][0..output.locking_script.bytes.len], output.locking_script.bytes);
            cursor += output.locking_script.bytes.len;
        }

        std.mem.writeInt(u32, out[cursor..][0..4], self.lock_time, .little);
        cursor += 4;
        std.debug.assert(cursor == len);

        return out;
    }

    pub fn parseHex(allocator: std.mem.Allocator, hex_text: []const u8) !Transaction {
        const bytes = try primitives.hex.decode(allocator, hex_text);
        defer allocator.free(bytes);
        return try parse(allocator, bytes);
    }

    pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) !Transaction {
        var cursor: usize = 0;
        var tx = try parseFromCursor(allocator, bytes, &cursor);
        if (cursor != bytes.len) {
            tx.deinit(allocator);
            return error.InvalidEncoding;
        }
        return tx;
    }

    pub fn parseFromCursor(
        allocator: std.mem.Allocator,
        bytes: []const u8,
        cursor: *usize,
    ) !Transaction {
        if (bytes.len < cursor.* + 4) return error.EndOfStream;
        const version = try readIntLE(i32, bytes, cursor);

        var extended = false;
        var input_count_varint = try primitives.varint.VarInt.parse(bytes[cursor.*..]);
        cursor.* += input_count_varint.len;
        var input_count = std.math.cast(usize, input_count_varint.value) orelse return error.Overflow;
        // When input_count is 0 we peek output_count; if >0 reuse it instead of reading twice.
        var prefetched_output_count: ?usize = null;

        if (input_count == 0) {
            const output_count_varint = try primitives.varint.VarInt.parse(bytes[cursor.*..]);
            cursor.* += output_count_varint.len;
            const oc = std.math.cast(usize, output_count_varint.value) orelse return error.Overflow;
            if (oc == 0) {
                const lock_bytes = try readIntBE(u32, bytes, cursor);
                if (lock_bytes == 0xEF) {
                    extended = true;
                    input_count_varint = try primitives.varint.VarInt.parse(bytes[cursor.*..]);
                    cursor.* += input_count_varint.len;
                    input_count = std.math.cast(usize, input_count_varint.value) orelse return error.Overflow;
                } else {
                    const empty_inputs = try allocator.alloc(Input, 0);
                    const empty_outputs = try allocator.alloc(Output, 0);
                    return .{
                        .version = version,
                        .inputs = empty_inputs,
                        .outputs = empty_outputs,
                        .lock_time = @byteSwap(lock_bytes),
                    };
                }
            } else {
                prefetched_output_count = oc;
            }
        }

        const inputs = try allocator.alloc(Input, input_count);
        errdefer allocator.free(inputs);
        for (inputs) |*input| input.* = Input.empty();
        errdefer for (inputs) |*input| input.deinit(allocator);

        for (inputs) |*input| {
            if (bytes.len < cursor.* + 36) return error.EndOfStream;
            var txid_bytes: [32]u8 = undefined;
            @memcpy(&txid_bytes, bytes[cursor.* .. cursor.* + 32]);
            const previous_txid = crypto.Hash256{ .bytes = txid_bytes };
            cursor.* += 32;
            const index = try readIntLE(u32, bytes, cursor);

            const script_len_varint = try primitives.varint.VarInt.parse(bytes[cursor.*..]);
            cursor.* += script_len_varint.len;
            const script_len = std.math.cast(usize, script_len_varint.value) orelse return error.Overflow;
            if (bytes.len < cursor.* + script_len + 4) return error.EndOfStream;

            const unlocking_script = try cloneScriptSlice(
                allocator,
                bytes[cursor.* .. cursor.* + script_len],
            );
            cursor.* += script_len;
            const sequence = try readIntLE(u32, bytes, cursor);

            var source_output: ?Output = null;
            if (extended) {
                const satoshis = try readIntLE(i64, bytes, cursor);
                const src_len_varint = try primitives.varint.VarInt.parse(bytes[cursor.*..]);
                cursor.* += src_len_varint.len;
                const src_len = std.math.cast(usize, src_len_varint.value) orelse return error.Overflow;
                if (src_len > 0) {
                    if (bytes.len < cursor.* + src_len) return error.EndOfStream;
                    source_output = .{
                        .satoshis = satoshis,
                        .locking_script = try cloneScriptSlice(
                            allocator,
                            bytes[cursor.* .. cursor.* + src_len],
                        ),
                    };
                    cursor.* += src_len;
                }
            }

            input.* = .{
                .previous_outpoint = .{ .txid = previous_txid, .index = index },
                .unlocking_script = unlocking_script,
                .sequence = sequence,
                .source_output = source_output,
            };
        }

        const output_count: usize = if (prefetched_output_count) |o| o else blk: {
            const output_count_varint = try primitives.varint.VarInt.parse(bytes[cursor.*..]);
            cursor.* += output_count_varint.len;
            break :blk std.math.cast(usize, output_count_varint.value) orelse return error.Overflow;
        };
        const outputs = try allocator.alloc(Output, output_count);
        errdefer allocator.free(outputs);
        for (outputs) |*output| output.* = Output.empty();
        errdefer for (outputs) |*output| output.deinit(allocator);

        for (outputs) |*output| {
            if (bytes.len < cursor.* + 8) return error.EndOfStream;
            const satoshis = try readIntLE(i64, bytes, cursor);
            const script_len_varint = try primitives.varint.VarInt.parse(bytes[cursor.*..]);
            cursor.* += script_len_varint.len;
            const script_len = std.math.cast(usize, script_len_varint.value) orelse return error.Overflow;
            if (bytes.len < cursor.* + script_len) return error.EndOfStream;
            output.* = .{
                .satoshis = satoshis,
                .locking_script = try cloneScriptSlice(
                    allocator,
                    bytes[cursor.* .. cursor.* + script_len],
                ),
            };
            cursor.* += script_len;
        }

        const lock_time = try readIntLE(u32, bytes, cursor);

        return .{
            .version = version,
            .inputs = inputs,
            .outputs = outputs,
            .lock_time = lock_time,
        };
    }

    pub fn deinit(self: Transaction, allocator: std.mem.Allocator) void {
        if (self.owns_merkle_path) {
            if (self.merkle_path) |mp| {
                var mut = mp;
                mut.deinit(allocator);
            }
        }
        for (self.inputs) |input| {
            var mut = input;
            mut.deinit(allocator);
        }
        for (self.outputs) |output| {
            var mut = output;
            mut.deinit(allocator);
        }
        allocator.free(self.inputs);
        allocator.free(self.outputs);
    }

    pub fn shallowClone(self: *const Transaction, allocator: std.mem.Allocator) !Transaction {
        return .{
            .version = self.version,
            .inputs = try cloneInputs(allocator, self.inputs),
            .outputs = try cloneOutputs(allocator, self.outputs),
            .lock_time = self.lock_time,
            .merkle_path = self.merkle_path,
            .owns_merkle_path = false,
        };
    }

    pub fn clone(self: *const Transaction, allocator: std.mem.Allocator) !Transaction {
        var copy = try self.shallowClone(allocator);
        if (self.merkle_path) |mp| {
            copy.merkle_path = try mp.clone(allocator);
            copy.owns_merkle_path = true;
        }
        return copy;
    }

    pub fn txid(self: *const Transaction, allocator: std.mem.Allocator) !crypto.Hash256 {
        const serialized = try self.serialize(allocator);
        defer allocator.free(serialized);
        return crypto.hash.hash256(serialized);
    }

    pub fn hex(self: *const Transaction, allocator: std.mem.Allocator) ![]u8 {
        const raw = try self.serialize(allocator);
        defer allocator.free(raw);
        const out = try allocator.alloc(u8, raw.len * 2);
        _ = try primitives.hex.encodeLower(raw, out);
        return out;
    }

    pub fn serializeExtended(self: *const Transaction, allocator: std.mem.Allocator) ![]u8 {
        var len: usize = 4 + 6;
        len += primitives.varint.VarInt.encodedLen(self.inputs.len);
        for (self.inputs) |input| {
            len += 32 + 4;
            len += primitives.varint.VarInt.encodedLen(input.unlocking_script.bytes.len);
            len += input.unlocking_script.bytes.len;
            len += 4;
            len += 8;
            if (sourceOutputForInput(&input)) |out| {
                len += primitives.varint.VarInt.encodedLen(out.locking_script.bytes.len);
                len += out.locking_script.bytes.len;
            } else {
                len += 1;
            }
        }
        len += primitives.varint.VarInt.encodedLen(self.outputs.len);
        for (self.outputs) |output| {
            len += 8;
            len += primitives.varint.VarInt.encodedLen(output.locking_script.bytes.len);
            len += output.locking_script.bytes.len;
        }
        len += 4;

        var out = try allocator.alloc(u8, len);
        errdefer allocator.free(out);
        var cursor: usize = 0;
        std.mem.writeInt(i32, out[cursor..][0..4], self.version, .little);
        cursor += 4;
        @memcpy(out[cursor..][0..6], &[_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0xEF });
        cursor += 6;

        cursor += try primitives.varint.VarInt.encodeInto(out[cursor..], self.inputs.len);
        for (self.inputs) |input| {
            @memcpy(out[cursor..][0..32], &input.previous_outpoint.txid.bytes);
            cursor += 32;
            std.mem.writeInt(u32, out[cursor..][0..4], input.previous_outpoint.index, .little);
            cursor += 4;
            cursor += try primitives.varint.VarInt.encodeInto(out[cursor..], input.unlocking_script.bytes.len);
            @memcpy(out[cursor..][0..input.unlocking_script.bytes.len], input.unlocking_script.bytes);
            cursor += input.unlocking_script.bytes.len;
            std.mem.writeInt(u32, out[cursor..][0..4], input.sequence, .little);
            cursor += 4;
            if (sourceOutputForInput(&input)) |outp| {
                std.mem.writeInt(i64, out[cursor..][0..8], outp.satoshis, .little);
                cursor += 8;
                cursor += try primitives.varint.VarInt.encodeInto(out[cursor..], outp.locking_script.bytes.len);
                @memcpy(out[cursor..][0..outp.locking_script.bytes.len], outp.locking_script.bytes);
                cursor += outp.locking_script.bytes.len;
            } else {
                std.mem.writeInt(i64, out[cursor..][0..8], 0, .little);
                cursor += 8;
                out[cursor] = 0;
                cursor += 1;
            }
        }

        cursor += try primitives.varint.VarInt.encodeInto(out[cursor..], self.outputs.len);
        for (self.outputs) |output| {
            std.mem.writeInt(i64, out[cursor..][0..8], output.satoshis, .little);
            cursor += 8;
            cursor += try primitives.varint.VarInt.encodeInto(out[cursor..], output.locking_script.bytes.len);
            @memcpy(out[cursor..][0..output.locking_script.bytes.len], output.locking_script.bytes);
            cursor += output.locking_script.bytes.len;
        }

        std.mem.writeInt(u32, out[cursor..][0..4], self.lock_time, .little);
        cursor += 4;
        std.debug.assert(cursor == len);
        return out;
    }

    pub fn extendedHex(self: *const Transaction, allocator: std.mem.Allocator) ![]u8 {
        const raw = try self.serializeExtended(allocator);
        defer allocator.free(raw);
        const out = try allocator.alloc(u8, raw.len * 2);
        _ = try primitives.hex.encodeLower(raw, out);
        return out;
    }
};

fn cloneScriptSlice(allocator: std.mem.Allocator, bytes: []const u8) !@import("../script/script.zig").Script {
    return .{
        .bytes = try allocator.dupe(u8, bytes),
        .owned = true,
    };
}

pub fn sourceTransactionForInput(input: *const Input) ?*const Transaction {
    const ptr = input.source_transaction orelse return null;
    return @as(*const Transaction, @ptrCast(@alignCast(ptr)));
}

pub fn sourceOutputForInput(input: *const Input) ?Output {
    if (sourceTransactionForInput(input)) |source_tx| {
        const index = std.math.cast(usize, input.previous_outpoint.index) orelse return input.source_output;
        if (index < source_tx.outputs.len) return source_tx.outputs[index];
    }
    return input.source_output;
}

fn cloneInputs(allocator: std.mem.Allocator, inputs: []const Input) ![]Input {
    const cloned = try allocator.alloc(Input, inputs.len);
    errdefer allocator.free(cloned);
    for (cloned) |*input| input.* = Input.empty();
    errdefer for (cloned) |*input| input.deinit(allocator);
    for (inputs, 0..) |input, index| {
        cloned[index] = try input.clone(allocator);
    }
    return cloned;
}

fn cloneOutputs(allocator: std.mem.Allocator, outputs: []const Output) ![]Output {
    const cloned = try allocator.alloc(Output, outputs.len);
    errdefer allocator.free(cloned);
    for (cloned) |*output| output.* = Output.empty();
    errdefer for (cloned) |*output| output.deinit(allocator);
    for (outputs, 0..) |output, index| {
        cloned[index] = try output.clone(allocator);
    }
    return cloned;
}

fn readIntLE(comptime T: type, bytes: []const u8, cursor: *usize) !T {
    const size = @sizeOf(T);
    if (bytes.len < cursor.* + size) return error.EndOfStream;
    const ptr = @as(*const [size]u8, @ptrCast(bytes[cursor.* .. cursor.* + size].ptr));
    const val = std.mem.readInt(T, ptr, .little);
    cursor.* += size;
    return val;
}

fn readIntBE(comptime T: type, bytes: []const u8, cursor: *usize) !T {
    const size = @sizeOf(T);
    if (bytes.len < cursor.* + size) return error.EndOfStream;
    const ptr = @as(*const [size]u8, @ptrCast(bytes[cursor.* .. cursor.* + size].ptr));
    const val = std.mem.readInt(T, ptr, .big);
    cursor.* += size;
    return val;
}

test "transaction serializes, parses, and hashes canonically" {
    const allocator = std.testing.allocator;

    const tx = Transaction{
        .version = 2,
        .inputs = @constCast(&[_]Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x11} ** 32 },
                    .index = 3,
                },
                .unlocking_script = .{ .bytes = &[_]u8{ 0x51, 0x21, 0x02 } },
                .sequence = 0xffff_fffe,
            },
        }),
        .outputs = @constCast(&[_]Output{
            .{
                .satoshis = 5_000,
                .locking_script = .{ .bytes = &[_]u8{ 0x76, 0xa9, 0x14, 0x88, 0xac } },
            },
            .{
                .satoshis = 42,
                .locking_script = .{ .bytes = &[_]u8{0x6a} },
            },
        }),
        .lock_time = 99,
    };

    const serialized = try tx.serialize(allocator);
    defer allocator.free(serialized);

    try std.testing.expectEqual(tx.serializedLen(), serialized.len);

    const parsed = try Transaction.parse(allocator, serialized);
    defer parsed.deinit(allocator);

    try std.testing.expectEqual(tx.version, parsed.version);
    try std.testing.expectEqual(tx.inputs.len, parsed.inputs.len);
    try std.testing.expectEqual(tx.outputs.len, parsed.outputs.len);
    try std.testing.expectEqual(tx.lock_time, parsed.lock_time);
    try std.testing.expectEqual(tx.inputs[0].previous_outpoint.index, parsed.inputs[0].previous_outpoint.index);
    try std.testing.expectEqualSlices(u8, &tx.inputs[0].previous_outpoint.txid.bytes, &parsed.inputs[0].previous_outpoint.txid.bytes);
    try std.testing.expectEqualSlices(u8, tx.inputs[0].unlocking_script.bytes, parsed.inputs[0].unlocking_script.bytes);
    try std.testing.expectEqual(tx.outputs[0].satoshis, parsed.outputs[0].satoshis);
    try std.testing.expectEqualSlices(u8, tx.outputs[0].locking_script.bytes, parsed.outputs[0].locking_script.bytes);
    try std.testing.expectEqual(tx.outputs[1].satoshis, parsed.outputs[1].satoshis);
    try std.testing.expectEqualSlices(u8, tx.outputs[1].locking_script.bytes, parsed.outputs[1].locking_script.bytes);
    try std.testing.expectEqual(crypto.hash.hash256(serialized), try tx.txid(allocator));
}

test "transaction hex helpers round trip" {
    const allocator = std.testing.allocator;
    const raw_hex =
        "01000000011111111111111111111111111111111111111111111111111111111111111111000000000151ffffffff010500000000000000015100000000";

    var tx = try Transaction.parseHex(allocator, raw_hex);
    defer tx.deinit(allocator);

    const hex_text = try tx.hex(allocator);
    defer allocator.free(hex_text);
    try std.testing.expectEqualStrings(raw_hex, hex_text);

    const extended_bytes = try tx.serializeExtended(allocator);
    defer allocator.free(extended_bytes);
    const expected_extended_hex = try allocator.alloc(u8, extended_bytes.len * 2);
    defer allocator.free(expected_extended_hex);
    _ = try primitives.hex.encodeLower(extended_bytes, expected_extended_hex);

    const extended_hex = try tx.extendedHex(allocator);
    defer allocator.free(extended_hex);
    try std.testing.expectEqualStrings(expected_extended_hex, extended_hex);
}

test "transaction txid matches the TS SDK legacy transaction vector" {
    const allocator = std.testing.allocator;

    const raw_tx = try primitives.hex.decode(
        allocator,
        "0200000001849c6419aec8b65d747cb72282cc02f3fc26dd018b46962f5de48957fac50528020000006a473044022008a60c611f3b48eaf0d07b5425d75f6ce65c3730bd43e6208560648081f9661b0220278fa51877100054d0d08e38e069b0afdb4f0f9d38844c68ee2233ace8e0de2141210360cd30f72e805be1f00d53f9ccd47dfd249cbb65b0d4aee5cfaf005a5258be37ffffffff03d0070000000000001976a914acc4d7c37bc9d0be0a4987483058a2d842f2265d88ac75330100000000001976a914db5b7964eecb19fcab929bf6bd29297ec005d52988ac809f7c09000000001976a914c0b0a42e92f062bdbc6a881b1777eed1213c19eb88ac00000000",
    );
    defer allocator.free(raw_tx);

    const expected_txid_display = try primitives.hex.decode(
        allocator,
        "710827fa697e25424e714082517064761914ddf960ede779044217559f75a0a4",
    );
    defer allocator.free(expected_txid_display);

    const expected_txid_raw = try allocator.dupe(u8, expected_txid_display);
    defer allocator.free(expected_txid_raw);
    std.mem.reverse(u8, expected_txid_raw);

    const tx = try Transaction.parse(allocator, raw_tx);
    defer tx.deinit(allocator);

    const serialized = try tx.serialize(allocator);
    defer allocator.free(serialized);

    try std.testing.expectEqualSlices(u8, raw_tx, serialized);
    try std.testing.expectEqualSlices(u8, expected_txid_raw, &((try tx.txid(allocator)).bytes));
}

test "transaction parse rejects segwit framing" {
    const allocator = std.testing.allocator;

    const witness_tx = try primitives.hex.decode(
        allocator,
        "0100000000010280e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b0000000000ffffffffe9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc0010000000000ffffffff0280969800000000001976a9146648a8cd4531e1ec47f35916de8e259237294d1e88ac80969800000000001976a914de4b231626ef508c9a74a8517e6783c0546d6b2888ac024730440220032521802a76ad7bf74d0e2c218b72cf0cbc867066e2e53db905ba37f130397e02207709e2188ed7f08f4c952d9d13986da504502b8c3be59617e043552f506c46ff83275163ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac02483045022100f6a10b8604e6dc910194b79ccfc93e1bc0ec7c03453caaa8987f7d6c3413566002206216229ede9b4d6ec2d325be245c5b508ff0339bf1794078e20bfe0babc7ffe683270063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac00000000",
    );
    defer allocator.free(witness_tx);

    try std.testing.expectError(error.InvalidEncoding, Transaction.parse(allocator, witness_tx));
}

test "transaction parse rejects truncated and trailing legacy bytes" {
    const allocator = std.testing.allocator;

    const raw_tx = try primitives.hex.decode(
        allocator,
        "0200000001849c6419aec8b65d747cb72282cc02f3fc26dd018b46962f5de48957fac50528020000006a473044022008a60c611f3b48eaf0d07b5425d75f6ce65c3730bd43e6208560648081f9661b0220278fa51877100054d0d08e38e069b0afdb4f0f9d38844c68ee2233ace8e0de2141210360cd30f72e805be1f00d53f9ccd47dfd249cbb65b0d4aee5cfaf005a5258be37ffffffff03d0070000000000001976a914acc4d7c37bc9d0be0a4987483058a2d842f2265d88ac75330100000000001976a914db5b7964eecb19fcab929bf6bd29297ec005d52988ac809f7c09000000001976a914c0b0a42e92f062bdbc6a881b1777eed1213c19eb88ac00000000",
    );
    defer allocator.free(raw_tx);

    try std.testing.expectError(error.EndOfStream, Transaction.parse(allocator, raw_tx[0 .. raw_tx.len - 1]));

    const trailing = try allocator.alloc(u8, raw_tx.len + 1);
    defer allocator.free(trailing);
    @memcpy(trailing[0..raw_tx.len], raw_tx);
    trailing[raw_tx.len] = 0x00;

    try std.testing.expectError(error.InvalidEncoding, Transaction.parse(allocator, trailing));
}

test "transaction clone deep copies owned scripts and merkle path" {
    const allocator = std.testing.allocator;

    var tx = try Transaction.parse(
        allocator,
        &[_]u8{
            0x01, 0x00, 0x00, 0x00,
            0x01, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11,
            0x11, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x51, 0xff,
            0xff, 0xff, 0xff, 0x01,
            0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x01, 0x51, 0x00, 0x00,
            0x00, 0x00,
        },
    );
    defer tx.deinit(allocator);

    tx.merkle_path = .{
        .block_height = 1,
        .path = try allocator.alloc([]PathElement, 1),
    };
    tx.owns_merkle_path = true;
    tx.merkle_path.?.path[0] = try allocator.alloc(PathElement, 1);
    const txid = try tx.txid(allocator);
    tx.merkle_path.?.path[0][0] = .{
        .offset = 0,
        .hash = txid,
        .txid = true,
    };

    var cloned = try tx.clone(allocator);
    defer cloned.deinit(allocator);

    try std.testing.expect(tx.inputs[0].unlocking_script.bytes.ptr != cloned.inputs[0].unlocking_script.bytes.ptr);
    try std.testing.expect(tx.outputs[0].locking_script.bytes.ptr != cloned.outputs[0].locking_script.bytes.ptr);
    try std.testing.expect(tx.merkle_path.?.path[0].ptr != cloned.merkle_path.?.path[0].ptr);
}

test "transaction clones detach non-owning ancestry pointers" {
    const allocator = std.testing.allocator;

    var parent = Transaction{
        .version = 1,
        .inputs = try allocator.alloc(Input, 0),
        .outputs = try allocator.alloc(Output, 1),
        .lock_time = 0,
    };
    defer parent.deinit(allocator);
    @constCast(parent.outputs)[0] = .{
        .satoshis = 9,
        .locking_script = .{ .bytes = &[_]u8{0x51} },
    };
    const parent_txid = try parent.txid(allocator);

    var tx = Transaction{
        .version = 1,
        .inputs = try allocator.alloc(Input, 1),
        .outputs = try allocator.alloc(Output, 1),
        .lock_time = 0,
    };
    defer tx.deinit(allocator);
    @constCast(tx.inputs)[0] = .{
        .previous_outpoint = .{
            .txid = .{ .bytes = parent_txid.bytes },
            .index = 0,
        },
        .unlocking_script = .{ .bytes = &[_]u8{0x51} },
        .sequence = 0xffff_ffff,
        .source_transaction = @ptrCast(&parent),
    };
    @constCast(tx.outputs)[0] = .{
        .satoshis = 1,
        .locking_script = .{ .bytes = &[_]u8{0x51} },
    };

    var shallow = try tx.shallowClone(allocator);
    defer shallow.deinit(allocator);
    var deep = try tx.clone(allocator);
    defer deep.deinit(allocator);

    try std.testing.expect(tx.inputs[0].source_transaction != null);
    try std.testing.expect(shallow.inputs[0].source_transaction == null);
    try std.testing.expect(deep.inputs[0].source_transaction == null);
}
