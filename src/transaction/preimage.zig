const crypto = @import("../crypto/lib.zig");
const Script = @import("../script/script.zig").Script;
const primitives = @import("../primitives/lib.zig");
const OutPoint = @import("outpoint.zig").OutPoint;

pub const Preimage = struct {
    raw: []const u8,
    version: i32,
    hash_prevouts: crypto.Hash256,
    hash_sequence: crypto.Hash256,
    outpoint: OutPoint,
    script_code: Script,
    satoshis: primitives.money.Satoshis,
    sequence: u32,
    hash_outputs: crypto.Hash256,
    lock_time: u32,
    sighash_type: u32,

    pub fn parse(raw: []const u8) !Preimage {
        if (raw.len < 4 + 32 + 32 + 36 + 1 + 8 + 4 + 32 + 4 + 4) return error.EndOfStream;

        var cursor: usize = 0;
        const version = std.mem.readInt(i32, raw[cursor..][0..4], .little);
        cursor += 4;

        const hash_prevouts = crypto.Hash256{ .bytes = raw[cursor..][0..32].* };
        cursor += 32;

        const hash_sequence = crypto.Hash256{ .bytes = raw[cursor..][0..32].* };
        cursor += 32;

        const txid = crypto.Hash256{ .bytes = raw[cursor..][0..32].* };
        cursor += 32;
        const index = std.mem.readInt(u32, raw[cursor..][0..4], .little);
        cursor += 4;

        const script_len = try primitives.varint.VarInt.parse(raw[cursor..]);
        cursor += script_len.len;
        if (raw.len < cursor + script_len.value + 8 + 4 + 32 + 4 + 4) return error.EndOfStream;

        const script_code = Script.init(raw[cursor .. cursor + script_len.value]);
        cursor += script_len.value;

        const satoshis = std.mem.readInt(i64, raw[cursor..][0..8], .little);
        cursor += 8;

        const sequence = std.mem.readInt(u32, raw[cursor..][0..4], .little);
        cursor += 4;

        const hash_outputs = crypto.Hash256{ .bytes = raw[cursor..][0..32].* };
        cursor += 32;

        const lock_time = std.mem.readInt(u32, raw[cursor..][0..4], .little);
        cursor += 4;

        const sighash_type = std.mem.readInt(u32, raw[cursor..][0..4], .little);
        cursor += 4;
        if (cursor != raw.len) return error.InvalidEncoding;

        return .{
            .raw = raw,
            .version = version,
            .hash_prevouts = hash_prevouts,
            .hash_sequence = hash_sequence,
            .outpoint = .{ .txid = txid, .index = index },
            .script_code = script_code,
            .satoshis = satoshis,
            .sequence = sequence,
            .hash_outputs = hash_outputs,
            .lock_time = lock_time,
            .sighash_type = sighash_type,
        };
    }

    pub fn hashPrevouts(self: Preimage) crypto.Hash256 {
        return self.hash_prevouts;
    }

    pub fn hashSequence(self: Preimage) crypto.Hash256 {
        return self.hash_sequence;
    }

    pub fn previousOutpoint(self: Preimage) OutPoint {
        return self.outpoint;
    }

    pub fn outpointBytes(self: Preimage) [36]u8 {
        var out: [36]u8 = undefined;
        @memcpy(out[0..32], &self.outpoint.txid.bytes);
        std.mem.writeInt(u32, out[32..36], self.outpoint.index, .little);
        return out;
    }

    pub fn hashOutputs(self: Preimage) crypto.Hash256 {
        return self.hash_outputs;
    }

    pub fn lockTime(self: Preimage) u32 {
        return self.lock_time;
    }
};

const std = @import("std");

pub fn extractHashPrevouts(raw: []const u8) !crypto.Hash256 {
    return (try Preimage.parse(raw)).hashPrevouts();
}

pub fn extractOutpoint(raw: []const u8) !OutPoint {
    return (try Preimage.parse(raw)).previousOutpoint();
}

pub fn extractOutpointBytes(raw: []const u8) ![36]u8 {
    return (try Preimage.parse(raw)).outpointBytes();
}

pub fn extractOutputHash(raw: []const u8) !crypto.Hash256 {
    return (try Preimage.parse(raw)).hashOutputs();
}

pub fn extractLocktime(raw: []const u8) !u32 {
    return (try Preimage.parse(raw)).lockTime();
}

test "preimage parser extracts canonical fields" {
    const raw =
        [_]u8{
            0x02, 0x00, 0x00, 0x00,
        } ++
        ([_]u8{0x11} ** 32) ++
        ([_]u8{0x22} ** 32) ++
        ([_]u8{0x33} ** 32) ++
        [_]u8{ 0x01, 0x00, 0x00, 0x00 } ++
        [_]u8{0x03} ++
        [_]u8{ 0x51, 0x76, 0xac } ++
        [_]u8{ 0x88, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } ++
        [_]u8{ 0xfe, 0xff, 0xff, 0xff } ++
        ([_]u8{0x44} ** 32) ++
        [_]u8{ 0x39, 0x30, 0x00, 0x00 } ++
        [_]u8{ 0x41, 0x00, 0x00, 0x00 };

    const preimage = try Preimage.parse(&raw);
    const outpoint_bytes = preimage.outpointBytes();

    try std.testing.expectEqual(@as(i32, 2), preimage.version);
    try std.testing.expectEqual(@as(u32, 1), preimage.outpoint.index);
    try std.testing.expectEqual(@as(usize, 3), preimage.script_code.len());
    try std.testing.expectEqual(@as(i64, 5000), preimage.satoshis);
    try std.testing.expectEqual(@as(u32, 0xfffffffe), preimage.sequence);
    try std.testing.expectEqual(@as(u32, 12345), preimage.lockTime());
    try std.testing.expectEqual(@as(u32, 65), preimage.sighash_type);
    try std.testing.expectEqualSlices(u8, &([_]u8{0x11} ** 32), &preimage.hashPrevouts().bytes);
    try std.testing.expectEqualSlices(u8, &([_]u8{0x44} ** 32), &preimage.hashOutputs().bytes);
    try std.testing.expectEqualSlices(u8, &([_]u8{0x33} ** 32), outpoint_bytes[0..32]);
}

test "preimage extractor helpers match parsed values" {
    const raw =
        [_]u8{
            0x02, 0x00, 0x00, 0x00,
        } ++
        ([_]u8{0x11} ** 32) ++
        ([_]u8{0x22} ** 32) ++
        ([_]u8{0x33} ** 32) ++
        [_]u8{ 0x02, 0x00, 0x00, 0x00 } ++
        [_]u8{0x01} ++
        [_]u8{0x51} ++
        [_]u8{ 0x88, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } ++
        [_]u8{ 0xfe, 0xff, 0xff, 0xff } ++
        ([_]u8{0x44} ** 32) ++
        [_]u8{ 0x39, 0x30, 0x00, 0x00 } ++
        [_]u8{ 0x41, 0x00, 0x00, 0x00 };

    const parsed = try Preimage.parse(&raw);
    const outpoint = try extractOutpoint(&raw);
    const parsed_outpoint_bytes = parsed.outpointBytes();
    const extracted_outpoint_bytes = try extractOutpointBytes(&raw);

    try std.testing.expectEqual(parsed.hashPrevouts(), try extractHashPrevouts(&raw));
    try std.testing.expectEqual(parsed.hashOutputs(), try extractOutputHash(&raw));
    try std.testing.expectEqual(parsed.lockTime(), try extractLocktime(&raw));
    try std.testing.expectEqual(parsed.previousOutpoint().index, outpoint.index);
    try std.testing.expectEqualSlices(u8, &parsed.previousOutpoint().txid.bytes, &outpoint.txid.bytes);
    try std.testing.expectEqualSlices(u8, &parsed_outpoint_bytes, &extracted_outpoint_bytes);
}

test "preimage parser rejects truncated and trailing bytes" {
    const raw =
        [_]u8{
            0x02, 0x00, 0x00, 0x00,
        } ++
        ([_]u8{0x11} ** 32) ++
        ([_]u8{0x22} ** 32) ++
        ([_]u8{0x33} ** 32) ++
        [_]u8{ 0x02, 0x00, 0x00, 0x00 } ++
        [_]u8{0x01} ++
        [_]u8{0x51} ++
        [_]u8{ 0x88, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } ++
        [_]u8{ 0xfe, 0xff, 0xff, 0xff } ++
        ([_]u8{0x44} ** 32) ++
        [_]u8{ 0x39, 0x30, 0x00, 0x00 } ++
        [_]u8{ 0x41, 0x00, 0x00, 0x00 };

    try std.testing.expectError(error.EndOfStream, Preimage.parse(raw[0 .. raw.len - 1]));

    const trailing = raw ++ [_]u8{0x00};
    try std.testing.expectError(error.InvalidEncoding, Preimage.parse(&trailing));
}
