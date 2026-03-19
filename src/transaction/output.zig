const std = @import("std");
const crypto = @import("../crypto/lib.zig");
const Script = @import("../script/script.zig").Script;
const primitives = @import("../primitives/lib.zig");

pub const Output = struct {
    satoshis: primitives.money.Satoshis,
    locking_script: Script,

    pub const Parsed = struct {
        output: Output,
        len: usize,
    };

    pub fn serializedLen(self: *const Output) usize {
        return 8 + primitives.varint.VarInt.encodedLen(self.locking_script.bytes.len) + self.locking_script.bytes.len;
    }

    pub fn writeInto(self: *const Output, out: []u8) usize {
        var cursor: usize = 0;
        std.mem.writeInt(i64, out[cursor..][0..8], self.satoshis, .little);
        cursor += 8;
        cursor += primitives.varint.VarInt.encodeInto(out[cursor..], self.locking_script.bytes.len) catch unreachable;
        @memcpy(out[cursor..][0..self.locking_script.bytes.len], self.locking_script.bytes);
        cursor += self.locking_script.bytes.len;
        return cursor;
    }

    pub fn serialize(self: *const Output, allocator: std.mem.Allocator) ![]u8 {
        const out = try allocator.alloc(u8, self.serializedLen());
        _ = self.writeInto(out);
        return out;
    }

    pub fn hash256(self: *const Output, allocator: std.mem.Allocator) !crypto.Hash256 {
        const serialized = try self.serialize(allocator);
        defer allocator.free(serialized);
        return crypto.hash.hash256(serialized);
    }

    pub fn parse(bytes_: []const u8) !Parsed {
        var cursor: usize = 0;
        if (bytes_.len < 8) return error.EndOfStream;

        const satoshis = std.mem.readInt(i64, bytes_[cursor..][0..8], .little);
        cursor += 8;

        const script_len_varint = try primitives.varint.VarInt.parse(bytes_[cursor..]);
        cursor += script_len_varint.len;
        const script_len = std.math.cast(usize, script_len_varint.value) orelse return error.Overflow;
        if (bytes_.len < cursor + script_len) return error.EndOfStream;

        return .{
            .output = .{
                .satoshis = satoshis,
                .locking_script = .{ .bytes = bytes_[cursor .. cursor + script_len] },
            },
            .len = cursor + script_len,
        };
    }

    pub fn hashAll(allocator: std.mem.Allocator, outputs: []const Output) !crypto.Hash256 {
        var total_len: usize = 0;
        for (outputs) |output| total_len += output.serializedLen();

        var buf = try allocator.alloc(u8, total_len);
        defer allocator.free(buf);

        var cursor: usize = 0;
        for (outputs) |output| cursor += output.writeInto(buf[cursor..]);

        return crypto.hash.hash256(buf);
    }
};

test "output serialize matches legacy encoding" {
    const output = Output{
        .satoshis = 42,
        .locking_script = .{ .bytes = &[_]u8{ 0x51, 0x51 } },
    };

    var buf = [_]u8{0} ** 11;
    const written = output.writeInto(&buf);

    try std.testing.expectEqual(@as(usize, 11), written);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x51, 0x51,
    }, &buf);
}

test "output hash256 matches serialized bytes hash" {
    const allocator = std.testing.allocator;

    const output = Output{
        .satoshis = 5000,
        .locking_script = .{ .bytes = &[_]u8{ 0x76, 0xa9, 0x14, 0x88, 0xac } },
    };

    const serialized = try output.serialize(allocator);
    defer allocator.free(serialized);

    const expected = crypto.hash.hash256(serialized);
    const actual = try output.hash256(allocator);

    try std.testing.expectEqualDeep(expected, actual);
}

test "output parse returns output and consumed length" {
    const raw = [_]u8{
        0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x51, 0x51,
        0xff,
    };

    const parsed = try Output.parse(&raw);

    try std.testing.expectEqual(@as(i64, 42), parsed.output.satoshis);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x51, 0x51 }, parsed.output.locking_script.bytes);
    try std.testing.expectEqual(@as(usize, 11), parsed.len);
}

test "output hashAll matches concatenated serialized bytes hash" {
    const allocator = std.testing.allocator;

    const outputs = [_]Output{
        .{
            .satoshis = 1,
            .locking_script = .{ .bytes = &[_]u8{0x51} },
        },
        .{
            .satoshis = 2,
            .locking_script = .{ .bytes = &[_]u8{ 0x6a, 0x00 } },
        },
    };

    var bytes_: std.ArrayListUnmanaged(u8) = .empty;
    defer bytes_.deinit(allocator);
    for (outputs) |output| {
        const start = bytes_.items.len;
        try bytes_.resize(allocator, start + output.serializedLen());
        _ = output.writeInto(bytes_.items[start..]);
    }

    try std.testing.expectEqualDeep(
        crypto.hash.hash256(bytes_.items),
        try Output.hashAll(allocator, &outputs),
    );
}
