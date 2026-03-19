const std = @import("std");
const crypto = @import("../crypto/lib.zig");
const Script = @import("../script/script.zig").Script;
const primitives = @import("../primitives/lib.zig");

pub const Output = struct {
    satoshis: primitives.money.Satoshis,
    locking_script: Script,

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
