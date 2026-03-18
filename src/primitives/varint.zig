const std = @import("std");

pub const VarInt = struct {
    value: u64,
    len: usize,

    pub fn encodedLen(value: u64) usize {
        return switch (value) {
            0...0xfc => 1,
            0xfd...0xffff => 3,
            0x10000...0xffff_ffff => 5,
            else => 9,
        };
    }

    pub fn parse(bytes: []const u8) !VarInt {
        if (bytes.len == 0) return error.EndOfStream;

        return switch (bytes[0]) {
            0xfd => if (bytes.len < 3) error.EndOfStream else .{
                .value = std.mem.readInt(u16, bytes[1..3], .little),
                .len = 3,
            },
            0xfe => if (bytes.len < 5) error.EndOfStream else .{
                .value = std.mem.readInt(u32, bytes[1..5], .little),
                .len = 5,
            },
            0xff => if (bytes.len < 9) error.EndOfStream else .{
                .value = std.mem.readInt(u64, bytes[1..9], .little),
                .len = 9,
            },
            else => .{
                .value = bytes[0],
                .len = 1,
            },
        };
    }

    pub fn encodeInto(out: []u8, value: u64) !usize {
        const len = encodedLen(value);
        if (out.len < len) return error.EndOfStream;

        switch (len) {
            1 => out[0] = @intCast(value),
            3 => {
                out[0] = 0xfd;
                std.mem.writeInt(u16, out[1..3], @intCast(value), .little);
            },
            5 => {
                out[0] = 0xfe;
                std.mem.writeInt(u32, out[1..5], @intCast(value), .little);
            },
            9 => {
                out[0] = 0xff;
                std.mem.writeInt(u64, out[1..9], value, .little);
            },
            else => unreachable,
        }

        return len;
    }
};

test "varint parses compact values" {
    const parsed = try VarInt.parse(&[_]u8{0xfd, 0x34, 0x12});
    try std.testing.expectEqual(@as(u64, 0x1234), parsed.value);
    try std.testing.expectEqual(@as(usize, 3), parsed.len);
}

test "varint parses each prefix width" {
    const one = try VarInt.parse(&[_]u8{0xfc});
    try std.testing.expectEqual(@as(u64, 0xfc), one.value);
    try std.testing.expectEqual(@as(usize, 1), one.len);

    const three = try VarInt.parse(&[_]u8{ 0xfd, 0xfd, 0x00 });
    try std.testing.expectEqual(@as(u64, 0xfd), three.value);
    try std.testing.expectEqual(@as(usize, 3), three.len);

    const five = try VarInt.parse(&[_]u8{ 0xfe, 0x00, 0x00, 0x01, 0x00 });
    try std.testing.expectEqual(@as(u64, 0x00010000), five.value);
    try std.testing.expectEqual(@as(usize, 5), five.len);

    const nine = try VarInt.parse(&[_]u8{ 0xff, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01 });
    try std.testing.expectEqual(@as(u64, 0x0102030405060708), nine.value);
    try std.testing.expectEqual(@as(usize, 9), nine.len);
}

test "varint rejects truncated prefixed encodings" {
    try std.testing.expectError(error.EndOfStream, VarInt.parse(&[_]u8{}));
    try std.testing.expectError(error.EndOfStream, VarInt.parse(&[_]u8{0xfd}));
    try std.testing.expectError(error.EndOfStream, VarInt.parse(&[_]u8{ 0xfe, 0x01, 0x02, 0x03 }));
    try std.testing.expectError(error.EndOfStream, VarInt.parse(&[_]u8{ 0xff, 0x01, 0x02, 0x03, 0x04 }));
}

test "varint encode and parse roundtrip across widths" {
    const values = [_]u64{ 0, 0xfc, 0xfd, 0xffff, 0x1_0000, 0xffff_ffff, 0x1_0000_0000 };

    for (values) |value| {
        var buf: [9]u8 = [_]u8{0} ** 9;
        const len = try VarInt.encodeInto(&buf, value);
        const parsed = try VarInt.parse(buf[0..len]);

        try std.testing.expectEqual(value, parsed.value);
        try std.testing.expectEqual(len, parsed.len);
        try std.testing.expectEqual(VarInt.encodedLen(value), len);
    }
}
