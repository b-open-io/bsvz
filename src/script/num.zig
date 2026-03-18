const std = @import("std");

pub const Error = error{
    Overflow,
    InvalidEncoding,
    NonMinimalEncoding,
};

pub const ScriptNum = struct {
    pub fn decode(bytes: []const u8) Error!i64 {
        return decodeInternal(bytes, false);
    }

    pub fn decodeMinimal(bytes: []const u8) Error!i64 {
        return decodeInternal(bytes, true);
    }

    pub fn encode(allocator: std.mem.Allocator, value: i64) ![]u8 {
        if (value == 0) return allocator.alloc(u8, 0);

        const negative = value < 0;
        const positive_value: i128 = if (negative) -@as(i128, value) else value;
        var magnitude: u64 = @intCast(positive_value);
        var tmp: [9]u8 = [_]u8{0} ** 9;
        var len: usize = 0;

        while (magnitude != 0) {
            tmp[len] = @truncate(magnitude & 0xff);
            magnitude >>= 8;
            len += 1;
        }

        if ((tmp[len - 1] & 0x80) != 0) {
            tmp[len] = 0;
            len += 1;
        }

        var out = try allocator.alloc(u8, len);
        @memcpy(out, tmp[0..len]);
        if (negative) out[len - 1] |= 0x80;
        return out;
    }

    pub fn num2bin(allocator: std.mem.Allocator, value: i64, size: usize) ![]u8 {
        const encoded = try encode(allocator, value);
        defer allocator.free(encoded);

        if (size == 0) {
            if (value == 0) return allocator.alloc(u8, 0);
            return error.InvalidEncoding;
        }
        if (encoded.len > size) return error.InvalidEncoding;

        var out = try allocator.alloc(u8, size);
        @memset(out, 0);
        @memcpy(out[0..encoded.len], encoded);
        return out;
    }

    pub fn bin2num(bytes: []const u8) Error!i64 {
        return decode(bytes);
    }

    fn decodeInternal(bytes: []const u8, require_minimal: bool) Error!i64 {
        if (bytes.len == 0) return 0;
        if (bytes.len > 8) return error.Overflow;
        if (require_minimal and !isMinimallyEncoded(bytes)) return error.NonMinimalEncoding;

        const last = bytes.len - 1;
        const negative = (bytes[last] & 0x80) != 0;

        var magnitude: u64 = 0;
        for (bytes, 0..) |byte, idx| {
            const part: u8 = if (idx == last) (byte & 0x7f) else byte;
            magnitude |= @as(u64, part) << @intCast(idx * 8);
        }

        if (!negative) {
            return std.math.cast(i64, magnitude) orelse error.Overflow;
        }

        if (magnitude == 0) return 0;
        if (magnitude > @as(u64, std.math.maxInt(i64))) return error.Overflow;
        return -@as(i64, @intCast(magnitude));
    }

    fn isMinimallyEncoded(bytes: []const u8) bool {
        if (bytes.len == 0) return true;
        if ((bytes[bytes.len - 1] & 0x7f) != 0) return true;
        if (bytes.len == 1) return false;
        return (bytes[bytes.len - 2] & 0x80) != 0;
    }
};

test "script num roundtrip for positive and negative values" {
    const allocator = std.testing.allocator;

    for ([_]i64{
        0,
        1,
        -1,
        16,
        -16,
        17,
        -17,
        127,
        -127,
        128,
        -128,
        255,
        -255,
        256,
        -256,
        32767,
        -32767,
        32768,
        -32768,
        std.math.maxInt(i32),
        std.math.minInt(i32),
    }) |value| {
        const encoded = try ScriptNum.encode(allocator, value);
        defer allocator.free(encoded);
        try std.testing.expectEqual(value, try ScriptNum.decode(encoded));
        try std.testing.expectEqual(value, try ScriptNum.decodeMinimal(encoded));
    }
}

test "num2bin and bin2num roundtrip" {
    const allocator = std.testing.allocator;
    const encoded = try ScriptNum.num2bin(allocator, 300, 2);
    defer allocator.free(encoded);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x2c, 0x01 }, encoded);
    try std.testing.expectEqual(@as(i64, 300), try ScriptNum.bin2num(encoded));
}

test "decodeMinimal rejects negative zero" {
    try std.testing.expectError(error.NonMinimalEncoding, ScriptNum.decodeMinimal(&[_]u8{0x80}));
}

test "decodeMinimal rejects redundant sign padding" {
    try std.testing.expectError(error.NonMinimalEncoding, ScriptNum.decodeMinimal(&[_]u8{ 0x01, 0x00 }));
    try std.testing.expectError(error.NonMinimalEncoding, ScriptNum.decodeMinimal(&[_]u8{ 0x01, 0x80 }));
}

test "num2bin rejects undersized non-zero encodings" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidEncoding, ScriptNum.num2bin(allocator, 128, 1));
    try std.testing.expectError(error.InvalidEncoding, ScriptNum.num2bin(allocator, -128, 1));
}
