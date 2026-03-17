const std = @import("std");

pub const ScriptNum = struct {
    pub fn decode(bytes: []const u8) !i64 {
        if (bytes.len == 0) return 0;
        if (bytes.len > 8) return error.Overflow;

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

    pub fn encode(allocator: std.mem.Allocator, value: i64) ![]u8 {
        if (value == 0) return allocator.alloc(u8, 0);

        const negative = value < 0;
        const positive_value: i128 = if (negative) -@as(i128, value) else value;
        var magnitude: u64 = @intCast(positive_value);
        var tmp: [9]u8 = [_]u8{0} ** 9;
        var len: usize = 0;

        while (magnitude != 0) : (len += 1) {
            tmp[len] = @truncate(magnitude & 0xff);
            magnitude >>= 8;
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
};

test "script num roundtrip" {
    const allocator = std.testing.allocator;
    const encoded = try ScriptNum.encode(allocator, 17);
    defer allocator.free(encoded);

    try std.testing.expectEqual(@as(i64, 17), try ScriptNum.decode(encoded));
}
