pub fn encodeLower(bytes: []const u8, out: []u8) ![]u8 {
    const alphabet = "0123456789abcdef";
    if (out.len < bytes.len * 2) return error.NoSpaceLeft;

    for (bytes, 0..) |byte, i| {
        out[i * 2] = alphabet[byte >> 4];
        out[i * 2 + 1] = alphabet[byte & 0x0f];
    }
    return out[0 .. bytes.len * 2];
}

pub fn decode(allocator: @import("std").mem.Allocator, text: []const u8) ![]u8 {
    if (text.len % 2 != 0) return error.InvalidLength;

    const out = try allocator.alloc(u8, text.len / 2);
    errdefer allocator.free(out);

    for (0..out.len) |idx| {
        const high = decodeNibble(text[idx * 2]) orelse return error.InvalidCharacter;
        const low = decodeNibble(text[idx * 2 + 1]) orelse return error.InvalidCharacter;
        out[idx] = (high << 4) | low;
    }

    return out;
}

fn decodeNibble(char: u8) ?u8 {
    return switch (char) {
        '0'...'9' => char - '0',
        'a'...'f' => char - 'a' + 10,
        'A'...'F' => char - 'A' + 10,
        else => null,
    };
}

test "hex decode roundtrip" {
    const std = @import("std");
    const allocator = std.testing.allocator;

    const decoded = try decode(allocator, "00ff10Ab");
    defer allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0xff, 0x10, 0xab }, decoded);

    var encoded: [8]u8 = undefined;
    try std.testing.expectEqualSlices(u8, "00ff10ab", try encodeLower(decoded, &encoded));
}
