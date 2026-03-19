const std = @import("std");

pub fn encodeLower(bytes: []const u8, out: []u8) ![]u8 {
    const alphabet = "0123456789abcdef";
    if (out.len < bytes.len * 2) return error.NoSpaceLeft;

    for (bytes, 0..) |byte, i| {
        out[i * 2] = alphabet[byte >> 4];
        out[i * 2 + 1] = alphabet[byte & 0x0f];
    }
    return out[0 .. bytes.len * 2];
}

pub fn decodedLen(text: []const u8) !usize {
    if (text.len % 2 != 0) return error.InvalidLength;
    return text.len / 2;
}

pub fn decodeInto(text: []const u8, out: []u8) ![]u8 {
    const out_len = try decodedLen(text);
    if (out.len < out_len) return error.NoSpaceLeft;

    var src_idx: usize = 0;
    while (src_idx < text.len) : (src_idx += 2) {
        const high = nibble_table[text[src_idx]];
        const low = nibble_table[text[src_idx + 1]];
        if (high == 0xff or low == 0xff) return error.InvalidCharacter;
        out[src_idx >> 1] = (high << 4) | low;
    }

    return out[0..out_len];
}

pub fn decode(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    const out_len = try decodedLen(text);
    const out = try allocator.alloc(u8, out_len);
    errdefer allocator.free(out);

    _ = try decodeInto(text, out);
    return out;
}

const nibble_table = buildNibbleTable();

fn buildNibbleTable() [256]u8 {
    var table = [_]u8{0xff} ** 256;
    for ('0'..'9' + 1) |char| table[char] = @intCast(char - '0');
    for ('a'..'f' + 1) |char| table[char] = @intCast(char - 'a' + 10);
    for ('A'..'F' + 1) |char| table[char] = @intCast(char - 'A' + 10);
    return table;
}

test "hex decode roundtrip" {
    const allocator = std.testing.allocator;

    const decoded = try decode(allocator, "00ff10Ab");
    defer allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0xff, 0x10, 0xab }, decoded);

    var encoded: [8]u8 = undefined;
    try std.testing.expectEqualSlices(u8, "00ff10ab", try encodeLower(decoded, &encoded));
}

test "hex decodeInto decodes into a caller-provided buffer" {
    var buf: [4]u8 = undefined;
    const decoded = try decodeInto("00ff10Ab", &buf);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0xff, 0x10, 0xab }, decoded);
}
