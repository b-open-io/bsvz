const std = @import("std");
const crypto = @import("../crypto/lib.zig");

pub const Error = error{
    InvalidCharacter,
    InvalidChecksum,
    InvalidPayloadLength,
};

const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn encode(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    if (bytes.len == 0) return allocator.alloc(u8, 0);

    var zeroes: usize = 0;
    while (zeroes < bytes.len and bytes[zeroes] == 0) : (zeroes += 1) {}

    const size = (bytes.len - zeroes) * 138 / 100 + 1;
    const digits = try allocator.alloc(u8, size);
    defer allocator.free(digits);
    @memset(digits, 0);

    var length: usize = 0;
    for (bytes[zeroes..]) |byte| {
        var carry: u32 = byte;
        var i: usize = 0;
        var j: usize = size;

        while ((carry != 0 or i < length) and j > 0) {
            j -= 1;
            carry += @as(u32, digits[j]) * 256;
            digits[j] = @intCast(carry % 58);
            carry /= 58;
            i += 1;
        }

        length = i;
    }

    var first_non_zero = size - length;
    while (first_non_zero < size and digits[first_non_zero] == 0) : (first_non_zero += 1) {}

    const out_len = zeroes + (size - first_non_zero);
    const out = try allocator.alloc(u8, out_len);
    @memset(out[0..zeroes], alphabet[0]);
    for (digits[first_non_zero..], 0..) |digit, idx| {
        out[zeroes + idx] = alphabet[digit];
    }
    return out;
}

pub fn decode(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    if (text.len == 0) return allocator.alloc(u8, 0);

    var zeroes: usize = 0;
    while (zeroes < text.len and text[zeroes] == alphabet[0]) : (zeroes += 1) {}

    const size = (text.len - zeroes) * 733 / 1000 + 1;
    const bytes = try allocator.alloc(u8, size);
    defer allocator.free(bytes);
    @memset(bytes, 0);

    var length: usize = 0;
    for (text[zeroes..]) |char| {
        const value = decodeChar(char) orelse return error.InvalidCharacter;
        var carry: u32 = value;
        var i: usize = 0;
        var j: usize = size;

        while ((carry != 0 or i < length) and j > 0) {
            j -= 1;
            carry += @as(u32, bytes[j]) * 58;
            bytes[j] = @intCast(carry % 256);
            carry /= 256;
            i += 1;
        }

        length = i;
    }

    var first_non_zero = size - length;
    while (first_non_zero < size and bytes[first_non_zero] == 0) : (first_non_zero += 1) {}

    const out_len = zeroes + (size - first_non_zero);
    const out = try allocator.alloc(u8, out_len);
    @memset(out[0..zeroes], 0);
    @memcpy(out[zeroes..], bytes[first_non_zero..]);
    return out;
}

pub fn encodeCheck(allocator: std.mem.Allocator, payload: []const u8) ![]u8 {
    const extended = try allocator.alloc(u8, payload.len + 4);
    defer allocator.free(extended);

    @memcpy(extended[0..payload.len], payload);
    const checksum = crypto.hash.hash256(payload);
    @memcpy(extended[payload.len..], checksum.bytes[0..4]);

    return encode(allocator, extended);
}

pub fn decodeCheck(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    const decoded = try decode(allocator, text);
    defer allocator.free(decoded);

    if (decoded.len < 4) return error.InvalidPayloadLength;

    const payload_len = decoded.len - 4;
    const checksum = crypto.hash.hash256(decoded[0..payload_len]);
    if (!std.mem.eql(u8, checksum.bytes[0..4], decoded[payload_len..])) {
        return error.InvalidChecksum;
    }

    return allocator.dupe(u8, decoded[0..payload_len]);
}

fn decodeChar(char: u8) ?u8 {
    return switch (char) {
        '1'...'9' => char - '1',
        'A'...'H' => char - 'A' + 9,
        'J'...'N' => char - 'J' + 17,
        'P'...'Z' => char - 'P' + 22,
        'a'...'k' => char - 'a' + 33,
        'm'...'z' => char - 'm' + 44,
        else => null,
    };
}

test "base58 preserves leading zero bytes" {
    const allocator = std.testing.allocator;
    const encoded = try encode(allocator, &[_]u8{ 0x00, 0x00, 0x01, 0x02 });
    defer allocator.free(encoded);

    try std.testing.expectEqualSlices(u8, "115T", encoded);

    const decoded = try decode(allocator, encoded);
    defer allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00, 0x01, 0x02 }, decoded);
}

test "base58check encodes the all-zero p2pkh payload vector" {
    const allocator = std.testing.allocator;
    const payload = [_]u8{0x00} ++ ([_]u8{0x00} ** 20);
    const encoded = try encodeCheck(allocator, &payload);
    defer allocator.free(encoded);

    try std.testing.expectEqualSlices(u8, "1111111111111111111114oLvT2", encoded);

    const decoded = try decodeCheck(allocator, encoded);
    defer allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, &payload, decoded);
}

test "base58check rejects invalid checksum" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidChecksum, decodeCheck(allocator, "1111111111111111111114oLvT3"));
}

test "base58 rejects ambiguous characters" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidCharacter, decode(allocator, "0"));
    try std.testing.expectError(error.InvalidCharacter, decode(allocator, "O"));
    try std.testing.expectError(error.InvalidCharacter, decode(allocator, "I"));
    try std.testing.expectError(error.InvalidCharacter, decode(allocator, "l"));
}
