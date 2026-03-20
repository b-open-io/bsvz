const std = @import("std");

const crypto_hash = @import("../crypto/hash.zig");

pub const HashSize = 32;
pub const MaxHashStringSize = HashSize * 2;

pub const DecodeError = error{
    HashStrTooLong,
    InvalidHex,
};

pub const Hash = struct {
    bytes: [HashSize]u8,

    pub fn zero() Hash {
        return .{ .bytes = [_]u8{0} ** HashSize };
    }

    pub fn eql(self: Hash, other: Hash) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }

    pub fn setBytes(self: *Hash, new_bytes: []const u8) !void {
        if (new_bytes.len != HashSize) return error.InvalidHex;
        @memcpy(&self.bytes, new_bytes);
    }

    pub fn toHex(self: Hash, out: *[MaxHashStringSize]u8) []const u8 {
        var tmp = self.bytes;
        reverseInPlace(&tmp);
        const encoded = std.fmt.bytesToHex(tmp, .lower);
        @memcpy(out, &encoded);
        return out[0..MaxHashStringSize];
    }

    pub fn fromHex(hex_str: []const u8) !Hash {
        var h = Hash.zero();
        try decode(&h, hex_str);
        return h;
    }
};

pub fn hashB(data: []const u8) [HashSize]u8 {
    return crypto_hash.sha256(data).bytes;
}

pub fn hashH(data: []const u8) Hash {
    return .{ .bytes = crypto_hash.sha256(data).bytes };
}

pub fn doubleHashB(data: []const u8) [HashSize]u8 {
    return crypto_hash.hash256(data).bytes;
}

pub fn doubleHashH(data: []const u8) Hash {
    return .{ .bytes = crypto_hash.hash256(data).bytes };
}

pub fn decode(dst: *Hash, src: []const u8) DecodeError!void {
    if (src.len > MaxHashStringSize) return error.HashStrTooLong;

    var buf: [MaxHashStringSize + 1]u8 = undefined;
    var src_len = src.len;
    if (src_len % 2 == 1) {
        buf[0] = '0';
        @memcpy(buf[1 .. 1 + src_len], src);
        src_len += 1;
    } else {
        @memcpy(buf[0..src_len], src);
    }

    const decoded_len = src_len / 2;
    var reversed: [HashSize]u8 = [_]u8{0} ** HashSize;
    const out_slice = reversed[HashSize - decoded_len .. HashSize];
    if (std.fmt.hexToBytes(out_slice, buf[0..src_len])) |_| {} else |_| {
        return error.InvalidHex;
    }

    for (0..HashSize) |i| {
        dst.bytes[i] = reversed[HashSize - 1 - i];
    }
}

fn reverseInPlace(bytes: *[HashSize]u8) void {
    var i: usize = 0;
    while (i < HashSize / 2) : (i += 1) {
        const j = HashSize - 1 - i;
        const tmp = bytes[i];
        bytes[i] = bytes[j];
        bytes[j] = tmp;
    }
}

test "hash string round trip (reverse hex)" {
    const input = "01";
    const h = try Hash.fromHex(input);
    var buf: [MaxHashStringSize]u8 = undefined;
    const out = h.toHex(&buf);
    try std.testing.expectEqual(@as(usize, MaxHashStringSize), out.len);
    try std.testing.expectEqualStrings(
        "0000000000000000000000000000000000000000000000000000000000000001",
        out,
    );
}

test "doubleHash matches hash256" {
    const data = "bsv";
    const h = doubleHashH(data);
    try std.testing.expectEqualSlices(u8, &h.bytes, &crypto_hash.hash256(data).bytes);
}
