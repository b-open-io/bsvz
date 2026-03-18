const std = @import("std");

const ripemd160_r = [_]u8{
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
};

const ripemd160_rp = [_]u8{
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
};

const ripemd160_s = [_]u5{
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
};

const ripemd160_sp = [_]u5{
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
};

const ripemd160_k = [_]u32{
    0x00000000,
    0x5a827999,
    0x6ed9eba1,
    0x8f1bbcdc,
    0xa953fd4e,
};

const ripemd160_kp = [_]u32{
    0x50a28be6,
    0x5c4dd124,
    0x6d703ef3,
    0x7a6d76e9,
    0x00000000,
};

pub const Hash160 = struct {
    bytes: [20]u8,

    pub fn zero() Hash160 {
        return .{ .bytes = [_]u8{0} ** 20 };
    }

    pub fn eql(self: Hash160, other: Hash160) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }
};

pub const Hash256 = struct {
    bytes: [32]u8,

    pub fn zero() Hash256 {
        return .{ .bytes = [_]u8{0} ** 32 };
    }

    pub fn eql(self: Hash256, other: Hash256) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }
};

pub fn sha256(data: []const u8) Hash256 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &out, .{});
    return .{ .bytes = out };
}

pub fn hash256(data: []const u8) Hash256 {
    const first = sha256(data);
    return sha256(&first.bytes);
}

pub fn ripemd160(data: []const u8) Hash160 {
    var out: [20]u8 = undefined;
    ripemd160Hash(&out, data);
    return .{ .bytes = out };
}

pub fn hash160(data: []const u8) Hash160 {
    const first = sha256(data);
    return ripemd160(&first.bytes);
}

fn ripemd160Hash(out: *[20]u8, data: []const u8) void {
    var h0: u32 = 0x67452301;
    var h1: u32 = 0xefcdab89;
    var h2: u32 = 0x98badcfe;
    var h3: u32 = 0x10325476;
    var h4: u32 = 0xc3d2e1f0;

    const full_blocks = data.len / 64;
    for (0..full_blocks) |block_index| {
        const block = data[block_index * 64 ..][0..64];
        ripemd160ProcessBlock(block, &h0, &h1, &h2, &h3, &h4);
    }

    var tail: [128]u8 = [_]u8{0} ** 128;
    const remainder = data.len % 64;
    @memcpy(tail[0..remainder], data[full_blocks * 64 ..]);
    tail[remainder] = 0x80;

    const bit_len: u64 = @as(u64, @intCast(data.len)) * 8;
    const tail_len: usize = if (remainder + 1 + 8 <= 64) 64 else 128;
    std.mem.writeInt(u64, tail[tail_len - 8 .. tail_len][0..8], bit_len, .little);

    ripemd160ProcessBlock(tail[0..64], &h0, &h1, &h2, &h3, &h4);
    if (tail_len == 128) {
        ripemd160ProcessBlock(tail[64..128], &h0, &h1, &h2, &h3, &h4);
    }

    std.mem.writeInt(u32, out[0..4], h0, .little);
    std.mem.writeInt(u32, out[4..8], h1, .little);
    std.mem.writeInt(u32, out[8..12], h2, .little);
    std.mem.writeInt(u32, out[12..16], h3, .little);
    std.mem.writeInt(u32, out[16..20], h4, .little);
}

fn ripemd160ProcessBlock(block: []const u8, h0: *u32, h1: *u32, h2: *u32, h3: *u32, h4: *u32) void {
    var x: [16]u32 = undefined;
    for (0..16) |word_index| {
        x[word_index] = std.mem.readInt(u32, block[word_index * 4 ..][0..4], .little);
    }

    var al = h0.*;
    var bl = h1.*;
    var cl = h2.*;
    var dl = h3.*;
    var el = h4.*;
    var ar = h0.*;
    var br = h1.*;
    var cr = h2.*;
    var dr = h3.*;
    var er = h4.*;

    for (0..80) |step| {
        const round = step / 16;

        const tl = std.math.rotl(
            u32,
            al +% ripemd160F(step, bl, cl, dl) +% x[ripemd160_r[step]] +% ripemd160_k[round],
            ripemd160_s[step],
        ) +% el;
        al = el;
        el = dl;
        dl = std.math.rotl(u32, cl, 10);
        cl = bl;
        bl = tl;

        const tr = std.math.rotl(
            u32,
            ar +% ripemd160F(79 - step, br, cr, dr) +% x[ripemd160_rp[step]] +% ripemd160_kp[round],
            ripemd160_sp[step],
        ) +% er;
        ar = er;
        er = dr;
        dr = std.math.rotl(u32, cr, 10);
        cr = br;
        br = tr;
    }

    const t = h1.* +% cl +% dr;
    h1.* = h2.* +% dl +% er;
    h2.* = h3.* +% el +% ar;
    h3.* = h4.* +% al +% br;
    h4.* = h0.* +% bl +% cr;
    h0.* = t;
}

fn ripemd160F(step: usize, x: u32, y: u32, z: u32) u32 {
    return switch (step / 16) {
        0 => x ^ y ^ z,
        1 => (x & y) | (~x & z),
        2 => (x | ~y) ^ z,
        3 => (x & z) | (y & ~z),
        else => x ^ (y | ~z),
    };
}

test "sha256 matches the known abc vector" {
    const expected = [_]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    try std.testing.expectEqualSlices(u8, &expected, &sha256("abc").bytes);
}

test "ripemd160 matches the known empty-string vector" {
    const expected = [_]u8{
        0x9c, 0x11, 0x85, 0xa5, 0xc5, 0xe9, 0xfc, 0x54,
        0x61, 0x28, 0x08, 0x97, 0x7e, 0xe8, 0xf5, 0x48,
        0xb2, 0x25, 0x8d, 0x31,
    };
    try std.testing.expectEqualSlices(u8, &expected, &ripemd160("").bytes);
}

test "hash160 returns a non-zero digest for non-empty data" {
    try std.testing.expect(!hash160("bsvz").eql(Hash160.zero()));
}

test "ripemd160 matches the known abc vector" {
    const expected = [_]u8{
        0x8e, 0xb2, 0x08, 0xf7, 0xe0, 0x5d, 0x98, 0x7a,
        0x9b, 0x04, 0x4a, 0x8e, 0x98, 0xc6, 0xb0, 0x87,
        0xf1, 0x5a, 0x0b, 0xfc,
    };
    try std.testing.expectEqualSlices(u8, &expected, &ripemd160("abc").bytes);
}
