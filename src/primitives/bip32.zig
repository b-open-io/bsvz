//! BIP32 hierarchical deterministic keys (SLIP-0010 / Bitcoin-style secp256k1).
//! Matches github.com/bsv-blockchain/go-sdk compat/bip32 ExtendedKey behavior.

const std = @import("std");
const hash = @import("../crypto/hash.zig");
const secp = @import("../crypto/secp256k1.zig");
const base58 = @import("base58.zig");
const StdScalar = std.crypto.ecc.Secp256k1.scalar;

pub const HardenedKeyStart: u32 = 0x80000000;
pub const min_seed_len = 16;
pub const max_seed_len = 64;
pub const serialized_payload_len = 78;

pub const Versions = struct {
    private: [4]u8,
    public: [4]u8,

    pub const mainnet: Versions = .{
        .private = .{ 0x04, 0x88, 0xad, 0xe4 },
        .public = .{ 0x04, 0x88, 0xb2, 0x1e },
    };
    pub const testnet: Versions = .{
        .private = .{ 0x04, 0x35, 0x83, 0x94 },
        .public = .{ 0x04, 0x35, 0x87, 0xcf },
    };
};

pub const Error = error{
    DeriveHardFromPublic,
    DeriveBeyondMaxDepth,
    InvalidChild,
    UnusableSeed,
    InvalidSeedLen,
    BadChecksum,
    InvalidKeyLen,
    UnknownHdVersion,
    InvalidPath,
    NotPrivExtKey,
} || secp.Error || std.mem.Allocator.Error || std.fmt.ParseIntError || base58.Error;

const master_key_label = "Bitcoin seed";

pub const ExtendedKey = struct {
    version: [4]u8,
    payload: union(enum) {
        private: [32]u8,
        public: [33]u8,
    },
    chain_code: [32]u8,
    parent_fp: [4]u8,
    child_num: u32,
    depth: u8,

    pub fn isPrivate(self: ExtendedKey) bool {
        return switch (self.payload) {
            .private => true,
            .public => false,
        };
    }

    pub fn pubCompressed(self: ExtendedKey) Error![33]u8 {
        switch (self.payload) {
            .public => |p| return p,
            .private => |sk| {
                const pk = try secp.PrivateKey.fromBytes(sk);
                const pubk = pk.publicKey() catch return error.InvalidChild;
                return pubk.bytes;
            },
        }
    }

    pub fn child(self: ExtendedKey, index: u32) Error!ExtendedKey {
        if (self.depth == 255) return error.DeriveBeyondMaxDepth;
        const hardened = index >= HardenedKeyStart;
        if (!self.isPrivate() and hardened) return error.DeriveHardFromPublic;

        var data: [37]u8 = undefined;
        if (hardened) {
            data[0] = 0;
            const sk = switch (self.payload) {
                .private => |k| k,
                .public => unreachable,
            };
            @memcpy(data[1..33], &sk);
        } else {
            const pk = try self.pubCompressed();
            @memcpy(data[0..33], &pk);
        }
        std.mem.writeInt(u32, data[33..][0..4], index, .big);

        const ilr = hash.hmacSha512(&data, &self.chain_code);
        const il = ilr[0..32].*;
        const child_chain = ilr[32..64].*;

        const il_sc = StdScalar.Scalar.fromBytes(il, .big) catch return error.InvalidChild;
        if (il_sc.isZero()) return error.InvalidChild;

        const pub_parent = try self.pubCompressed();
        const parent_fp = hash.hash160(&pub_parent).bytes[0..4].*;

        if (self.isPrivate()) {
            const sk = self.payload.private;
            const child_sk = StdScalar.add(il, sk, .big) catch return error.InvalidChild;
            _ = try secp.PrivateKey.fromBytes(child_sk);
            return ExtendedKey{
                .version = self.version,
                .payload = .{ .private = child_sk },
                .chain_code = child_chain,
                .parent_fp = parent_fp,
                .child_num = index,
                .depth = self.depth + 1,
            };
        }

        const il_pt = secp.Point.basePointMul(il) catch return error.InvalidChild;
        const par_pt = try secp.Point.fromCompressedSec1(&pub_parent);
        const sum = il_pt.add(par_pt);
        if (sum.isIdentity()) return error.InvalidChild;
        const child_pub = try secp.PublicKey.fromPoint(sum);

        return ExtendedKey{
            .version = self.version,
            .payload = .{ .public = child_pub.bytes },
            .chain_code = child_chain,
            .parent_fp = parent_fp,
            .child_num = index,
            .depth = self.depth + 1,
        };
    }

    pub fn neuter(self: ExtendedKey) Error!ExtendedKey {
        switch (self.payload) {
            .public => return self,
            .private => {},
        }
        const pub_ver = mapPrivToPubVersion(self.version) orelse return error.UnknownHdVersion;
        const pk = try self.pubCompressed();
        return ExtendedKey{
            .version = pub_ver,
            .payload = .{ .public = pk },
            .chain_code = self.chain_code,
            .parent_fp = self.parent_fp,
            .child_num = self.child_num,
            .depth = self.depth,
        };
    }

    pub fn privateKey(self: ExtendedKey) Error!secp.PrivateKey {
        return switch (self.payload) {
            .private => |k| secp.PrivateKey.fromBytes(k),
            .public => error.NotPrivExtKey,
        };
    }

    pub fn derivePath(self: ExtendedKey, path: []const u8) Error!ExtendedKey {
        if (path.len == 0) return self;
        var cur = self;
        var it = std.mem.splitScalar(u8, path, '/');
        while (it.next()) |seg| {
            if (seg.len == 0) continue;
            const idx = try parsePathSegment(seg);
            cur = try cur.child(idx);
        }
        return cur;
    }

    pub fn derivePub(self: ExtendedKey, path: []const u8) Error![33]u8 {
        return (try self.derivePath(path)).pubCompressed();
    }

    pub fn toStringAlloc(self: ExtendedKey, allocator: std.mem.Allocator) Error![]u8 {
        var payload: [serialized_payload_len]u8 = undefined;
        try self.serializeInto(&payload);
        return base58.encodeCheck(allocator, &payload);
    }

    fn serializeInto(self: ExtendedKey, out: *[serialized_payload_len]u8) Error!void {
        @memcpy(out[0..4], &self.version);
        out[4] = self.depth;
        @memcpy(out[5..9], &self.parent_fp);
        std.mem.writeInt(u32, out[9..13], self.child_num, .big);
        @memcpy(out[13..45], &self.chain_code);
        switch (self.payload) {
            .private => |k| {
                out[45] = 0;
                @memcpy(out[46..78], &k);
            },
            .public => |p| {
                @memcpy(out[45..78], &p);
            },
        }
    }
};

fn mapPrivToPubVersion(priv_ver: [4]u8) ?[4]u8 {
    const pairs: []const Versions = &.{ Versions.mainnet, Versions.testnet };
    for (pairs) |v| {
        if (std.mem.eql(u8, &priv_ver, &v.private)) return v.public;
    }
    return null;
}

pub fn newMaster(seed: []const u8, net: Versions) Error!ExtendedKey {
    if (seed.len < min_seed_len or seed.len > max_seed_len) return error.InvalidSeedLen;

    const lr = hash.hmacSha512(seed, master_key_label);
    const secret = lr[0..32].*;
    const chain = lr[32..64].*;

    const sc = StdScalar.Scalar.fromBytes(secret, .big) catch return error.UnusableSeed;
    if (sc.isZero()) return error.UnusableSeed;

    _ = try secp.PrivateKey.fromBytes(secret);

    return ExtendedKey{
        .version = net.private,
        .payload = .{ .private = secret },
        .chain_code = chain,
        .parent_fp = .{ 0, 0, 0, 0 },
        .child_num = 0,
        .depth = 0,
    };
}

pub fn parseAlloc(allocator: std.mem.Allocator, text: []const u8) Error!ExtendedKey {
    const raw = try base58.decodeCheck(allocator, text);
    defer allocator.free(raw);
    if (raw.len != serialized_payload_len) return error.InvalidKeyLen;

    const version = raw[0..4].*;
    const depth = raw[4];
    const parent_fp = raw[5..9].*;
    const child_num = std.mem.readInt(u32, raw[9..13], .big);
    const chain_code = raw[13..45].*;
    const key_data = raw[45..78];

    if (key_data[0] == 0) {
        const sk = key_data[1..33].*;
        const sc = StdScalar.Scalar.fromBytes(sk, .big) catch return error.UnusableSeed;
        if (sc.isZero()) return error.UnusableSeed;
        _ = try secp.PrivateKey.fromBytes(sk);
        return ExtendedKey{
            .version = version,
            .payload = .{ .private = sk },
            .chain_code = chain_code,
            .parent_fp = parent_fp,
            .child_num = child_num,
            .depth = depth,
        };
    }

    _ = try secp.PublicKey.fromSec1(key_data);
    return ExtendedKey{
        .version = version,
        .payload = .{ .public = key_data[0..33].* },
        .chain_code = chain_code,
        .parent_fp = parent_fp,
        .child_num = child_num,
        .depth = depth,
    };
}

pub fn parsePathSegment(seg: []const u8) Error!u32 {
    if (seg.len == 0) return error.InvalidPath;
    var s = seg;
    var hard = false;
    if (std.mem.endsWith(u8, s, "'")) {
        hard = true;
        s = s[0 .. s.len - 1];
    }
    if (s.len == 0) return error.InvalidPath;
    const v = try std.fmt.parseUnsigned(u32, s, 10);
    if (v >= HardenedKeyStart) return error.InvalidPath;
    if (hard) return v + HardenedKeyStart;
    return v;
}

test "bip32 master from spec seed matches xprv" {
    const allocator = std.testing.allocator;
    var seed: [16]u8 = undefined;
    for (0..16) |i| seed[i] = @intCast(i);

    const m = try newMaster(&seed, Versions.mainnet);
    const s = try m.toStringAlloc(allocator);
    defer allocator.free(s);

    const expected = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    try std.testing.expectEqualStrings(expected, s);
}

test "bip32 parse and derive paths match go-sdk vectors" {
    const allocator = std.testing.allocator;

    const cases = [_]struct { path: []const u8, exp_priv: []const u8, exp_pub: []const u8 }{
        .{
            .path = "0/1",
            .exp_priv = "xprv9ww7sMFLzJMzy7bV1qs7nGBxgKYrgcm3HcJvGb4yvNhT9vxXC7eX7WVULzCfxucFEn2TsVvJw25hH9d4mchywguGQCZvRgsiRaTY1HCqN8G",
            .exp_pub = "xpub6AvUGrnEpfvJBbfx7sQ89Q8hEMPM65UteqEX4yUbUiES2jHfjexmfJoxCGSwFMZiPBaKQT1RiKWrKfuDV4vpgVs4Xn8PpPTR2i79rwHd4Zr",
        },
        .{
            .path = "0/1/100000",
            .exp_priv = "xprv9xrdP7iD2MKJthXr1NiyGJ5KqmD2sLbYYFi49AMq9bXrKJGKBnjx5ivSzXRfLhXxzQNsqCi51oUjniwGemvfAZpzpAGohpzFkat42ohU5bR",
            .exp_pub = "xpub6BqyndF6risc7BcK7QFydS24Po3XGoKPuUdewYmShw4qC6bTjL4CdXEvqow6yhsfAtvU8e6kHPNFM2LzeWwKQoJm6hrYttTcxVQrk42WRE3",
        },
        .{
            .path = "0/1'",
            .exp_priv = "xprv9ww7sMFVKxty8iXvY7Yn2NyvHZ2CgEoAYXmvf2a4XvkhzBUBmYmaMWyjyAhSxgyKK4zYzbJT6hT4JeGW5fFcNaYsBsBR9a8TxVX1LJQiZ1P",
            .exp_pub = "xpub6AvUGrnPALTGMCcPe95nPWveqarh5hX1ukhXTQyg6GHgryoLK65puKJDpTcMBKJKdtXQYVwbK3zMgydcTcf5qpLpJcULu9hKUxx5rzgYhrk",
        },
        .{
            .path = "10/1'/1000'/15'",
            .exp_priv = "xprvA1bKm9LnkQbMvUW6kwKDLFapT9V9vTeh9D9VnVSJhRf8KmqQTc9W5YboNYcUUkZLreNq1NmeuPpw8x86C87gGyxyV6jNBV4kztFrPdSWz2t",
            .exp_pub = "xpub6EagAesgan9f8xaZrxrDhPXZ1BKeKvNYWS56asqvFmC7CaAZ19TkdLvHDrzubSMiC6tAqTMcumVFkgT2duhZncV3KieshEDHNc4jPWkRMGD",
        },
    };

    const xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    const k = try parseAlloc(allocator, xprv);

    for (cases) |c| {
        const d = try k.derivePath(c.path);
        const ps = try d.toStringAlloc(allocator);
        defer allocator.free(ps);
        try std.testing.expectEqualStrings(c.exp_priv, ps);

        const n = try d.neuter();
        const xs = try n.toStringAlloc(allocator);
        defer allocator.free(xs);
        try std.testing.expectEqualStrings(c.exp_pub, xs);
    }
}

test "bip32 roundtrip parse toString" {
    const allocator = std.testing.allocator;
    const xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    const k = try parseAlloc(allocator, xprv);
    const again = try k.toStringAlloc(allocator);
    defer allocator.free(again);
    try std.testing.expectEqualStrings(xprv, again);
}

test "bip32 errors" {
    const allocator = std.testing.allocator;
    var k = try parseAlloc(allocator, "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi");
    const xp = try k.neuter();
    try std.testing.expectError(error.DeriveHardFromPublic, xp.child(HardenedKeyStart));
    try std.testing.expectError(error.NotPrivExtKey, xp.privateKey());

    try std.testing.expectError(error.InvalidSeedLen, newMaster(&[_]u8{0} ** 8, Versions.mainnet));
    try std.testing.expectError(error.InvalidChecksum, parseAlloc(allocator, "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHx"));
}
