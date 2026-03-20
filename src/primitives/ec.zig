const std = @import("std");
const secp256k1 = @import("../crypto/secp256k1.zig");
const sig = @import("../crypto/signature.zig");
const compact = @import("../crypto/compact.zig");
const compat_wif = @import("../compat/wif.zig");
const hex = @import("hex.zig");
const network = @import("network.zig");
const keyshares = @import("keyshares.zig");
const crypto_hash = @import("../crypto/hash.zig");

// Curve wrapper built on Zig stdlib secp256k1.

pub const CurveParams = struct {
    p: [32]u8,
    n: [32]u8,
    b: [32]u8,
    gx: [32]u8,
    gy: [32]u8,
    bit_size: u16,
    name: []const u8,
};

pub const Secp256k1 = struct {
    pub fn params() *const CurveParams {
        return &secp256k1_params;
    }

    pub fn isOnCurve(x: [32]u8, y: [32]u8) bool {
        _ = secp256k1.Point.fromAffineBytes32(x, y) catch return false;
        return true;
    }

    pub fn add(x1: [32]u8, y1: [32]u8, x2: [32]u8, y2: [32]u8) !secp256k1.AffineBytes32 {
        const p1 = try secp256k1.Point.fromAffineBytes32(x1, y1);
        const p2 = try secp256k1.Point.fromAffineBytes32(x2, y2);
        return p1.add(p2).affineBytes32();
    }

    pub fn double(x: [32]u8, y: [32]u8) !secp256k1.AffineBytes32 {
        const p = try secp256k1.Point.fromAffineBytes32(x, y);
        return p.add(p).affineBytes32();
    }

    pub fn scalarMult(x: [32]u8, y: [32]u8, scalar32: [32]u8) !secp256k1.AffineBytes32 {
        const p = try secp256k1.Point.fromAffineBytes32(x, y);
        return (try p.mul(scalar32)).affineBytes32();
    }

    pub fn scalarBaseMult(scalar32: [32]u8) !secp256k1.AffineBytes32 {
        return (try secp256k1.Point.basePointMul(scalar32)).affineBytes32();
    }
};

pub const PrivateKey = struct {
    inner: secp256k1.PrivateKey,

    pub fn generate() !PrivateKey {
        var bytes: [32]u8 = undefined;
        while (true) {
            std.crypto.random.bytes(&bytes);
            if (secp256k1.PrivateKey.fromBytes(bytes)) |key| {
                return .{ .inner = key };
            } else |_| {
                continue;
            }
        }
    }

    pub fn fromBytes(bytes: [32]u8) !PrivateKey {
        return .{ .inner = try secp256k1.PrivateKey.fromBytes(bytes) };
    }

    pub fn fromHex(text: []const u8) !PrivateKey {
        if (text.len == 0) return error.InvalidEncoding;
        var buf: [32]u8 = undefined;
        const decoded = try hex.decodeInto(text, &buf);
        if (decoded.len != 32) return error.InvalidEncoding;
        return fromBytes(buf);
    }

    pub fn fromWif(allocator: std.mem.Allocator, text: []const u8) !PrivateKey {
        const decoded = try compat_wif.decode(allocator, text);
        return .{ .inner = decoded.private_key };
    }

    pub fn toBytes(self: PrivateKey) [32]u8 {
        return self.inner.toBytes();
    }

    pub fn toHex(self: PrivateKey, out: *[64]u8) []const u8 {
        const bytes = self.inner.toBytes();
        return hex.encodeLower(&bytes, out) catch out[0..0];
    }

    pub fn toWif(
        self: PrivateKey,
        allocator: std.mem.Allocator,
        net: network.Network,
        compressed: bool,
    ) ![]u8 {
        return compat_wif.encode(allocator, net, self.inner, compressed);
    }

    pub fn publicKey(self: PrivateKey) !PublicKey {
        return .{ .inner = try self.inner.publicKey() };
    }

    pub fn signDigest(self: PrivateKey, digest: [32]u8) !sig.DerSignature {
        return self.inner.signDigest256(digest);
    }

    /// Bitcoin 65-byte compact ECDSA over a double-SHA256 digest. Matches Go `SignCompact` (Sha256d preimage).
    pub fn signCompact(self: PrivateKey, digest: [32]u8, is_compressed_key: bool) compact.CompactError![compact.compact_sig_len]u8 {
        return compact.signCompactDigest256(self.inner, digest, is_compressed_key);
    }

    pub fn signHash256(self: PrivateKey, message: []const u8) !sig.DerSignature {
        return self.inner.signHash256(message);
    }

    /// ECDH: `priv * other` as a point. Matches Go `PrivateKey.DeriveSharedSecret`.
    pub fn deriveSharedSecret(self: PrivateKey, other: PublicKey) !PublicKey {
        if (!other.validate()) return error.InvalidEncoding;
        const pt = try other.inner.toPoint().mul(self.inner.toBytes());
        return .{ .inner = try secp256k1.PublicKey.fromPoint(pt) };
    }

    /// BRC-42 child key. Matches Go `PrivateKey.DeriveChild` (invoice HMAC key = compressed shared point).
    pub fn deriveChild(self: PrivateKey, other: PublicKey, invoice: []const u8) !PrivateKey {
        const shared = try self.deriveSharedSecret(other);
        const comp = shared.toCompressedSec1();
        const h = crypto_hash.hmacSha256(invoice, &comp);
        return scalarAddModOrder(self.toBytes(), h);
    }

    pub fn toPolynomial(self: PrivateKey, allocator: std.mem.Allocator, threshold: usize) !keyshares.Polynomial {
        if (threshold < 2) return error.InvalidEncoding;
        const points = try allocator.alloc(keyshares.Point, threshold);
        points[0] = keyshares.Point.new(0, bytesToU256(self.inner.toBytes()[0..]));
        var i: usize = 1;
        while (i < threshold) : (i += 1) {
            const x = randomFieldNonZero();
            const y = randomFieldNonZero();
            points[i] = keyshares.Point.new(x, y);
        }
        return .{ .points = points, .threshold = threshold };
    }

    pub fn toKeyShares(
        self: PrivateKey,
        allocator: std.mem.Allocator,
        threshold: usize,
        total_shares: usize,
    ) !keyshares.KeyShares {
        if (threshold < 2 or total_shares < 2 or threshold > total_shares) {
            return error.InvalidEncoding;
        }

        const poly = try self.toPolynomial(allocator, threshold);
        errdefer allocator.free(poly.points);

        var points = try allocator.alloc(keyshares.Point, total_shares);
        errdefer allocator.free(points);

        var seed: [64]u8 = undefined;
        std.crypto.random.bytes(&seed);

        var used = std.AutoHashMap(u256, void).init(allocator);
        defer used.deinit();

        var i: usize = 0;
        while (i < total_shares) : (i += 1) {
            var attempt: u32 = 0;
            var x: u256 = 0;
            while (attempt < 5) : (attempt += 1) {
                var counter: [40]u8 = undefined;
                std.mem.writeInt(u32, counter[0..4], @intCast(i), .big);
                std.mem.writeInt(u32, counter[4..8], attempt, .big);
                std.crypto.random.bytes(counter[8..40]);
                const h = crypto_hash.hmacSha512(counter[0..], &seed);
                x = bytesToU256(h[0..32]) % keyshares.Curve.p;
                if (x == 0) continue;
                if (used.contains(x)) continue;
                try used.put(x, {});
                break;
            }
            if (x == 0) return error.InvalidEncoding;
            const y = poly.valueAt(x);
            points[i] = keyshares.Point.new(x, y);
        }

        const integrity = integrityTag(self);
        return .{ .points = points, .threshold = threshold, .integrity = integrity };
    }

    pub fn toBackupShares(
        self: PrivateKey,
        allocator: std.mem.Allocator,
        threshold: usize,
        total_shares: usize,
    ) ![][]u8 {
        const shares = try self.toKeyShares(allocator, threshold, total_shares);
        return shares.toBackupFormat(allocator);
    }
};

pub const PublicKey = struct {
    inner: secp256k1.PublicKey,

    pub fn fromSec1(sec1: []const u8) !PublicKey {
        return .{ .inner = try secp256k1.PublicKey.fromSec1(sec1) };
    }

    pub fn fromSec1Relaxed(sec1: []const u8) !PublicKey {
        return .{ .inner = try secp256k1.PublicKey.fromSec1Relaxed(sec1) };
    }

    pub fn fromAffineBytes32(x: [32]u8, y: [32]u8) !PublicKey {
        const point = try secp256k1.Point.fromAffineBytes32(x, y);
        return .{ .inner = try secp256k1.PublicKey.fromPoint(point) };
    }

    pub fn fromHex(text: []const u8) !PublicKey {
        var buf: [65]u8 = undefined;
        const decoded = try hex.decodeInto(text, &buf);
        if (decoded.len != 33 and decoded.len != 65) return error.InvalidEncoding;
        return fromSec1Relaxed(decoded);
    }

    pub fn toCompressedSec1(self: PublicKey) [33]u8 {
        return self.inner.toCompressedSec1();
    }

    pub fn toUncompressedSec1(self: PublicKey) [65]u8 {
        return self.inner.toUncompressedSec1();
    }

    pub fn toHybridSec1(self: PublicKey) [65]u8 {
        var out = self.inner.toUncompressedSec1();
        const y_is_odd = (out[64] & 1) != 0;
        out[0] = if (y_is_odd) 0x07 else 0x06;
        return out;
    }

    pub fn add(self: PublicKey, other: PublicKey) !PublicKey {
        const sum = self.inner.toPoint().add(other.inner.toPoint());
        return .{ .inner = try secp256k1.PublicKey.fromPoint(sum) };
    }

    pub fn mulScalar(self: PublicKey, scalar32: [32]u8) !PublicKey {
        const point = try self.inner.toPoint().mul(scalar32);
        return .{ .inner = try secp256k1.PublicKey.fromPoint(point) };
    }

    pub fn eql(self: PublicKey, other: PublicKey) bool {
        return std.mem.eql(u8, &self.toCompressedSec1(), &other.toCompressedSec1());
    }

    pub fn verifyDigest(self: PublicKey, digest: [32]u8, der: sig.DerSignature) !bool {
        return self.inner.verifyDigest256(digest, der);
    }

    /// ECDH from the public side. Matches Go `PublicKey.DeriveSharedSecret`.
    pub fn deriveSharedSecret(self: PublicKey, other: PrivateKey) !PublicKey {
        if (!self.validate()) return error.InvalidEncoding;
        const pt = try self.inner.toPoint().mul(other.inner.toBytes());
        return .{ .inner = try secp256k1.PublicKey.fromPoint(pt) };
    }

    /// BRC-42 public key for a child. Matches Go `PublicKey.DeriveChild`.
    pub fn deriveChild(self: PublicKey, other: PrivateKey, invoice: []const u8) !PublicKey {
        const shared = try self.deriveSharedSecret(other);
        const comp = shared.toCompressedSec1();
        const h = crypto_hash.hmacSha256(invoice, &comp);
        const pt = try secp256k1.Point.basePointMul(h);
        const sum = pt.add(self.inner.toPoint());
        return .{ .inner = try secp256k1.PublicKey.fromPoint(sum) };
    }

    /// HASH160 of compressed SEC1 (P2PKH address hash input).
    pub fn hash160(self: PublicKey) crypto_hash.Hash160 {
        const c = self.toCompressedSec1();
        return crypto_hash.hash160(&c);
    }

    /// Go `PublicKey.Hash()` — same as `hash160`.
    pub fn pubkeyHash(self: PublicKey) crypto_hash.Hash160 {
        return self.hash160();
    }

    pub fn validate(self: PublicKey) bool {
        return self.inner.toPoint().isOnCurve();
    }

    /// Go `PublicKey.ToDER` returns compressed SEC1 (33 bytes), not ASN.1 SPKI.
    pub fn toDer(self: PublicKey) [33]u8 {
        return self.toCompressedSec1();
    }

    pub fn toDerHex(self: PublicKey, out: *[66]u8) []const u8 {
        return hex.encodeLower(&self.toDer(), out) catch unreachable;
    }
};

/// Recover pubkey from compact signature + double-SHA256 digest. Matches Go `RecoverCompact(sig, hash)`.
pub fn recoverCompact(sig65: [compact.compact_sig_len]u8, digest: [32]u8) compact.CompactError!struct { pubkey: PublicKey, is_compressed: bool } {
    const r = try compact.recoverCompactDigest256(sig65, digest);
    return .{ .pubkey = .{ .inner = r.pubkey }, .is_compressed = r.is_compressed };
}

fn scalarAddModOrder(a: [32]u8, b: [32]u8) !PrivateKey {
    const n_lo = std.mem.readInt(u256, &Secp256k1.params().n, .big);
    const n = @as(u512, n_lo);
    const aa = @as(u512, std.mem.readInt(u256, &a, .big));
    const bb = @as(u512, std.mem.readInt(u256, &b, .big));
    const sum = (aa + bb) % n;
    var out: [32]u8 = undefined;
    std.mem.writeInt(u256, &out, @intCast(sum), .big);
    return PrivateKey.fromBytes(out);
}

fn hex32(comptime text: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;
    return out;
}

const secp256k1_params = CurveParams{
    .p = hex32("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
    .n = hex32("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
    .b = hex32("0000000000000000000000000000000000000000000000000000000000000007"),
    .gx = hex32("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
    .gy = hex32("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
    .bit_size = 256,
    .name = "secp256k1",
};

pub fn privateKeyFromKeyShares(
    shares: keyshares.KeyShares,
) !PrivateKey {
    if (shares.threshold < 2) return error.InvalidEncoding;
    if (shares.points.len < shares.threshold) return error.InvalidEncoding;
    var i: usize = 0;
    while (i < shares.threshold) : (i += 1) {
        var j: usize = i + 1;
        while (j < shares.threshold) : (j += 1) {
            if (shares.points[i].x == shares.points[j].x) return error.InvalidEncoding;
        }
    }

    const poly = keyshares.Polynomial{
        .points = shares.points[0..shares.threshold],
        .threshold = shares.threshold,
    };
    const secret = poly.valueAt(0);
    var bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &bytes, secret, .big);
    const priv = try PrivateKey.fromBytes(bytes);
    if (!std.mem.eql(u8, &integrityTag(priv), &shares.integrity)) {
        return error.InvalidEncoding;
    }
    return priv;
}

pub fn privateKeyFromBackupShares(
    allocator: std.mem.Allocator,
    shares: []const []const u8,
) !PrivateKey {
    const ks = try keyshares.KeyShares.fromBackupFormat(allocator, shares);
    return privateKeyFromKeyShares(ks);
}

fn integrityTag(key: PrivateKey) [8]u8 {
    const pub_key = key.publicKey() catch return [_]u8{0} ** 8;
    const compressed = pub_key.toCompressedSec1();
    const digest = crypto_hash.hash160(&compressed).bytes;
    var out: [8]u8 = undefined;
    var hex_buf: [40]u8 = undefined;
    _ = hex.encodeLower(digest[0..], &hex_buf) catch unreachable;
    @memcpy(&out, hex_buf[0..8]);
    return out;
}

fn bytesToU256(bytes: []const u8) u256 {
    var buf: [32]u8 = [_]u8{0} ** 32;
    if (bytes.len > 32) {
        @memcpy(buf[0..32], bytes[bytes.len - 32 ..]);
    } else {
        @memcpy(buf[32 - bytes.len ..], bytes);
    }
    return std.mem.readInt(u256, &buf, .big);
}

fn randomFieldNonZero() u256 {
    var out: [32]u8 = undefined;
    while (true) {
        std.crypto.random.bytes(&out);
        const v = std.mem.readInt(u256, &out, .big) % keyshares.Curve.p;
        if (v != 0) return v;
    }
}

test "BRC-42 private vector 0 matches go-sdk" {
    const sender_pub = try PublicKey.fromHex("033f9160df035156f1c48e75eae99914fa1a1546bec19781e8eddb900200bff9d1");
    const recipient = try PrivateKey.fromHex("6a1751169c111b4667a6539ee1be6b7cd9f6e9c8fe011a5f2fe31e03a15e0ede");
    const derived = try recipient.deriveChild(sender_pub, "f3WCaUmnN9U=");
    var hx: [64]u8 = undefined;
    try std.testing.expectEqualStrings(
        "761656715bbfa172f8f9f58f5af95d9d0dfd69014cfdcacc9a245a10ff8893ef",
        derived.toHex(&hx),
    );
}

test "BRC-42 private and public paths agree (recipient priv + sender pub vs recipient pub + sender priv)" {
    const sender_priv = try PrivateKey.generate();
    const sender_pub = try sender_priv.publicKey();
    const recipient_priv = try PrivateKey.generate();
    const recipient_pub = try recipient_priv.publicKey();
    const invoice = "inv-agree-test";
    const priv_path = try recipient_priv.deriveChild(sender_pub, invoice);
    const pub_path = try recipient_pub.deriveChild(sender_priv, invoice);
    try std.testing.expect((try priv_path.publicKey()).eql(pub_path));
}

test "BRC-42 public vector 0 matches go-sdk" {
    const sender_priv = try PrivateKey.fromHex("583755110a8c059de5cd81b8a04e1be884c46083ade3f779c1e022f6f89da94c");
    const recipient_pub = try PublicKey.fromHex("02c0c1e1a1f7d247827d1bcf399f0ef2deef7695c322fd91a01a91378f101b6ffc");
    const derived = try recipient_pub.deriveChild(sender_priv, "IBioA4D/OaE=");
    var hx: [66]u8 = undefined;
    try std.testing.expectEqualStrings(
        "03c1bf5baadee39721ae8c9882b3cf324f0bf3b9eb3fc1b8af8089ca7a7c2e669f",
        derived.toDerHex(&hx),
    );
}

test "deriveSharedSecret is symmetric" {
    const a = try PrivateKey.generate();
    const b = try PrivateKey.generate();
    const pub_b = try b.publicKey();
    const sab = try a.deriveSharedSecret(pub_b);
    const sba = try pub_b.deriveSharedSecret(a);
    try std.testing.expect(sab.eql(sba));
}

test "secp256k1 params match base point" {
    const params = Secp256k1.params();
    try std.testing.expect(Secp256k1.isOnCurve(params.gx, params.gy));
    var scalar_one = [_]u8{0} ** 32;
    scalar_one[31] = 1;
    const base = try Secp256k1.scalarBaseMult(scalar_one);
    try std.testing.expectEqualSlices(u8, &params.gx, &base.x);
    try std.testing.expectEqualSlices(u8, &params.gy, &base.y);
}
