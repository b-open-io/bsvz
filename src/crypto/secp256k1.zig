const std = @import("std");
const signature = @import("signature.zig");

const StdPoint = std.crypto.ecc.Secp256k1;
const EcdsaSha256 = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
const EcdsaSha256d = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256oSha256;

pub const Error = error{
    InvalidLength,
    InvalidEncoding,
    SignatureVerificationFailed,
};

pub const Sec1Bytes = struct {
    bytes: [65]u8,
    len: usize,

    pub fn slice(self: *const Sec1Bytes) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const AffineBytes32 = struct {
    x: [32]u8,
    y: [32]u8,
};

pub const Point = struct {
    inner: StdPoint,

    pub fn identity() Point {
        return .{ .inner = StdPoint.identityElement };
    }

    pub fn fromSec1(sec1: []const u8) !Point {
        const parsed = StdPoint.fromSec1(sec1) catch return error.InvalidEncoding;
        return .{ .inner = parsed };
    }

    pub fn fromCompressedSec1(sec1: []const u8) !Point {
        if (sec1.len == 1 and sec1[0] == 0x00) return identity();
        if (sec1.len != 33) return error.InvalidLength;
        return fromSec1(sec1);
    }

    pub fn fromUncompressedSec1(sec1: []const u8) !Point {
        if (sec1.len == 1 and sec1[0] == 0x00) return identity();
        if (sec1.len != 65) return error.InvalidLength;
        return fromSec1(sec1);
    }

    pub fn fromAffineBytes32(x: [32]u8, y: [32]u8) !Point {
        if (std.mem.allEqual(u8, &x, 0) and std.mem.allEqual(u8, &y, 0)) return error.InvalidEncoding;
        const parsed = StdPoint.fromSerializedAffineCoordinates(x, y, .big) catch return error.InvalidEncoding;
        return .{ .inner = parsed };
    }

    pub fn fromRaw64(raw: []const u8) !Point {
        if (raw.len != 64) return error.InvalidLength;
        if (std.mem.allEqual(u8, raw, 0)) return error.InvalidEncoding;

        var x: [32]u8 = undefined;
        var y: [32]u8 = undefined;
        @memcpy(&x, raw[0..32]);
        @memcpy(&y, raw[32..64]);
        return fromAffineBytes32(x, y);
    }

    pub fn toCompressedSec1(self: Point) Sec1Bytes {
        var out = Sec1Bytes{
            .bytes = [_]u8{0} ** 65,
            .len = 1,
        };
        if (self.isIdentity()) {
            out.bytes[0] = 0x00;
            return out;
        }

        const compressed = self.inner.toCompressedSec1();
        out.len = compressed.len;
        @memcpy(out.bytes[0..compressed.len], &compressed);
        return out;
    }

    pub fn toUncompressedSec1(self: Point) Sec1Bytes {
        var out = Sec1Bytes{
            .bytes = [_]u8{0} ** 65,
            .len = 1,
        };
        if (self.isIdentity()) {
            out.bytes[0] = 0x00;
            return out;
        }

        const uncompressed = self.inner.toUncompressedSec1();
        out.len = uncompressed.len;
        @memcpy(out.bytes[0..uncompressed.len], &uncompressed);
        return out;
    }

    pub fn toRaw64(self: Point) [64]u8 {
        var out = [_]u8{0} ** 64;
        if (self.isIdentity()) return out;

        const affine = self.inner.affineCoordinates();
        out[0..32].* = affine.x.toBytes(.big);
        out[32..64].* = affine.y.toBytes(.big);
        return out;
    }

    pub fn add(self: Point, other: Point) Point {
        return .{ .inner = self.inner.add(other.inner) };
    }

    pub fn mul(self: Point, scalar32: [32]u8) !Point {
        const result = self.inner.mul(scalar32, .big) catch |err| switch (err) {
            error.IdentityElement => return identity(),
        };
        return .{ .inner = result };
    }

    pub fn basePointMul(scalar32: [32]u8) !Point {
        const result = StdPoint.basePoint.mul(scalar32, .big) catch |err| switch (err) {
            error.IdentityElement => return identity(),
        };
        return .{ .inner = result };
    }

    pub fn negate(self: Point) Point {
        return .{ .inner = self.inner.neg() };
    }

    pub fn isOnCurve(self: Point) bool {
        if (self.isIdentity()) return true;

        const affine = self.affineBytes32();
        _ = StdPoint.fromSerializedAffineCoordinates(affine.x, affine.y, .big) catch return false;
        return true;
    }

    pub fn isIdentity(self: Point) bool {
        return self.inner.equivalent(StdPoint.identityElement);
    }

    pub fn affineBytes32(self: Point) AffineBytes32 {
        if (self.isIdentity()) {
            return .{
                .x = [_]u8{0} ** 32,
                .y = [_]u8{0} ** 32,
            };
        }

        const affine = self.inner.affineCoordinates();
        return .{
            .x = affine.x.toBytes(.big),
            .y = affine.y.toBytes(.big),
        };
    }

    pub fn xBytes32(self: Point) [32]u8 {
        return self.affineBytes32().x;
    }

    pub fn yBytes32(self: Point) [32]u8 {
        return self.affineBytes32().y;
    }
};

pub const PrivateKey = struct {
    bytes: [32]u8,

    pub fn fromBytes(bytes: [32]u8) !PrivateKey {
        _ = try EcdsaSha256.SecretKey.fromBytes(bytes);
        return .{ .bytes = bytes };
    }

    pub fn toBytes(self: PrivateKey) [32]u8 {
        return self.bytes;
    }

    pub fn publicKey(self: PrivateKey) !PublicKey {
        const key_pair = try EcdsaSha256.KeyPair.fromSecretKey(try self.stdSecretKeySha256());
        return PublicKey{ .bytes = key_pair.public_key.toCompressedSec1() };
    }

    pub fn signSha256(self: PrivateKey, message: []const u8) !signature.DerSignature {
        const key_pair = try EcdsaSha256.KeyPair.fromSecretKey(try self.stdSecretKeySha256());
        const sig = try key_pair.sign(message, null);
        return signature.DerSignature.fromStdSignature(EcdsaSha256, sig);
    }

    pub fn signHash256(self: PrivateKey, message: []const u8) !signature.DerSignature {
        const key_pair = try EcdsaSha256d.KeyPair.fromSecretKey(try self.stdSecretKeySha256d());
        const sig = try key_pair.sign(message, null);
        return signature.DerSignature.fromStdSignature(EcdsaSha256d, sig);
    }

    pub fn signDigest256(self: PrivateKey, digest: [32]u8) !signature.DerSignature {
        const key_pair = try EcdsaSha256d.KeyPair.fromSecretKey(try self.stdSecretKeySha256d());
        const sig = try key_pair.signPrehashed(digest, null);
        return signature.DerSignature.fromStdSignature(EcdsaSha256d, sig);
    }

    fn stdSecretKeySha256(self: PrivateKey) !EcdsaSha256.SecretKey {
        return EcdsaSha256.SecretKey.fromBytes(self.bytes);
    }

    fn stdSecretKeySha256d(self: PrivateKey) !EcdsaSha256d.SecretKey {
        return EcdsaSha256d.SecretKey.fromBytes(self.bytes);
    }
};

pub const PublicKey = struct {
    bytes: [33]u8,

    pub fn fromSec1(sec1: []const u8) !PublicKey {
        const parsed = EcdsaSha256.PublicKey.fromSec1(sec1) catch return error.InvalidEncoding;
        return .{ .bytes = parsed.toCompressedSec1() };
    }

    pub fn fromSec1Relaxed(sec1: []const u8) !PublicKey {
        if (sec1.len == 65 and (sec1[0] == 0x06 or sec1[0] == 0x07)) {
            const y_is_odd = (sec1[64] & 1) != 0;
            const prefix_is_odd = sec1[0] == 0x07;
            if (y_is_odd != prefix_is_odd) return error.InvalidEncoding;

            var uncompressed: [65]u8 = undefined;
            @memcpy(&uncompressed, sec1);
            uncompressed[0] = 0x04;
            return fromSec1(&uncompressed);
        }
        return fromSec1(sec1);
    }

    pub fn toCompressedSec1(self: PublicKey) [33]u8 {
        return self.bytes;
    }

    pub fn toUncompressedSec1(self: PublicKey) [65]u8 {
        return self.toPoint().toUncompressedSec1().bytes[0..65].*;
    }

    pub fn toPoint(self: PublicKey) Point {
        return .{ .inner = StdPoint.fromSec1(&self.bytes) catch unreachable };
    }

    pub fn fromPoint(point: Point) !PublicKey {
        if (point.isIdentity()) return error.InvalidEncoding;
        return .{ .bytes = point.inner.toCompressedSec1() };
    }

    pub fn verifySha256(self: PublicKey, message: []const u8, sig: signature.DerSignature) !bool {
        const public_key = EcdsaSha256.PublicKey.fromSec1(&self.bytes) catch return error.InvalidEncoding;
        const parsed_sig = sig.toStdSignature(EcdsaSha256) catch return error.InvalidEncoding;
        parsed_sig.verify(message, public_key) catch |err| switch (err) {
            error.SignatureVerificationFailed => return false,
            else => return error.InvalidEncoding,
        };
        return true;
    }

    pub fn verifyHash256(self: PublicKey, message: []const u8, sig: signature.DerSignature) !bool {
        const public_key = EcdsaSha256d.PublicKey.fromSec1(&self.bytes) catch return error.InvalidEncoding;
        const parsed_sig = sig.toStdSignature(EcdsaSha256d) catch return error.InvalidEncoding;
        parsed_sig.verify(message, public_key) catch |err| switch (err) {
            error.SignatureVerificationFailed => return false,
            else => return error.InvalidEncoding,
        };
        return true;
    }

    pub fn verifyDigest256(self: PublicKey, digest: [32]u8, sig: signature.DerSignature) !bool {
        return verifyDigest256Sec1(&self.bytes, digest, sig);
    }

    pub fn verifyDigest256Relaxed(self: PublicKey, digest: [32]u8, der_bytes: []const u8) !bool {
        return verifyDigest256RelaxedSec1(&self.bytes, digest, der_bytes);
    }

};

pub fn verifyDigest256Sec1(sec1: []const u8, digest: [32]u8, sig: signature.DerSignature) !bool {
    const public_key = EcdsaSha256d.PublicKey.fromSec1(sec1) catch return error.InvalidEncoding;
    return verifyDigest256WithParsedKey(public_key, digest, sig);
}

pub fn verifyDigest256RelaxedSec1(sec1: []const u8, digest: [32]u8, der_bytes: []const u8) !bool {
    const public_key = try parseStdPublicKeyRelaxed(sec1);
    return verifyDigest256RelaxedWithParsedKey(public_key, digest, der_bytes);
}

fn verifyDigest256WithParsedKey(
    public_key: EcdsaSha256d.PublicKey,
    digest: [32]u8,
    sig: signature.DerSignature,
) !bool {
    const parsed_sig = sig.toStdSignature(EcdsaSha256d) catch return error.InvalidEncoding;
    return verifyDigest256WithStdlib(public_key, digest, parsed_sig);
}

fn verifyDigest256RelaxedWithParsedKey(
    public_key: EcdsaSha256d.PublicKey,
    digest: [32]u8,
    der_bytes: []const u8,
) !bool {
    const parsed_sig = parseLaxDerSignature(der_bytes) catch return error.InvalidEncoding;
    return verifyDigest256WithStdlib(public_key, digest, parsed_sig);
}

fn verifyDigest256WithStdlib(
    public_key: EcdsaSha256d.PublicKey,
    digest: [32]u8,
    parsed_sig: EcdsaSha256d.Signature,
) !bool {
    parsed_sig.verifyPrehashed(digest, public_key) catch |err| switch (err) {
        error.SignatureVerificationFailed => return false,
        else => return error.InvalidEncoding,
    };
    return true;
}

fn parseStdPublicKeyRelaxed(sec1: []const u8) !EcdsaSha256d.PublicKey {
    if (sec1.len == 65 and (sec1[0] == 0x06 or sec1[0] == 0x07)) {
        const y_is_odd = (sec1[64] & 1) != 0;
        const prefix_is_odd = sec1[0] == 0x07;
        if (y_is_odd != prefix_is_odd) return error.InvalidEncoding;

        var uncompressed: [65]u8 = undefined;
        @memcpy(&uncompressed, sec1);
        uncompressed[0] = 0x04;
        return EcdsaSha256d.PublicKey.fromSec1(&uncompressed) catch error.InvalidEncoding;
    }
    return EcdsaSha256d.PublicKey.fromSec1(sec1) catch error.InvalidEncoding;
}

fn parseLaxDerSignature(der_bytes: []const u8) Error!EcdsaSha256d.Signature {
    if (der_bytes.len < 8) return error.InvalidEncoding;
    if (der_bytes[0] != 0x30) return error.InvalidEncoding;

    const total_len = 2 + @as(usize, der_bytes[1]);
    if (total_len > der_bytes.len or total_len < 8) return error.InvalidEncoding;
    if (total_len > signature.max_der_signature_len) return error.InvalidEncoding;

    const der = der_bytes[0..total_len];
    var index: usize = 2;

    if (der[index] != 0x02) return error.InvalidEncoding;
    index += 1;

    const r_len = @as(usize, der[index]);
    index += 1;
    if (r_len == 0 or r_len > der.len - index - 3) return error.InvalidEncoding;
    const r_bytes = der[index .. index + r_len];
    index += r_len;

    if (der[index] != 0x02) return error.InvalidEncoding;
    index += 1;

    const s_len = @as(usize, der[index]);
    index += 1;
    if (s_len == 0 or s_len > der.len - index) return error.InvalidEncoding;
    const s_bytes = der[index .. index + s_len];
    index += s_len;

    if (index != der.len) return error.InvalidEncoding;

    return .{
        .r = try normalizeLaxDerInt(r_bytes),
        .s = try normalizeLaxDerInt(s_bytes),
    };
}

fn normalizeLaxDerInt(raw: []const u8) Error![32]u8 {
    var bytes = raw;
    while (bytes.len > 1 and bytes[0] == 0x00) {
        bytes = bytes[1..];
    }
    if (bytes.len > 32) return error.InvalidEncoding;

    var out = [_]u8{0} ** 32;
    @memcpy(out[32 - bytes.len ..], bytes);
    if (std.mem.allEqual(u8, &out, 0)) return error.InvalidEncoding;
    return out;
}

test "public key derivation and sha256 sign/verify roundtrip" {
    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;

    const private_key = try PrivateKey.fromBytes(key_bytes);
    const public_key = try private_key.publicKey();
    const sig = try private_key.signSha256("bsvz");
    const std_secret_key = try EcdsaSha256.SecretKey.fromBytes(key_bytes);
    const std_key_pair = try EcdsaSha256.KeyPair.fromSecretKey(std_secret_key);
    const raw_std_sig = try std_key_pair.sign("bsvz", null);
    const std_sig = try sig.toStdSignature(EcdsaSha256);
    var der_buf: [EcdsaSha256.Signature.der_encoded_length_max]u8 = undefined;
    const expected_der = raw_std_sig.toDer(&der_buf);

    try std.testing.expectEqualSlices(u8, &std_key_pair.public_key.toCompressedSec1(), &public_key.bytes);
    try std.testing.expectEqualSlices(u8, expected_der, sig.asSlice());
    try std_sig.verify("bsvz", std_key_pair.public_key);

    try std.testing.expect(try public_key.verifySha256("bsvz", sig));
    try std.testing.expect(!(try public_key.verifySha256("wrong", sig)));
}

test "relaxed der parser accepts padded integers that strict der rejects" {
    const lax_sig =
        "\x30\x44\x02\x20\x00\x5e\xce\x13\x35\xe7\xf6\x57\xa1\xa1\xf4\x76\xa7\xfb\x5b\xd9\x09\x64\xe8\xa0\x22\x48\x9f\x89\x06\x14\xa0\x4a\xcf\xb7\x34\xc0" ++
        "\x02\x20\x6c\x12\xb8\x29\x4a\x65\x13\xc7\x71\x0e\x8c\x82\xd3\xc2\x3d\x75\xcd\xbf\xe8\x32\x00\xeb\x7e\xfb\x49\x57\x01\x95\x85\x01\xa5\xd6";

    const parsed = try parseLaxDerSignature(lax_sig);
    try std.testing.expect(!std.mem.allEqual(u8, &parsed.r, 0));
    try std.testing.expect(!std.mem.allEqual(u8, &parsed.s, 0));
}

test "digest verification helpers match expected truth values" {
    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;

    const private_key = try PrivateKey.fromBytes(key_bytes);
    const public_key = try private_key.publicKey();
    const digest = [_]u8{0x42} ** 32;
    const wrong_digest = [_]u8{0x24} ** 32;
    const sig = try private_key.signDigest256(digest);

    try std.testing.expect(try verifyDigest256Sec1(&public_key.bytes, digest, sig));
    try std.testing.expect(!(try verifyDigest256Sec1(&public_key.bytes, wrong_digest, sig)));
    try std.testing.expect(try public_key.verifyDigest256(digest, sig));
    try std.testing.expect(!(try public_key.verifyDigest256(wrong_digest, sig)));
}

test "point sec1 and arithmetic wrap stdlib secp256k1" {
    var scalar_one = [_]u8{0} ** 32;
    scalar_one[31] = 1;

    var scalar_two = [_]u8{0} ** 32;
    scalar_two[31] = 2;

    const g = try Point.basePointMul(scalar_one);
    const g2 = try Point.basePointMul(scalar_two);

    try std.testing.expect(!g.isIdentity());
    try std.testing.expect(g.isOnCurve());
    try std.testing.expectEqualSlices(u8, StdPoint.basePoint.toCompressedSec1()[0..], g.toCompressedSec1().slice());
    try std.testing.expectEqualSlices(u8, StdPoint.basePoint.toUncompressedSec1()[0..], g.toUncompressedSec1().slice());
    try std.testing.expectEqualSlices(u8, g2.toCompressedSec1().slice(), g.add(g).toCompressedSec1().slice());
    try std.testing.expectEqualSlices(u8, Point.identity().toCompressedSec1().slice(), g.add(g.negate()).toCompressedSec1().slice());
}

test "point raw64 and public key bridging" {
    var scalar = [_]u8{0} ** 32;
    scalar[31] = 1;

    const point = try Point.basePointMul(scalar);
    const raw = point.toRaw64();
    const reparsed = try Point.fromRaw64(&raw);
    const public_key = try PublicKey.fromPoint(point);
    const x = point.xBytes32();
    const y = point.yBytes32();

    try std.testing.expectEqualSlices(u8, point.toCompressedSec1().slice(), reparsed.toCompressedSec1().slice());
    try std.testing.expectEqualSlices(u8, &public_key.toCompressedSec1(), point.toCompressedSec1().slice());
    try std.testing.expectEqualSlices(u8, &public_key.toUncompressedSec1(), point.toUncompressedSec1().slice());
    try std.testing.expectEqualSlices(u8, raw[0..32], &x);
    try std.testing.expectEqualSlices(u8, raw[32..64], &y);
    try std.testing.expectEqualSlices(u8, Point.identity().toCompressedSec1().slice(), (try point.mul([_]u8{0} ** 32)).toCompressedSec1().slice());
}

test "point affine/raw/sec1 roundtrips stay aligned" {
    const scalars = [_]u8{ 1, 2, 3, 7, 42 };

    for (scalars) |scalar_value| {
        var scalar = [_]u8{0} ** 32;
        scalar[31] = scalar_value;

        const point = try Point.basePointMul(scalar);
        const affine = point.affineBytes32();
        const raw = point.toRaw64();

        const from_affine = try Point.fromAffineBytes32(affine.x, affine.y);
        const from_raw = try Point.fromRaw64(&raw);
        const from_compressed = try Point.fromCompressedSec1(point.toCompressedSec1().slice());
        const from_uncompressed = try Point.fromUncompressedSec1(point.toUncompressedSec1().slice());

        try std.testing.expect(point.isOnCurve());
        try std.testing.expectEqualSlices(u8, point.toCompressedSec1().slice(), from_affine.toCompressedSec1().slice());
        try std.testing.expectEqualSlices(u8, point.toCompressedSec1().slice(), from_raw.toCompressedSec1().slice());
        try std.testing.expectEqualSlices(u8, point.toCompressedSec1().slice(), from_compressed.toCompressedSec1().slice());
        try std.testing.expectEqualSlices(u8, point.toCompressedSec1().slice(), from_uncompressed.toCompressedSec1().slice());
        try std.testing.expectEqualSlices(u8, raw[0..32], &affine.x);
        try std.testing.expectEqualSlices(u8, raw[32..64], &affine.y);
        try std.testing.expectEqualSlices(u8, &affine.x, &point.xBytes32());
        try std.testing.expectEqualSlices(u8, &affine.y, &point.yBytes32());
    }
}

test "point identity encodings roundtrip across public helpers" {
    const identity = Point.identity();
    const compressed = identity.toCompressedSec1();
    const uncompressed = identity.toUncompressedSec1();
    const affine = identity.affineBytes32();
    const raw = identity.toRaw64();

    try std.testing.expect(identity.isIdentity());
    try std.testing.expect(identity.isOnCurve());
    try std.testing.expectEqual(@as(usize, 1), compressed.len);
    try std.testing.expectEqual(@as(u8, 0x00), compressed.bytes[0]);
    try std.testing.expectEqual(@as(usize, 1), uncompressed.len);
    try std.testing.expectEqual(@as(u8, 0x00), uncompressed.bytes[0]);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 32), &affine.x);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 32), &affine.y);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 64), &raw);
    try std.testing.expect((try Point.fromCompressedSec1(compressed.slice())).isIdentity());
    try std.testing.expect((try Point.fromUncompressedSec1(uncompressed.slice())).isIdentity());
    try std.testing.expectError(error.InvalidEncoding, Point.fromAffineBytes32(affine.x, affine.y));
    try std.testing.expectError(error.InvalidEncoding, Point.fromRaw64(&raw));
    try std.testing.expectError(error.InvalidEncoding, PublicKey.fromPoint(identity));
}
