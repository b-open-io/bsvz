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
        if (std.mem.allEqual(u8, &x, 0) and std.mem.allEqual(u8, &y, 0)) return identity();
        const parsed = StdPoint.fromSerializedAffineCoordinates(x, y, .big) catch return error.InvalidEncoding;
        return .{ .inner = parsed };
    }

    pub fn fromRaw64(raw: []const u8) !Point {
        if (raw.len != 64) return error.InvalidLength;
        if (std.mem.allEqual(u8, raw, 0)) return identity();

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
        _ = self;
        return true;
    }

    pub fn isIdentity(self: Point) bool {
        return self.inner.equivalent(StdPoint.identityElement);
    }

    pub fn xBytes32(self: Point) [32]u8 {
        if (self.isIdentity()) return [_]u8{0} ** 32;
        return self.inner.affineCoordinates().x.toBytes(.big);
    }

    pub fn yBytes32(self: Point) [32]u8 {
        if (self.isIdentity()) return [_]u8{0} ** 32;
        return self.inner.affineCoordinates().y.toBytes(.big);
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
        const public_key = EcdsaSha256d.PublicKey.fromSec1(&self.bytes) catch return error.InvalidEncoding;
        const parsed_sig = sig.toStdSignature(EcdsaSha256d) catch return error.InvalidEncoding;
        parsed_sig.verifyPrehashed(digest, public_key) catch |err| switch (err) {
            error.SignatureVerificationFailed => return false,
            else => return error.InvalidEncoding,
        };
        return true;
    }

    pub fn verifyDigest256Relaxed(self: PublicKey, digest: [32]u8, der_bytes: []const u8) !bool {
        const public_key = EcdsaSha256d.PublicKey.fromSec1(&self.bytes) catch return error.InvalidEncoding;
        const normalized = normalizeLaxDer(der_bytes) catch return error.InvalidEncoding;
        const parsed_sig = EcdsaSha256d.Signature.fromDer(normalized) catch return error.InvalidEncoding;
        parsed_sig.verifyPrehashed(digest, public_key) catch |err| switch (err) {
            error.SignatureVerificationFailed => return false,
            else => return error.InvalidEncoding,
        };
        return true;
    }
};

fn normalizeLaxDer(der_bytes: []const u8) Error![]const u8 {
    if (der_bytes.len < 2) return error.InvalidEncoding;
    if (der_bytes[0] != 0x30) return error.InvalidEncoding;
    const total_len = 2 + der_bytes[1];
    if (total_len > der_bytes.len) return error.InvalidEncoding;
    if (total_len > signature.max_der_signature_len) return error.InvalidEncoding;
    return der_bytes[0..total_len];
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
