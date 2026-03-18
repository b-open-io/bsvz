const std = @import("std");
const signature = @import("signature.zig");

const EcdsaSha256 = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
const EcdsaSha256d = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256oSha256;

pub const Error = error{
    InvalidLength,
    InvalidEncoding,
    SignatureVerificationFailed,
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
