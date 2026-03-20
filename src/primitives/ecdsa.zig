const std = @import("std");
const secp256k1 = @import("../crypto/secp256k1.zig");
const sig = @import("../crypto/signature.zig");

const StdSig = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256oSha256.Signature;

pub const Signature = struct {
    r: [32]u8,
    s: [32]u8,

    pub fn fromDer(der: []const u8) !Signature {
        const parsed = StdSig.fromDer(der) catch return error.InvalidEncoding;
        return .{ .r = parsed.r, .s = parsed.s };
    }

    pub fn toDer(self: Signature, out: *[sig.max_der_signature_len]u8) []const u8 {
        const parsed = StdSig{ .r = self.r, .s = self.s };
        return parsed.toDer(out);
    }

    pub fn toDerCanonical(self: Signature, out: *[sig.max_der_signature_len]u8) []const u8 {
        const r = self.r;
        var s = self.s;
        if (cmpBe(s, curve_half_n) == 1) {
            s = subBe(curve_n, s);
        }
        const parsed = StdSig{ .r = r, .s = s };
        return parsed.toDer(out);
    }

    pub fn verifyDigest(self: Signature, digest: [32]u8, pub_key: secp256k1.PublicKey) !bool {
        var buf: [sig.max_der_signature_len]u8 = undefined;
        const der = self.toDerCanonical(&buf);
        const der_sig = try sig.DerSignature.fromDer(der);
        return pub_key.verifyDigest256(digest, der_sig);
    }
};

fn cmpBe(a: [32]u8, b: [32]u8) i2 {
    for (0..32) |i| {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

fn subBe(a: [32]u8, b: [32]u8) [32]u8 {
    var out = a;
    var borrow: u16 = 0;
    var i: usize = 32;
    while (i > 0) {
        i -= 1;
        const ai = @as(u16, out[i]);
        const bi = @as(u16, b[i]);
        const val = ai -% bi -% borrow;
        out[i] = @intCast(val & 0xff);
        borrow = if (ai < bi + borrow) 1 else 0;
    }
    return out;
}

fn hex32(comptime text: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;
    return out;
}

const curve_n = hex32("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
const curve_half_n = hex32("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0");

test "signature DER roundtrip and low-S normalization" {
    const msg_digest = [_]u8{0x11} ** 32;
    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;
    const priv = try secp256k1.PrivateKey.fromBytes(key_bytes);
    const pub_key = try priv.publicKey();
    const der_sig = try priv.signDigest256(msg_digest);
    const parsed = try Signature.fromDer(der_sig.asSlice());
    var buf: [sig.max_der_signature_len]u8 = undefined;
    const der = parsed.toDerCanonical(&buf);
    const parsed2 = try Signature.fromDer(der);
    try std.testing.expect(try parsed2.verifyDigest(msg_digest, pub_key));
}
