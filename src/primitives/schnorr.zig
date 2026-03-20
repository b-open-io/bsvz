const std = @import("std");
const ec = @import("ec.zig");
const hash = @import("../crypto/hash.zig");

const Scalar = std.crypto.ecc.Secp256k1.scalar.Scalar;

pub const Proof = struct {
    r: ec.PublicKey,
    s_prime: ec.PublicKey,
    z: [32]u8,
};

pub const Schnorr = struct {
    pub fn generateProof(
        a: ec.PrivateKey,
        A: ec.PublicKey,
        B: ec.PublicKey,
        S: ec.PublicKey,
    ) !Proof {
        const r = try ec.PrivateKey.generate();
        const R = try r.publicKey();
        const S_prime = try B.mulScalar(r.toBytes());
        const e = computeChallenge(A, B, S, S_prime, R);

        const r_scalar = try Scalar.fromBytes(r.toBytes(), .big);
        const a_scalar = try Scalar.fromBytes(a.toBytes(), .big);
        const z_scalar = r_scalar.add(e.mul(a_scalar));
        const z = z_scalar.toBytes(.big);

        return .{
            .r = R,
            .s_prime = S_prime,
            .z = z,
        };
    }

    pub fn verifyProof(
        A: ec.PublicKey,
        B: ec.PublicKey,
        S: ec.PublicKey,
        proof: Proof,
    ) !bool {
        const e = computeChallenge(A, B, S, proof.s_prime, proof.r);
        const zG = try ec.Secp256k1.scalarBaseMult(proof.z);
        const eA = try A.mulScalar(e.toBytes(.big));
        const r_plus_ea = try proof.r.add(eA);
        const zG_pub = try ec.PublicKey.fromAffineBytes32(zG.x, zG.y);
        if (!zG_pub.eql(r_plus_ea)) return false;

        const zB = try B.mulScalar(proof.z);
        const eS = try S.mulScalar(e.toBytes(.big));
        const s_prime_plus_es = try proof.s_prime.add(eS);

        if (!zB.eql(s_prime_plus_es)) return false;
        return true;
    }
};

fn computeChallenge(
    A: ec.PublicKey,
    B: ec.PublicKey,
    S: ec.PublicKey,
    S_prime: ec.PublicKey,
    R: ec.PublicKey,
) Scalar {
    var msg: [33 * 5]u8 = undefined;
    var offset: usize = 0;
    const a_bytes = A.toCompressedSec1();
    const b_bytes = B.toCompressedSec1();
    const s_bytes = S.toCompressedSec1();
    const sp_bytes = S_prime.toCompressedSec1();
    const r_bytes = R.toCompressedSec1();
    @memcpy(msg[offset .. offset + 33], &a_bytes);
    offset += 33;
    @memcpy(msg[offset .. offset + 33], &b_bytes);
    offset += 33;
    @memcpy(msg[offset .. offset + 33], &s_bytes);
    offset += 33;
    @memcpy(msg[offset .. offset + 33], &sp_bytes);
    offset += 33;
    @memcpy(msg[offset .. offset + 33], &r_bytes);

    const digest = hash.sha256(&msg).bytes;
    return reduceScalar(digest);
}

fn reduceScalar(digest: [32]u8) Scalar {
    var reduced = [_]u8{0} ** 48;
    @memcpy(reduced[reduced.len - digest.len ..], &digest);
    return Scalar.fromBytes48(reduced, .big);
}

test "schnorr proof roundtrip" {
    const a = try ec.PrivateKey.generate();
    const b = try ec.PrivateKey.generate();
    const A = try a.publicKey();
    const B = try b.publicKey();
    const S = try B.mulScalar(a.toBytes());
    const proof = try Schnorr.generateProof(a, A, B, S);
    try std.testing.expect(try Schnorr.verifyProof(A, B, S, proof));
}
