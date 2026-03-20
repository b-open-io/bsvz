//! Bitcoin compact ECDSA signatures (65 bytes: recovery header + R + S), matching
//! go-sdk `primitives/ec/signature.go` `SignCompact` / `RecoverCompact`.
const std = @import("std");
const hash_mod = @import("hash.zig");
const secp256k1 = @import("secp256k1.zig");

const StdPoint = std.crypto.ecc.Secp256k1;
const EcdsaSha256d = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256oSha256;
const SecpScalar = StdPoint.scalar;
const Fe = StdPoint.Fe;

/// secp256k1 field prime P (big-endian).
const p_be: [32]u8 = .{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
};
/// Subgroup order N (big-endian).
const n_be: [32]u8 = .{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
};

pub const CompactError = error{
    InvalidCompactSignature,
    RxOutOfRange,
    NoRecoveryMatch,
    NotSquare,
    NTimesRInvalid,
};

pub const compact_sig_len: usize = 65;

pub const RecoveredPubkey = struct {
    pubkey: secp256k1.PublicKey,
    is_compressed: bool,
};

/// Double-SHA256 digest -> scalar e, matching OpenSSL / go-sdk `hashToInt` for 32-byte digests.
fn hashToIntScalar(digest: [32]u8) [32]u8 {
    var wide: [48]u8 = [_]u8{0} ** 48;
    @memcpy(wide[wide.len - 32 ..], &digest);
    return SecpScalar.reduce48(wide, .big);
}

fn readScalarCanonical(r: [32]u8) CompactError!SecpScalar.Scalar {
    const s = SecpScalar.Scalar.fromBytes(r, .big) catch return error.InvalidCompactSignature;
    if (s.isZero()) return error.InvalidCompactSignature;
    return s;
}

fn rxLessThanP(rx: [32]u8) bool {
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        if (rx[i] < p_be[i]) return true;
        if (rx[i] > p_be[i]) return false;
    }
    return false;
}

/// SEC1 4.1.6–style recovery (same control flow as go-sdk `recoverKeyFromSignature`).
pub fn recoverKeyFromSignature(
    r_be: [32]u8,
    s_be: [32]u8,
    msg_hash: [32]u8,
    iter: usize,
    do_checks: bool,
) CompactError!StdPoint {
    const r_sc = try readScalarCanonical(r_be);
    const s_sc = try readScalarCanonical(s_be);

    const n_u256 = std.mem.readInt(u256, &n_be, .big);
    const r_u256 = std.mem.readInt(u256, &r_be, .big);
    const rx_u512 = @as(u512, @intCast(iter / 2)) *% @as(u512, n_u256) +% @as(u512, r_u256);
    const p_u512: u512 = @intCast(std.mem.readInt(u256, &p_be, .big));
    if (rx_u512 >= p_u512) return error.RxOutOfRange;

    var rx_bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &rx_bytes, @truncate(rx_u512), .big);
    if (!rxLessThanP(rx_bytes)) return error.RxOutOfRange;

    const x_fe = Fe.fromBytes(rx_bytes, .big) catch return error.InvalidCompactSignature;
    const y_odd = (iter % 2) == 1;
    const y_fe = StdPoint.recoverY(x_fe, y_odd) catch return error.NotSquare;

    const r_point = StdPoint.fromAffineCoordinates(.{ .x = x_fe, .y = y_fe }) catch return error.InvalidCompactSignature;
    r_point.rejectIdentity() catch return error.InvalidCompactSignature;

    if (do_checks) {
        if (r_point.mul(n_be, .big)) |q| {
            if (!q.equivalent(StdPoint.identityElement)) return error.NTimesRInvalid;
        } else |err| switch (err) {
            error.IdentityElement => {}, // n*R = infinity (expected for subgroup)
        }
    }

    const e_be = hashToIntScalar(msg_hash);
    const invr_be = r_sc.invert().toBytes(.big);
    const invr_s_be = SecpScalar.mul(invr_be, s_sc.toBytes(.big), .big) catch return error.InvalidCompactSignature;
    const neg_e_be = SecpScalar.neg(e_be, .big) catch return error.InvalidCompactSignature;
    const neg_e_invr_be = SecpScalar.mul(neg_e_be, invr_be, .big) catch return error.InvalidCompactSignature;

    const v1 = SecpScalar.Scalar.fromBytes(neg_e_invr_be, .big) catch return error.InvalidCompactSignature;
    const v2 = SecpScalar.Scalar.fromBytes(invr_s_be, .big) catch return error.InvalidCompactSignature;

    const sum = StdPoint.mulDoubleBasePublic(
        StdPoint.basePoint,
        v1.toBytes(.little),
        r_point,
        v2.toBytes(.little),
        .little,
    ) catch |err| switch (err) {
        error.IdentityElement => return error.InvalidCompactSignature,
    };
    return sum;
}

/// Build a 65-byte compact signature for a **double-SHA256** digest (`hash256` / `Sha256d`), matching go-sdk.
pub fn signCompactDigest256(
    key: secp256k1.PrivateKey,
    digest: [32]u8,
    is_compressed_key: bool,
) CompactError![compact_sig_len]u8 {
    const der = key.signDigest256(digest) catch return error.InvalidCompactSignature;
    const std_sig = der.toStdSignature(EcdsaSha256d) catch return error.InvalidCompactSignature;
    const r_be = std_sig.r;
    const s_be = std_sig.s;

    const my_pub = key.publicKey() catch return error.InvalidCompactSignature;
    const want = my_pub.bytes;

    const max_iter = 4; // (H+1)*2 for secp256k1 with H=1
    var i: usize = 0;
    while (i < max_iter) : (i += 1) {
        const pk = recoverKeyFromSignature(r_be, s_be, digest, i, true) catch |err| switch (err) {
            error.NotSquare,
            error.RxOutOfRange,
            error.NTimesRInvalid,
            error.InvalidCompactSignature,
            => continue,
            else => |e| return e,
        };
        const recovered = secp256k1.PublicKey.fromPoint(secp256k1.Point{ .inner = pk }) catch continue;
        if (!std.mem.eql(u8, &recovered.bytes, &want)) continue;

        var out: [compact_sig_len]u8 = undefined;
        out[0] = 27 + @as(u8, @intCast(i));
        if (is_compressed_key) out[0] += 4;
        @memcpy(out[1..33], &r_be);
        @memcpy(out[33..65], &s_be);
        return out;
    }
    return error.NoRecoveryMatch;
}

/// Recover public key and compressed flag from a compact signature and **double-SHA256** digest.
pub fn recoverCompactDigest256(sig: [compact_sig_len]u8, digest: [32]u8) CompactError!RecoveredPubkey {
    // Match go-sdk: no strict header range; invalid headers fail in recovery math.
    const iter = @as(usize, @intCast((sig[0] -% 27) & ~@as(u8, 4)));
    const is_compressed = ((sig[0] -% 27) & 4) == 4;

    const r_be = sig[1..33].*;
    const s_be = sig[33..65].*;

    const pk = try recoverKeyFromSignature(r_be, s_be, digest, iter, false);
    const pubkey = secp256k1.PublicKey.fromPoint(secp256k1.Point{ .inner = pk }) catch return error.InvalidCompactSignature;
    return .{ .pubkey = pubkey, .is_compressed = is_compressed };
}

test "compact sign and recover roundtrip (random keys)" {
    var rng_buf: [32]u8 = undefined;
    var c: u8 = 0;
    while (c < 16) : (c += 1) {
        std.crypto.random.bytes(&rng_buf);
        const digest = hash_mod.hash256(&rng_buf).bytes;
        const sk = secp256k1.PrivateKey.fromBytes(rng_buf) catch continue;
        const compressed = (c & 1) == 1;

        const sig = try signCompactDigest256(sk, digest, compressed);
        const rec = try recoverCompactDigest256(sig, digest);
        const exp = try sk.publicKey();

        try std.testing.expectEqualSlices(u8, &exp.bytes, &rec.pubkey.bytes);
        try std.testing.expectEqual(compressed, rec.is_compressed);

        var sig2 = sig;
        if (compressed) sig2[0] -= 4 else sig2[0] += 4;
        const rec2 = try recoverCompactDigest256(sig2, digest);
        try std.testing.expectEqualSlices(u8, &exp.bytes, &rec2.pubkey.bytes);
        try std.testing.expectEqual(!compressed, rec2.is_compressed);
    }
}

test "recoverCompact vectors from go-sdk recoveryTests" {
    const E = CompactError;
    const cases = [_]struct {
        msg_hex: []const u8,
        sig_hex: []const u8,
        pub_hex: ?[]const u8,
        want_err: ?CompactError,
    }{
        .{
            .msg_hex = "ce0677bb30baa8cf067c88db9811f4333d131bf8bcf12fe7065d211dce971008",
            .sig_hex = "0190f27b8b488db00b00606796d2987f6a5f59ae62ea05effe84fef5b8b0e549984a691139ad57a3f0b906637673aa2f63d1f55cb1a69199d4009eea23ceaddc93",
            .pub_hex = "04E32DF42865E97135ACFB65F3BAE71BDC86F4D49150AD6A440B6F15878109880A0A2B2667F7E725CEEA70C673093BF67663E0312623C8E091B13CF2C0F11EF652",
            .want_err = null,
        },
        .{
            .msg_hex = "00c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c",
            .sig_hex = "0100b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75f00b940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549",
            .pub_hex = null,
            .want_err = E.NotSquare,
        },
        .{
            .msg_hex = "ba09edc1275a285fb27bfe82c4eea240a907a0dbaf9e55764b8f318c37d5974f",
            .sig_hex = "00000000000000000000000000000000000000000000000000000000000000002c0000000000000000000000000000000000000000000000000000000000000004",
            .pub_hex = "04A7640409AA2083FDAD38B2D8DE1263B2251799591D840653FB02DBBA503D7745FCB83D80E08A1E02896BE691EA6AFFB8A35939A646F1FC79052A744B1C82EDC3",
            .want_err = null,
        },
        .{
            .msg_hex = "3060d2c77c1e192d62ad712fb400e04e6f779914a6876328ff3b213fa85d2012",
            .sig_hex = "65000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000037a3",
            .pub_hex = null,
            .want_err = E.InvalidCompactSignature,
        },
        .{
            .msg_hex = "2bcebac60d8a78e520ae81c2ad586792df495ed429bd730dcd897b301932d054",
            .sig_hex = "060000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007c",
            .pub_hex = null,
            .want_err = E.InvalidCompactSignature,
        },
        .{
            .msg_hex = "2bcebac60d8a78e520ae81c2ad586792df495ed429bd730dcd897b301932d054",
            .sig_hex = "65fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036414100000000000000000000000000000000000000000000000000000000000037a3",
            .pub_hex = null,
            .want_err = E.InvalidCompactSignature,
        },
        .{
            .msg_hex = "ce0677bb30baa8cf067c88db9811f4333d131bf8bcf12fe7065d211dce971008",
            .sig_hex = "0190f27b8b488db00b00606796d2987f6a5f59ae62ea05effe84fef5b8b0e549980000000000000000000000000000000000000000000000000000000000000000",
            .pub_hex = null,
            .want_err = E.InvalidCompactSignature,
        },
        .{
            .msg_hex = "ce0677bb30baa8cf067c88db9811f4333d131bf8bcf12fe7065d211dce971008",
            .sig_hex = "0190f27b8b488db00b00606796d2987f6a5f59ae62ea05effe84fef5b8b0e54998fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            .pub_hex = null,
            .want_err = E.InvalidCompactSignature,
        },
    };

    for (cases) |tc| {
        var msg: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&msg, tc.msg_hex);

        var sig_raw: [65]u8 = undefined;
        _ = try std.fmt.hexToBytes(&sig_raw, tc.sig_hex);
        sig_raw[0] +%= 27;

        const result = recoverCompactDigest256(sig_raw, msg);
        if (tc.want_err) |we| {
            try std.testing.expectError(we, result);
        } else {
            const got = try result;
            var want_uncompressed: [65]u8 = undefined;
            _ = try std.fmt.hexToBytes(&want_uncompressed, tc.pub_hex.?);
            var want_pk = try secp256k1.PublicKey.fromSec1(&want_uncompressed);
            try std.testing.expectEqualSlices(u8, &want_pk.bytes, &got.pubkey.bytes);
        }
    }
}
