//! Electrum (BIE1) and Bitcore-style ECIES on secp256k1. Matches go-sdk `compat/ecies`.
const std = @import("std");
const aescbc = @import("../primitives/aescbc.zig");
const hash = @import("hash.zig");
const secp = @import("secp256k1.zig");

pub const Error = error{
    InvalidCipher,
    MacMismatch,
    InvalidKey,
    KeyGenFailed,
} || secp.Error || aescbc.Error || std.mem.Allocator.Error;

const magic = "BIE1";

fn hmacEqual32(a: []const u8, b: *const [32]u8) bool {
    if (a.len != 32) return false;
    var v: u8 = 0;
    for (a, 0..) |x, i| v |= x ^ b[i];
    return v == 0;
}

fn randomPrivateKey() Error!secp.PrivateKey {
    var buf: [32]u8 = undefined;
    for (0..256) |_| {
        std.crypto.random.bytes(&buf);
        if (secp.PrivateKey.fromBytes(buf)) |k| return k else |_| {}
    }
    return error.KeyGenFailed;
}

fn electrumSharedCompressed(to_pub: secp.PublicKey, priv: secp.PrivateKey) Error![33]u8 {
    const shared = try to_pub.toPoint().mul(priv.bytes);
    if (shared.isIdentity()) return error.InvalidKey;
    const pk = try secp.PublicKey.fromPoint(shared);
    return pk.bytes;
}

fn publicKeyBytes(k: secp.PrivateKey) Error![33]u8 {
    const pk = k.publicKey() catch return error.InvalidKey;
    return pk.bytes;
}

/// Bitcore/go-sdk uses `P.X.Bytes()` (big.Int) — minimal big-endian, leading zero bytes dropped.
/// `x` must outlive the hash call (slice must not point at a callee stack copy).
fn bitcoreSha512KdfFromX(x: *const [32]u8) [64]u8 {
    var i: usize = 0;
    while (i < 32 and x[i] == 0) i += 1;
    const in: []const u8 = if (i == 32) &[_]u8{0} else x[i..];
    return hash.sha512(in);
}

/// Electrum ECIES encrypt. `from_priv` null → random ephemeral sender key.
/// `no_key` → omit ephemeral pubkey after magic (receiver must know sender pubkey).
pub fn electrumEncryptAlloc(
    allocator: std.mem.Allocator,
    message: []const u8,
    to_pub: secp.PublicKey,
    from_priv: ?secp.PrivateKey,
    no_key: bool,
) Error![]u8 {
    const ephemeral = from_priv orelse try randomPrivateKey();
    const ecdh = try electrumSharedCompressed(to_pub, ephemeral);
    const key_mat = hash.sha512(&ecdh);
    const iv = key_mat[0..16];
    const key_e = key_mat[16..32];
    const key_m = key_mat[32..64];

    const cipher = try aescbc.aesCbcEncrypt(allocator, message, key_e, iv, false);
    defer allocator.free(cipher);

    var prefix = std.ArrayListUnmanaged(u8){};
    defer prefix.deinit(allocator);
    try prefix.appendSlice(allocator, magic);
    if (!no_key) {
        const epb = try publicKeyBytes(ephemeral);
        try prefix.appendSlice(allocator, &epb);
    }
    try prefix.appendSlice(allocator, cipher);

    const mac = hash.hmacSha256(prefix.items, key_m);
    const out = try allocator.alloc(u8, prefix.items.len + mac.len);
    @memcpy(out[0..prefix.items.len], prefix.items);
    @memcpy(out[prefix.items.len..], &mac);
    return out;
}

/// Decrypt Electrum payload. `from_pub` set → shared from counterparty pubkey + receiver priv; else parse ephemeral from ciphertext.
pub fn electrumDecryptAlloc(
    allocator: std.mem.Allocator,
    encrypted: []const u8,
    to_priv: secp.PrivateKey,
    from_pub: ?secp.PublicKey,
) Error![]u8 {
    if (encrypted.len < 4 + 16 + 32) return error.InvalidCipher;
    if (!std.mem.eql(u8, encrypted[0..4], magic)) return error.InvalidCipher;

    const shared: [33]u8 = blk: {
        if (from_pub) |fp| {
            break :blk try electrumSharedCompressed(fp, to_priv);
        }
        if (encrypted.len < 4 + 33 + 32) return error.InvalidCipher;
        const epk = try secp.PublicKey.fromSec1(encrypted[4..37]);
        break :blk try electrumSharedCompressed(epk, to_priv);
    };

    const cipher: []const u8 = blk: {
        if (from_pub) |_| {
            if (encrypted.len > 69) {
                break :blk encrypted[37 .. encrypted.len - 32];
            }
            break :blk encrypted[4 .. encrypted.len - 32];
        }
        break :blk encrypted[37 .. encrypted.len - 32];
    };

    const key_mat = hash.sha512(&shared);
    const iv = key_mat[0..16];
    const key_e = key_mat[16..32];
    const key_m = key_mat[32..64];

    const body = encrypted[0 .. encrypted.len - 32];
    const mac = encrypted[encrypted.len - 32 ..];
    const expect = hash.hmacSha256(body, key_m);
    if (!std.mem.eql(u8, &expect, mac)) return error.MacMismatch;

    return try aescbc.aesCbcDecrypt(allocator, cipher, key_e, iv);
}

/// Bitcore ECIES. `iv` null → zero IV. `from_priv` null → random ephemeral.
pub fn bitcoreEncryptAlloc(
    allocator: std.mem.Allocator,
    message: []const u8,
    to_pub: secp.PublicKey,
    from_priv: ?secp.PrivateKey,
    iv_in: ?[16]u8,
) Error![]u8 {
    const sender = from_priv orelse try randomPrivateKey();
    var iv: [16]u8 = iv_in orelse [_]u8{0} ** 16;

    const r_buf = try publicKeyBytes(sender);
    const p = try to_pub.toPoint().mul(sender.bytes);
    if (p.isIdentity()) return error.InvalidKey;
    const px = p.xBytes32();
    const k_ek_m = bitcoreSha512KdfFromX(&px);
    const k_e = k_ek_m[0..32];
    const k_m = k_ek_m[32..64];

    const cc = try aescbc.aesCbcEncrypt(allocator, message, k_e, &iv, true);
    defer allocator.free(cc);

    const d = hash.hmacSha256(cc, k_m);
    const out = try allocator.alloc(u8, r_buf.len + cc.len + d.len);
    @memcpy(out[0..33], &r_buf);
    @memcpy(out[33..][0..cc.len], cc);
    @memcpy(out[33 + cc.len ..], &d);
    return out;
}

pub fn bitcoreDecryptAlloc(
    allocator: std.mem.Allocator,
    encrypted: []const u8,
    to_priv: secp.PrivateKey,
) Error![]u8 {
    // R (33) + AES-CBC payload: IV (16) + ≥1 block (16) + HMAC (32). Go matches 33+32+32 for "hello world".
    if (encrypted.len < 33 + 32 + 32) return error.InvalidCipher;
    const from_pub = try secp.PublicKey.fromSec1(encrypted[0..33]);
    const p = try from_pub.toPoint().mul(to_priv.bytes);
    if (p.isIdentity()) return error.InvalidKey;

    const px = p.xBytes32();
    const k_ek_m = bitcoreSha512KdfFromX(&px);
    const k_e = k_ek_m[0..32];
    const k_m = k_ek_m[32..64];

    const cipher_text = encrypted[33 .. encrypted.len - 32];
    const mac = encrypted[encrypted.len - 32 ..];
    const expect = hash.hmacSha256(cipher_text, k_m);
    if (!hmacEqual32(mac, &expect)) return error.MacMismatch;

    if (cipher_text.len < 16) return error.InvalidCipher;
    const iv = cipher_text[0..16];
    return try aescbc.aesCbcDecrypt(allocator, cipher_text[16..], k_e, iv);
}

test "electrum vector matches go-sdk TestElectrumEncryptDecryptSingle" {
    const allocator = std.testing.allocator;
    const wif = "L211enC224G1kV8pyyq7bjVd9SxZebnRYEzzM3i7ZHCc1c5E7dQu";
    const compat_wif = @import("../compat/wif.zig");
    const pk = (try compat_wif.decode(allocator, wif)).private_key;
    const pk_pub = try pk.publicKey();

    const enc = try electrumEncryptAlloc(allocator, "hello world", pk_pub, pk, false);
    defer allocator.free(enc);

    const expected_b64 = "QklFMQO7zpX/GS4XpthCy6/hT38ZKsBGbn8JKMGHOY5ifmaoT890Krt9cIRk/ULXaB5uC08owRICzenFbm31pZGu0gCM2uOxpofwHacKidwZ0Q7aEw==";
    const dec_len = try std.base64.standard.Decoder.calcSizeForSlice(expected_b64);
    const dec = try allocator.alloc(u8, dec_len);
    defer allocator.free(dec);
    try std.base64.standard.Decoder.decode(dec, expected_b64);
    try std.testing.expectEqualSlices(u8, dec, enc);

    const plain = try electrumDecryptAlloc(allocator, enc, pk, null);
    defer allocator.free(plain);
    try std.testing.expectEqualSlices(u8, "hello world", plain);
}

test "electrum encrypt/decrypt with explicit ephemeral key" {
    const allocator = std.testing.allocator;
    const wif = "L211enC224G1kV8pyyq7bjVd9SxZebnRYEzzM3i7ZHCc1c5E7dQu";
    const compat_wif = @import("../compat/wif.zig");
    const pk = (try compat_wif.decode(allocator, wif)).private_key;
    const pk_pub = try pk.publicKey();

    var eph_sk = [_]u8{0} ** 32;
    eph_sk[16] = 0x42;
    const eph = try secp.PrivateKey.fromBytes(eph_sk);

    const enc = try electrumEncryptAlloc(allocator, "hello world", pk_pub, eph, false);
    defer allocator.free(enc);
    const plain = try electrumDecryptAlloc(allocator, enc, pk, null);
    defer allocator.free(plain);
    try std.testing.expectEqualSlices(u8, "hello world", plain);
}

test "electrum shared encrypt/decrypt with counterparty pubkey" {
    const allocator = std.testing.allocator;
    const compat_wif = @import("../compat/wif.zig");
    const pk1 = (try compat_wif.decode(allocator, "L211enC224G1kV8pyyq7bjVd9SxZebnRYEzzM3i7ZHCc1c5E7dQu")).private_key;
    var counter_bytes: [33]u8 = undefined;
    _ = try std.fmt.hexToBytes(&counter_bytes, "03121a7afe56fc8e25bca4bb2c94f35eb67ebe5b84df2e149d65b9423ee65b8b4b");
    const counter = try secp.PublicKey.fromSec1(&counter_bytes);

    const enc = try electrumEncryptAlloc(allocator, "hello world", counter, pk1, false);
    defer allocator.free(enc);
    const plain = try electrumDecryptAlloc(allocator, enc, pk1, counter);
    defer allocator.free(plain);
    try std.testing.expectEqualSlices(u8, "hello world", plain);

    const enc_nk = try electrumEncryptAlloc(allocator, "hello world", counter, pk1, true);
    defer allocator.free(enc_nk);
    const plain_nk = try electrumDecryptAlloc(allocator, enc_nk, pk1, counter);
    defer allocator.free(plain_nk);
    try std.testing.expectEqualSlices(u8, "hello world", plain_nk);
}

test "bitcore self roundtrip (fixed sender key)" {
    const allocator = std.testing.allocator;
    const compat_wif = @import("../compat/wif.zig");
    const pk = (try compat_wif.decode(allocator, "L211enC224G1kV8pyyq7bjVd9SxZebnRYEzzM3i7ZHCc1c5E7dQu")).private_key;
    const pk_pub = try pk.publicKey();

    const enc_pk = try bitcoreEncryptAlloc(allocator, "hello world", pk_pub, pk, null);
    defer allocator.free(enc_pk);
    const p1 = try bitcoreDecryptAlloc(allocator, enc_pk, pk);
    defer allocator.free(p1);
    try std.testing.expectEqualSlices(u8, "hello world", p1);

    const pk1 = (try compat_wif.decode(allocator, "L211enC224G1kV8pyyq7bjVd9SxZebnRYEzzM3i7ZHCc1c5E7dQu")).private_key;
    const pk2 = (try compat_wif.decode(allocator, "L27ZSAC1xTsZrghYHqnxwAQZ12bH57piaAdoGaLizTp3JZrjkZjK")).private_key;
    const pub2 = try pk2.publicKey();
    const enc2 = try bitcoreEncryptAlloc(allocator, "hello world", pub2, pk1, null);
    defer allocator.free(enc2);
    const p2 = try bitcoreDecryptAlloc(allocator, enc2, pk2);
    defer allocator.free(p2);
    try std.testing.expectEqualSlices(u8, "hello world", p2);
}

test "bitcore decrypt go-sdk base64 ciphertexts" {
    const allocator = std.testing.allocator;
    const compat_wif = @import("../compat/wif.zig");
    const pk = (try compat_wif.decode(allocator, "L211enC224G1kV8pyyq7bjVd9SxZebnRYEzzM3i7ZHCc1c5E7dQu")).private_key;

    const go1 = "A7vOlf8ZLhem2ELLr+FPfxkqwEZufwkowYc5jmJ+ZqhPAAAAAAAAAAAAAAAAAAAAAB27kUY/HpNbiwhYSpEoEZZDW+wEjMmPNcAAxnc0kiuQ73FpFzf6p6afe4wwVtKAAg==";
    const l1 = try std.base64.standard.Decoder.calcSizeForSlice(go1);
    var buf1: [256]u8 = undefined;
    try std.base64.standard.Decoder.decode(buf1[0..l1], go1);
    const from_go1 = try bitcoreDecryptAlloc(allocator, buf1[0..l1], pk);
    defer allocator.free(from_go1);
    try std.testing.expectEqualSlices(u8, "hello world", from_go1);

    const pk2 = (try compat_wif.decode(allocator, "L27ZSAC1xTsZrghYHqnxwAQZ12bH57piaAdoGaLizTp3JZrjkZjK")).private_key;
    const go2 = "A7vOlf8ZLhem2ELLr+FPfxkqwEZufwkowYc5jmJ+ZqhPAAAAAAAAAAAAAAAAAAAAAAmFslNpNc4TrjaMPmPLdooZwoP6/fE7GN3AeyLpFf2f+QGYRKIke8zbhxu8FcLOsA==";
    const l2 = try std.base64.standard.Decoder.calcSizeForSlice(go2);
    var buf2: [256]u8 = undefined;
    try std.base64.standard.Decoder.decode(buf2[0..l2], go2);
    const from_go2 = try bitcoreDecryptAlloc(allocator, buf2[0..l2], pk2);
    defer allocator.free(from_go2);
    try std.testing.expectEqualSlices(u8, "hello world", from_go2);
}
