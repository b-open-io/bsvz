//! BRC-77 portable signed messages (go-sdk `message/signed.go` wire: `BB3\\x01`, invoice `2-message signing-…`).
const std = @import("std");
const ec = @import("../primitives/ec.zig");
const DerSignature = @import("../crypto/signature.zig").DerSignature;

pub const version_bytes = [4]u8{ 0x42, 0x42, 0x33, 0x01 };

/// Placeholder private key used when signing/verifying for "anyone" (go `PrivateKeyFromBytes([]byte{1})`).
pub fn anyonePrivateKey() !ec.PrivateKey {
    var scalar: [32]u8 = [_]u8{0} ** 32;
    scalar[31] = 1;
    return ec.PrivateKey.fromBytes(scalar);
}

fn invoiceSigningAlloc(allocator: std.mem.Allocator, key_id: *const [32]u8) ![]u8 {
    const prefix = "2-message signing-";
    const b64_len = std.base64.standard.Encoder.calcSize(32);
    const out = try allocator.alloc(u8, prefix.len + b64_len);
    @memcpy(out[0..prefix.len], prefix);
    _ = std.base64.standard.Encoder.encode(out[prefix.len..], key_id);
    return out;
}

/// Deterministic signing for tests / cross-runtime vectors (`key_id` matches go-sdk `rand` replacement).
pub fn signAllocWithKeyId(
    allocator: std.mem.Allocator,
    message: []const u8,
    signer: ec.PrivateKey,
    recipient: ?ec.PublicKey,
    key_id: [32]u8,
) ![]u8 {
    const recipient_anyone = recipient == null;
    const verifier = recipient orelse try (try anyonePrivateKey()).publicKey();

    const invoice = try invoiceSigningAlloc(allocator, &key_id);
    defer allocator.free(invoice);
    const signing_priv = try signer.deriveChild(verifier, invoice);

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(message, &digest, .{});

    const der = try signing_priv.signDigest(digest);
    const sender_pub = try signer.publicKey();
    const sender_comp = sender_pub.toCompressedSec1();

    const der_slice = der.asSlice();
    const total_len = 4 + 33 + (if (recipient_anyone) @as(usize, 1) else 33) + 32 + der_slice.len;
    const sig = try allocator.alloc(u8, total_len);
    var off: usize = 0;
    @memcpy(sig[off..][0..4], &version_bytes);
    off += 4;
    @memcpy(sig[off..][0..33], &sender_comp);
    off += 33;
    if (recipient_anyone) {
        sig[off] = 0;
        off += 1;
    } else {
        const rp = recipient.?;
        @memcpy(sig[off..][0..33], &rp.toCompressedSec1());
        off += 33;
    }
    @memcpy(sig[off..][0..32], &key_id);
    off += 32;
    @memcpy(sig[off..][0..der_slice.len], der_slice);
    return sig;
}

/// Build a BRC-77 signature. Caller frees returned slice. `recipient` null → anyone can verify.
pub fn signAlloc(
    allocator: std.mem.Allocator,
    message: []const u8,
    signer: ec.PrivateKey,
    recipient: ?ec.PublicKey,
) ![]u8 {
    var key_id: [32]u8 = undefined;
    std.crypto.random.bytes(&key_id);
    return signAllocWithKeyId(allocator, message, signer, recipient, key_id);
}

pub const VerifyError = error{
    VersionMismatch,
    RecipientRequired,
    RecipientMismatch,
    InvalidEncoding,
    InvalidSignatureEncoding,
};

/// Verify BRC-77 signature. `recipient` null only valid for "anyone" signatures (marker byte 0).
pub fn verify(message: []const u8, sig: []const u8, recipient: ?ec.PrivateKey) VerifyError!bool {
    if (sig.len < 4 + 33 + 1 + 32 + 8) return error.InvalidEncoding;

    if (!std.mem.eql(u8, sig[0..4], &version_bytes)) {
        return error.VersionMismatch;
    }
    var counter: usize = 4;

    const sender_pub = ec.PublicKey.fromSec1(sig[counter .. counter + 33]) catch return error.InvalidEncoding;
    counter += 33;

    const rec_priv: ec.PrivateKey = blk: {
        if (sig[counter] == 0) {
            counter += 1;
            break :blk try anyonePrivateKey();
        }
        const rec = recipient orelse return error.RecipientRequired;
        const verifier_first = sig[counter];
        counter += 1;
        const verifier_rest = sig[counter .. counter + 32];
        counter += 32;
        var verifier_comp: [33]u8 = undefined;
        verifier_comp[0] = verifier_first;
        @memcpy(verifier_comp[1..], verifier_rest);
        const expected = rec.publicKey() catch return error.InvalidEncoding;
        if (!std.mem.eql(u8, &expected.toCompressedSec1(), &verifier_comp)) {
            return error.RecipientMismatch;
        }
        break :blk rec;
    };

    const key_id = sig[counter .. counter + 32];
    counter += 32;
    const der_slice = sig[counter..];
    if (der_slice.len < 8) return error.InvalidSignatureEncoding;

    const der = DerSignature.fromDer(der_slice) catch return error.InvalidSignatureEncoding;

    var invoice_buf: [80]u8 = undefined;
    const prefix = "2-message signing-";
    const b64_len = std.base64.standard.Encoder.calcSize(32);
    if (prefix.len + b64_len > invoice_buf.len) return error.InvalidEncoding;
    @memcpy(invoice_buf[0..prefix.len], prefix);
    _ = std.base64.standard.Encoder.encode(invoice_buf[prefix.len..][0..b64_len], key_id[0..32]);
    const invoice = invoice_buf[0 .. prefix.len + b64_len];

    const signing_pub = try sender_pub.deriveChild(rec_priv, invoice);

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(message, &digest, .{});

    return signing_pub.verifyDigest(digest, der) catch false;
}

test "BRC-77 sign/verify with recipient" {
    const allocator = std.testing.allocator;
    const sender = try ec.PrivateKey.fromBytes([_]u8{15} ** 32);
    const recipient = try ec.PrivateKey.fromBytes([_]u8{21} ** 32);
    const recipient_pub = try recipient.publicKey();
    const msg = [_]u8{ 1, 2, 4, 8, 16, 32 };

    const sig = try signAlloc(allocator, &msg, sender, recipient_pub);
    defer allocator.free(sig);

    try std.testing.expect(try verify(&msg, sig, recipient));
}

test "BRC-77 sign/verify anyone" {
    const allocator = std.testing.allocator;
    const sender = try ec.PrivateKey.fromBytes([_]u8{15} ** 32);
    const msg = [_]u8{ 1, 2, 4, 8, 16, 32 };

    const sig = try signAlloc(allocator, &msg, sender, null);
    defer allocator.free(sig);

    try std.testing.expect(try verify(&msg, sig, null));
}

test "BRC-77 version mismatch" {
    const allocator = std.testing.allocator;
    const sender = try ec.PrivateKey.fromBytes([_]u8{15} ** 32);
    const recipient = try ec.PrivateKey.fromBytes([_]u8{21} ** 32);
    const recipient_pub = try recipient.publicKey();
    const msg = [_]u8{ 1, 2, 4, 8, 16, 32 };

    const sig = try signAlloc(allocator, &msg, sender, recipient_pub);
    defer allocator.free(sig);

    var bad = try allocator.dupe(u8, sig);
    defer allocator.free(bad);
    bad[0] = 1;

    try std.testing.expectError(error.VersionMismatch, verify(&msg, bad, recipient));
}

test "BRC-77 recipient required" {
    const allocator = std.testing.allocator;
    const sender = try ec.PrivateKey.fromBytes([_]u8{15} ** 32);
    const recipient = try ec.PrivateKey.fromBytes([_]u8{21} ** 32);
    const recipient_pub = try recipient.publicKey();
    const msg = [_]u8{ 1, 2, 4, 8, 16, 32 };

    const sig = try signAlloc(allocator, &msg, sender, recipient_pub);
    defer allocator.free(sig);

    try std.testing.expectError(error.RecipientRequired, verify(&msg, sig, null));
}

test "BRC-77 wrong recipient" {
    const allocator = std.testing.allocator;
    const sender = try ec.PrivateKey.fromBytes([_]u8{15} ** 32);
    const recipient = try ec.PrivateKey.fromBytes([_]u8{21} ** 32);
    var wrong_s: [32]u8 = [_]u8{0} ** 32;
    wrong_s[31] = 22;
    const wrong = try ec.PrivateKey.fromBytes(wrong_s);
    const recipient_pub = try recipient.publicKey();
    const msg = [_]u8{ 1, 2, 4, 8, 16, 32 };

    const sig = try signAlloc(allocator, &msg, sender, recipient_pub);
    defer allocator.free(sig);

    try std.testing.expectError(error.RecipientMismatch, verify(&msg, sig, wrong));
}

test "BRC-77 tampered message" {
    const allocator = std.testing.allocator;
    const sender = try ec.PrivateKey.fromBytes([_]u8{15} ** 32);
    var msg = [_]u8{ 1, 2, 4, 8, 16, 32 };

    const sig = try signAlloc(allocator, &msg, sender, null);
    defer allocator.free(sig);

    msg[msg.len - 1] = 64;
    try std.testing.expect(!(try verify(&msg, sig, null)));
}
