//! BRC-78 portable encrypted messages (go-sdk `message/encrypted.go`).
const std = @import("std");
const ec = @import("../primitives/ec.zig");
const symmetric = @import("../primitives/symmetric.zig");

pub const version_hex = "42421033";
/// Wire prefix bytes (hex `42421033`).
pub const version_bytes = [4]u8{ 0x42, 0x42, 0x10, 0x33 };

fn invoiceEncryptionAlloc(allocator: std.mem.Allocator, key_id: *const [32]u8) ![]u8 {
    const prefix = "2-message encryption-";
    const b64_len = std.base64.standard.Encoder.calcSize(32);
    const out = try allocator.alloc(u8, prefix.len + b64_len);
    @memcpy(out[0..prefix.len], prefix);
    _ = std.base64.standard.Encoder.encode(out[prefix.len..], key_id);
    return out;
}

/// Encrypt with a fixed `key_id` (for tests / parity with captured go-sdk blobs).
pub fn encryptAllocWithKeyId(
    allocator: std.mem.Allocator,
    message: []const u8,
    sender: ec.PrivateKey,
    recipient: ec.PublicKey,
    key_id: [32]u8,
) ![]u8 {
    const invoice = try invoiceEncryptionAlloc(allocator, &key_id);
    defer allocator.free(invoice);

    const signing_priv = try sender.deriveChild(recipient, invoice);
    const recipient_pub = try recipient.deriveChild(sender, invoice);
    const shared = try signing_priv.deriveSharedSecret(recipient_pub);
    const comp = shared.toCompressedSec1();

    const sk1 = symmetric.SymmetricKey.newFromBytes(comp[1..]);
    const sk2 = symmetric.SymmetricKey.newFromBytes(&sk1.toBytes());

    const ciphertext = try sk2.encrypt(allocator, message);
    defer allocator.free(ciphertext);

    const sender_comp = (try sender.publicKey()).toCompressedSec1();
    const recipient_comp = recipient.toCompressedSec1();

    const total = 4 + 33 + 33 + 32 + ciphertext.len;
    const out = try allocator.alloc(u8, total);
    @memcpy(out[0..4], &version_bytes);
    @memcpy(out[4..37], &sender_comp);
    @memcpy(out[37..70], &recipient_comp);
    @memcpy(out[70..102], &key_id);
    @memcpy(out[102..], ciphertext);
    return out;
}

/// Encrypt for `recipient`'s public key. Caller frees returned buffer.
pub fn encryptAlloc(
    allocator: std.mem.Allocator,
    message: []const u8,
    sender: ec.PrivateKey,
    recipient: ec.PublicKey,
) ![]u8 {
    var key_id: [32]u8 = undefined;
    std.crypto.random.bytes(&key_id);
    return encryptAllocWithKeyId(allocator, message, sender, recipient, key_id);
}

pub const DecryptError = error{
    MessageTooShort,
    VersionMismatch,
    RecipientMismatch,
    InvalidCiphertext,
    InvalidEncoding,
};

/// Decrypt BRC-78 message. Caller frees returned plaintext.
pub fn decryptAlloc(allocator: std.mem.Allocator, message: []const u8, recipient: ec.PrivateKey) DecryptError![]u8 {
    const min_len = 4 + 33 + 33 + 32 + 1;
    if (message.len < min_len) return error.MessageTooShort;

    if (!std.mem.eql(u8, message[0..4], &version_bytes)) {
        return error.VersionMismatch;
    }

    const sender_pub = ec.PublicKey.fromSec1(message[4..37]) catch return error.InvalidEncoding;
    var expected_recipient: [33]u8 = undefined;
    @memcpy(&expected_recipient, message[37..70]);
    const actual_recipient = (recipient.publicKey() catch return error.InvalidEncoding).toCompressedSec1();
    if (!std.mem.eql(u8, &expected_recipient, &actual_recipient)) {
        return error.RecipientMismatch;
    }

    const key_id = message[70..102];
    const encrypted = message[102..];

    var invoice_buf: [80]u8 = undefined;
    const prefix = "2-message encryption-";
    const b64_len = std.base64.standard.Encoder.calcSize(32);
    if (prefix.len + b64_len > invoice_buf.len) return error.InvalidEncoding;
    @memcpy(invoice_buf[0..prefix.len], prefix);
    _ = std.base64.standard.Encoder.encode(invoice_buf[prefix.len..][0..b64_len], key_id[0..32]);
    const invoice = invoice_buf[0 .. prefix.len + b64_len];

    const recipient_child_priv = try recipient.deriveChild(sender_pub, invoice);
    const signing_pub = try sender_pub.deriveChild(recipient, invoice);
    const shared = try signing_pub.deriveSharedSecret(recipient_child_priv);
    const comp = shared.toCompressedSec1();

    const sk1 = symmetric.SymmetricKey.newFromBytes(comp[1..]);
    const sk2 = symmetric.SymmetricKey.newFromBytes(&sk1.toBytes());

    return sk2.decrypt(allocator, encrypted) catch error.InvalidCiphertext;
}

test "BRC-78 ecdh encrypt vs decrypt paths" {
    const sender = try ec.PrivateKey.fromBytes([_]u8{15} ** 32);
    const recipient_priv = try ec.PrivateKey.fromBytes([_]u8{21} ** 32);
    const recipient_pub = try recipient_priv.publicKey();
    var key_id: [32]u8 = [_]u8{42} ** 32;
    const allocator = std.testing.allocator;
    const invoice = try invoiceEncryptionAlloc(allocator, &key_id);
    defer allocator.free(invoice);

    const signing_priv = try sender.deriveChild(recipient_pub, invoice);
    const derived_pub = try recipient_pub.deriveChild(sender, invoice);
    const s_encrypt = try signing_priv.deriveSharedSecret(derived_pub);

    const recipient_child_priv = try recipient_priv.deriveChild(try sender.publicKey(), invoice);
    const signing_pub = try (try sender.publicKey()).deriveChild(recipient_priv, invoice);
    const s_decrypt = try signing_pub.deriveSharedSecret(recipient_child_priv);

    try std.testing.expect(s_encrypt.eql(s_decrypt));
}

test "BRC-78 derived signing pub matches priv" {
    const sender = try ec.PrivateKey.fromBytes([_]u8{15} ** 32);
    const recipient_priv = try ec.PrivateKey.fromBytes([_]u8{21} ** 32);
    const recipient_pub = try recipient_priv.publicKey();
    var key_id: [32]u8 = [_]u8{42} ** 32;
    const allocator = std.testing.allocator;
    const invoice = try invoiceEncryptionAlloc(allocator, &key_id);
    defer allocator.free(invoice);

    const signing_priv = try sender.deriveChild(recipient_pub, invoice);
    const signing_pub = try (try sender.publicKey()).deriveChild(recipient_priv, invoice);
    try std.testing.expect((try signing_priv.publicKey()).eql(signing_pub));
}

test "BRC-78 roundtrip" {
    const allocator = std.testing.allocator;
    const sender = try ec.PrivateKey.fromBytes([_]u8{15} ** 32);
    const recipient = try ec.PrivateKey.fromBytes([_]u8{21} ** 32);
    const recipient_pub = try recipient.publicKey();
    const msg = [_]u8{ 1, 2, 4, 8, 16, 32 };

    const enc = try encryptAlloc(allocator, &msg, sender, recipient_pub);
    defer allocator.free(enc);

    const dec = try decryptAlloc(allocator, enc, recipient);
    defer allocator.free(dec);

    try std.testing.expectEqualSlices(u8, &msg, dec);
}

test "BRC-78 version mismatch" {
    const allocator = std.testing.allocator;
    const sender = try ec.PrivateKey.fromBytes([_]u8{15} ** 32);
    const recipient = try ec.PrivateKey.fromBytes([_]u8{21} ** 32);
    const recipient_pub = try recipient.publicKey();
    const msg = [_]u8{ 1, 2, 4, 8, 16, 32 };

    const enc = try encryptAlloc(allocator, &msg, sender, recipient_pub);
    defer allocator.free(enc);

    var bad = try allocator.dupe(u8, enc);
    defer allocator.free(bad);
    bad[0] = 1;

    try std.testing.expectError(error.VersionMismatch, decryptAlloc(allocator, bad, recipient));
}

test "BRC-78 wrong recipient" {
    const allocator = std.testing.allocator;
    const sender = try ec.PrivateKey.fromBytes([_]u8{15} ** 32);
    const recipient = try ec.PrivateKey.fromBytes([_]u8{21} ** 32);
    var wrong_s: [32]u8 = [_]u8{0} ** 32;
    wrong_s[31] = 22;
    const wrong = try ec.PrivateKey.fromBytes(wrong_s);
    const recipient_pub = try recipient.publicKey();
    const msg = [_]u8{ 1, 2, 4, 8, 16, 32 };

    const enc = try encryptAlloc(allocator, &msg, sender, recipient_pub);
    defer allocator.free(enc);

    try std.testing.expectError(error.RecipientMismatch, decryptAlloc(allocator, enc, wrong));
}
