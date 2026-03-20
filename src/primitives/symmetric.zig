const std = @import("std");
const aesgcm = @import("aesgcm.zig");

pub const Error = error{
    InvalidCiphertext,
};

pub const SymmetricKey = struct {
    key: [32]u8,

    pub fn newFromBytes(bytes: []const u8) SymmetricKey {
        var out = [_]u8{0} ** 32;
        if (bytes.len >= 32) {
            @memcpy(&out, bytes[bytes.len - 32 ..]);
        } else {
            @memcpy(out[32 - bytes.len ..], bytes);
        }
        return .{ .key = out };
    }

    pub fn newFromRandom() SymmetricKey {
        var out = [_]u8{0} ** 32;
        std.crypto.random.bytes(&out);
        return .{ .key = out };
    }

    pub fn newFromBase64(text: []const u8) !SymmetricKey {
        const out_len = std.base64.standard.Decoder.calcSizeForSlice(text) catch return error.InvalidCiphertext;
        var buf: [64]u8 = undefined;
        if (out_len > buf.len) return error.InvalidCiphertext;
        const out = buf[0..out_len];
        std.base64.standard.Decoder.decode(out, text) catch return error.InvalidCiphertext;
        return newFromBytes(out);
    }

    pub fn toBytes(self: SymmetricKey) [32]u8 {
        return self.key;
    }

    pub fn encrypt(
        self: SymmetricKey,
        allocator: std.mem.Allocator,
        plaintext: []const u8,
    ) ![]u8 {
        var iv: [32]u8 = undefined;
        std.crypto.random.bytes(&iv);
        const enc = try aesgcm.aesGcmEncrypt(allocator, plaintext, &self.key, &iv, "");
        defer allocator.free(enc.ciphertext);

        const out = try allocator.alloc(u8, iv.len + enc.ciphertext.len + aesgcm.TagLen);
        @memcpy(out[0..iv.len], &iv);
        @memcpy(out[iv.len .. iv.len + enc.ciphertext.len], enc.ciphertext);
        @memcpy(out[iv.len + enc.ciphertext.len ..], &enc.tag);
        return out;
    }

    pub fn decrypt(
        self: SymmetricKey,
        allocator: std.mem.Allocator,
        ciphertext: []const u8,
    ) ![]u8 {
        if (ciphertext.len < 32 + aesgcm.TagLen) return error.InvalidCiphertext;
        const iv = ciphertext[0..32];
        const tag_start = ciphertext.len - aesgcm.TagLen;
        const ct = ciphertext[32..tag_start];
        var tag: [aesgcm.TagLen]u8 = undefined;
        @memcpy(&tag, ciphertext[tag_start..]);
        return aesgcm.aesGcmDecrypt(allocator, ct, &self.key, iv, "", tag);
    }
};

test "symmetric key encrypt/decrypt roundtrip" {
    const allocator = std.testing.allocator;
    const key = SymmetricKey.newFromRandom();
    const msg = "bsvz symmetric";
    const enc = try key.encrypt(allocator, msg);
    defer allocator.free(enc);
    const dec = try key.decrypt(allocator, enc);
    defer allocator.free(dec);
    try std.testing.expectEqualSlices(u8, msg, dec);
}
