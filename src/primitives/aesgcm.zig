const std = @import("std");

const crypto = std.crypto;
const aes = crypto.core.aes;
const modes = crypto.core.modes;
const Ghash = crypto.onetimeauth.Ghash;

pub const Error = error{
    InvalidKeyLength,
    InvalidNonceLength,
    InvalidLength,
    AuthenticationFailed,
} || std.mem.Allocator.Error;

pub const TagLen = 16;
pub const BlockLen = 16;

pub fn aesEncryptBlock(plaintext: []const u8, key: []const u8) Error![16]u8 {
    if (plaintext.len != BlockLen) return error.InvalidLength;
    var out: [16]u8 = undefined;
    var block: [16]u8 = undefined;
    @memcpy(&block, plaintext);
    switch (key.len) {
        16 => {
            var key_bytes: [16]u8 = undefined;
            @memcpy(&key_bytes, key);
            const ctx = aes.Aes128.initEnc(key_bytes);
            ctx.encrypt(&out, &block);
        },
        32 => {
            var key_bytes: [32]u8 = undefined;
            @memcpy(&key_bytes, key);
            const ctx = aes.Aes256.initEnc(key_bytes);
            ctx.encrypt(&out, &block);
        },
        else => return error.InvalidKeyLength,
    }
    return out;
}

pub fn aesDecryptBlock(ciphertext: []const u8, key: []const u8) Error![16]u8 {
    if (ciphertext.len != BlockLen) return error.InvalidLength;
    var out: [16]u8 = undefined;
    var block: [16]u8 = undefined;
    @memcpy(&block, ciphertext);
    switch (key.len) {
        16 => {
            var key_bytes: [16]u8 = undefined;
            @memcpy(&key_bytes, key);
            const ctx = aes.Aes128.initDec(key_bytes);
            ctx.decrypt(&out, &block);
        },
        32 => {
            var key_bytes: [32]u8 = undefined;
            @memcpy(&key_bytes, key);
            const ctx = aes.Aes256.initDec(key_bytes);
            ctx.decrypt(&out, &block);
        },
        else => return error.InvalidKeyLength,
    }
    return out;
}

pub const GcmResult = struct {
    ciphertext: []u8,
    tag: [TagLen]u8,
};

pub fn aesGcmEncrypt(
    allocator: std.mem.Allocator,
    plaintext: []const u8,
    key: []const u8,
    nonce: []const u8,
    ad: []const u8,
) Error!GcmResult {
    return switch (key.len) {
        16 => aesGcmEncryptWith(aes.Aes128, allocator, plaintext, key, nonce, ad),
        32 => aesGcmEncryptWith(aes.Aes256, allocator, plaintext, key, nonce, ad),
        else => error.InvalidKeyLength,
    };
}

pub fn aesGcmDecrypt(
    allocator: std.mem.Allocator,
    ciphertext: []const u8,
    key: []const u8,
    nonce: []const u8,
    ad: []const u8,
    tag: [TagLen]u8,
) Error![]u8 {
    return switch (key.len) {
        16 => aesGcmDecryptWith(aes.Aes128, allocator, ciphertext, key, nonce, ad, tag),
        32 => aesGcmDecryptWith(aes.Aes256, allocator, ciphertext, key, nonce, ad, tag),
        else => error.InvalidKeyLength,
    };
}

fn aesGcmEncryptWith(
    comptime Aes: type,
    allocator: std.mem.Allocator,
    plaintext: []const u8,
    key: []const u8,
    nonce: []const u8,
    ad: []const u8,
) Error!GcmResult {
    if (nonce.len == 0) return error.InvalidNonceLength;
    var key_bytes: [Aes.key_bits / 8]u8 = undefined;
    @memcpy(&key_bytes, key);
    const ctx = Aes.initEnc(key_bytes);

    var h: [16]u8 = undefined;
    const zeros = [_]u8{0} ** 16;
    ctx.encrypt(&h, &zeros);

    const j0 = computeJ0(h, nonce);
    var tag_base: [16]u8 = undefined;
    ctx.encrypt(&tag_base, &j0);

    const ciphertext = try allocator.alloc(u8, plaintext.len);
    errdefer allocator.free(ciphertext);

    var ctr_block = j0;
    inc32(&ctr_block);
    modes.ctr(@TypeOf(ctx), ctx, ciphertext, plaintext, ctr_block, .big);

    const tag = computeTag(h, ad, ciphertext, tag_base);
    return .{ .ciphertext = ciphertext, .tag = tag };
}

fn aesGcmDecryptWith(
    comptime Aes: type,
    allocator: std.mem.Allocator,
    ciphertext: []const u8,
    key: []const u8,
    nonce: []const u8,
    ad: []const u8,
    tag: [TagLen]u8,
) Error![]u8 {
    if (nonce.len == 0) return error.InvalidNonceLength;
    var key_bytes: [Aes.key_bits / 8]u8 = undefined;
    @memcpy(&key_bytes, key);
    const ctx = Aes.initEnc(key_bytes);

    var h: [16]u8 = undefined;
    const zeros = [_]u8{0} ** 16;
    ctx.encrypt(&h, &zeros);

    const j0 = computeJ0(h, nonce);
    var tag_base: [16]u8 = undefined;
    ctx.encrypt(&tag_base, &j0);

    const computed = computeTag(h, ad, ciphertext, tag_base);
    if (!crypto.timing_safe.eql([TagLen]u8, computed, tag)) {
        return error.AuthenticationFailed;
    }

    const plaintext = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(plaintext);
    var ctr_block = j0;
    inc32(&ctr_block);
    modes.ctr(@TypeOf(ctx), ctx, plaintext, ciphertext, ctr_block, .big);
    return plaintext;
}

fn computeJ0(h: [16]u8, nonce: []const u8) [16]u8 {
    if (nonce.len == 12) {
        var out = [_]u8{0} ** 16;
        @memcpy(out[0..12], nonce);
        std.mem.writeInt(u32, out[12..16], 1, .big);
        return out;
    }

    const block_count =
        (std.math.divCeil(usize, nonce.len, Ghash.block_length) catch unreachable) + 1;
    var mac = Ghash.initForBlockCount(&h, block_count);
    mac.update(nonce);
    mac.pad();
    var final_block: [16]u8 = [_]u8{0} ** 16;
    std.mem.writeInt(u64, final_block[8..16], @as(u64, nonce.len) * 8, .big);
    mac.update(&final_block);
    var out: [16]u8 = undefined;
    mac.final(&out);
    return out;
}

fn computeTag(h: [16]u8, ad: []const u8, c: []const u8, tag_base: [16]u8) [16]u8 {
    const block_count =
        (std.math.divCeil(usize, ad.len, Ghash.block_length) catch unreachable) +
        (std.math.divCeil(usize, c.len, Ghash.block_length) catch unreachable) + 1;
    var mac = Ghash.initForBlockCount(&h, block_count);
    mac.update(ad);
    mac.pad();
    mac.update(c);
    mac.pad();

    var final_block: [16]u8 = h;
    std.mem.writeInt(u64, final_block[0..8], @as(u64, ad.len) * 8, .big);
    std.mem.writeInt(u64, final_block[8..16], @as(u64, c.len) * 8, .big);
    mac.update(&final_block);

    var tag: [16]u8 = undefined;
    mac.final(&tag);
    for (tag_base, 0..) |x, i| tag[i] ^= x;
    return tag;
}

fn inc32(block: *[16]u8) void {
    var counter = std.mem.readInt(u32, block[12..16], .big);
    counter +%= 1;
    std.mem.writeInt(u32, block[12..16], counter, .big);
}

test "aes-gcm encrypt/decrypt roundtrip with 12-byte nonce" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x11} ** 32;
    const nonce = [_]u8{0x22} ** 12;
    const msg = "bsvz aesgcm";
    const ad = "aad";
    const enc = try aesGcmEncrypt(allocator, msg, &key, &nonce, ad);
    defer allocator.free(enc.ciphertext);
    const dec = try aesGcmDecrypt(allocator, enc.ciphertext, &key, &nonce, ad, enc.tag);
    defer allocator.free(dec);
    try std.testing.expectEqualSlices(u8, msg, dec);
}

test "aes-gcm encrypt/decrypt roundtrip with 32-byte nonce" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x33} ** 32;
    const nonce = [_]u8{0x44} ** 32;
    const msg = "bsvz aesgcm long nonce";
    const enc = try aesGcmEncrypt(allocator, msg, &key, &nonce, "");
    defer allocator.free(enc.ciphertext);
    const dec = try aesGcmDecrypt(allocator, enc.ciphertext, &key, &nonce, "", enc.tag);
    defer allocator.free(dec);
    try std.testing.expectEqualSlices(u8, msg, dec);
}
