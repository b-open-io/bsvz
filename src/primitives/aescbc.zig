const std = @import("std");

const aes = std.crypto.core.aes;

pub const Error = error{
    InvalidKeyLength,
    InvalidIvLength,
    InvalidPadding,
};

const BlockLen = 16;

pub fn pkcs7Pad(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const padding = BlockLen - (data.len % BlockLen);
    const out = try allocator.alloc(u8, data.len + padding);
    @memcpy(out[0..data.len], data);
    @memset(out[data.len..], @intCast(padding));
    return out;
}

pub fn pkcs7Unpad(data: []const u8) Error![]const u8 {
    if (data.len == 0 or data.len % BlockLen != 0) return error.InvalidPadding;
    const padding = data[data.len - 1];
    if (padding == 0 or padding > BlockLen) return error.InvalidPadding;
    const start = data.len - padding;
    for (data[start..]) |b| {
        if (b != padding) return error.InvalidPadding;
    }
    return data[0..start];
}

pub fn aesCbcEncrypt(
    allocator: std.mem.Allocator,
    data: []const u8,
    key: []const u8,
    iv: []const u8,
    concat_iv: bool,
) ![]u8 {
    if (iv.len != BlockLen) return error.InvalidIvLength;
    const padded = try pkcs7Pad(allocator, data);
    defer allocator.free(padded);

    const out_len = padded.len + (if (concat_iv) iv.len else 0);
    const out = try allocator.alloc(u8, out_len);
    errdefer allocator.free(out);

    const dst = if (concat_iv) out[iv.len..] else out;
    if (concat_iv) @memcpy(out[0..iv.len], iv);

    switch (key.len) {
        16 => {
            var key_bytes: [16]u8 = undefined;
            @memcpy(&key_bytes, key);
            const ctx = aes.Aes128.initEnc(key_bytes);
            encryptBlocks(ctx, padded, iv, dst);
        },
        32 => {
            var key_bytes: [32]u8 = undefined;
            @memcpy(&key_bytes, key);
            const ctx = aes.Aes256.initEnc(key_bytes);
            encryptBlocks(ctx, padded, iv, dst);
        },
        else => return error.InvalidKeyLength,
    }

    return out;
}

pub fn aesCbcDecrypt(
    allocator: std.mem.Allocator,
    data: []const u8,
    key: []const u8,
    iv: []const u8,
) ![]u8 {
    if (iv.len != BlockLen) return error.InvalidIvLength;
    if (data.len % BlockLen != 0) return error.InvalidPadding;

    const out = try allocator.alloc(u8, data.len);
    errdefer allocator.free(out);

    switch (key.len) {
        16 => {
            var key_bytes: [16]u8 = undefined;
            @memcpy(&key_bytes, key);
            const ctx = aes.Aes128.initDec(key_bytes);
            decryptBlocks(ctx, data, iv, out);
        },
        32 => {
            var key_bytes: [32]u8 = undefined;
            @memcpy(&key_bytes, key);
            const ctx = aes.Aes256.initDec(key_bytes);
            decryptBlocks(ctx, data, iv, out);
        },
        else => return error.InvalidKeyLength,
    }

    const unpadded = try pkcs7Unpad(out);
    const trimmed = try allocator.alloc(u8, unpadded.len);
    @memcpy(trimmed, unpadded);
    allocator.free(out);
    return trimmed;
}

fn encryptBlocks(ctx: anytype, plain: []const u8, iv: []const u8, out: []u8) void {
    var prev: [BlockLen]u8 = undefined;
    @memcpy(&prev, iv);
    var offset: usize = 0;
    while (offset < plain.len) : (offset += BlockLen) {
        var block: [BlockLen]u8 = undefined;
        @memcpy(&block, plain[offset .. offset + BlockLen]);
        for (&block, 0..) |*b, i| b.* ^= prev[i];
        var out_block: [BlockLen]u8 = undefined;
        ctx.encrypt(&out_block, &block);
        @memcpy(out[offset .. offset + BlockLen], &out_block);
        prev = out_block;
    }
}

fn decryptBlocks(ctx: anytype, cipher: []const u8, iv: []const u8, out: []u8) void {
    var prev: [BlockLen]u8 = undefined;
    @memcpy(&prev, iv);
    var offset: usize = 0;
    while (offset < cipher.len) : (offset += BlockLen) {
        var block: [BlockLen]u8 = undefined;
        @memcpy(&block, cipher[offset .. offset + BlockLen]);
        var out_block: [BlockLen]u8 = undefined;
        ctx.decrypt(&out_block, &block);
        for (&out_block, 0..) |*b, i| b.* ^= prev[i];
        @memcpy(out[offset .. offset + BlockLen], &out_block);
        prev = block;
    }
}

test "aes-cbc encrypt/decrypt roundtrip" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x11} ** 32;
    const iv = [_]u8{0x22} ** 16;
    const msg = "bsvz aes cbc";
    const enc = try aesCbcEncrypt(allocator, msg, &key, &iv, false);
    defer allocator.free(enc);
    const dec = try aesCbcDecrypt(allocator, enc, &key, &iv);
    defer allocator.free(dec);
    try std.testing.expectEqualSlices(u8, msg, dec);
}
