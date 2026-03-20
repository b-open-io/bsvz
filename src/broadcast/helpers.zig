const std = @import("std");
const crypto = @import("../crypto/lib.zig");
const primitives = @import("../primitives/lib.zig");

pub fn txidDisplayHex(allocator: std.mem.Allocator, h: crypto.Hash256) ![]u8 {
    const ch = primitives.chainhash.Hash{ .bytes = h.bytes };
    var buf: [primitives.chainhash.MaxHashStringSize]u8 = undefined;
    const s = ch.toHex(&buf);
    return allocator.dupe(u8, s);
}

pub fn hexEncodeLower(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const hexdigits = "0123456789abcdef";
    const out = try allocator.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |b, i| {
        out[i * 2] = hexdigits[b >> 4];
        out[i * 2 + 1] = hexdigits[b & 15];
    }
    return out;
}
