//! ts-sdk `RPuzzle` / BRC-17 — lock extracts R from signature, compares to pushed value, then `OP_CHECKSIG`.
//! See https://bsv.brc.dev/scripts/0017
const std = @import("std");
const opcode = @import("../opcode.zig").Opcode;
const pushdrop = @import("pushdrop.zig");

pub const Kind = enum {
    raw,
    sha1,
    sha256,
    hash256,
    ripemd160,
    hash160,
};

/// Fixed stack-manipulation prefix before optional hash + push (ts-sdk `RPuzzle.lock`).
pub const stack_split_prefix: [9]u8 = .{
    @intFromEnum(opcode.OP_OVER),
    @intFromEnum(opcode.OP_3),
    @intFromEnum(opcode.OP_SPLIT),
    @intFromEnum(opcode.OP_NIP),
    @intFromEnum(opcode.OP_1),
    @intFromEnum(opcode.OP_SPLIT),
    @intFromEnum(opcode.OP_SWAP),
    @intFromEnum(opcode.OP_SPLIT),
    @intFromEnum(opcode.OP_DROP),
};

fn hashOpcode(kind: Kind) ?opcode {
    return switch (kind) {
        .raw => null,
        .sha1 => .OP_SHA1,
        .sha256 => .OP_SHA256,
        .hash256 => .OP_HASH256,
        .ripemd160 => .OP_RIPEMD160,
        .hash160 => .OP_HASH160,
    };
}

/// Locking script bytes: stack-split R from sig, optional hash, compare to `value`, `OP_CHECKSIG`.
pub fn encodeLock(a: std.mem.Allocator, kind: Kind, value: []const u8) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(a);
    try buf.appendSlice(a, &stack_split_prefix);
    if (hashOpcode(kind)) |hop| {
        try buf.append(a, @intFromEnum(hop));
    }
    try pushdrop.appendMinPush(a, &buf, value);
    try buf.append(a, @intFromEnum(opcode.OP_EQUALVERIFY));
    try buf.append(a, @intFromEnum(opcode.OP_CHECKSIG));
    return try buf.toOwnedSlice(a);
}

test "r puzzle raw lock matches single-byte vector" {
    const a = std.testing.allocator;
    const out = try encodeLock(a, .raw, &[_]u8{0x42});
    defer a.free(out);
    const expected: [13]u8 = .{
        0x78, 0x53, 0x7f, 0x77, 0x51, 0x7f, 0x7c, 0x7f, 0x75,
        0x01, 0x42, 0x88, 0xac,
    };
    try std.testing.expectEqualSlices(u8, &expected, out);
}

test "r puzzle HASH160 adds hash opcode before push" {
    const a = std.testing.allocator;
    const h = [_]u8{0xab} ** 20;
    const out = try encodeLock(a, .hash160, &h);
    defer a.free(out);
    try std.testing.expect(std.mem.indexOfScalar(u8, out, 0xa9) != null);
    try std.testing.expect(out[out.len - 2] == 0x88 and out[out.len - 1] == 0xac);
}
