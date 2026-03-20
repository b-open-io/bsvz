//! Cross-checked field shapes from go-sdk `transaction/template/pushdrop/pushdrop_test.go`
//! (TestPushDrop_TestVectors) and structural checks aligned with ts-sdk templates.
const std = @import("std");
const bsvz = @import("bsvz");

test "pushdrop encode-decode matches go-sdk field vector shapes" {
    const a = std.testing.allocator;
    const crypto = bsvz.crypto;
    const pushdrop = bsvz.script.templates.pushdrop;
    const Script = bsvz.script.Script;

    const sk = [_]u8{0x01} ++ [_]u8{0} ** 31;
    const pk = try (try crypto.PrivateKey.fromBytes(sk)).publicKey();

    const pi = [_]u8{ 3, 1, 4, 1, 5, 9 };

    const ff200 = try a.alloc(u8, 200);
    defer a.free(ff200);
    @memset(ff200, 0xff);

    const ff400 = try a.alloc(u8, 400);
    defer a.free(ff400);
    @memset(ff400, 0xff);

    const ff70k = try a.alloc(u8, 70_000);
    defer a.free(ff70k);
    @memset(ff70k, 0xff);

    const cases: []const []const []const u8 = &.{
        &.{},
        &.{&[_]u8{}},
        &.{&[_]u8{0}},
        &.{&[_]u8{1}},
        &.{&[_]u8{0x81}},
        &.{&pi},
        &.{ff200},
        &.{ff400},
        &.{ff70k},
        &.{ &[_]u8{0}, &[_]u8{1}, &[_]u8{2} },
        &.{ &[_]u8{0}, &[_]u8{1}, &[_]u8{2}, &[_]u8{3} },
    };

    for (cases) |fields| {
        const script_bytes = try pushdrop.encodeLockBefore(a, &pk.bytes, fields);
        defer a.free(script_bytes);

        var d = (try pushdrop.decodeLockBefore(a, Script.init(script_bytes))) orelse
            return error.DecodeFailed;
        defer pushdrop.deinitDecoded(a, &d);

        try std.testing.expect(d.locking_pubkey.bytes.len == pk.bytes.len);
        try std.testing.expectEqualSlices(u8, &pk.bytes, &d.locking_pubkey.bytes);
        try std.testing.expectEqual(fields.len, d.fields.len);
        for (fields, d.fields) |exp, got| {
            // Empty field encodes as OP_0; decode yields one byte 0x00 (same as go/ts minimal push).
            if (exp.len == 0) {
                try std.testing.expectEqualSlices(u8, &[_]u8{0}, got);
            } else {
                try std.testing.expectEqualSlices(u8, exp, got);
            }
        }
    }
}

test "r puzzle lock layout matches ts-sdk prefix and per-kind hash opcodes" {
    const a = std.testing.allocator;
    const rp = bsvz.script.templates.r_puzzle;
    const opcode = bsvz.script.opcode.Opcode;

    const v20 = [_]u8{0xcd} ** 20;
    const v32 = [_]u8{0xef} ** 32;

    const raw = try rp.encodeLock(a, .raw, &[_]u8{0x42});
    defer a.free(raw);
    try std.testing.expectEqualSlices(u8, &rp.stack_split_prefix, raw[0..9]);
    try std.testing.expect(raw[9] == 0x01 and raw[10] == 0x42);
    try std.testing.expect(raw[11] == @intFromEnum(opcode.OP_EQUALVERIFY));
    try std.testing.expect(raw[12] == @intFromEnum(opcode.OP_CHECKSIG));

    const h160 = try rp.encodeLock(a, .hash160, &v20);
    defer a.free(h160);
    try std.testing.expectEqualSlices(u8, &rp.stack_split_prefix, h160[0..9]);
    try std.testing.expect(h160[9] == @intFromEnum(opcode.OP_HASH160));

    const sha1 = try rp.encodeLock(a, .sha1, &v20);
    defer a.free(sha1);
    try std.testing.expect(sha1[9] == @intFromEnum(opcode.OP_SHA1));

    const sha256 = try rp.encodeLock(a, .sha256, &v32);
    defer a.free(sha256);
    try std.testing.expect(sha256[9] == @intFromEnum(opcode.OP_SHA256));

    const h256 = try rp.encodeLock(a, .hash256, &v32);
    defer a.free(h256);
    try std.testing.expect(h256[9] == @intFromEnum(opcode.OP_HASH256));

    const rmd = try rp.encodeLock(a, .ripemd160, &v20);
    defer a.free(rmd);
    try std.testing.expect(rmd[9] == @intFromEnum(opcode.OP_RIPEMD160));
}

test "p2pkh locking script matches go-sdk compat hex" {
    const a = std.testing.allocator;
    const p2pkh = bsvz.script.templates.p2pkh;
    const hex = bsvz.primitives.hex;

    const locking = try hex.decode(a, "76a914c7c6987b6e2345a6b138e3384141520a0fbc18c588ac");
    defer a.free(locking);

    try std.testing.expect(p2pkh.matches(locking));
    const h = try p2pkh.extractPubKeyHash(locking);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xc7, 0xc6, 0x98, 0x7b, 0x6e, 0x23, 0x45, 0xa6, 0xb1, 0x38,
        0xe3, 0x38, 0x41, 0x41, 0x52, 0x0a, 0x0f, 0xbc, 0x18, 0xc5,
    }, &h.bytes);
}

test "op_true BRC-19 locking is OP_1" {
    const op_true = bsvz.script.templates.op_true;
    const s = op_true.lockingScript();
    try std.testing.expectEqual(@as(usize, 1), s.len);
    try std.testing.expectEqual(@as(u8, 0x51), s[0]);
    try std.testing.expect(op_true.matches(&s));
}
