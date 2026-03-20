//! Script classification (go-sdk `IsP2PKH`, `IsP2PK`, `IsData`, `IsMultiSigOut`, `IsP2SH`, `PublicKeyHash`).
const std = @import("std");
const crypto = @import("../crypto/lib.zig");
const Opcode = @import("opcode.zig").Opcode;
const Script = @import("script.zig").Script;
const parser = @import("parser.zig");
const chunk = @import("chunk.zig");
const templates = @import("templates/p2pkh.zig");

pub const Error = parser.Error || error{ NotP2PKH, EmptyScript, InvalidScriptTemplate };

fn allocScratch() std.mem.Allocator {
    const buf: [16384]u8 = undefined;
    var fba = std.heap.stackFallback(buf.len, std.heap.page_allocator);
    return fba.get();
}

fn isSmallIntOpByte(b: u8) bool {
    return b == 0x00 or (b >= @intFromEnum(Opcode.OP_1) and b <= @intFromEnum(Opcode.OP_16));
}

/// go-sdk `(*Script).IsP2PKH`.
pub fn isP2PKH(script: Script) bool {
    return templates.matches(script.bytes);
}

/// go-sdk `(*Script).IsP2SH`.
pub fn isP2SH(script: Script) bool {
    const b = script.bytes;
    return b.len == 23 and
        b[0] == @intFromEnum(Opcode.OP_HASH160) and
        b[1] == 0x14 and
        b[22] == @intFromEnum(Opcode.OP_EQUAL);
}

/// go-sdk `(*Script).IsData`.
pub fn isData(script: Script) bool {
    const b = script.bytes;
    return (b.len > 0 and b[0] == @intFromEnum(Opcode.OP_RETURN)) or
        (b.len > 1 and b[0] == @intFromEnum(Opcode.OP_0) and b[1] == @intFromEnum(Opcode.OP_RETURN));
}

/// go-sdk `(*Script).IsP2PK` (DecodeScript-based).
pub fn isP2PK(script: Script) bool {
    const a = allocScratch();
    const parts = parser.parseAlloc(a, script) catch return false;
    defer a.free(parts);
    if (parts.len != 2) return false;
    if (parts[0] != .push_data) return false;
    if (parts[1] != .opcode) return false;
    if (parts[1].opcode != .OP_CHECKSIG) return false;
    const pubkey = parts[0].push_data.data;
    if (pubkey.len == 0) return false;
    return switch (pubkey[0]) {
        0x04, 0x06, 0x07 => pubkey.len == 65,
        0x02, 0x03 => pubkey.len == 33,
        else => false,
    };
}

/// go-sdk `(*Script).IsMultiSigOut`.
pub fn isMultiSigOut(script: Script) bool {
    const a = allocScratch();
    const parts = parser.parseAlloc(a, script) catch return false;
    defer a.free(parts);
    if (parts.len < 3) return false;

    const first: u8 = switch (parts[0]) {
        .opcode => |op| op.toByte(),
        .push_data => |p| pushChunkTag(p),
        .op_return_data => return false,
    };
    if (!isSmallIntOpByte(first)) return false;

    const n = parts.len;
    const pen: u8 = switch (parts[n - 2]) {
        .opcode => |op| op.toByte(),
        .push_data => |p| pushChunkTag(p),
        .op_return_data => return false,
    };
    if (!isSmallIntOpByte(pen)) return false;

    const last = parts[n - 1];
    if (last != .opcode or last.opcode != .OP_CHECKMULTISIG) return false;

    var i: usize = 1;
    while (i < n - 2) : (i += 1) {
        switch (parts[i]) {
            .push_data => |p| {
                if (p.data.len < 1) return false;
            },
            else => return false,
        }
    }
    return true;
}

fn pushChunkTag(p: chunk.PushData) u8 {
    return switch (p.encoding) {
        .direct => @intCast(p.data.len),
        .OP_PUSHDATA1 => @intFromEnum(Opcode.OP_PUSHDATA1),
        .OP_PUSHDATA2 => @intFromEnum(Opcode.OP_PUSHDATA2),
        .OP_PUSHDATA4 => @intFromEnum(Opcode.OP_PUSHDATA4),
    };
}

/// go-sdk `(*Script).PublicKeyHash`.
pub fn publicKeyHash(script: Script) Error!crypto.Hash160 {
    if (script.bytes.len == 0) return error.EmptyScript;
    if (!isP2PKH(script)) return error.NotP2PKH;
    return templates.extractPubKeyHash(script.bytes);
}

test "standard vectors match go-sdk script tests" {
    var b: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&b, "76a91403ececf2d12a7f614aef4c82ecf13c303bd9975d88ac");
    try std.testing.expect(isP2PKH(Script.init(b[0..25])));

    var p2pk: [35]u8 = undefined;
    _ = try std.fmt.hexToBytes(&p2pk, "2102f0d97c290e79bf2a8660c406aa56b6f189ff79f2245cc5aff82808b58131b4d5ac");
    try std.testing.expect(isP2PK(Script.init(&p2pk)));

    var p2sh: [23]u8 = undefined;
    _ = try std.fmt.hexToBytes(&p2sh, "a9149de5aeaff9c48431ba4dd6e8af73d51f38e451cb87");
    try std.testing.expect(isP2SH(Script.init(&p2sh)));

    var ms: [9]u8 = undefined;
    _ = try std.fmt.hexToBytes(&ms, "5201110122013353ae");
    try std.testing.expect(isMultiSigOut(Script.init(&ms)));

    var pkh_expect: [20]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pkh_expect, "04d03f746652cfcb6cb55119ab473a045137d265");
    var pkh_script: [25]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pkh_script, "76a91404d03f746652cfcb6cb55119ab473a045137d26588ac");
    try std.testing.expectEqual(pkh_expect, (try publicKeyHash(Script.init(&pkh_script))).bytes);
}
