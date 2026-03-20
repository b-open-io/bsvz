//! Bitcoin script ASM (go-sdk `script.NewFromASM` / `Script.ToASM`).
const std = @import("std");
const Opcode = @import("opcode.zig").Opcode;
const Script = @import("script.zig").Script;
const builder = @import("builder.zig");

pub const Error = error{ InvalidOpcode, InvalidHex, InvalidPushData, OutOfMemory } || std.mem.Allocator.Error || builder.Error;

/// Go `OpCodeValues[byte]` naming: OP_FALSE / OP_TRUE for 0x00 / 0x51.
fn opcodeToGoAsmName(byte: u8) []const u8 {
    return switch (byte) {
        0x00 => "OP_FALSE",
        0x51 => "OP_TRUE",
        else => {
            const op = Opcode.fromByte(byte);
            return op.name();
        },
    };
}

fn hexEncodeLowerAlloc(allocator: std.mem.Allocator, data: []const u8) Error![]const u8 {
    const hex = "0123456789abcdef";
    const out = try allocator.alloc(u8, data.len * 2);
    for (data, 0..) |b, i| {
        out[i * 2] = hex[b >> 4];
        out[i * 2 + 1] = hex[b & 0xf];
    }
    return out;
}

/// Go `ScriptChunk.String` / `ToASM` token for one op or push.
fn chunkToAsmPart(allocator: std.mem.Allocator, op_byte: u8, data: []const u8) Error![]const u8 {
    if (op_byte > 0 and op_byte <= @intFromEnum(Opcode.OP_PUSHDATA4)) {
        if (data.len == 0 and op_byte >= 0x01 and op_byte <= 0x4b) return error.InvalidPushData;
        return hexEncodeLowerAlloc(allocator, data);
    }
    return allocator.dupe(u8, opcodeToGoAsmName(op_byte));
}

/// Walk script like go-sdk `ReadOp` (script_chunk.go).
fn readOp(script: []const u8, pos: *usize) ?struct { op: u8, data: []const u8 } {
    if (pos.* >= script.len) return null;
    switch (script[pos.*]) {
        @intFromEnum(Opcode.OP_PUSHDATA1) => {
            if (script.len < pos.* + 2) return null;
            const l: usize = script[pos.* + 1];
            pos.* += 2;
            if (script.len < pos.* + l) return null;
            const data = script[pos.*..][0..l];
            pos.* += l;
            return .{ .op = @intFromEnum(Opcode.OP_PUSHDATA1), .data = data };
        },
        @intFromEnum(Opcode.OP_PUSHDATA2) => {
            if (script.len < pos.* + 3) return null;
            const l = std.mem.readInt(u16, script[pos.* + 1 ..][0..2], .little);
            pos.* += 3;
            if (script.len < pos.* + l) return null;
            const data = script[pos.*..][0..l];
            pos.* += l;
            return .{ .op = @intFromEnum(Opcode.OP_PUSHDATA2), .data = data };
        },
        @intFromEnum(Opcode.OP_PUSHDATA4) => {
            if (script.len < pos.* + 5) return null;
            const l32 = std.mem.readInt(u32, script[pos.* + 1 ..][0..4], .little);
            const l: usize = std.math.cast(usize, l32) orelse return null;
            pos.* += 5;
            if (script.len < pos.* + l) return null;
            const data = script[pos.*..][0..l];
            pos.* += l;
            return .{ .op = @intFromEnum(Opcode.OP_PUSHDATA4), .data = data };
        },
        else => {
            if (script[pos.*] >= 0x01 and script[pos.*] < @intFromEnum(Opcode.OP_PUSHDATA1)) {
                const l: usize = script[pos.*];
                pos.* += 1;
                if (script.len < pos.* + l) return null;
                const data = script[pos.*..][0..l];
                pos.* += l;
                return .{ .op = @intCast(l), .data = data };
            }
            const b = script[pos.*];
            pos.* += 1;
            return .{ .op = b, .data = &.{} };
        },
    }
}

/// go-sdk `(*Script).ToASM`.
pub fn toAsmAlloc(allocator: std.mem.Allocator, script: Script) Error![]const u8 {
    if (script.bytes.len == 0) return allocator.alloc(u8, 0);

    var parts: std.ArrayListUnmanaged([]const u8) = .empty;
    defer {
        for (parts.items) |p| allocator.free(p);
        parts.deinit(allocator);
    }

    var pos: usize = 0;
    while (pos < script.bytes.len) {
        const before = pos;
        const chunk = readOp(script.bytes, &pos) orelse return error.InvalidPushData;
        if (pos == before) return error.InvalidPushData;
        const part = try chunkToAsmPart(allocator, chunk.op, chunk.data);
        try parts.append(allocator, part);
    }

    return std.mem.join(allocator, " ", parts.items);
}

fn hexDigit(c: u8) ?u4 {
    return switch (c) {
        '0'...'9' => @truncate(c - '0'),
        'a'...'f' => @truncate(10 + c - 'a'),
        'A'...'F' => @truncate(10 + c - 'A'),
        else => null,
    };
}

fn isHexToken(tok: []const u8) bool {
    if (tok.len == 0 or tok.len % 2 != 0) return false;
    for (tok) |c| {
        if (hexDigit(c) == null) return false;
    }
    return true;
}

fn tokenToOpcodeByte(tok: []const u8) ?u8 {
    if (std.mem.eql(u8, tok, "OP_FALSE")) return 0x00;
    if (std.mem.eql(u8, tok, "OP_TRUE")) return 0x51;
    var i: usize = 0;
    while (i < 256) : (i += 1) {
        const op = Opcode.fromByte(@intCast(i));
        if (std.mem.eql(u8, tok, op.name())) return op.toByte();
    }
    return null;
}

/// go-sdk `NewFromASM`. Opcode names plus hex pushdata (`AppendPushDataHex`).
pub fn fromAsmAlloc(allocator: std.mem.Allocator, str: []const u8) Error![]u8 {
    if (str.len == 0) return allocator.alloc(u8, 0);

    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);

    var it = std.mem.tokenizeScalar(u8, str, ' ');
    while (it.next()) |tok| {
        if (tok.len == 0) continue;
        if (tokenToOpcodeByte(tok)) |b| {
            try out.append(allocator, b);
            continue;
        }
        if (isHexToken(tok)) {
            const n = tok.len / 2;
            const raw = try allocator.alloc(u8, n);
            defer allocator.free(raw);
            _ = std.fmt.hexToBytes(raw, tok) catch return error.InvalidHex;
            try builder.appendPushData(&out, allocator, raw);
            continue;
        }
        return error.InvalidOpcode;
    }

    return try out.toOwnedSlice(allocator);
}

test "toAsm and fromAsm match go-sdk p2pkh" {
    const allocator = std.testing.allocator;
    const hex_in = "76a914e2a623699e81b291c0327f408fea765d534baa2a88ac";
    var raw: [25]u8 = undefined;
    _ = try std.fmt.hexToBytes(&raw, hex_in);
    const asm_str = try toAsmAlloc(allocator, Script.init(&raw));
    defer allocator.free(asm_str);
    try std.testing.expectEqualStrings(
        "OP_DUP OP_HASH160 e2a623699e81b291c0327f408fea765d534baa2a OP_EQUALVERIFY OP_CHECKSIG",
        asm_str,
    );
    const round = try fromAsmAlloc(allocator, asm_str);
    defer allocator.free(round);
    try std.testing.expectEqualSlices(u8, &raw, round);
}
