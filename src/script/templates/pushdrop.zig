//! go-sdk `transaction/template/pushdrop.Decode` + ts-sdk `PushDrop` — lock-before pattern:
//! `[pubkey push, OP_CHECKSIG, field pushes..., OP_DROP|OP_2DROP...]`.
const std = @import("std");
const opcode = @import("../opcode.zig").Opcode;
const parser = @import("../parser.zig");
const Script = @import("../script.zig").Script;
const secp = @import("../../crypto/secp256k1.zig");

pub const Data = struct {
    locking_pubkey: secp.PublicKey,
    fields: []const []const u8,
};

/// Minimal push encoding matching ts-sdk `createMinimallyEncodedScriptChunk` / go-sdk `CreateMinimallyEncodedScriptChunk`.
pub fn appendMinPush(a: std.mem.Allocator, buf: *std.ArrayListUnmanaged(u8), data: []const u8) !void {
    if (data.len == 0) {
        try buf.append(a, @intFromEnum(opcode.OP_0));
        return;
    }
    if (data.len == 1 and data[0] == 0) {
        try buf.append(a, @intFromEnum(opcode.OP_0));
        return;
    }
    if (data.len == 1 and data[0] > 0 and data[0] <= 16) {
        try buf.append(a, @intFromEnum(opcode.OP_1) + (data[0] - 1));
        return;
    }
    if (data.len == 1 and data[0] == 0x81) {
        try buf.append(a, @intFromEnum(opcode.OP_1NEGATE));
        return;
    }
    if (data.len <= 75) {
        try buf.append(a, @intCast(data.len));
        try buf.appendSlice(a, data);
        return;
    }
    if (data.len <= 255) {
        try buf.append(a, @intFromEnum(opcode.OP_PUSHDATA1));
        try buf.append(a, @intCast(data.len));
        try buf.appendSlice(a, data);
        return;
    }
    if (data.len <= 65535) {
        try buf.append(a, @intFromEnum(opcode.OP_PUSHDATA2));
        var len_le: [2]u8 = undefined;
        std.mem.writeInt(u16, &len_le, @intCast(data.len), .little);
        try buf.appendSlice(a, &len_le);
        try buf.appendSlice(a, data);
        return;
    }
    try buf.append(a, @intFromEnum(opcode.OP_PUSHDATA4));
    var len_le32: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_le32, @intCast(data.len), .little);
    try buf.appendSlice(a, &len_le32);
    try buf.appendSlice(a, data);
}

/// Lock-before PushDrop without wallet signing (fields only). Matches go `PushDrop.Lock` with `includeSignature=false`.
pub fn encodeLockBefore(a: std.mem.Allocator, pubkey_sec1: []const u8, fields: []const []const u8) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(a);
    try appendMinPush(a, &buf, pubkey_sec1);
    try buf.append(a, @intFromEnum(opcode.OP_CHECKSIG));
    for (fields) |f| {
        try appendMinPush(a, &buf, f);
    }
    var n = fields.len;
    while (n > 1) {
        try buf.append(a, @intFromEnum(opcode.OP_2DROP));
        n -= 2;
    }
    if (n != 0) try buf.append(a, @intFromEnum(opcode.OP_DROP));
    return try buf.toOwnedSlice(a);
}

fn fieldFromChunk(a: std.mem.Allocator, ch: @import("../chunk.zig").ScriptChunk) ![]u8 {
    switch (ch) {
        .push_data => |p| return try a.dupe(u8, p.data),
        .opcode => |op| {
            if (op == .OP_DROP or op == .OP_2DROP) return error.InvalidField;
            if (op == .OP_0) return try a.dupe(u8, &[_]u8{0});
            if (op == .OP_1NEGATE) return try a.dupe(u8, &[_]u8{0x81});
            const b = op.toByte();
            if (b >= @intFromEnum(opcode.OP_1) and b <= @intFromEnum(opcode.OP_16)) {
                return try a.dupe(u8, &[_]u8{b - 80});
            }
            return error.InvalidField;
        },
        .op_return_data => return error.InvalidField,
    }
}

fn verifyDropSuffix(chunks: []const @import("../chunk.zig").ScriptChunk, start: usize, field_count: usize) bool {
    var i = start;
    var n = field_count;
    while (n > 1) {
        if (i >= chunks.len) return false;
        if (chunks[i] != .opcode or chunks[i].opcode != .OP_2DROP) return false;
        i += 1;
        n -= 2;
    }
    if (n != 0) {
        if (i >= chunks.len) return false;
        if (chunks[i] != .opcode or chunks[i].opcode != .OP_DROP) return false;
        i += 1;
    }
    return i == chunks.len;
}

fn freeDecodedFields(allocator: std.mem.Allocator, fields: *std.ArrayListUnmanaged([]const u8)) void {
    for (fields.items) |field| allocator.free(field);
    fields.deinit(allocator);
}

pub fn decodeLockBefore(allocator: std.mem.Allocator, script: Script) !?Data {
    const chunks = try parser.parseAlloc(allocator, script);
    defer allocator.free(chunks);
    if (chunks.len < 2) return null;
    if (chunks[0] != .push_data) return null;
    if (chunks[1] != .opcode or chunks[1].opcode != .OP_CHECKSIG) return null;

    const pk = secp.PublicKey.fromSec1(chunks[0].push_data.data) catch return null;

    var fields = std.ArrayListUnmanaged([]const u8){};
    errdefer freeDecodedFields(allocator, &fields);

    var i: usize = 2;
    while (i < chunks.len) {
        if (chunks[i] == .opcode) {
            const op = chunks[i].opcode;
            if (op == .OP_DROP or op == .OP_2DROP) break;
        }
        const field = fieldFromChunk(allocator, chunks[i]) catch {
            freeDecodedFields(allocator, &fields);
            return null;
        };
        try fields.append(allocator, field);
        i += 1;
    }

    if (!verifyDropSuffix(chunks, i, fields.items.len)) {
        freeDecodedFields(allocator, &fields);
        return null;
    }

    const owned = try fields.toOwnedSlice(allocator);
    return .{
        .locking_pubkey = pk,
        .fields = owned,
    };
}

pub fn deinitDecoded(allocator: std.mem.Allocator, d: *Data) void {
    for (d.fields) |f| allocator.free(f);
    allocator.free(d.fields);
    d.fields = &.{};
}

test "pushdrop encode lock-before decode roundtrip" {
    const a = std.testing.allocator;
    const crypto = @import("../../crypto/secp256k1.zig");
    const sk = [_]u8{0x01} ++ [_]u8{0} ** 31;
    const pk = try (try crypto.PrivateKey.fromBytes(sk)).publicKey();

    const fields: []const []const u8 = &.{ &[_]u8{3}, &[_]u8{ 2, 1 } };
    const script_bytes = try encodeLockBefore(a, &pk.bytes, fields);
    defer a.free(script_bytes);

    var d = (try decodeLockBefore(a, .{ .bytes = script_bytes })) orelse return error.DecodeFailed;
    defer deinitDecoded(a, &d);

    try std.testing.expectEqualSlices(u8, fields[0], d.fields[0]);
    try std.testing.expectEqualSlices(u8, fields[1], d.fields[1]);
}

test "pushdrop small-int field roundtrip" {
    const a = std.testing.allocator;
    const crypto = @import("../../crypto/secp256k1.zig");
    const sk = [_]u8{0x01} ++ [_]u8{0} ** 31;
    const pk = try (try crypto.PrivateKey.fromBytes(sk)).publicKey();
    const fields: []const []const u8 = &.{&[_]u8{1}};
    const script_bytes = try encodeLockBefore(a, &pk.bytes, fields);
    defer a.free(script_bytes);
    var d = (try decodeLockBefore(a, .{ .bytes = script_bytes })) orelse return error.DecodeFailed;
    defer deinitDecoded(a, &d);
    try std.testing.expectEqualSlices(u8, &[_]u8{1}, d.fields[0]);
}

test "pushdrop rejects bad drop suffix and trailing junk" {
    const allocator = std.testing.allocator;
    const crypto = @import("../../crypto/secp256k1.zig");
    const sk = [_]u8{0x01} ++ [_]u8{0} ** 31;
    const pk = try (try crypto.PrivateKey.fromBytes(sk)).publicKey();

    var wrong = try encodeLockBefore(allocator, &pk.bytes, &[_][]const u8{ "one", "two", "three" });
    defer allocator.free(wrong);
    wrong[wrong.len - 1] = @intFromEnum(opcode.OP_2DROP);
    try std.testing.expectEqual(@as(?Data, null), try decodeLockBefore(allocator, Script.init(wrong)));

    var junk = try encodeLockBefore(allocator, &pk.bytes, &[_][]const u8{"field"});
    junk = try allocator.realloc(junk, junk.len + 1);
    defer allocator.free(junk);
    junk[junk.len - 1] = @intFromEnum(opcode.OP_1);
    try std.testing.expectEqual(@as(?Data, null), try decodeLockBefore(allocator, Script.init(junk)));
}
