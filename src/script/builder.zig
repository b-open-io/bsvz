//! Mutable script buffer helpers (go-sdk `AppendPushData` / `AppendOpcodes`).
const std = @import("std");
const Opcode = @import("opcode.zig").Opcode;

pub const Error = error{ InvalidOpcodeType, DataTooBig } || std.mem.Allocator.Error;

/// go-sdk `PushDataPrefix` + payload.
pub fn appendPushData(out: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, data: []const u8) Error!void {
    const l: usize = data.len;
    if (l <= 75) {
        try out.append(allocator, @intCast(l));
    } else if (l <= 0xff) {
        try out.append(allocator, @intFromEnum(Opcode.OP_PUSHDATA1));
        try out.append(allocator, @intCast(l));
    } else if (l <= 0xffff) {
        try out.append(allocator, @intFromEnum(Opcode.OP_PUSHDATA2));
        var buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &buf, @intCast(l), .little);
        try out.appendSlice(allocator, &buf);
    } else {
        if (l > std.math.maxInt(u32)) return error.DataTooBig;
        try out.append(allocator, @intFromEnum(Opcode.OP_PUSHDATA4));
        var buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &buf, @intCast(l), .little);
        try out.appendSlice(allocator, &buf);
    }
    try out.appendSlice(allocator, data);
}

/// go-sdk `AppendOpcodes` — rejects raw pushdata opcode bytes.
pub fn appendOpcodes(out: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, oo: []const u8) Error!void {
    for (oo) |o| {
        if (o >= 0x01 and o <= @intFromEnum(Opcode.OP_PUSHDATA4)) return error.InvalidOpcodeType;
        try out.append(allocator, o);
    }
}

test "appendOpcodes rejects pushdata range" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    try std.testing.expectError(error.InvalidOpcodeType, appendOpcodes(&buf, std.testing.allocator, &.{0x4c}));
}
