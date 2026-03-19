const std = @import("std");
const bsvz = @import("bsvz");

const Opcode = bsvz.script.opcode.Opcode;

pub fn appendPushData(bytes: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, data: []const u8) !void {
    if (data.len == 0) {
        try bytes.append(allocator, 0x00);
        return;
    }
    if (data.len <= 75) {
        try bytes.append(allocator, @intCast(data.len));
    } else if (data.len <= std.math.maxInt(u8)) {
        try bytes.appendSlice(allocator, &.{ @intFromEnum(Opcode.OP_PUSHDATA1), @intCast(data.len) });
    } else if (data.len <= std.math.maxInt(u16)) {
        try bytes.append(allocator, @intFromEnum(Opcode.OP_PUSHDATA2));
        var len_buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &len_buf, @intCast(data.len), .little);
        try bytes.appendSlice(allocator, &len_buf);
    } else {
        try bytes.append(allocator, @intFromEnum(Opcode.OP_PUSHDATA4));
        var len_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &len_buf, @intCast(data.len), .little);
        try bytes.appendSlice(allocator, &len_buf);
    }
    try bytes.appendSlice(allocator, data);
}

pub fn appendIntegerToken(bytes: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, value: i64) !void {
    if (value == 0) {
        try bytes.append(allocator, @intFromEnum(Opcode.OP_0));
        return;
    }
    if (value == -1) {
        try bytes.append(allocator, @intFromEnum(Opcode.OP_1NEGATE));
        return;
    }
    if (value >= 1 and value <= 16) {
        try bytes.append(allocator, @intFromEnum(Opcode.OP_1) + @as(u8, @intCast(value - 1)));
        return;
    }

    const encoded = try bsvz.script.ScriptNum.encode(allocator, value);
    try appendPushData(bytes, allocator, encoded);
}

pub fn appendOpcodeToken(bytes: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, token: []const u8) !void {
    if (std.mem.eql(u8, token, "2MUL")) {
        try bytes.append(allocator, 0x8d);
        return;
    }
    if (std.mem.eql(u8, token, "2DIV")) {
        try bytes.append(allocator, 0x8e);
        return;
    }

    var name_buf: [64]u8 = undefined;
    const full_name = try std.fmt.bufPrint(&name_buf, "OP_{s}", .{token});
    const op = std.meta.stringToEnum(Opcode, full_name) orelse return error.UnknownOpcode;
    try bytes.append(allocator, @intFromEnum(op));
}

pub fn assembleScript(allocator: std.mem.Allocator, script_asm: []const u8) ![]u8 {
    var bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer bytes.deinit(allocator);

    var index: usize = 0;
    while (index < script_asm.len) {
        while (index < script_asm.len and std.ascii.isWhitespace(script_asm[index])) : (index += 1) {}
        if (index >= script_asm.len) break;

        if (script_asm[index] == '\'') {
            const end = std.mem.indexOfScalarPos(u8, script_asm, index + 1, '\'') orelse return error.InvalidEncoding;
            try appendPushData(&bytes, allocator, script_asm[index + 1 .. end]);
            index = end + 1;
            continue;
        }

        const start = index;
        while (index < script_asm.len and !std.ascii.isWhitespace(script_asm[index])) : (index += 1) {}
        const token = script_asm[start..index];
        if (token.len == 0) continue;

        if (std.mem.startsWith(u8, token, "0x") or std.mem.startsWith(u8, token, "0X")) {
            const raw = try bsvz.primitives.hex.decode(allocator, token[2..]);
            try bytes.appendSlice(allocator, raw);
            continue;
        }

        const maybe_int = std.fmt.parseInt(i64, token, 10) catch null;
        if (maybe_int) |value| {
            try appendIntegerToken(&bytes, allocator, value);
            continue;
        }

        try appendOpcodeToken(&bytes, allocator, token);
    }

    return bytes.toOwnedSlice(allocator);
}
