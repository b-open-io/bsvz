const std = @import("std");
const errors = @import("errors.zig");
const chunk = @import("chunk.zig");
const Opcode = @import("opcode.zig").Opcode;
const Script = @import("script.zig").Script;

pub const Error = errors.ScriptError || error{OutOfMemory};

fn updateConditionalDepth(op: Opcode, depth: *usize) bool {
    switch (op) {
        .OP_IF, .OP_NOTIF => depth.* += 1,
        .OP_ENDIF => {
            if (depth.* > 0) depth.* -= 1;
        },
        .OP_RETURN => return depth.* == 0,
        else => {},
    }
    return false;
}

pub fn parseAlloc(allocator: std.mem.Allocator, script: Script) Error![]chunk.ScriptChunk {
    var chunks: std.ArrayListUnmanaged(chunk.ScriptChunk) = .empty;
    errdefer chunks.deinit(allocator);

    var cursor: usize = 0;
    var conditional_depth: usize = 0;
    while (cursor < script.bytes.len) {
        const opcode_byte = script.bytes[cursor];
        cursor += 1;
        const op = Opcode.fromByte(opcode_byte);

        if (updateConditionalDepth(op, &conditional_depth)) {
            try chunks.append(allocator, .{
                .op_return_data = script.bytes[cursor..],
            });
            return try chunks.toOwnedSlice(allocator);
        }

        if (opcode_byte >= 0x01 and opcode_byte <= 0x4b) {
            const len: usize = opcode_byte;
            if (script.bytes.len < cursor + len) return error.InvalidPushData;
            try chunks.append(allocator, .{
                .push_data = .{
                    .data = script.bytes[cursor .. cursor + len],
                    .encoding = .direct,
                },
            });
            cursor += len;
            continue;
        }

        if (opcode_byte == @intFromEnum(Opcode.OP_PUSHDATA1)) {
            if (cursor >= script.bytes.len) return error.InvalidPushData;
            const len = script.bytes[cursor];
            cursor += 1;
            if (script.bytes.len < cursor + len) return error.InvalidPushData;
            try chunks.append(allocator, .{
                .push_data = .{
                    .data = script.bytes[cursor .. cursor + len],
                    .encoding = .OP_PUSHDATA1,
                },
            });
            cursor += len;
            continue;
        }

        if (opcode_byte == @intFromEnum(Opcode.OP_PUSHDATA2)) {
            if (script.bytes.len < cursor + 2) return error.InvalidPushData;
            const len = std.mem.readInt(u16, script.bytes[cursor..][0..2], .little);
            cursor += 2;
            if (script.bytes.len < cursor + len) return error.InvalidPushData;
            try chunks.append(allocator, .{
                .push_data = .{
                    .data = script.bytes[cursor .. cursor + len],
                    .encoding = .OP_PUSHDATA2,
                },
            });
            cursor += len;
            continue;
        }

        if (opcode_byte == @intFromEnum(Opcode.OP_PUSHDATA4)) {
            if (script.bytes.len < cursor + 4) return error.InvalidPushData;
            const len32 = std.mem.readInt(u32, script.bytes[cursor..][0..4], .little);
            const len = std.math.cast(usize, len32) orelse return error.Overflow;
            cursor += 4;
            if (script.bytes.len < cursor + len) return error.InvalidPushData;
            try chunks.append(allocator, .{
                .push_data = .{
                    .data = script.bytes[cursor .. cursor + len],
                    .encoding = .OP_PUSHDATA4,
                },
            });
            cursor += len;
            continue;
        }

        try chunks.append(allocator, .{ .opcode = op });
    }

    return try chunks.toOwnedSlice(allocator);
}

pub fn serializedLen(chunks: []const chunk.ScriptChunk) usize {
    var len: usize = 0;
    for (chunks) |item| {
        switch (item) {
            .opcode => len += 1,
            .push_data => |push| {
                len += switch (push.encoding) {
                    .direct => 1 + push.data.len,
                    .OP_PUSHDATA1 => 2 + push.data.len,
                    .OP_PUSHDATA2 => 3 + push.data.len,
                    .OP_PUSHDATA4 => 5 + push.data.len,
                };
            },
            .op_return_data => |data| len += 1 + data.len,
        }
    }
    return len;
}

pub fn serializeAlloc(allocator: std.mem.Allocator, chunks: []const chunk.ScriptChunk) Error![]u8 {
    var out = try allocator.alloc(u8, serializedLen(chunks));
    errdefer allocator.free(out);

    var cursor: usize = 0;
    for (chunks) |item| {
        switch (item) {
            .opcode => |opcode| {
                out[cursor] = opcode.toByte();
                cursor += 1;
            },
            .push_data => |push| {
                out[cursor] = try push.encoding.opcodeByte(push.data.len);
                cursor += 1;

                switch (push.encoding) {
                    .direct => {},
                    .OP_PUSHDATA1 => {
                        if (push.data.len > std.math.maxInt(u8)) return error.InvalidPushData;
                        out[cursor] = @intCast(push.data.len);
                        cursor += 1;
                    },
                    .OP_PUSHDATA2 => {
                        if (push.data.len > std.math.maxInt(u16)) return error.InvalidPushData;
                        std.mem.writeInt(u16, out[cursor..][0..2], @intCast(push.data.len), .little);
                        cursor += 2;
                    },
                    .OP_PUSHDATA4 => {
                        if (push.data.len > std.math.maxInt(u32)) return error.InvalidPushData;
                        std.mem.writeInt(u32, out[cursor..][0..4], @intCast(push.data.len), .little);
                        cursor += 4;
                    },
                }

                @memcpy(out[cursor..][0..push.data.len], push.data);
                cursor += push.data.len;
            },
            .op_return_data => |data| {
                out[cursor] = @intFromEnum(Opcode.OP_RETURN);
                cursor += 1;
                @memcpy(out[cursor..][0..data.len], data);
                cursor += data.len;
            },
        }
    }

    std.debug.assert(cursor == out.len);
    return out;
}

pub fn isPushOnly(script: Script) Error!bool {
    var cursor: usize = 0;
    while (cursor < script.bytes.len) {
        const opcode_byte = script.bytes[cursor];
        cursor += 1;

        if (opcode_byte >= 0x01 and opcode_byte <= 0x4b) {
            if (script.bytes.len < cursor + opcode_byte) return error.InvalidPushData;
            cursor += opcode_byte;
            continue;
        }

        switch (opcode_byte) {
            0x00, 0x4c, 0x4d, 0x4e, 0x4f, 0x51...0x60 => {},
            else => return false,
        }

        if (opcode_byte == @intFromEnum(Opcode.OP_PUSHDATA1)) {
            if (cursor >= script.bytes.len) return error.InvalidPushData;
            const len = script.bytes[cursor];
            cursor += 1;
            if (script.bytes.len < cursor + len) return error.InvalidPushData;
            cursor += len;
            continue;
        }

        if (opcode_byte == @intFromEnum(Opcode.OP_PUSHDATA2)) {
            if (script.bytes.len < cursor + 2) return error.InvalidPushData;
            const len = std.mem.readInt(u16, script.bytes[cursor..][0..2], .little);
            cursor += 2;
            if (script.bytes.len < cursor + len) return error.InvalidPushData;
            cursor += len;
            continue;
        }

        if (opcode_byte == @intFromEnum(Opcode.OP_PUSHDATA4)) {
            if (script.bytes.len < cursor + 4) return error.InvalidPushData;
            const len32 = std.mem.readInt(u32, script.bytes[cursor..][0..4], .little);
            const len = std.math.cast(usize, len32) orelse return error.Overflow;
            cursor += 4;
            if (script.bytes.len < cursor + len) return error.InvalidPushData;
            cursor += len;
            continue;
        }
    }

    return true;
}

pub fn hasCodeSeparator(script: Script) Error!bool {
    var cursor: usize = 0;
    while (cursor < script.bytes.len) {
        const opcode_byte = script.bytes[cursor];
        cursor += 1;

        if (opcode_byte >= 0x01 and opcode_byte <= 0x4b) {
            if (script.bytes.len < cursor + opcode_byte) return error.InvalidPushData;
            cursor += opcode_byte;
            continue;
        }

        if (opcode_byte == @intFromEnum(Opcode.OP_PUSHDATA1)) {
            if (cursor >= script.bytes.len) return error.InvalidPushData;
            const len = script.bytes[cursor];
            cursor += 1;
            if (script.bytes.len < cursor + len) return error.InvalidPushData;
            cursor += len;
            continue;
        }

        if (opcode_byte == @intFromEnum(Opcode.OP_PUSHDATA2)) {
            if (script.bytes.len < cursor + 2) return error.InvalidPushData;
            const len = std.mem.readInt(u16, script.bytes[cursor..][0..2], .little);
            cursor += 2;
            if (script.bytes.len < cursor + len) return error.InvalidPushData;
            cursor += len;
            continue;
        }

        if (opcode_byte == @intFromEnum(Opcode.OP_PUSHDATA4)) {
            if (script.bytes.len < cursor + 4) return error.InvalidPushData;
            const len32 = std.mem.readInt(u32, script.bytes[cursor..][0..4], .little);
            const len = std.math.cast(usize, len32) orelse return error.Overflow;
            cursor += 4;
            if (script.bytes.len < cursor + len) return error.InvalidPushData;
            cursor += len;
            continue;
        }

        if (opcode_byte == @intFromEnum(Opcode.OP_CODESEPARATOR)) return true;
    }

    return false;
}

test "parser roundtrips mixed push encodings" {
    const allocator = std.testing.allocator;

    const script = Script.init(&[_]u8{
        0x02, 0xaa, 0xbb,
        0x4c, 0x01, 0xcc,
        0x4d, 0x02, 0x00,
        0xdd, 0xee, 0x76,
    });

    const chunks = try parseAlloc(allocator, script);
    defer allocator.free(chunks);

    try std.testing.expectEqual(@as(usize, 4), chunks.len);
    try std.testing.expect(chunks[0] == .push_data);
    try std.testing.expect(chunks[1] == .push_data);
    try std.testing.expect(chunks[2] == .push_data);
    try std.testing.expect(chunks[3] == .opcode);
    try std.testing.expectEqual(Opcode.OP_DUP, chunks[3].opcode);

    const serialized = try serializeAlloc(allocator, chunks);
    defer allocator.free(serialized);
    try std.testing.expectEqualSlices(u8, script.bytes, serialized);
}

test "parser treats top-level op_return tail as raw data like go-sdk" {
    const allocator = std.testing.allocator;
    const script = Script.init(&[_]u8{
        @intFromEnum(Opcode.OP_RETURN),
        @intFromEnum(Opcode.OP_PUSHDATA1),
        0x01,
    });

    const chunks = try parseAlloc(allocator, script);
    defer allocator.free(chunks);

    try std.testing.expectEqual(@as(usize, 1), chunks.len);
    try std.testing.expect(chunks[0] == .op_return_data);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        @intFromEnum(Opcode.OP_PUSHDATA1),
        0x01,
    }, chunks[0].op_return_data);

    const serialized = try serializeAlloc(allocator, chunks);
    defer allocator.free(serialized);
    try std.testing.expectEqualSlices(u8, script.bytes, serialized);
}

test "parser still validates malformed pushdata before op_return" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.InvalidPushData, parseAlloc(allocator, Script.init(&[_]u8{
        @intFromEnum(Opcode.OP_PUSHDATA1),
        0x02,
        0xaa,
    })));
}

test "isPushOnly rejects non-push opcodes and malformed pushes" {
    try std.testing.expect(try isPushOnly(Script.init(&[_]u8{ 0x51, 0x01, 0xaa })));
    try std.testing.expect(!(try isPushOnly(Script.init(&[_]u8{@intFromEnum(Opcode.OP_DUP)}))));
    try std.testing.expectError(error.InvalidPushData, isPushOnly(Script.init(&[_]u8{ 0x02, 0xaa })));
}

test "hasCodeSeparator detects separators and malformed pushdata" {
    try std.testing.expect(try hasCodeSeparator(Script.init(&[_]u8{
        @intFromEnum(Opcode.OP_CODESEPARATOR),
        @intFromEnum(Opcode.OP_DUP),
    })));
    try std.testing.expect(!(try hasCodeSeparator(Script.init(&[_]u8{@intFromEnum(Opcode.OP_DUP)}))));
    try std.testing.expectError(error.InvalidPushData, hasCodeSeparator(Script.init(&[_]u8{ 0x02, 0xaa })));
}

test "parser rejects malformed pushdata length prefixes" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.InvalidPushData, parseAlloc(allocator, Script.init(&[_]u8{
        @intFromEnum(Opcode.OP_PUSHDATA1),
    })));
    try std.testing.expectError(error.InvalidPushData, parseAlloc(allocator, Script.init(&[_]u8{
        @intFromEnum(Opcode.OP_PUSHDATA2),
        0x01,
    })));
    try std.testing.expectError(error.InvalidPushData, parseAlloc(allocator, Script.init(&[_]u8{
        @intFromEnum(Opcode.OP_PUSHDATA4),
        0x01, 0x00, 0x00,
    })));
}

test "parser rejects malformed pushdata payload truncation" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.InvalidPushData, parseAlloc(allocator, Script.init(&[_]u8{
        @intFromEnum(Opcode.OP_PUSHDATA1),
        0x02,
        0xaa,
    })));
    try std.testing.expectError(error.InvalidPushData, parseAlloc(allocator, Script.init(&[_]u8{
        @intFromEnum(Opcode.OP_PUSHDATA2),
        0x02, 0x00,
        0xaa,
    })));
    try std.testing.expectError(error.InvalidPushData, parseAlloc(allocator, Script.init(&[_]u8{
        @intFromEnum(Opcode.OP_PUSHDATA4),
        0x02, 0x00, 0x00, 0x00,
        0xaa,
    })));
}
