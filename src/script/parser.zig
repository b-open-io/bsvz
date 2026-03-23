const std = @import("std");
const errors = @import("errors.zig");
const chunk = @import("chunk.zig");
const Opcode = @import("opcode.zig").Opcode;
const Script = @import("script.zig").Script;

pub const Error = errors.ScriptError || error{OutOfMemory};

pub const ScriptIterator = struct {
    bytes: []const u8,
    cursor: usize = 0,
    conditional_depth: usize = 0,
    done: bool = false,

    pub fn init(script: Script) ScriptIterator {
        return .{ .bytes = script.bytes };
    }

    pub fn initBytes(bytes: []const u8) ScriptIterator {
        return .{ .bytes = bytes };
    }

    pub fn next(self: *ScriptIterator) errors.ScriptError!?chunk.ScriptChunk {
        if (self.done or self.cursor >= self.bytes.len) return null;

        const opcode_byte = self.bytes[self.cursor];
        self.cursor += 1;
        const op = Opcode.fromByte(opcode_byte);

        switch (op) {
            .OP_IF, .OP_NOTIF => self.conditional_depth += 1,
            .OP_ENDIF => {
                if (self.conditional_depth > 0) self.conditional_depth -= 1;
            },
            .OP_RETURN => {
                if (self.conditional_depth == 0) {
                    self.done = true;
                    return .{ .op_return_data = self.bytes[self.cursor..] };
                }
            },
            else => {},
        }

        if (opcode_byte >= 0x01 and opcode_byte <= 0x4b) {
            const len: usize = opcode_byte;
            if (self.bytes.len < self.cursor + len) return error.InvalidPushData;
            const data = self.bytes[self.cursor .. self.cursor + len];
            self.cursor += len;
            return .{ .push_data = .{ .data = data, .encoding = .direct } };
        }

        if (opcode_byte == @intFromEnum(Opcode.OP_PUSHDATA1)) {
            if (self.cursor >= self.bytes.len) return error.InvalidPushData;
            const len = self.bytes[self.cursor];
            self.cursor += 1;
            if (self.bytes.len < self.cursor + len) return error.InvalidPushData;
            const data = self.bytes[self.cursor .. self.cursor + len];
            self.cursor += len;
            return .{ .push_data = .{ .data = data, .encoding = .OP_PUSHDATA1 } };
        }

        if (opcode_byte == @intFromEnum(Opcode.OP_PUSHDATA2)) {
            if (self.bytes.len < self.cursor + 2) return error.InvalidPushData;
            const len = std.mem.readInt(u16, self.bytes[self.cursor..][0..2], .little);
            self.cursor += 2;
            if (self.bytes.len < self.cursor + len) return error.InvalidPushData;
            const data = self.bytes[self.cursor .. self.cursor + len];
            self.cursor += len;
            return .{ .push_data = .{ .data = data, .encoding = .OP_PUSHDATA2 } };
        }

        if (opcode_byte == @intFromEnum(Opcode.OP_PUSHDATA4)) {
            if (self.bytes.len < self.cursor + 4) return error.InvalidPushData;
            const len32 = std.mem.readInt(u32, self.bytes[self.cursor..][0..4], .little);
            const len = std.math.cast(usize, len32) orelse return error.Overflow;
            self.cursor += 4;
            if (self.bytes.len < self.cursor + len) return error.InvalidPushData;
            const data = self.bytes[self.cursor .. self.cursor + len];
            self.cursor += len;
            return .{ .push_data = .{ .data = data, .encoding = .OP_PUSHDATA4 } };
        }

        return .{ .opcode = op };
    }

    /// Current byte position in the script.
    pub fn pos(self: ScriptIterator) usize {
        return self.cursor;
    }
};

fn countChunks(script: Script) Error!usize {
    var count: usize = 0;
    var iter = ScriptIterator.init(script);
    while (try iter.next()) |_| {
        count += 1;
    }
    return count;
}

pub fn validate(script: Script) Error!void {
    _ = try countChunks(script);
}

pub fn parseAlloc(allocator: std.mem.Allocator, script: Script) Error![]chunk.ScriptChunk {
    var chunks: std.ArrayListUnmanaged(chunk.ScriptChunk) = .empty;
    errdefer chunks.deinit(allocator);
    try chunks.ensureTotalCapacityPrecise(allocator, try countChunks(script));

    var iter = ScriptIterator.init(script);
    while (try iter.next()) |c| {
        try chunks.append(allocator, c);
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
    var iter = ScriptIterator.init(script);
    while (try iter.next()) |c| {
        switch (c) {
            .push_data => {},
            .op_return_data => return false,
            .opcode => |op| {
                switch (op) {
                    .OP_0, .OP_1NEGATE, .OP_RESERVED,
                    .OP_1, .OP_2, .OP_3, .OP_4, .OP_5, .OP_6, .OP_7, .OP_8,
                    .OP_9, .OP_10, .OP_11, .OP_12, .OP_13, .OP_14, .OP_15, .OP_16,
                    => {},
                    else => return false,
                }
            },
        }
    }
    return true;
}

pub fn hasCodeSeparator(script: Script) Error!bool {
    var iter = ScriptIterator.init(script);
    while (try iter.next()) |c| {
        switch (c) {
            .opcode => |op| if (op == .OP_CODESEPARATOR) return true,
            else => {},
        }
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

test "parser preserves malformed top-level op_return tail bytes verbatim" {
    const allocator = std.testing.allocator;
    const script = Script.init(&[_]u8{
        @intFromEnum(Opcode.OP_RETURN),
        @intFromEnum(Opcode.OP_PUSHDATA4),
        0x01,
        0x00,
    });

    const chunks = try parseAlloc(allocator, script);
    defer allocator.free(chunks);

    try std.testing.expectEqual(@as(usize, 1), chunks.len);
    try std.testing.expect(chunks[0] == .op_return_data);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        @intFromEnum(Opcode.OP_PUSHDATA4),
        0x01,
        0x00,
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

test "parser does not short-circuit nested op_return before malformed pushdata" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.InvalidPushData, parseAlloc(allocator, Script.init(&[_]u8{
        @intFromEnum(Opcode.OP_1),
        @intFromEnum(Opcode.OP_IF),
        @intFromEnum(Opcode.OP_RETURN),
        @intFromEnum(Opcode.OP_PUSHDATA1),
        0x03,
        0xaa,
        @intFromEnum(Opcode.OP_ENDIF),
    })));
}

test "isPushOnly rejects non-push opcodes and malformed pushes" {
    try std.testing.expect(try isPushOnly(Script.init(&[_]u8{ 0x51, 0x01, 0xaa })));
    try std.testing.expect(!(try isPushOnly(Script.init(&[_]u8{@intFromEnum(Opcode.OP_DUP)}))));
    try std.testing.expectError(error.InvalidPushData, isPushOnly(Script.init(&[_]u8{ 0x02, 0xaa })));
}

test "isPushOnly treats top-level op_return as non-push without parsing the tail" {
    try std.testing.expect(!(try isPushOnly(Script.init(&[_]u8{
        @intFromEnum(Opcode.OP_RETURN),
        @intFromEnum(Opcode.OP_DUP),
        @intFromEnum(Opcode.OP_CODESEPARATOR),
        @intFromEnum(Opcode.OP_PUSHDATA1),
    }))));
}

test "isPushOnly ignores malformed pushdata tails after top-level op_return" {
    try std.testing.expect(!(try isPushOnly(Script.init(&[_]u8{
        @intFromEnum(Opcode.OP_RETURN),
        @intFromEnum(Opcode.OP_PUSHDATA2),
        0x01,
    }))));
}

test "hasCodeSeparator detects separators and malformed pushdata" {
    try std.testing.expect(try hasCodeSeparator(Script.init(&[_]u8{
        @intFromEnum(Opcode.OP_CODESEPARATOR),
        @intFromEnum(Opcode.OP_DUP),
    })));
    try std.testing.expect(!(try hasCodeSeparator(Script.init(&[_]u8{@intFromEnum(Opcode.OP_DUP)}))));
    try std.testing.expectError(error.InvalidPushData, hasCodeSeparator(Script.init(&[_]u8{ 0x02, 0xaa })));
}

test "hasCodeSeparator ignores trailing bytes after top-level op_return" {
    try std.testing.expect(!(try hasCodeSeparator(Script.init(&[_]u8{
        @intFromEnum(Opcode.OP_RETURN),
        @intFromEnum(Opcode.OP_CODESEPARATOR),
        @intFromEnum(Opcode.OP_DUP),
        @intFromEnum(Opcode.OP_PUSHDATA1),
    }))));
}

test "hasCodeSeparator ignores malformed pushdata tails after top-level op_return" {
    try std.testing.expect(!(try hasCodeSeparator(Script.init(&[_]u8{
        @intFromEnum(Opcode.OP_RETURN),
        @intFromEnum(Opcode.OP_PUSHDATA4),
        0x01,
        0x00,
        0x00,
    }))));
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

test "parser roundtrips pushdata boundary encodings" {
    const allocator = std.testing.allocator;

    const direct_75 = &[_]u8{0x11} ** 75;
    const pushdata1_76 = &[_]u8{0x22} ** 76;
    const pushdata1_255 = &[_]u8{0x33} ** 255;
    const pushdata2_256 = &[_]u8{0x44} ** 256;

    const script = Script.init(
        &[_]u8{75} ++ direct_75 ++
        [_]u8{ @intFromEnum(Opcode.OP_PUSHDATA1), 76 } ++ pushdata1_76 ++
        [_]u8{ @intFromEnum(Opcode.OP_PUSHDATA1), 255 } ++ pushdata1_255 ++
        [_]u8{ @intFromEnum(Opcode.OP_PUSHDATA2), 0x00, 0x01 } ++ pushdata2_256,
    );

    const chunks = try parseAlloc(allocator, script);
    defer allocator.free(chunks);
    try std.testing.expectEqual(@as(usize, 4), chunks.len);
    try std.testing.expectEqual(chunk.PushEncoding.direct, chunks[0].push_data.encoding);
    try std.testing.expectEqual(chunk.PushEncoding.OP_PUSHDATA1, chunks[1].push_data.encoding);
    try std.testing.expectEqual(chunk.PushEncoding.OP_PUSHDATA1, chunks[2].push_data.encoding);
    try std.testing.expectEqual(chunk.PushEncoding.OP_PUSHDATA2, chunks[3].push_data.encoding);

    const serialized = try serializeAlloc(allocator, chunks);
    defer allocator.free(serialized);
    try std.testing.expectEqualSlices(u8, script.bytes, serialized);
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
