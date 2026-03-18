const errors = @import("errors.zig");
const Opcode = @import("opcode.zig").Opcode;

pub const PushEncoding = enum(u8) {
    direct = 0,
    OP_PUSHDATA1 = 0x4c,
    OP_PUSHDATA2 = 0x4d,
    OP_PUSHDATA4 = 0x4e,

    pub fn opcodeByte(self: PushEncoding, data_len: usize) errors.ScriptError!u8 {
        return switch (self) {
            .direct => {
                if (data_len > 75) return error.InvalidPushData;
                return @intCast(data_len);
            },
            .OP_PUSHDATA1 => @intFromEnum(Opcode.OP_PUSHDATA1),
            .OP_PUSHDATA2 => @intFromEnum(Opcode.OP_PUSHDATA2),
            .OP_PUSHDATA4 => @intFromEnum(Opcode.OP_PUSHDATA4),
        };
    }
};

pub const PushData = struct {
    data: []const u8,
    encoding: PushEncoding,
};

pub const ScriptChunk = union(enum) {
    opcode: Opcode,
    push_data: PushData,
};
