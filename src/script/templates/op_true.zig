//! BRC-19 / OP_TRUE return: one-byte locking script `OP_1` (spendable anyone-can-spend pattern).
const std = @import("std");
const opcode = @import("../opcode.zig").Opcode;

pub const locking_len: usize = 1;

pub fn lockingScript() [locking_len]u8 {
    return .{@intFromEnum(opcode.OP_1)};
}

pub fn matches(locking: []const u8) bool {
    return locking.len == 1 and locking[0] == @intFromEnum(opcode.OP_1);
}

test "op_true matches single byte" {
    const s = lockingScript();
    try std.testing.expect(matches(&s));
}
