const std = @import("std");
const bsvz = @import("bsvz");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    var traced = bsvz.script.thread.verifyScriptsTraced(.{
        .allocator = allocator,
    }, bsvz.script.Script.init(&[_]u8{}), bsvz.script.Script.init(&[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_1),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_FROMALTSTACK),
    }));
    defer traced.deinit(allocator);

    try traced.writeDebug(std.io.getStdOut().writer());
    try std.io.getStdOut().writer().writeByte('\n');
}
