const std = @import("std");
const opcode = @import("../opcode.zig").Opcode;

pub fn encode(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    if (data.len > 75) return error.UnsupportedDataPush;

    var out = try allocator.alloc(u8, 2 + data.len);
    out[0] = @intFromEnum(opcode.OP_RETURN);
    out[1] = @intCast(data.len);
    @memcpy(out[2..], data);
    return out;
}

pub fn matches(script_bytes: []const u8) bool {
    return script_bytes.len >= 1 and script_bytes[0] == @intFromEnum(opcode.OP_RETURN);
}

test "op_return encode emits a direct push" {
    const allocator = std.testing.allocator;
    const encoded = try encode(allocator, "bsvz");
    defer allocator.free(encoded);

    try std.testing.expect(matches(encoded));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x6a, 0x04, 'b', 's', 'v', 'z' }, encoded);
}

test "op_return encode handles zero-length and max direct pushes" {
    const allocator = std.testing.allocator;

    const empty = try encode(allocator, "");
    defer allocator.free(empty);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x6a, 0x00 }, empty);

    const max_push = try encode(allocator, &([_]u8{0x42} ** 75));
    defer allocator.free(max_push);
    try std.testing.expectEqual(@as(usize, 77), max_push.len);
    try std.testing.expectEqual(@as(u8, 0x6a), max_push[0]);
    try std.testing.expectEqual(@as(u8, 75), max_push[1]);
    try std.testing.expectEqualSlices(u8, &([_]u8{0x42} ** 75), max_push[2..]);
}

test "op_return encode rejects oversized direct pushes" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.UnsupportedDataPush, encode(allocator, &([_]u8{0} ** 76)));
}

test "op_return matches rejects non-op-return scripts" {
    try std.testing.expect(!matches(""));
    try std.testing.expect(!matches(&[_]u8{0x51}));
}
