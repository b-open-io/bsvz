const std = @import("std");
const Script = @import("script.zig").Script;

pub fn cat(allocator: std.mem.Allocator, left: []const u8, right: []const u8) ![]u8 {
    var out = try allocator.alloc(u8, left.len + right.len);
    @memcpy(out[0..left.len], left);
    @memcpy(out[left.len..], right);
    return out;
}

pub fn substr(allocator: std.mem.Allocator, bytes: []const u8, start: usize, len: usize) ![]u8 {
    if (start >= bytes.len) return allocator.alloc(u8, 0);
    const end = @min(start + len, bytes.len);
    return allocator.dupe(u8, bytes[start..end]);
}

pub fn findStateSeparatorOpReturnOffset(script: []const u8) error{InvalidPushData}!?usize {
    var cursor: usize = 0;
    while (cursor < script.len) {
        const opcode = script[cursor];
        cursor += 1;

        if (opcode == 0x6a) return cursor - 1;

        if (opcode >= 0x01 and opcode <= 0x4b) {
            if (script.len < cursor + opcode) return error.InvalidPushData;
            cursor += opcode;
            continue;
        }

        if (opcode == 0x4c) {
            if (cursor >= script.len) return error.InvalidPushData;
            const len = script[cursor];
            cursor += 1;
            if (script.len < cursor + len) return error.InvalidPushData;
            cursor += len;
            continue;
        }

        if (opcode == 0x4d) {
            if (script.len < cursor + 2) return error.InvalidPushData;
            const len = std.mem.readInt(u16, script[cursor..][0..2], .little);
            cursor += 2;
            if (script.len < cursor + len) return error.InvalidPushData;
            cursor += len;
            continue;
        }

        if (opcode == 0x4e) {
            if (script.len < cursor + 4) return error.InvalidPushData;
            const len = std.mem.readInt(u32, script[cursor..][0..4], .little);
            cursor += 4;
            if (script.len < cursor + len) return error.InvalidPushData;
            cursor += len;
            continue;
        }
    }

    return null;
}

pub fn executableCodePart(script: Script) error{InvalidPushData}!Script {
    const offset = try findStateSeparatorOpReturnOffset(script.bytes);
    return Script.init(if (offset) |value| script.bytes[0..value] else script.bytes);
}

test "findStateSeparatorOpReturnOffset skips pushdata bytes and finds the separator" {
    try std.testing.expectEqual(@as(?usize, 3), try findStateSeparatorOpReturnOffset(&[_]u8{
        0x01, 0x6a, 0x51, 0x6a, 0x01, 0x2a,
    }));
}

test "findStateSeparatorOpReturnOffset returns null when the script has no separator" {
    try std.testing.expectEqual(@as(?usize, null), try findStateSeparatorOpReturnOffset(&[_]u8{
        0x51, 0x76, 0x87,
    }));
}

test "executableCodePart trims the state suffix after the separator" {
    const full = Script.init(&[_]u8{
        0x51,
        0x6a,
        0x01,
        0x2a,
    });
    const executable = try executableCodePart(full);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x51}, executable.bytes);
}
