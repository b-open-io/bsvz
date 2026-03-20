const std = @import("std");

pub const Script = struct {
    bytes: []const u8,
    owned: bool = false,

    pub fn init(bytes: []const u8) Script {
        return .{ .bytes = bytes };
    }

    pub fn empty() Script {
        return .{ .bytes = &.{} };
    }

    pub fn clone(self: Script, allocator: std.mem.Allocator) !Script {
        return .{
            .bytes = try allocator.dupe(u8, self.bytes),
            .owned = true,
        };
    }

    pub fn deinit(self: *Script, allocator: std.mem.Allocator) void {
        if (self.owned) allocator.free(self.bytes);
        self.* = Script.empty();
    }

    pub fn len(self: Script) usize {
        return self.bytes.len;
    }

    pub fn isEmpty(self: Script) bool {
        return self.bytes.len == 0;
    }
};

pub const LockingScript = Script;
pub const UnlockingScript = Script;
