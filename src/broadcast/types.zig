const std = @import("std");

pub const BroadcastSuccess = struct {
    txid: []u8,
    message: []u8 = &[_]u8{},

    pub fn deinit(self: *BroadcastSuccess, allocator: std.mem.Allocator) void {
        allocator.free(self.txid);
        if (self.message.len > 0) allocator.free(self.message);
    }
};

pub const BroadcastFailure = struct {
    code: []u8,
    description: []u8,

    pub fn deinit(self: *BroadcastFailure, allocator: std.mem.Allocator) void {
        allocator.free(self.code);
        allocator.free(self.description);
    }
};

/// Result of a broadcast attempt (mirrors Go `*BroadcastSuccess` / `*BroadcastFailure`).
pub const BroadcastResult = union(enum) {
    ok: BroadcastSuccess,
    err: BroadcastFailure,

    pub fn deinit(self: *BroadcastResult, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .ok => |*s| s.deinit(allocator),
            .err => |*e| e.deinit(allocator),
        }
    }
};
