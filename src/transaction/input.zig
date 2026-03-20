const std = @import("std");
const Script = @import("../script/script.zig").Script;
const OutPoint = @import("outpoint.zig").OutPoint;
const Output = @import("output.zig").Output;

pub const Input = struct {
    previous_outpoint: OutPoint,
    unlocking_script: Script,
    sequence: u32,
    source_output: ?Output = null,
    /// Non-owning ancestry link hydrated by higher-level containers such as BEEF.
    source_transaction: ?*const anyopaque = null,

    pub fn empty() Input {
        return .{
            .previous_outpoint = .{
                .txid = .zero(),
                .index = 0,
            },
            .unlocking_script = Script.empty(),
            .sequence = 0,
            .source_output = null,
            .source_transaction = null,
        };
    }

    pub fn clone(self: Input, allocator: std.mem.Allocator) !Input {
        return .{
            .previous_outpoint = self.previous_outpoint,
            .unlocking_script = try self.unlocking_script.clone(allocator),
            .sequence = self.sequence,
            .source_output = if (self.source_output) |source_output|
                try source_output.clone(allocator)
            else
                null,
            .source_transaction = null,
        };
    }

    pub fn shallowClone(self: Input, allocator: std.mem.Allocator) !Input {
        return self.clone(allocator);
    }

    pub fn deinit(self: *Input, allocator: std.mem.Allocator) void {
        self.unlocking_script.deinit(allocator);
        if (self.source_output) |*source_output| source_output.deinit(allocator);
        self.* = Input.empty();
    }
};
