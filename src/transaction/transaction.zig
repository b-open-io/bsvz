const std = @import("std");
const crypto = @import("../crypto/lib.zig");
const Input = @import("input.zig").Input;
const Output = @import("output.zig").Output;

pub const Transaction = struct {
    version: i32,
    inputs: []Input,
    outputs: []Output,
    lock_time: u32,

    pub fn txid(self: *const Transaction) crypto.Hash256 {
        return crypto.hash.sha256(std.mem.asBytes(&self.version));
    }
};
