const std = @import("std");
const thread = @import("thread.zig");
const Script = @import("script.zig").Script;
const Transaction = @import("../transaction/transaction.zig").Transaction;

pub const Error = thread.Error;

pub const P2pkhSpendContext = struct {
    allocator: std.mem.Allocator,
    tx: *const Transaction,
    input_index: usize,
    previous_satoshis: i64,
    unlocking_script: Script,
    locking_script: Script,
};

pub fn verify(ctx: P2pkhSpendContext) Error!bool {
    return thread.verifyExecutableScripts(.{
        .allocator = ctx.allocator,
        .tx = ctx.tx,
        .input_index = ctx.input_index,
        .previous_locking_script = ctx.locking_script,
        .previous_satoshis = ctx.previous_satoshis,
    }, ctx.unlocking_script, ctx.locking_script);
}
