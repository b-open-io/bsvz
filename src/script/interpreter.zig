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
    return thread.verifyExecutableScripts(
        .forSpend(ctx.allocator, ctx.tx, ctx.input_index, ctx.previous_satoshis),
        ctx.unlocking_script,
        ctx.locking_script,
    );
}
