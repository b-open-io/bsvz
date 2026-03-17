pub const OutPoint = @import("outpoint.zig").OutPoint;
pub const Input = @import("input.zig").Input;
pub const Output = @import("output.zig").Output;
pub const Transaction = @import("transaction.zig").Transaction;

pub const sighash = @import("sighash.zig");
pub const preimage = @import("preimage.zig");
pub const builder = @import("builder.zig");

pub const templates = struct {
    pub const p2pkh_spend = @import("templates/p2pkh_spend.zig");
};
