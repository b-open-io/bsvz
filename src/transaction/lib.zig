pub const OutPoint = @import("outpoint.zig").OutPoint;
pub const Input = @import("input.zig").Input;
pub const Output = @import("output.zig").Output;
pub const Transaction = @import("transaction.zig").Transaction;
pub const Preimage = @import("preimage.zig").Preimage;

pub const sighash = @import("sighash.zig");
pub const preimage = @import("preimage.zig");

pub const extractHashPrevouts = preimage.extractHashPrevouts;
pub const extractOutpoint = preimage.extractOutpoint;
pub const extractOutpointBytes = preimage.extractOutpointBytes;
pub const extractOutputHash = preimage.extractOutputHash;
pub const extractLocktime = preimage.extractLocktime;

pub const templates = struct {
    pub const p2pkh_spend = @import("templates/p2pkh_spend.zig");
};
