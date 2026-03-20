pub const OutPoint = @import("outpoint.zig").OutPoint;
pub const Input = @import("input.zig").Input;
pub const Output = @import("output.zig").Output;
pub const Transaction = @import("transaction.zig").Transaction;
pub const Builder = @import("builder.zig").Builder;
pub const beef = @import("beef.zig");
pub const Beef = beef.Beef;
pub const BeefTx = beef.BeefTx;
pub const ParsedBeef = beef.ParsedBeef;
pub const ValidationResult = beef.ValidationResult;
pub const newBeefV1 = beef.newBeefV1;
pub const newBeefV2 = beef.newBeefV2;
pub const newBeefFromHex = beef.newBeefFromHex;
pub const newBeefFromBytes = beef.newBeefFromBytes;
pub const newTransactionFromBeef = beef.newTransactionFromBeef;
pub const newTransactionFromBeefHex = beef.newTransactionFromBeefHex;
pub const sourceTransactionForInput = @import("transaction.zig").sourceTransactionForInput;
pub const sourceOutputForInput = @import("transaction.zig").sourceOutputForInput;
pub const fees = @import("fees.zig");
pub const Preimage = @import("preimage.zig").Preimage;
pub const fee_model = @import("fee_model/lib.zig");

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
