const crypto = @import("../crypto/lib.zig");

pub const OutPoint = struct {
    txid: crypto.Hash256,
    index: u32,
};
