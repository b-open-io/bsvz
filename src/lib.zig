//! bsvz is a BSV foundation library for Zig.
//! It provides canonical primitives for hashes, keys, script, transactions,
//! SPV verification, and broadcasting.

pub const primitives = @import("primitives/lib.zig");
pub const crypto = @import("crypto/lib.zig");
pub const script = @import("script/lib.zig");
pub const transaction = @import("transaction/lib.zig");
pub const spv = @import("spv/lib.zig");
pub const broadcast = @import("broadcast/lib.zig");
pub const compat = @import("compat/lib.zig");
pub const wallet_core = @import("wallet_core/lib.zig");

test {
    @import("std").testing.refAllDeclsRecursive(@This());
}
