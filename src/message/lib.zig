//! BRC-77 signed and BRC-78 encrypted peer messages (go-sdk `message` package parity).
pub const signed = @import("signed.zig");
pub const encrypted = @import("encrypted.zig");
