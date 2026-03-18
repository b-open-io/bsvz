const std = @import("std");
const limits = @import("limits.zig");
const Script = @import("script.zig").Script;
const Transaction = @import("../transaction/transaction.zig").Transaction;

pub const ExecutionFlags = struct {
    max_ops: usize = 500_000,
    max_stack_items: usize = 1_000,
    max_script_size: usize = std.math.maxInt(i32),
    max_script_element_size: usize = std.math.maxInt(i32),
    max_script_number_length: usize = 750_000,
    utxo_after_genesis: bool = true,
    enable_reenabled_opcodes: bool = true,
    enable_sighash_forkid: bool = true,
    verify_bip143_sighash: bool = true,
    strict_encoding: bool = true,
    der_signatures: bool = false,
    low_s: bool = false,
    strict_pubkey_encoding: bool = false,
    null_dummy: bool = false,
    null_fail: bool = false,
    sig_push_only: bool = false,
    clean_stack: bool = false,
    minimal_data: bool = false,
    minimal_if: bool = false,

    pub fn postGenesisBsv() ExecutionFlags {
        return .{};
    }

    pub fn legacyReference() ExecutionFlags {
        return .{
            .max_ops = 500,
            .max_script_size = limits.default_max_script_size,
            .max_stack_items = 1_000,
            .max_script_element_size = 520,
            .max_script_number_length = 4,
            .utxo_after_genesis = false,
            .enable_reenabled_opcodes = true,
            .enable_sighash_forkid = false,
            .verify_bip143_sighash = false,
            .strict_encoding = false,
            .der_signatures = false,
            .low_s = false,
            .strict_pubkey_encoding = false,
            .null_dummy = false,
            .null_fail = false,
            .sig_push_only = false,
            .clean_stack = false,
            .minimal_data = false,
            .minimal_if = false,
        };
    }
};

pub const ExecutionContext = struct {
    allocator: std.mem.Allocator,
    tx: ?*const Transaction = null,
    input_index: usize = 0,
    previous_locking_script: ?Script = null,
    previous_satoshis: i64 = 0,
    flags: ExecutionFlags = .{},
};

pub const ExecutionState = struct {
    stack: std.ArrayListUnmanaged([]u8) = .empty,
    alt_stack: std.ArrayListUnmanaged([]u8) = .empty,
    condition_stack: std.ArrayListUnmanaged(bool) = .empty,
    else_seen_stack: std.ArrayListUnmanaged(bool) = .empty,
    ops_executed: usize = 0,
    max_stack_depth: usize = 0,
    last_code_separator: usize = 0,

    pub fn deinit(self: *ExecutionState, allocator: std.mem.Allocator) void {
        for (self.stack.items) |item| allocator.free(item);
        for (self.alt_stack.items) |item| allocator.free(item);
        self.stack.deinit(allocator);
        self.alt_stack.deinit(allocator);
        self.condition_stack.deinit(allocator);
        self.else_seen_stack.deinit(allocator);
        self.* = .{};
    }

    pub fn clearAltStack(self: *ExecutionState, allocator: std.mem.Allocator) void {
        for (self.alt_stack.items) |item| allocator.free(item);
        self.alt_stack.clearRetainingCapacity();
    }
};

pub const ExecutionResult = struct {
    success: bool,
    state: ExecutionState,

    pub fn deinit(self: *ExecutionResult, allocator: std.mem.Allocator) void {
        self.state.deinit(allocator);
    }
};

test "execution flag presets expose legacy and BSV policy envelopes" {
    const legacy = ExecutionFlags.legacyReference();
    try std.testing.expectEqual(@as(usize, 500), legacy.max_ops);
    try std.testing.expectEqual(limits.default_max_script_size, legacy.max_script_size);
    try std.testing.expectEqual(@as(usize, 520), legacy.max_script_element_size);
    try std.testing.expectEqual(@as(usize, 4), legacy.max_script_number_length);
    try std.testing.expect(!legacy.utxo_after_genesis);
    try std.testing.expect(!legacy.enable_sighash_forkid);
    try std.testing.expect(!legacy.verify_bip143_sighash);
    try std.testing.expect(!legacy.strict_encoding);

    const bsv = ExecutionFlags.postGenesisBsv();
    try std.testing.expectEqual(std.math.maxInt(i32), bsv.max_script_size);
    try std.testing.expect(bsv.utxo_after_genesis);
    try std.testing.expect(bsv.enable_sighash_forkid);
    try std.testing.expect(bsv.verify_bip143_sighash);
    try std.testing.expect(bsv.strict_encoding);
}
