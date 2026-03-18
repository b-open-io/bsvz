const std = @import("std");
const Script = @import("script.zig").Script;
const Transaction = @import("../transaction/transaction.zig").Transaction;

pub const ExecutionFlags = struct {
    max_ops: usize = 500_000,
    max_stack_items: usize = 1_000,
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
