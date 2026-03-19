const std = @import("std");
const limits = @import("limits.zig");
const opcode = @import("opcode.zig");
const Script = @import("script.zig").Script;
const Transaction = @import("../transaction/transaction.zig").Transaction;
const Output = @import("../transaction/output.zig").Output;

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
    discourage_upgradable_nops: bool = false,
    verify_check_locktime: bool = false,
    verify_check_sequence: bool = false,

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
            .discourage_upgradable_nops = false,
            .verify_check_locktime = false,
            .verify_check_sequence = false,
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

    pub fn forSpend(
        allocator: std.mem.Allocator,
        tx: *const Transaction,
        input_index: usize,
        previous_satoshis: i64,
    ) ExecutionContext {
        return .{
            .allocator = allocator,
            .tx = tx,
            .input_index = input_index,
            .previous_satoshis = previous_satoshis,
        };
    }

    pub fn forPrevoutSpend(
        allocator: std.mem.Allocator,
        tx: *const Transaction,
        input_index: usize,
        previous_output: Output,
    ) ExecutionContext {
        return .{
            .allocator = allocator,
            .tx = tx,
            .input_index = input_index,
            .previous_locking_script = previous_output.locking_script,
            .previous_satoshis = previous_output.satoshis,
        };
    }
};

pub const ScriptPhase = enum {
    unlocking,
    locking,
    final,

    pub fn label(self: ScriptPhase) []const u8 {
        return @tagName(self);
    }
};

pub const VerificationTerminal = enum {
    success,
    false_result,
    script_error,

    pub fn label(self: VerificationTerminal) []const u8 {
        return @tagName(self);
    }
};

pub const TraceStep = struct {
    phase: ScriptPhase = .locking,
    opcode_offset: usize = 0,
    opcode_byte: u8 = 0,
    should_execute_before: bool = false,
    early_return_before: bool = false,
    ops_executed_before: usize = 0,
    last_code_separator_before: usize = 0,
    stack: [][]u8 = &.{},
    alt_stack: [][]u8 = &.{},
    condition_stack: []bool = &.{},

    pub fn deinit(self: *TraceStep, allocator: std.mem.Allocator) void {
        freeItems(allocator, self.stack);
        freeItems(allocator, self.alt_stack);
        allocator.free(self.stack);
        allocator.free(self.alt_stack);
        allocator.free(self.condition_stack);
        self.* = .{};
    }

    pub fn writeDebug(self: TraceStep, writer: anytype) !void {
        const op = opcode.Opcode.fromByte(self.opcode_byte);
        try writer.print(
            "{s} offset={} {s} (0x{x:0>2}) execute_before={} early_return_before={} stack={} alt={} cond={} ops_before={} last_cs_before={}",
            .{
                self.phase.label(),
                self.opcode_offset,
                op.name(),
                self.opcode_byte,
                self.should_execute_before,
                self.early_return_before,
                self.stack.len,
                self.alt_stack.len,
                self.condition_stack.len,
                self.ops_executed_before,
                self.last_code_separator_before,
            },
        );
    }
};

pub const ExecutionTrace = struct {
    steps: std.ArrayListUnmanaged(TraceStep) = .empty,

    pub fn deinit(self: *ExecutionTrace, allocator: std.mem.Allocator) void {
        for (self.steps.items) |*step| step.deinit(allocator);
        self.steps.deinit(allocator);
        self.* = .{};
    }

    pub fn appendSnapshot(
        self: *ExecutionTrace,
        allocator: std.mem.Allocator,
        phase: ScriptPhase,
        opcode_offset: usize,
        opcode_byte: u8,
        should_execute_before: bool,
        early_return_before: bool,
        state: *const ExecutionState,
    ) !void {
        try self.steps.append(allocator, .{
            .phase = phase,
            .opcode_offset = opcode_offset,
            .opcode_byte = opcode_byte,
            .should_execute_before = should_execute_before,
            .early_return_before = early_return_before,
            .ops_executed_before = state.ops_executed,
            .last_code_separator_before = state.last_code_separator,
            .stack = try cloneItems(allocator, state.stack.items),
            .alt_stack = try cloneItems(allocator, state.alt_stack.items),
            .condition_stack = try allocator.dupe(bool, state.condition_stack.items),
        });
    }

    pub fn lastStep(self: *const ExecutionTrace) ?*const TraceStep {
        if (self.steps.items.len == 0) return null;
        return &self.steps.items[self.steps.items.len - 1];
    }

    pub fn writeDebug(self: ExecutionTrace, writer: anytype) !void {
        try writer.print("ExecutionTrace(steps={})", .{self.steps.items.len});
        for (self.steps.items, 0..) |step, index| {
            try writer.print("\n  [{}] ", .{index});
            try step.writeDebug(writer);
        }
    }
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
        freeItems(allocator, self.stack.items);
        freeItems(allocator, self.alt_stack.items);
        self.stack.deinit(allocator);
        self.alt_stack.deinit(allocator);
        self.condition_stack.deinit(allocator);
        self.else_seen_stack.deinit(allocator);
        self.* = .{};
    }

    pub fn clearAltStack(self: *ExecutionState, allocator: std.mem.Allocator) void {
        freeItems(allocator, self.alt_stack.items);
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

fn freeItems(allocator: std.mem.Allocator, items: []const []u8) void {
    for (items) |item| allocator.free(item);
}

fn cloneItems(allocator: std.mem.Allocator, items: []const []const u8) ![][]u8 {
    const out = try allocator.alloc([]u8, items.len);
    var initialized: usize = 0;
    errdefer {
        for (out[0..initialized]) |item| allocator.free(item);
        allocator.free(out);
    }

    for (items, 0..) |item, index| {
        out[index] = try allocator.dupe(u8, item);
        initialized += 1;
    }
    return out;
}

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
    try std.testing.expect(!bsv.discourage_upgradable_nops);
    try std.testing.expect(!bsv.verify_check_locktime);
    try std.testing.expect(!bsv.verify_check_sequence);
}

test "execution context can be built directly from a previous output" {
    const tx = Transaction{
        .version = 2,
        .inputs = &.{},
        .outputs = &.{},
        .lock_time = 0,
    };
    const previous_output = Output{
        .satoshis = 1234,
        .locking_script = Script.init(&[_]u8{ 0x51, 0x6a }),
    };

    const ctx = ExecutionContext.forPrevoutSpend(std.testing.allocator, &tx, 3, previous_output);
    try std.testing.expectEqual(@as(?*const Transaction, &tx), ctx.tx);
    try std.testing.expectEqual(@as(usize, 3), ctx.input_index);
    try std.testing.expectEqual(@as(i64, 1234), ctx.previous_satoshis);
    try std.testing.expectEqualSlices(u8, previous_output.locking_script.bytes, ctx.previous_locking_script.?.bytes);
}

test "execution trace captures independent snapshots" {
    const allocator = std.testing.allocator;
    var trace: ExecutionTrace = .{};
    defer trace.deinit(allocator);

    var state: ExecutionState = .{};
    defer state.deinit(allocator);

    try state.stack.append(allocator, try allocator.dupe(u8, &[_]u8{0x01}));
    try state.alt_stack.append(allocator, try allocator.dupe(u8, &[_]u8{0x02}));
    try state.condition_stack.append(allocator, true);
    state.ops_executed = 7;
    state.last_code_separator = 5;

    try trace.appendSnapshot(allocator, .locking, 3, 0x76, true, false, &state);

    allocator.free(state.stack.items[0]);
    state.stack.items[0] = try allocator.dupe(u8, &[_]u8{0x09});

    try std.testing.expectEqual(@as(usize, 1), trace.steps.items.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x01}, trace.steps.items[0].stack[0]);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x02}, trace.steps.items[0].alt_stack[0]);
    try std.testing.expectEqualSlices(bool, &[_]bool{true}, trace.steps.items[0].condition_stack);
    try std.testing.expectEqual(@as(?*const TraceStep, &trace.steps.items[0]), trace.lastStep());

    var rendered: std.ArrayListUnmanaged(u8) = .empty;
    defer rendered.deinit(allocator);
    try trace.writeDebug(rendered.writer(allocator));
    try std.testing.expect(std.mem.indexOf(u8, rendered.items, "ExecutionTrace(steps=1)") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered.items, "OP_DUP") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered.items, "0x76") != null);
}
