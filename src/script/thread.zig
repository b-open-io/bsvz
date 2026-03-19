const std = @import("std");
const context = @import("context.zig");
const bytes = @import("bytes.zig");
const engine = @import("engine.zig");
const Script = @import("script.zig").Script;
const Output = @import("../transaction/output.zig").Output;
const Transaction = @import("../transaction/transaction.zig").Transaction;

pub const Error = engine.Error;
pub const ExecutionContext = context.ExecutionContext;
pub const ExecutionFlags = context.ExecutionFlags;
pub const ExecutionState = context.ExecutionState;
pub const ExecutionResult = context.ExecutionResult;
pub const ExecutionTrace = context.ExecutionTrace;
pub const ScriptPhase = context.ScriptPhase;
pub const VerificationTerminal = context.VerificationTerminal;
pub const VerificationOutcome = union(enum) {
    success,
    false_result,
    script_error: Error,

    pub fn ok(self: VerificationOutcome) bool {
        return self == .success;
    }

    pub fn label(self: VerificationOutcome) []const u8 {
        return @tagName(self);
    }

    pub fn writeDebug(self: VerificationOutcome, writer: anytype) !void {
        switch (self) {
            .success, .false_result => try writer.writeAll(self.label()),
            .script_error => |err| try writer.print("{s}({})", .{ self.label(), err }),
        }
    }
};

pub const VerificationResult = struct {
    success: bool,
    terminal: VerificationTerminal,
    phase: ScriptPhase,
    script_error: ?Error = null,
    state: ExecutionState,

    pub fn deinit(self: *VerificationResult, allocator: std.mem.Allocator) void {
        self.state.deinit(allocator);
    }

    pub fn toLegacy(self: VerificationResult) Error!bool {
        if (self.script_error) |err| return err;
        return self.success;
    }

    pub fn outcome(self: VerificationResult) VerificationOutcome {
        return switch (self.terminal) {
            .success => .success,
            .false_result => .false_result,
            .script_error => .{ .script_error = self.script_error.? },
        };
    }

    pub fn deinitToOutcome(self: *VerificationResult, allocator: std.mem.Allocator) VerificationOutcome {
        defer self.deinit(allocator);
        return self.outcome();
    }

    pub fn writeDebug(self: VerificationResult, writer: anytype) !void {
        try writer.print(
            "VerificationResult(terminal={s}, phase={s}, success={}, stack={}, alt={}, cond={}",
            .{
                self.terminal.label(),
                self.phase.label(),
                self.success,
                self.state.stack.items.len,
                self.state.alt_stack.items.len,
                self.state.condition_stack.items.len,
            },
        );
        if (self.script_error) |err| {
            try writer.print(", error={}", .{err});
        }
        try writer.writeAll(")");
    }
};

pub const TracedExecutionResult = struct {
    result: ExecutionResult,
    trace: ExecutionTrace,

    pub fn deinit(self: *TracedExecutionResult, allocator: std.mem.Allocator) void {
        self.result.deinit(allocator);
        self.trace.deinit(allocator);
    }

    pub fn lastStep(self: *const TracedExecutionResult) ?*const context.TraceStep {
        return self.trace.lastStep();
    }
};

pub const TracedVerificationResult = struct {
    result: VerificationResult,
    trace: ExecutionTrace,

    pub fn deinit(self: *TracedVerificationResult, allocator: std.mem.Allocator) void {
        self.result.deinit(allocator);
        self.trace.deinit(allocator);
    }

    pub fn lastStep(self: *const TracedVerificationResult) ?*const context.TraceStep {
        return self.trace.lastStep();
    }

    pub fn failureStep(self: *const TracedVerificationResult) ?*const context.TraceStep {
        return switch (self.result.terminal) {
            .success => null,
            .false_result, .script_error => self.trace.lastStep(),
        };
    }

    pub fn outcome(self: TracedVerificationResult) VerificationOutcome {
        return self.result.outcome();
    }

    pub fn deinitToOutcome(self: *TracedVerificationResult, allocator: std.mem.Allocator) VerificationOutcome {
        defer self.deinit(allocator);
        return self.outcome();
    }

    pub fn writeDebug(self: TracedVerificationResult, writer: anytype) !void {
        try self.result.writeDebug(writer);
        try writer.writeByte('\n');
        try self.trace.writeDebug(writer);
    }
};

pub const ScriptThread = struct {
    ctx: ExecutionContext,
    state: ExecutionState = .{},

    pub fn init(ctx: ExecutionContext) ScriptThread {
        return .{ .ctx = ctx };
    }

    pub fn deinit(self: *ScriptThread) void {
        self.state.deinit(self.ctx.allocator);
    }

    pub fn executeScript(self: *ScriptThread, script: Script) Error!ExecutionResult {
        errdefer self.state.deinit(self.ctx.allocator);
        try engine.executeLockingScript(self.ctx, &self.state, script);
        const success = try finalResult(self.ctx, &self.state);
        return .{
            .success = success,
            .state = self.takeState(),
        };
    }

    pub fn executeScriptTraced(self: *ScriptThread, script: Script) Error!TracedExecutionResult {
        var trace: ExecutionTrace = .{};
        errdefer trace.deinit(self.ctx.allocator);
        errdefer self.state.deinit(self.ctx.allocator);
        try engine.executeLockingScriptTraced(self.ctx, &self.state, script, &trace);
        const success = try finalResult(self.ctx, &self.state);
        return .{
            .result = .{
                .success = success,
                .state = self.takeState(),
            },
            .trace = trace,
        };
    }

    pub fn verifyPair(self: *ScriptThread, unlocking_script: Script, locking_script: Script) Error!bool {
        var result = self.verifyPairDetailed(unlocking_script, locking_script);
        defer result.deinit(self.ctx.allocator);
        return result.toLegacy();
    }

    pub fn verifyPairDetailed(self: *ScriptThread, unlocking_script: Script, locking_script: Script) VerificationResult {
        return self.verifyPairImpl(unlocking_script, locking_script, false, null);
    }

    pub fn verifyPairTraced(self: *ScriptThread, unlocking_script: Script, locking_script: Script) TracedVerificationResult {
        var trace: ExecutionTrace = .{};
        return .{
            .result = self.verifyPairImpl(unlocking_script, locking_script, false, &trace),
            .trace = trace,
        };
    }

    pub fn verifyPairWithLegacyP2SH(
        self: *ScriptThread,
        unlocking_script: Script,
        locking_script: Script,
        enable_legacy_p2sh: bool,
    ) Error!bool {
        var result = self.verifyPairWithLegacyP2SHDetailed(unlocking_script, locking_script, enable_legacy_p2sh);
        defer result.deinit(self.ctx.allocator);
        return result.toLegacy();
    }

    pub fn verifyPairWithLegacyP2SHDetailed(
        self: *ScriptThread,
        unlocking_script: Script,
        locking_script: Script,
        enable_legacy_p2sh: bool,
    ) VerificationResult {
        return self.verifyPairImpl(unlocking_script, locking_script, enable_legacy_p2sh, null);
    }

    fn verifyPairImpl(
        self: *ScriptThread,
        unlocking_script: Script,
        locking_script: Script,
        enable_legacy_p2sh: bool,
        trace: ?*ExecutionTrace,
    ) VerificationResult {
        const use_legacy_p2sh = enable_legacy_p2sh and engine.isPayToScriptHash(locking_script);
        if (self.checkPushOnly(unlocking_script, self.ctx.flags.sig_push_only or use_legacy_p2sh)) |result| return result;

        if (self.executePhaseDetailedImpl(.unlocking, unlocking_script, trace)) |result| return result;

        var p2sh_stack: std.ArrayListUnmanaged([]u8) = .empty;
        defer deinitOwnedStack(self.ctx.allocator, &p2sh_stack);
        if (use_legacy_p2sh) {
            cloneStackInto(self.ctx.allocator, &p2sh_stack, self.state.stack.items) catch |err| {
                return self.finishVerification(.script_error, .unlocking, err);
            };
        }

        self.state.clearAltStack(self.ctx.allocator);
        if (self.executePhaseDetailedImpl(.locking, locking_script, trace)) |result| return result;

        if (use_legacy_p2sh) {
            if (!stackTopTruthy(&self.state)) {
                return self.finishVerification(.false_result, .final, null);
            }

            self.state.clearAltStack(self.ctx.allocator);
            replaceMainStack(self.ctx.allocator, &self.state, &p2sh_stack);
            if (self.state.stack.items.len == 0) {
                return self.finishVerification(.false_result, .locking, null);
            }

            const redeem_script = self.state.stack.pop() orelse unreachable;
            defer self.ctx.allocator.free(redeem_script);

            const previous_locking_script = self.ctx.previous_locking_script;
            self.ctx.previous_locking_script = Script.init(redeem_script);
            defer self.ctx.previous_locking_script = previous_locking_script;

            if (self.executePhaseDetailedImpl(.locking, Script.init(redeem_script), trace)) |result| return result;
        }

        const success = finalResult(self.ctx, &self.state) catch |err| {
            return self.finishVerification(.script_error, .final, err);
        };
        return self.finishVerification(if (success) .success else .false_result, .final, null);
    }

    fn checkPushOnly(self: *ScriptThread, unlocking_script: Script, enabled: bool) ?VerificationResult {
        if (!enabled) return null;
        const push_only = engine.isPushOnly(unlocking_script) catch |err| {
            return self.finishVerification(.script_error, .unlocking, err);
        };
        if (!push_only) return self.finishVerification(.script_error, .unlocking, error.SigPushOnly);
        return null;
    }

    fn executePhaseDetailedImpl(
        self: *ScriptThread,
        which: ScriptPhase,
        script: Script,
        trace: ?*ExecutionTrace,
    ) ?VerificationResult {
        const result = if (trace) |execution_trace|
            switch (which) {
                .unlocking => engine.executeUnlockingScriptTraced(self.ctx, &self.state, script, execution_trace),
                .locking => engine.executeLockingScriptTraced(self.ctx, &self.state, script, execution_trace),
                .final => unreachable,
            }
        else switch (which) {
            .unlocking => engine.executeUnlockingScript(self.ctx, &self.state, script),
            .locking => engine.executeLockingScript(self.ctx, &self.state, script),
            .final => unreachable,
        };

        result catch |err| switch (err) {
            error.VerifyFailed => return self.finishVerification(.false_result, which, null),
            error.ReturnEncountered => if (self.ctx.flags.utxo_after_genesis) {
                return self.finishVerification(.false_result, which, null);
            } else {
                return self.finishVerification(.script_error, which, err);
            },
            else => return self.finishVerification(.script_error, which, err),
        };

        if (self.state.condition_stack.items.len != 0) {
            return self.finishVerification(.script_error, which, error.UnbalancedConditionals);
        }
        return null;
    }

    fn finishVerification(
        self: *ScriptThread,
        terminal: VerificationTerminal,
        phase: ScriptPhase,
        script_error: ?Error,
    ) VerificationResult {
        return .{
            .success = terminal == .success,
            .terminal = terminal,
            .phase = phase,
            .script_error = script_error,
            .state = self.takeState(),
        };
    }

    fn takeState(self: *ScriptThread) ExecutionState {
        const state = self.state;
        self.state = .{};
        return state;
    }
};

pub fn executeScript(ctx: ExecutionContext, script: Script) Error!ExecutionResult {
    var thread = ScriptThread.init(ctx);
    return thread.executeScript(script);
}

pub fn executeScriptTraced(ctx: ExecutionContext, script: Script) Error!TracedExecutionResult {
    var thread = ScriptThread.init(ctx);
    return thread.executeScriptTraced(script);
}

pub fn verifyScripts(ctx: ExecutionContext, unlocking_script: Script, locking_script: Script) Error!bool {
    var result = verifyScriptsDetailed(ctx, unlocking_script, locking_script);
    defer result.deinit(ctx.allocator);
    return result.toLegacy();
}

pub fn verifyScriptsWithLegacyP2SH(
    ctx: ExecutionContext,
    unlocking_script: Script,
    locking_script: Script,
    enable_legacy_p2sh: bool,
) Error!bool {
    var result = verifyScriptsWithLegacyP2SHDetailed(ctx, unlocking_script, locking_script, enable_legacy_p2sh);
    defer result.deinit(ctx.allocator);
    return result.toLegacy();
}

pub fn verifyScriptsOutcome(
    ctx: ExecutionContext,
    unlocking_script: Script,
    locking_script: Script,
) VerificationOutcome {
    var result = verifyScriptsDetailed(ctx, unlocking_script, locking_script);
    return result.deinitToOutcome(ctx.allocator);
}

pub fn verificationOutcome(result: Error!bool) VerificationOutcome {
    const verified = result catch |err| return .{ .script_error = err };
    return if (verified) .success else .false_result;
}

pub fn verifyScriptsDetailed(
    ctx: ExecutionContext,
    unlocking_script: Script,
    locking_script: Script,
) VerificationResult {
    var thread = ScriptThread.init(genericPairContext(ctx));
    defer thread.deinit();
    return thread.verifyPairDetailed(unlocking_script, locking_script);
}

pub fn verifyScriptsWithLegacyP2SHDetailed(
    ctx: ExecutionContext,
    unlocking_script: Script,
    locking_script: Script,
    enable_legacy_p2sh: bool,
) VerificationResult {
    var thread = ScriptThread.init(genericPairContext(ctx));
    defer thread.deinit();
    return thread.verifyPairWithLegacyP2SHDetailed(unlocking_script, locking_script, enable_legacy_p2sh);
}

pub fn verifyScriptsTraced(
    ctx: ExecutionContext,
    unlocking_script: Script,
    locking_script: Script,
) TracedVerificationResult {
    var thread = ScriptThread.init(genericPairContext(ctx));
    defer thread.deinit();
    return thread.verifyPairTraced(unlocking_script, locking_script);
}

pub fn verifyExecutableScripts(
    ctx: ExecutionContext,
    unlocking_script: Script,
    full_locking_script: Script,
) Error!bool {
    var result = verifyExecutableScriptsDetailed(ctx, unlocking_script, full_locking_script);
    defer result.deinit(ctx.allocator);
    return result.toLegacy();
}

pub fn verifyExecutableScriptsOutcome(
    ctx: ExecutionContext,
    unlocking_script: Script,
    full_locking_script: Script,
) VerificationOutcome {
    var result = verifyExecutableScriptsDetailed(ctx, unlocking_script, full_locking_script);
    return result.deinitToOutcome(ctx.allocator);
}

pub fn verifyExecutableScriptsDetailed(
    ctx: ExecutionContext,
    unlocking_script: Script,
    full_locking_script: Script,
) VerificationResult {
    var thread = ScriptThread.init(executableContext(ctx, full_locking_script));
    defer thread.deinit();

    const executable_locking_script = bytes.executableCodePart(full_locking_script) catch |err| {
        return thread.finishVerification(.script_error, .locking, err);
    };
    return thread.verifyPairDetailed(unlocking_script, executable_locking_script);
}

pub fn verifyExecutableScriptsTraced(
    ctx: ExecutionContext,
    unlocking_script: Script,
    full_locking_script: Script,
) TracedVerificationResult {
    var thread = ScriptThread.init(executableContext(ctx, full_locking_script));
    defer thread.deinit();

    var trace: ExecutionTrace = .{};
    const executable_locking_script = bytes.executableCodePart(full_locking_script) catch |err| {
        return .{
            .result = thread.finishVerification(.script_error, .locking, err),
            .trace = trace,
        };
    };
    return .{
        .result = thread.verifyPairImpl(unlocking_script, executable_locking_script, false, &trace),
        .trace = trace,
    };
}

fn cloneStackInto(
    allocator: std.mem.Allocator,
    target: *std.ArrayListUnmanaged([]u8),
    items: []const []const u8,
) !void {
    errdefer deinitOwnedStack(allocator, target);
    for (items) |item| {
        try target.append(allocator, try allocator.dupe(u8, item));
    }
}

fn deinitOwnedStack(allocator: std.mem.Allocator, stack: *std.ArrayListUnmanaged([]u8)) void {
    for (stack.items) |item| allocator.free(item);
    stack.deinit(allocator);
    stack.* = .empty;
}

fn replaceMainStack(
    allocator: std.mem.Allocator,
    state: *ExecutionState,
    replacement: *std.ArrayListUnmanaged([]u8),
) void {
    for (state.stack.items) |item| allocator.free(item);
    state.stack.deinit(allocator);
    state.stack = replacement.*;
    replacement.* = .empty;
}

fn stackTopTruthy(state: *const ExecutionState) bool {
    if (state.condition_stack.items.len != 0) return false;
    if (state.stack.items.len == 0) return false;
    return engine.isTruthy(state.stack.items[state.stack.items.len - 1]);
}

pub fn verifyPrevoutSpend(
    allocator: std.mem.Allocator,
    tx: *const Transaction,
    input_index: usize,
    previous_output: Output,
    unlocking_script: Script,
) Error!bool {
    return verifyExecutableScripts(
        ExecutionContext.forPrevoutSpend(allocator, tx, input_index, previous_output),
        unlocking_script,
        previous_output.locking_script,
    );
}

pub fn verifyPrevoutSpendOutcome(
    allocator: std.mem.Allocator,
    tx: *const Transaction,
    input_index: usize,
    previous_output: Output,
    unlocking_script: Script,
) VerificationOutcome {
    return verifyExecutableScriptsOutcome(
        ExecutionContext.forPrevoutSpend(allocator, tx, input_index, previous_output),
        unlocking_script,
        previous_output.locking_script,
    );
}

pub fn verifyPrevoutSpendDetailed(
    allocator: std.mem.Allocator,
    tx: *const Transaction,
    input_index: usize,
    previous_output: Output,
    unlocking_script: Script,
) VerificationResult {
    return verifyExecutableScriptsDetailed(
        ExecutionContext.forPrevoutSpend(allocator, tx, input_index, previous_output),
        unlocking_script,
        previous_output.locking_script,
    );
}

pub fn verifyPrevoutSpendTraced(
    allocator: std.mem.Allocator,
    tx: *const Transaction,
    input_index: usize,
    previous_output: Output,
    unlocking_script: Script,
) TracedVerificationResult {
    return verifyExecutableScriptsTraced(
        ExecutionContext.forPrevoutSpend(allocator, tx, input_index, previous_output),
        unlocking_script,
        previous_output.locking_script,
    );
}

fn finalResult(ctx: ExecutionContext, state: *ExecutionState) Error!bool {
    if (state.condition_stack.items.len != 0) return error.UnbalancedConditionals;
    if (state.stack.items.len == 0) return false;
    if (ctx.flags.clean_stack and state.stack.items.len != 1) return error.CleanStack;
    return engine.isTruthy(state.stack.items[state.stack.items.len - 1]);
}

fn executableContext(ctx: ExecutionContext, full_locking_script: Script) ExecutionContext {
    var result = ctx;
    result.previous_locking_script = full_locking_script;
    return result;
}

fn genericPairContext(ctx: ExecutionContext) ExecutionContext {
    var result = ctx;
    result.previous_locking_script = null;
    return result;
}

test "thread verifyExecutableScripts trims state suffix for execution but preserves full locking script in context" {
    const allocator = std.testing.allocator;

    try std.testing.expect(try verifyExecutableScripts(.{
        .allocator = allocator,
    }, Script.init(&[_]u8{}), Script.init(&[_]u8{
        @intFromEnum(@import("opcode.zig").Opcode.OP_1),
        @intFromEnum(@import("opcode.zig").Opcode.OP_RETURN),
        0x01,
        0x2a,
    })));
}

test "thread verifyScriptsDetailed ignores stale previous locking script context" {
    const allocator = std.testing.allocator;
    const interpreter = @import("../transaction/templates/p2pkh_spend.zig");
    const p2pkh = @import("templates/p2pkh.zig");
    const Input = @import("../transaction/input.zig").Input;

    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;

    const private_key = try @import("../crypto/lib.zig").PrivateKey.fromBytes(key_bytes);
    const public_key = try private_key.publicKey();
    const pubkey_hash = @import("../crypto/lib.zig").hash.hash160(&public_key.bytes);
    const locking_script_bytes = p2pkh.encode(pubkey_hash);
    const locking_script = Script.init(&locking_script_bytes);
    const stale_script = Script.init(&[_]u8{
        @intFromEnum(@import("opcode.zig").Opcode.OP_0),
    });

    var tx = Transaction{
        .version = 2,
        .inputs = &[_]Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x44} ** 32 },
                    .index = 0,
                },
                .unlocking_script = Script.init(""),
                .sequence = 0xffff_fffe,
            },
        },
        .outputs = &[_]Output{
            .{
                .satoshis = 900,
                .locking_script = locking_script,
            },
        },
        .lock_time = 0,
    };

    const unlocking_script = try interpreter.signAndBuildUnlockingScript(
        allocator,
        &tx,
        0,
        locking_script,
        1_000,
        private_key,
        interpreter.default_scope,
    );
    defer allocator.free(unlocking_script.bytes);

    var result = verifyScriptsDetailed(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = stale_script,
        .previous_satoshis = 1_000,
    }, unlocking_script, locking_script);
    defer result.deinit(allocator);

    try std.testing.expect(result.success);
    try std.testing.expectEqual(VerificationTerminal.success, result.terminal);
}

test "thread verifyPair clears altstack between unlocking and locking scripts" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.AltStackUnderflow, verifyScripts(.{
        .allocator = allocator,
    }, Script.init(&[_]u8{
        @intFromEnum(@import("opcode.zig").Opcode.OP_1),
        @intFromEnum(@import("opcode.zig").Opcode.OP_TOALTSTACK),
    }), Script.init(&[_]u8{
        @intFromEnum(@import("opcode.zig").Opcode.OP_FROMALTSTACK),
        @intFromEnum(@import("opcode.zig").Opcode.OP_1),
    })));
}

test "thread executeScript transfers state ownership to result" {
    const allocator = std.testing.allocator;

    var thread = ScriptThread.init(.{ .allocator = allocator });
    var result = try thread.executeScript(Script.init(&[_]u8{
        @intFromEnum(@import("opcode.zig").Opcode.OP_1),
    }));
    defer result.deinit(allocator);

    thread.deinit();
    try std.testing.expect(result.success);
}

test "thread verifyScriptsDetailed reports final false results without throwing" {
    const allocator = std.testing.allocator;

    var result = verifyScriptsDetailed(.{
        .allocator = allocator,
    }, Script.init(&[_]u8{}), Script.init(&[_]u8{
        @intFromEnum(@import("opcode.zig").Opcode.OP_0),
    }));
    defer result.deinit(allocator);

    try std.testing.expect(!result.success);
    try std.testing.expectEqual(VerificationTerminal.false_result, result.terminal);
    try std.testing.expectEqual(ScriptPhase.final, result.phase);
    try std.testing.expectEqual(@as(?Error, null), result.script_error);
}

test "thread verifyScriptsOutcome collapses owned detailed results" {
    const allocator = std.testing.allocator;

    try std.testing.expectEqualDeep(
        VerificationOutcome.false_result,
        verifyScriptsOutcome(
            .{ .allocator = allocator },
            Script.init(&[_]u8{}),
            Script.init(&[_]u8{@intFromEnum(@import("opcode.zig").Opcode.OP_0)}),
        ),
    );
}

test "thread verifyScriptsDetailed reports script errors with owned state" {
    const allocator = std.testing.allocator;

    var result = verifyScriptsDetailed(.{
        .allocator = allocator,
    }, Script.init(&[_]u8{}), Script.init(&[_]u8{
        @intFromEnum(@import("opcode.zig").Opcode.OP_FROMALTSTACK),
    }));
    defer result.deinit(allocator);

    try std.testing.expect(!result.success);
    try std.testing.expectEqual(VerificationTerminal.script_error, result.terminal);
    try std.testing.expectEqual(ScriptPhase.locking, result.phase);
    try std.testing.expectEqual(error.AltStackUnderflow, result.script_error.?);
}

test "thread verifyExecutableScriptsDetailed preserves code-part parse failures as structured results" {
    const allocator = std.testing.allocator;

    var result = verifyExecutableScriptsDetailed(.{
        .allocator = allocator,
    }, Script.init(&[_]u8{}), Script.init(&[_]u8{
        @intFromEnum(@import("opcode.zig").Opcode.OP_PUSHDATA1),
    }));
    defer result.deinit(allocator);

    try std.testing.expect(!result.success);
    try std.testing.expectEqual(VerificationTerminal.script_error, result.terminal);
    try std.testing.expectEqual(ScriptPhase.locking, result.phase);
    try std.testing.expectEqual(error.InvalidPushData, result.script_error.?);
}

test "thread verifyScriptsTraced captures opcode snapshots before terminal failure" {
    const allocator = std.testing.allocator;

    var traced = verifyScriptsTraced(.{
        .allocator = allocator,
    }, Script.init(&[_]u8{}), Script.init(&[_]u8{
        @intFromEnum(@import("opcode.zig").Opcode.OP_1),
        @intFromEnum(@import("opcode.zig").Opcode.OP_FROMALTSTACK),
    }));
    defer traced.deinit(allocator);

    try std.testing.expectEqual(VerificationTerminal.script_error, traced.result.terminal);
    try std.testing.expectEqual(@as(usize, 2), traced.trace.steps.items.len);
    try std.testing.expectEqual(ScriptPhase.locking, traced.trace.steps.items[0].phase);
    try std.testing.expectEqual(@as(u8, @intFromEnum(@import("opcode.zig").Opcode.OP_1)), traced.trace.steps.items[0].opcode_byte);
    try std.testing.expectEqual(@as(u8, @intFromEnum(@import("opcode.zig").Opcode.OP_FROMALTSTACK)), traced.trace.steps.items[1].opcode_byte);
    try std.testing.expectEqual(@as(usize, 1), traced.trace.steps.items[1].stack.len);
    try std.testing.expectEqual(@as(?*const context.TraceStep, &traced.trace.steps.items[1]), traced.lastStep());
    try std.testing.expectEqual(@as(?*const context.TraceStep, &traced.trace.steps.items[1]), traced.failureStep());
    try std.testing.expectEqualStrings("OP_FROMALTSTACK", traced.failureStep().?.opcodeName());
    try std.testing.expectEqualDeep(VerificationOutcome{ .script_error = error.AltStackUnderflow }, traced.outcome());

    var rendered: std.ArrayListUnmanaged(u8) = .empty;
    defer rendered.deinit(allocator);
    try traced.writeDebug(rendered.writer(allocator));
    try std.testing.expect(std.mem.indexOf(u8, rendered.items, "VerificationResult") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered.items, "AltStackUnderflow") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered.items, "OP_FROMALTSTACK") != null);
}

test "thread verificationOutcome maps legacy bool-or-error results" {
    try std.testing.expectEqualDeep(VerificationOutcome.success, verificationOutcome(@as(Error!bool, true)));
    try std.testing.expectEqualDeep(VerificationOutcome.false_result, verificationOutcome(@as(Error!bool, false)));
    try std.testing.expectEqualDeep(
        VerificationOutcome{ .script_error = error.CleanStack },
        verificationOutcome(@as(Error!bool, error.CleanStack)),
    );

    var rendered: std.ArrayListUnmanaged(u8) = .empty;
    defer rendered.deinit(std.testing.allocator);
    const outcome = VerificationOutcome{ .script_error = error.CleanStack };
    try outcome.writeDebug(rendered.writer(std.testing.allocator));
    try std.testing.expect(std.mem.indexOf(u8, rendered.items, "script_error(") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered.items, "CleanStack") != null);
}

test "thread verifyPrevoutSpendDetailed uses previous output directly" {
    const allocator = std.testing.allocator;
    var tx = Transaction{
        .version = 2,
        .inputs = &[_]@import("../transaction/input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0} ** 32 },
                    .index = 0,
                },
                .unlocking_script = Script.init(&[_]u8{}),
                .sequence = 0xffff_ffff,
            },
        },
        .outputs = &[_]Output{
            .{
                .satoshis = 1,
                .locking_script = Script.init(&[_]u8{
                    @intFromEnum(@import("opcode.zig").Opcode.OP_0),
                }),
            },
        },
        .lock_time = 0,
    };

    var result = verifyPrevoutSpendDetailed(
        allocator,
        &tx,
        0,
        tx.outputs[0],
        tx.inputs[0].unlocking_script,
    );
    defer result.deinit(allocator);

    try std.testing.expectEqual(VerificationTerminal.false_result, result.terminal);
    try std.testing.expectEqual(ScriptPhase.final, result.phase);
}

test "thread verifyPrevoutSpendOutcome exposes compact results directly" {
    const allocator = std.testing.allocator;
    var tx = Transaction{
        .version = 2,
        .inputs = &[_]@import("../transaction/input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0} ** 32 },
                    .index = 0,
                },
                .unlocking_script = Script.init(&[_]u8{}),
                .sequence = 0xffff_ffff,
            },
        },
        .outputs = &[_]Output{
            .{
                .satoshis = 1,
                .locking_script = Script.init(&[_]u8{
                    @intFromEnum(@import("opcode.zig").Opcode.OP_0),
                }),
            },
        },
        .lock_time = 0,
    };

    try std.testing.expectEqualDeep(
        VerificationOutcome.false_result,
        verifyPrevoutSpendOutcome(
            allocator,
            &tx,
            0,
            tx.outputs[0],
            tx.inputs[0].unlocking_script,
        ),
    );
}
