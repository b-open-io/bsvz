const std = @import("std");
const context = @import("context.zig");
const bytes = @import("bytes.zig");
const engine = @import("engine.zig");
const Script = @import("script.zig").Script;

pub const Error = engine.Error;
pub const ExecutionContext = context.ExecutionContext;
pub const ExecutionFlags = context.ExecutionFlags;
pub const ExecutionState = context.ExecutionState;
pub const ExecutionResult = context.ExecutionResult;
pub const ScriptPhase = context.ScriptPhase;
pub const VerificationTerminal = context.VerificationTerminal;

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

    pub fn verifyPair(self: *ScriptThread, unlocking_script: Script, locking_script: Script) Error!bool {
        var result = self.verifyPairDetailed(unlocking_script, locking_script);
        defer result.deinit(self.ctx.allocator);
        return result.toLegacy();
    }

    pub fn verifyPairDetailed(self: *ScriptThread, unlocking_script: Script, locking_script: Script) VerificationResult {
        if (self.ctx.flags.sig_push_only) {
            const push_only = engine.isPushOnly(unlocking_script) catch |err| {
                return self.finishVerification(.script_error, .unlocking, err);
            };
            if (!push_only) return self.finishVerification(.script_error, .unlocking, error.SigPushOnly);
        }

        if (self.executePhaseDetailed(.unlocking, unlocking_script)) |result| return result;
        self.state.clearAltStack(self.ctx.allocator);
        if (self.executePhaseDetailed(.locking, locking_script)) |result| return result;

        const success = finalResult(self.ctx, &self.state) catch |err| {
            return self.finishVerification(.script_error, .final, err);
        };
        return self.finishVerification(if (success) .success else .false_result, .final, null);
    }

    fn executePhaseDetailed(self: *ScriptThread, which: ScriptPhase, script: Script) ?VerificationResult {
        const result = switch (which) {
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

pub fn verifyScripts(ctx: ExecutionContext, unlocking_script: Script, locking_script: Script) Error!bool {
    var result = verifyScriptsDetailed(ctx, unlocking_script, locking_script);
    defer result.deinit(ctx.allocator);
    return result.toLegacy();
}

pub fn verifyScriptsDetailed(
    ctx: ExecutionContext,
    unlocking_script: Script,
    locking_script: Script,
) VerificationResult {
    var thread = ScriptThread.init(ctx);
    defer thread.deinit();
    return thread.verifyPairDetailed(unlocking_script, locking_script);
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
