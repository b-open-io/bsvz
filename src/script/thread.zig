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
        return .{
            .success = try finalResult(self.ctx, &self.state),
            .state = self.state,
        };
    }

    pub fn verifyPair(self: *ScriptThread, unlocking_script: Script, locking_script: Script) Error!bool {
        if (self.ctx.flags.sig_push_only and !(try engine.isPushOnly(unlocking_script))) return error.SigPushOnly;

        if (!(try self.executePhase(.unlocking, unlocking_script))) return false;
        self.state.clearAltStack(self.ctx.allocator);
        if (!(try self.executePhase(.locking, locking_script))) return false;

        return finalResult(self.ctx, &self.state);
    }

    fn executePhase(self: *ScriptThread, which: enum { unlocking, locking }, script: Script) Error!bool {
        const result = switch (which) {
            .unlocking => engine.executeUnlockingScript(self.ctx, &self.state, script),
            .locking => engine.executeLockingScript(self.ctx, &self.state, script),
        };

        result catch |err| switch (err) {
            error.VerifyFailed => return false,
            error.ReturnEncountered => if (self.ctx.flags.utxo_after_genesis) return false else return err,
            else => return err,
        };

        if (self.state.condition_stack.items.len != 0) return error.UnbalancedConditionals;
        return true;
    }
};

pub fn executeScript(ctx: ExecutionContext, script: Script) Error!ExecutionResult {
    var thread = ScriptThread.init(ctx);
    return thread.executeScript(script);
}

pub fn verifyScripts(ctx: ExecutionContext, unlocking_script: Script, locking_script: Script) Error!bool {
    var thread = ScriptThread.init(ctx);
    defer thread.deinit();
    return thread.verifyPair(unlocking_script, locking_script);
}

pub fn verifyExecutableScripts(
    ctx: ExecutionContext,
    unlocking_script: Script,
    full_locking_script: Script,
) Error!bool {
    const executable_locking_script = try bytes.executableCodePart(full_locking_script);
    return verifyScripts(executableContext(ctx, full_locking_script), unlocking_script, executable_locking_script);
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
