const context = @import("context.zig");
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
        if (self.state.condition_stack.items.len != 0) return error.UnbalancedConditionals;

        return .{
            .success = self.state.stack.items.len > 0 and engine.isTruthy(self.state.stack.items[self.state.stack.items.len - 1]),
            .state = self.state,
        };
    }

    pub fn verifyPair(self: *ScriptThread, unlocking_script: Script, locking_script: Script) Error!bool {
        if (self.ctx.flags.sig_push_only and !(try engine.isPushOnly(unlocking_script))) return error.SigPushOnly;

        engine.executeUnlockingScript(self.ctx, &self.state, unlocking_script) catch |err| switch (err) {
            error.VerifyFailed => return false,
            error.ReturnEncountered => if (self.ctx.flags.utxo_after_genesis) return false else return err,
            else => return err,
        };
        if (self.state.condition_stack.items.len != 0) return error.UnbalancedConditionals;
        self.state.clearAltStack(self.ctx.allocator);

        engine.executeLockingScript(self.ctx, &self.state, locking_script) catch |err| switch (err) {
            error.VerifyFailed => return false,
            error.ReturnEncountered => if (self.ctx.flags.utxo_after_genesis) return false else return err,
            else => return err,
        };

        return finalResult(self.ctx, &self.state);
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

fn finalResult(ctx: ExecutionContext, state: *ExecutionState) Error!bool {
    if (state.condition_stack.items.len != 0) return error.UnbalancedConditionals;
    if (state.stack.items.len == 0) return false;
    if (ctx.flags.clean_stack and state.stack.items.len != 1) return error.CleanStack;
    return engine.isTruthy(state.stack.items[state.stack.items.len - 1]);
}
