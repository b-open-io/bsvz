const std = @import("std");
const thread = @import("thread.zig");
const Script = @import("script.zig").Script;
const Input = @import("../transaction/input.zig").Input;
const OutPoint = @import("../transaction/outpoint.zig").OutPoint;
const Output = @import("../transaction/output.zig").Output;
const Transaction = @import("../transaction/transaction.zig").Transaction;

pub const Error = thread.Error;
pub const ScriptPhase = thread.ScriptPhase;
pub const VerificationTerminal = thread.VerificationTerminal;
pub const VerificationResult = thread.VerificationResult;

pub const P2pkhSpendContext = struct {
    allocator: std.mem.Allocator,
    tx: *const Transaction,
    input_index: usize,
    previous_satoshis: i64,
    unlocking_script: Script,
    locking_script: Script,
};

pub fn verify(ctx: P2pkhSpendContext) Error!bool {
    var result = verifyDetailed(ctx);
    defer result.deinit(ctx.allocator);
    return result.toLegacy();
}

pub fn verifyDetailed(ctx: P2pkhSpendContext) VerificationResult {
    return thread.verifyExecutableScriptsDetailed(
        .forSpend(ctx.allocator, ctx.tx, ctx.input_index, ctx.previous_satoshis),
        ctx.unlocking_script,
        ctx.locking_script,
    );
}

test "interpreter verifyDetailed exposes structured false results" {
    const allocator = std.testing.allocator;
    var tx = Transaction{
        .version = 2,
        .inputs = &[_]Input{
            .{
                .previous_outpoint = OutPoint{
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

    var result = verifyDetailed(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_satoshis = 1,
        .unlocking_script = Script.init(&[_]u8{}),
        .locking_script = tx.outputs[0].locking_script,
    });
    defer result.deinit(allocator);

    try std.testing.expect(!result.success);
    try std.testing.expectEqual(VerificationTerminal.false_result, result.terminal);
    try std.testing.expectEqual(ScriptPhase.final, result.phase);
}
