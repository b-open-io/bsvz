const std = @import("std");
const bsvz = @import("bsvz");
const go_asm = @import("go_asm.zig");

const Script = bsvz.script.Script;

pub const Expectation = union(enum) {
    success: bool,
    err: anyerror,
};

pub const Case = struct {
    name: []const u8,
    unlocking_asm: []const u8,
    locking_asm: []const u8,
    flags: bsvz.script.engine.ExecutionFlags,
    expected: Expectation,
    enable_legacy_p2sh: bool = false,
    output_value: i64 = 0,
    tx_version: i32 = 1,
    tx_lock_time: u32 = 0,
    input_sequence: u32 = 0xffff_ffff,
};

pub fn runCase(allocator: std.mem.Allocator, case: Case) !void {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const unlocking_bytes = try go_asm.assembleScript(arena, case.unlocking_asm);
    const locking_bytes = try go_asm.assembleScript(arena, case.locking_asm);
    const empty_script = Script.init(&.{});
    const prev_locking_script = Script.init(locking_bytes);

    var coinbase_inputs = [_]bsvz.transaction.Input{
        .{
            .previous_outpoint = .{
                .txid = .{ .bytes = [_]u8{0} ** 32 },
                .index = std.math.maxInt(u32),
            },
            .unlocking_script = Script.init(&.{ 0x00, 0x00 }),
            .sequence = 0xffff_ffff,
        },
    };
    var coinbase_outputs = [_]bsvz.transaction.Output{
        .{
            .satoshis = case.output_value,
            .locking_script = prev_locking_script,
        },
    };
    var coinbase_tx = bsvz.transaction.Transaction{
        .version = 1,
        .inputs = &coinbase_inputs,
        .outputs = &coinbase_outputs,
        .lock_time = 0,
    };
    const prev_txid = try coinbase_tx.txid(arena);

    var spending_inputs = [_]bsvz.transaction.Input{
        .{
            .previous_outpoint = .{
                .txid = prev_txid,
                .index = 0,
            },
            .unlocking_script = Script.init(unlocking_bytes),
            .sequence = case.input_sequence,
        },
    };
    var spending_outputs = [_]bsvz.transaction.Output{
        .{
            .satoshis = case.output_value,
            .locking_script = empty_script,
        },
    };
    const spending_tx = bsvz.transaction.Transaction{
        .version = case.tx_version,
        .inputs = &spending_inputs,
        .outputs = &spending_outputs,
        .lock_time = case.tx_lock_time,
    };

    var exec_ctx = bsvz.script.engine.ExecutionContext.forSpend(
        allocator,
        &spending_tx,
        0,
        case.output_value,
    );
    exec_ctx.previous_locking_script = prev_locking_script;
    exec_ctx.flags = case.flags;

    const result = bsvz.script.thread.verifyScriptsWithLegacyP2SH(
        exec_ctx,
        Script.init(unlocking_bytes),
        prev_locking_script,
        case.enable_legacy_p2sh,
    );

    switch (case.expected) {
        .success => |want| try std.testing.expectEqual(want, try result),
        .err => |want_err| try std.testing.expectError(want_err, result),
    }
}
