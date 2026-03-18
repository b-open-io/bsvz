const std = @import("std");
const bsvz = @import("bsvz");

const Script = bsvz.script.Script;

pub const Expectation = union(enum) {
    success: bool,
    err: anyerror,
};

pub const Case = struct {
    name: []const u8,
    unlocking_hex: []const u8,
    locking_hex: []const u8,
    flags: bsvz.script.engine.ExecutionFlags,
    expected: Expectation,
    previous_satoshis: i64 = 1_000,
};

pub fn runCase(allocator: std.mem.Allocator, case: Case) !void {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const unlocking_bytes = try decodeScriptHex(arena, case.unlocking_hex);
    const locking_bytes = try decodeScriptHex(arena, case.locking_hex);

    const unlocking_script = Script.init(unlocking_bytes);
    const locking_script = Script.init(locking_bytes);

    var inputs = [_]bsvz.transaction.Input{
        .{
            .previous_outpoint = .{
                .txid = .{ .bytes = [_]u8{0x42} ** 32 },
                .index = 0,
            },
            .unlocking_script = Script.init(""),
            .sequence = 0xffff_fffe,
        },
    };
    var outputs = [_]bsvz.transaction.Output{
        .{
            .satoshis = case.previous_satoshis - 1,
            .locking_script = locking_script,
        },
    };
    const tx = bsvz.transaction.Transaction{
        .version = 2,
        .inputs = &inputs,
        .outputs = &outputs,
        .lock_time = 0,
    };

    var exec_ctx = bsvz.script.engine.ExecutionContext.forSpend(
        allocator,
        &tx,
        0,
        case.previous_satoshis,
    );
    exec_ctx.previous_locking_script = locking_script;
    exec_ctx.flags = case.flags;

    const result = bsvz.script.thread.verifyScripts(exec_ctx, unlocking_script, locking_script);

    switch (case.expected) {
        .success => |want| try std.testing.expectEqual(want, try result),
        .err => |want_err| try std.testing.expectError(want_err, result),
    }
}

fn decodeScriptHex(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    var normalized: std.ArrayListUnmanaged(u8) = .empty;
    defer normalized.deinit(allocator);

    var index: usize = 0;
    while (index < text.len) {
        const ch = text[index];
        if (std.ascii.isWhitespace(ch) or ch == ',') {
            index += 1;
            continue;
        }
        if (ch == '0' and index + 1 < text.len and (text[index + 1] == 'x' or text[index + 1] == 'X')) {
            index += 2;
            continue;
        }

        try normalized.append(allocator, ch);
        index += 1;
    }

    return bsvz.primitives.hex.decode(allocator, normalized.items);
}
