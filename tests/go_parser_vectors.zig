const std = @import("std");
const bsvz = @import("bsvz");
const harness = @import("support/go_script_harness.zig");

const GoRow = struct {
    row: usize,
    name: []const u8,
    unlocking_hex: []const u8,
    locking_hex: []const u8,
    expected: harness.Expectation,
};

fn runRows(
    allocator: std.mem.Allocator,
    flags: bsvz.script.engine.ExecutionFlags,
    rows: []const GoRow,
) !void {
    for (rows) |row| {
        try harness.runCase(allocator, .{
            .name = row.name,
            .unlocking_hex = row.unlocking_hex,
            .locking_hex = row.locking_hex,
            .flags = flags,
            .expected = row.expected,
        });
    }
}

test "go direct parser rows: malformed pushdata lengths" {
    const allocator = std.testing.allocator;
    const flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    const rows = [_]GoRow{
        .{
            .row = 831,
            .name = "row 831 pushdata1 with not enough bytes",
            .unlocking_hex = "4c01",
            .locking_hex = "0161",
            .expected = .{ .err = error.InvalidPushData },
        },
        .{
            .row = 832,
            .name = "row 832 pushdata2 with not enough bytes",
            .unlocking_hex = "4d0200ff",
            .locking_hex = "0161",
            .expected = .{ .err = error.InvalidPushData },
        },
        .{
            .row = 833,
            .name = "row 833 pushdata4 with not enough bytes",
            .unlocking_hex = "4e03000000ffff",
            .locking_hex = "0161",
            .expected = .{ .err = error.InvalidPushData },
        },
    };

    try runRows(allocator, flags, &rows);
}

test "go direct parser rows: op_return tail scanning and result shapes" {
    const allocator = std.testing.allocator;
    const legacy_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    const post_genesis_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();

    const legacy_rows = [_]GoRow{
        .{
            .row = 129,
            .name = "row 129 skipped if does not hide top-level bad opcode after endif before genesis",
            .unlocking_hex = "00",
            .locking_hex = "636a68ba",
            .expected = .{ .err = error.UnknownOpcode },
        },
        .{
            .row = 131,
            .name = "row 131 executed op_return stops before bad opcode tail before genesis",
            .unlocking_hex = "51",
            .locking_hex = "63556a68ba",
            .expected = .{ .err = error.ReturnEncountered },
        },
        .{
            .row = 134,
            .name = "row 134 top-level op_return before bad opcode tail returns op_return before genesis",
            .unlocking_hex = "00",
            .locking_hex = "636a686aba",
            .expected = .{ .err = error.ReturnEncountered },
        },
        .{
            .row = 149,
            .name = "row 149 top-level op_return stops before bad opcode tail before genesis",
            .unlocking_hex = "51",
            .locking_hex = "6aba",
            .expected = .{ .err = error.ReturnEncountered },
        },
        .{
            .row = 150,
            .name = "row 150 skipped branch ignores op_return and bad opcode bytes before genesis",
            .unlocking_hex = "00",
            .locking_hex = "636aba6855",
            .expected = .{ .success = true },
        },
        .{
            .row = 151,
            .name = "row 151 executed branch hits op_return before skipped bad opcode before genesis",
            .unlocking_hex = "51",
            .locking_hex = "63556aba6855",
            .expected = .{ .err = error.ReturnEncountered },
        },
    };

    const post_genesis_rows = [_]GoRow{
        .{
            .row = 130,
            .name = "row 130 skipped if does not hide top-level bad opcode after endif after genesis",
            .unlocking_hex = "00",
            .locking_hex = "636a68ba",
            .expected = .{ .err = error.UnknownOpcode },
        },
        .{
            .row = 132,
            .name = "row 132 executed op_return stops before bad opcode tail after genesis",
            .unlocking_hex = "51",
            .locking_hex = "63556a68ba",
            .expected = .{ .success = true },
        },
        .{
            .row = 135,
            .name = "row 135 top-level op_return after skipped branch leaves false result after genesis",
            .unlocking_hex = "00",
            .locking_hex = "636a686aba",
            .expected = .{ .success = false },
        },
        .{
            .row = 137,
            .name = "row 137 top-level op_return preserves truthy stack result after genesis",
            .unlocking_hex = "00",
            .locking_hex = "636a68556aba",
            .expected = .{ .success = true },
        },
        .{
            .row = 146,
            .name = "row 146 top-level op_return still leaves unbalanced conditional state after genesis",
            .unlocking_hex = "51",
            .locking_hex = "636a6863",
            .expected = .{ .err = error.UnbalancedConditionals },
        },
    };

    try runRows(allocator, legacy_flags, &legacy_rows);
    try runRows(allocator, post_genesis_flags, &post_genesis_rows);
}
