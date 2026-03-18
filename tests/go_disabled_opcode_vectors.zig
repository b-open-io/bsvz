const std = @import("std");
const bsvz = @import("bsvz");
const harness = @import("support/go_script_harness.zig");

const GoRow = struct {
    row: ?usize = null,
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

test "go direct script rows: executed and skipped disabled opcode precedence" {
    const allocator = std.testing.allocator;
    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.strict_encoding = true;

    try harness.runCase(allocator, .{
        .name = "executed vernotif remains a bad opcode",
        .unlocking_hex = "51",
        .locking_hex = "6366675168",
        .flags = flags,
        .expected = .{ .err = error.UnknownOpcode },
    });

    var post_genesis_flags = flags;
    post_genesis_flags.utxo_after_genesis = true;

    try harness.runCase(allocator, .{
        .name = "multiple else beats later vernotif after genesis",
        .unlocking_hex = "51",
        .locking_hex = "636751676668",
        .flags = post_genesis_flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });

    try harness.runCase(allocator, .{
        .name = "skipped disabled opcode in untaken branch is still ok",
        .unlocking_hex = "00",
        .locking_hex = "63ec675168",
        .flags = flags,
        .expected = .{ .success = true },
    });
}

test "go direct script rows: skipped disabled opcode exact row" {
    const allocator = std.testing.allocator;
    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.strict_encoding = true;

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 353, .name = "if disabled opcode in untaken branch remains ok", .unlocking_hex = "00", .locking_hex = "63ec675168", .expected = .{ .success = true } },
    });

    try harness.runCase(allocator, .{
        .name = "if disabled 2div in untaken branch remains ok after genesis",
        .unlocking_hex = "5200",
        .locking_hex = "639668",
        .flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv(),
        .expected = .{ .success = true },
    });
}

test "go direct script rows: small integer opcode push sanity" {
    const allocator = std.testing.allocator;

    try runRows(allocator, bsvz.script.engine.ExecutionFlags.legacyReference(), &[_]GoRow{
        .{ .row = 552, .name = "op_10 pushes byte 0x0a", .unlocking_hex = "010a", .locking_hex = "5a87", .expected = .{ .success = true } },
    });
}
