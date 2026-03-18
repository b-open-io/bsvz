const std = @import("std");
const bsvz = @import("bsvz");
const harness = @import("support/go_script_harness.zig");

const GoRow = struct {
    name: []const u8,
    unlocking_hex: []const u8,
    locking_hex: []const u8,
    flags: bsvz.script.engine.ExecutionFlags,
    expected: harness.Expectation,
};

fn runRows(allocator: std.mem.Allocator, rows: []const GoRow) !void {
    for (rows) |row| {
        try harness.runCase(allocator, .{
            .name = row.name,
            .unlocking_hex = row.unlocking_hex,
            .locking_hex = row.locking_hex,
            .flags = row.flags,
            .expected = row.expected,
        });
    }
}

test "reserved and version opcodes fail when executed and do not affect skipped branches" {
    const allocator = std.testing.allocator;

    const legacy_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    var post_genesis_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();
    post_genesis_flags.strict_encoding = false;

    try runRows(allocator, &[_]GoRow{
        .{
            .name = "reserved opcode in skipped branch does not affect legacy success path",
            .unlocking_hex = "00",
            .locking_hex = "6350675168",
            .flags = legacy_flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "ver opcode in skipped branch does not affect post-genesis success path",
            .unlocking_hex = "00",
            .locking_hex = "6362675168",
            .flags = post_genesis_flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "verif opcode in skipped branch does not affect post-genesis success path",
            .unlocking_hex = "00",
            .locking_hex = "6365675168",
            .flags = post_genesis_flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "vernotif opcode in skipped branch does not affect post-genesis success path",
            .unlocking_hex = "00",
            .locking_hex = "6366675168",
            .flags = post_genesis_flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "reserved1 and reserved2 in skipped branch do not affect success path",
            .unlocking_hex = "00",
            .locking_hex = "63898a675168",
            .flags = post_genesis_flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "ver opcode fails when executed",
            .unlocking_hex = "51",
            .locking_hex = "62",
            .flags = post_genesis_flags,
            .expected = .{ .err = error.UnknownOpcode },
        },
        .{
            .name = "reserved opcode fails when executed",
            .unlocking_hex = "51",
            .locking_hex = "50",
            .flags = post_genesis_flags,
            .expected = .{ .err = error.UnknownOpcode },
        },
        .{
            .name = "reserved1 opcode fails when executed",
            .unlocking_hex = "51",
            .locking_hex = "89",
            .flags = post_genesis_flags,
            .expected = .{ .err = error.UnknownOpcode },
        },
        .{
            .name = "reserved2 opcode fails when executed",
            .unlocking_hex = "51",
            .locking_hex = "8a",
            .flags = post_genesis_flags,
            .expected = .{ .err = error.UnknownOpcode },
        },
        .{
            .name = "verif opcode fails when selected by condition",
            .unlocking_hex = "51",
            .locking_hex = "6365675168",
            .flags = post_genesis_flags,
            .expected = .{ .err = error.UnknownOpcode },
        },
        .{
            .name = "vernotif opcode fails when selected by condition",
            .unlocking_hex = "51",
            .locking_hex = "6366675168",
            .flags = post_genesis_flags,
            .expected = .{ .err = error.UnknownOpcode },
        },
    });
}

test "nop family and cltv csv aliases currently behave as no-ops" {
    const allocator = std.testing.allocator;
    const flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    try runRows(allocator, &[_]GoRow{
        .{
            .name = "nop family chain preserves success path",
            .unlocking_hex = "51",
            .locking_hex = "b0b1b2b3b4b5b6b7b8b95187",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "nop1 behaves as a no-op",
            .unlocking_hex = "61",
            .locking_hex = "b051",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "cltv alias currently behaves as a no-op",
            .unlocking_hex = "61",
            .locking_hex = "b151",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "csv alias currently behaves as a no-op",
            .unlocking_hex = "61",
            .locking_hex = "b251",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "nop4 behaves as a no-op",
            .unlocking_hex = "61",
            .locking_hex = "b351",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "nop5 behaves as a no-op",
            .unlocking_hex = "61",
            .locking_hex = "b451",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "nop6 behaves as a no-op",
            .unlocking_hex = "61",
            .locking_hex = "b551",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "nop7 behaves as a no-op",
            .unlocking_hex = "61",
            .locking_hex = "b651",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "nop8 behaves as a no-op",
            .unlocking_hex = "61",
            .locking_hex = "b751",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "nop9 behaves as a no-op",
            .unlocking_hex = "61",
            .locking_hex = "b851",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "nop10 behaves as a no-op",
            .unlocking_hex = "61",
            .locking_hex = "b951",
            .flags = flags,
            .expected = .{ .success = true },
        },
    });
}
