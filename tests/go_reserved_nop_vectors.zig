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
            .name = "verif opcode in skipped branch still fails before genesis",
            .unlocking_hex = "00",
            .locking_hex = "6365675168",
            .flags = legacy_flags,
            .expected = .{ .err = error.UnknownOpcode },
        },
        .{
            .name = "vernotif opcode in skipped branch still fails before genesis",
            .unlocking_hex = "00",
            .locking_hex = "6366675168",
            .flags = legacy_flags,
            .expected = .{ .err = error.UnknownOpcode },
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

test "nop family and cltv csv aliases behave as no-ops in the current BSV profile" {
    const allocator = std.testing.allocator;
    const flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();

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

test "discourage_upgradable_nops rejects executed nop soft-fork surface" {
    const allocator = std.testing.allocator;
    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.discourage_upgradable_nops = true;

    try runRows(allocator, &[_]GoRow{
        .{
            .name = "nop1 is rejected when discourage_upgradable_nops is enabled",
            .unlocking_hex = "51",
            .locking_hex = "b0",
            .flags = flags,
            .expected = .{ .err = error.DiscourageUpgradableNops },
        },
        .{
            .name = "cltv alias is rejected as nop2 when discourage_upgradable_nops is enabled",
            .unlocking_hex = "51",
            .locking_hex = "b1",
            .flags = flags,
            .expected = .{ .err = error.DiscourageUpgradableNops },
        },
        .{
            .name = "csv alias is rejected as nop3 when discourage_upgradable_nops is enabled",
            .unlocking_hex = "51",
            .locking_hex = "b2",
            .flags = flags,
            .expected = .{ .err = error.DiscourageUpgradableNops },
        },
        .{
            .name = "nop4 is rejected when discourage_upgradable_nops is enabled",
            .unlocking_hex = "51",
            .locking_hex = "b3",
            .flags = flags,
            .expected = .{ .err = error.DiscourageUpgradableNops },
        },
        .{
            .name = "nop5 is rejected when discourage_upgradable_nops is enabled",
            .unlocking_hex = "51",
            .locking_hex = "b4",
            .flags = flags,
            .expected = .{ .err = error.DiscourageUpgradableNops },
        },
        .{
            .name = "nop6 is rejected when discourage_upgradable_nops is enabled",
            .unlocking_hex = "51",
            .locking_hex = "b5",
            .flags = flags,
            .expected = .{ .err = error.DiscourageUpgradableNops },
        },
        .{
            .name = "nop7 is rejected when discourage_upgradable_nops is enabled",
            .unlocking_hex = "51",
            .locking_hex = "b6",
            .flags = flags,
            .expected = .{ .err = error.DiscourageUpgradableNops },
        },
        .{
            .name = "nop8 is rejected when discourage_upgradable_nops is enabled",
            .unlocking_hex = "51",
            .locking_hex = "b7",
            .flags = flags,
            .expected = .{ .err = error.DiscourageUpgradableNops },
        },
        .{
            .name = "nop9 is rejected when discourage_upgradable_nops is enabled",
            .unlocking_hex = "51",
            .locking_hex = "b8",
            .flags = flags,
            .expected = .{ .err = error.DiscourageUpgradableNops },
        },
        .{
            .name = "nop10 is rejected when discourage_upgradable_nops is enabled",
            .unlocking_hex = "51",
            .locking_hex = "b9",
            .flags = flags,
            .expected = .{ .err = error.DiscourageUpgradableNops },
        },
    });
}

test "discourage_upgradable_nops does not fire for untaken branches" {
    const allocator = std.testing.allocator;

    var flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();
    flags.discourage_upgradable_nops = true;

    try runRows(allocator, &[_]GoRow{
        .{
            .name = "skipped nop1 does not trigger discourage_upgradable_nops",
            .unlocking_hex = "00",
            .locking_hex = "63b06851",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "skipped cltv alias does not trigger discourage_upgradable_nops",
            .unlocking_hex = "00",
            .locking_hex = "63b16851",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "skipped csv alias does not trigger discourage_upgradable_nops",
            .unlocking_hex = "00",
            .locking_hex = "63b26851",
            .flags = flags,
            .expected = .{ .success = true },
        },
    });
}

test "legacy reference flags can activate cltv and csv instead of treating them as nops" {
    const allocator = std.testing.allocator;

    var cltv_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    cltv_flags.verify_check_locktime = true;
    try runRows(allocator, &[_]GoRow{
        .{
            .name = "legacy cltv succeeds when tx lock_time satisfies the operand",
            .unlocking_hex = "",
            .locking_hex = "00b151",
            .flags = cltv_flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "legacy cltv fails when tx lock_time is lower than the operand",
            .unlocking_hex = "",
            .locking_hex = "51b151",
            .flags = cltv_flags,
            .expected = .{ .err = error.UnsatisfiedLockTime },
        },
    });

    var csv_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    csv_flags.verify_check_sequence = true;
    try runRows(allocator, &[_]GoRow{
        .{
            .name = "legacy csv fails when tx sequence disables relative locktime",
            .unlocking_hex = "",
            .locking_hex = "00b251",
            .flags = csv_flags,
            .expected = .{ .err = error.UnsatisfiedLockTime },
        },
    });
}
