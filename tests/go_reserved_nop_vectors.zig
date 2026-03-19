const std = @import("std");
const bsvz = @import("bsvz");
const harness = @import("support/go_script_harness.zig");

const GoRow = struct {
    row: ?usize = null,
    name: []const u8,
    unlocking_hex: []const u8,
    locking_hex: []const u8,
    flags: bsvz.script.engine.ExecutionFlags,
    expected: harness.Expectation,
    tx_version: i32 = 2,
    tx_lock_time: u32 = 0,
    input_sequence: u32 = 0xffff_fffe,
};

fn runRows(allocator: std.mem.Allocator, rows: []const GoRow) !void {
    for (rows) |row| {
        try harness.runCase(allocator, .{
            .name = row.name,
            .unlocking_hex = row.unlocking_hex,
            .locking_hex = row.locking_hex,
            .flags = row.flags,
            .expected = row.expected,
            .tx_version = row.tx_version,
            .tx_lock_time = row.tx_lock_time,
            .input_sequence = row.input_sequence,
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
    const legacy_flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    try runRows(allocator, &[_]GoRow{
        .{
            .name = "nop and locktime aliases preserve one in the permissive legacy profile",
            .unlocking_hex = "51",
            .locking_hex = "b0b1b2b3b4b5b6b7b8b95187",
            .flags = legacy_flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "nop and locktime aliases preserve the exact marker string in the permissive legacy profile",
            .unlocking_hex = "0b4e4f505f315f746f5f3130b0b1b2b3b4b5b6b7b8b9",
            .locking_hex = "0b4e4f505f315f746f5f313087",
            .flags = legacy_flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "cltv alias acts as a nop when the verify flag is off",
            .unlocking_hex = "61",
            .locking_hex = "b151",
            .flags = legacy_flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "csv alias acts as a nop when the verify flag is off",
            .unlocking_hex = "61",
            .locking_hex = "b251",
            .flags = legacy_flags,
            .expected = .{ .success = true },
        },
        .{
            .row = 471,
            .name = "row 471 codeseparator followed by one stays a permissive success path",
            .unlocking_hex = "61",
            .locking_hex = "ab51",
            .flags = legacy_flags,
            .expected = .{ .success = true },
        },
        .{
            .row = 472,
            .name = "row 472 nop1 followed by one stays a permissive success path",
            .unlocking_hex = "61",
            .locking_hex = "b051",
            .flags = legacy_flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "nop and locktime aliases compare false against two in the permissive legacy profile",
            .unlocking_hex = "51",
            .locking_hex = "b0b1b2b3b4b5b6b7b8b95287",
            .flags = legacy_flags,
            .expected = .{ .success = false },
        },
        .{
            .name = "nop and locktime aliases compare false against a different marker string",
            .unlocking_hex = "0b4e4f505f315f746f5f3130b0b1b2b3b4b5b6b7b8b9",
            .locking_hex = "0b4e4f505f315f746f5f313187",
            .flags = legacy_flags,
            .expected = .{ .success = false },
        },
        .{
            .name = "cltv is discouraged when discourage upgradable nops is enabled",
            .unlocking_hex = "51",
            .locking_hex = "b1",
            .flags = blk: {
                var discourage = bsvz.script.engine.ExecutionFlags.legacyReference();
                discourage.discourage_upgradable_nops = true;
                break :blk discourage;
            },
            .expected = .{ .err = error.DiscourageUpgradableNops },
        },
        .{
            .name = "csv is discouraged when discourage upgradable nops is enabled",
            .unlocking_hex = "51",
            .locking_hex = "b2",
            .flags = blk: {
                var discourage = bsvz.script.engine.ExecutionFlags.legacyReference();
                discourage.discourage_upgradable_nops = true;
                break :blk discourage;
            },
            .expected = .{ .err = error.DiscourageUpgradableNops },
        },
        .{
            .name = "plain nop behaves as a no-op",
            .unlocking_hex = "",
            .locking_hex = "6151",
            .flags = flags,
            .expected = .{ .success = true },
        },
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
        .{
            .name = "nop aliases fail equality against two before genesis",
            .unlocking_hex = "51",
            .locking_hex = "b0b1b2b3b4b5b6b7b8b95287",
            .flags = legacy_flags,
            .expected = .{ .success = false },
        },
        .{
            .name = "nop aliases fail equality against alternate marker string",
            .unlocking_hex = "0b4e4f505f315f746f5f3130b0b1b2b3b4b5b6b7b8b9",
            .locking_hex = "0b4e4f505f315f746f5f313187",
            .flags = legacy_flags,
            .expected = .{ .success = false },
        },
        .{
            .name = "go row 1237 nop1 through nop10 chain fails equality against two before genesis",
            .unlocking_hex = "51",
            .locking_hex = "b0b1b2b3b4b5b6b7b8b95287",
            .flags = legacy_flags,
            .expected = .{ .success = false },
        },
        .{
            .name = "go row 1238 nop1 through nop10 chain fails equality against alternate marker string",
            .unlocking_hex = "0b4e4f505f315f746f5f3130b0b1b2b3b4b5b6b7b8b9",
            .locking_hex = "0b4e4f505f315f746f5f313187",
            .flags = legacy_flags,
            .expected = .{ .success = false },
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
        .{
            .name = "go row 1252 discouraged nop10 in unlocking script",
            .unlocking_hex = "b9",
            .locking_hex = "51",
            .flags = flags,
            .expected = .{ .err = error.DiscourageUpgradableNops },
        },
    });
}

test "go exact discourage_upgradable_nops rows keep nop semantics narrow" {
    const allocator = std.testing.allocator;
    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.discourage_upgradable_nops = true;

    try runRows(allocator, &[_]GoRow{
        .{
            .name = "go row 348 discourage_upgradable_nops still allows plain nop",
            .unlocking_hex = "51",
            .locking_hex = "61",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "go row 350 discourage_upgradable_nops does not fire for untaken nop10",
            .unlocking_hex = "00",
            .locking_hex = "63b96851",
            .flags = flags,
            .expected = .{ .success = true },
        },
    });
}

test "go exact nop alias rows treat cltv csv and nopx as no-ops when verify flags are off" {
    const allocator = std.testing.allocator;
    const flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    try runRows(allocator, &[_]GoRow{
        .{
            .name = "go row 554 nop in unlocking script still allows nop1 in locking script",
            .unlocking_hex = "61",
            .locking_hex = "b051",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "go row 556 nop in unlocking script still allows csv alias in locking script",
            .unlocking_hex = "61",
            .locking_hex = "b251",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "go row 557 nop in unlocking script still allows nop4 in locking script",
            .unlocking_hex = "61",
            .locking_hex = "b351",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "go row 558 nop in unlocking script still allows nop5 in locking script",
            .unlocking_hex = "61",
            .locking_hex = "b451",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "go row 559 nop in unlocking script still allows nop6 in locking script",
            .unlocking_hex = "61",
            .locking_hex = "b551",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "go row 560 nop in unlocking script still allows nop7 in locking script",
            .unlocking_hex = "61",
            .locking_hex = "b651",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "go row 561 nop in unlocking script still allows nop8 in locking script",
            .unlocking_hex = "61",
            .locking_hex = "b751",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "go row 562 nop in unlocking script still allows nop9 in locking script",
            .unlocking_hex = "61",
            .locking_hex = "b851",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "go row 563 nop in unlocking script still allows nop10 in locking script",
            .unlocking_hex = "61",
            .locking_hex = "b951",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "go row 1373 nop aliases compare false against a different nop alias",
            .unlocking_hex = "b0",
            .locking_hex = "b9",
            .flags = flags,
            .expected = .{ .success = false },
        },
    });
}

test "go csv corpus rows map onto the legacy verify_check_sequence surface" {
    const allocator = std.testing.allocator;
    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.verify_check_sequence = true;

    var minimal_flags = flags;
    minimal_flags.minimal_data = true;

    try runRows(allocator, &[_]GoRow{
        .{
            .name = "go row 2345 csv fails on empty stack",
            .unlocking_hex = "",
            .locking_hex = "b2",
            .flags = flags,
            .expected = .{ .err = error.StackUnderflow },
        },
        .{
            .name = "go row 2346 csv fails on negative operand",
            .unlocking_hex = "4f",
            .locking_hex = "b2",
            .flags = flags,
            .expected = .{ .err = error.NegativeLockTime },
        },
        .{
            .name = "go row 2347 csv enforces minimal encoding on operand",
            .unlocking_hex = "020100",
            .locking_hex = "b2",
            .flags = minimal_flags,
            .expected = .{ .err = error.MinimalData },
        },
        .{
            .name = "go row 2348 csv fails when tx version is below two",
            .unlocking_hex = "00",
            .locking_hex = "b2",
            .flags = flags,
            .expected = .{ .err = error.UnsatisfiedLockTime },
            .tx_version = 1,
        },
        .{
            .name = "go row 2349 csv fails when operand exceeds uint32",
            .unlocking_hex = "050000000001",
            .locking_hex = "b2",
            .flags = flags,
            .expected = .{ .err = error.UnsatisfiedLockTime },
        },
        .{
            .name = "go row 676 csv passes when the disable flag bit is set in the operand",
            .unlocking_hex = "050000008000",
            .locking_hex = "b2",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "go row 814 csv passes when the disable flag bit is set in the operand",
            .unlocking_hex = "050000008000",
            .locking_hex = "b2",
            .flags = flags,
            .expected = .{ .success = true },
        },
    });
}

test "go row 1495 script-sig push-only policy rejects nop in unlocking script" {
    const allocator = std.testing.allocator;
    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.sig_push_only = true;

    try runRows(allocator, &[_]GoRow{
        .{
            .name = "go row 1495 sig_push_only rejects nop1 in unlocking script",
            .unlocking_hex = "b0010151",
            .locking_hex = "a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87",
            .flags = flags,
            .expected = .{ .err = error.SigPushOnly },
        },
    });
}

test "post-genesis bsv still treats cltv and csv as nops even if verify flags are enabled" {
    const allocator = std.testing.allocator;

    var flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();
    flags.verify_check_locktime = true;
    flags.verify_check_sequence = true;

    try runRows(allocator, &[_]GoRow{
        .{
            .name = "post-genesis cltv ignores verify_check_locktime and behaves as nop",
            .unlocking_hex = "",
            .locking_hex = "51b151",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "post-genesis csv ignores verify_check_sequence and behaves as nop",
            .unlocking_hex = "",
            .locking_hex = "51b251",
            .flags = flags,
            .expected = .{ .success = true },
        },
    });
}

test "post-genesis discourage_upgradable_nops still rejects cltv and csv even if verify flags are enabled" {
    const allocator = std.testing.allocator;

    var flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();
    flags.discourage_upgradable_nops = true;
    flags.verify_check_locktime = true;
    flags.verify_check_sequence = true;

    try runRows(allocator, &[_]GoRow{
        .{
            .name = "post-genesis cltv is still rejected as nop2 when discourage_upgradable_nops is enabled",
            .unlocking_hex = "51",
            .locking_hex = "b1",
            .flags = flags,
            .expected = .{ .err = error.DiscourageUpgradableNops },
        },
        .{
            .name = "post-genesis csv is still rejected as nop3 when discourage_upgradable_nops is enabled",
            .unlocking_hex = "51",
            .locking_hex = "b2",
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
