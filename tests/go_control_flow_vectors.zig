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

test "go direct control-flow rows: compact op_return and sigpushonly" {
    const allocator = std.testing.allocator;

    const legacy_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    const post_genesis_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();
    var post_genesis_sigpushonly_flags = post_genesis_flags;
    post_genesis_sigpushonly_flags.sig_push_only = true;

    try runRows(allocator, &[_]GoRow{
        .{
            .name = "row 78 return before genesis errors",
            .unlocking_hex = "51",
            .locking_hex = "6a",
            .flags = legacy_flags,
            .expected = .{ .err = error.ReturnEncountered },
        },
        .{
            .name = "row 79 false stack plus return before genesis errors",
            .unlocking_hex = "00",
            .locking_hex = "6a",
            .flags = legacy_flags,
            .expected = .{ .err = error.ReturnEncountered },
        },
        .{
            .name = "row 80 return after genesis succeeds with true top stack",
            .unlocking_hex = "51",
            .locking_hex = "6a",
            .flags = post_genesis_flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "row 81 return after genesis yields false with false top stack",
            .unlocking_hex = "00",
            .locking_hex = "6a",
            .flags = post_genesis_flags,
            .expected = .{ .success = false },
        },
        .{
            .name = "row 84 unlocking script op_return is sigpushonly violation after genesis",
            .unlocking_hex = "516a",
            .locking_hex = "51",
            .flags = post_genesis_sigpushonly_flags,
            .expected = .{ .err = error.SigPushOnly },
        },
        .{
            .name = "row 85 return if before genesis errors",
            .unlocking_hex = "51",
            .locking_hex = "6a63",
            .flags = legacy_flags,
            .expected = .{ .err = error.ReturnEncountered },
        },
        .{
            .name = "row 86 return if after genesis succeeds",
            .unlocking_hex = "51",
            .locking_hex = "6a63",
            .flags = post_genesis_flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "row 87 return data before genesis errors",
            .unlocking_hex = "51",
            .locking_hex = "6a01ba",
            .flags = legacy_flags,
            .expected = .{ .err = error.ReturnEncountered },
        },
    });
}

test "go direct script rows: false control-flow result shapes" {
    const allocator = std.testing.allocator;

    try runRows(allocator, &[_]GoRow{
        .{ .name = "row 45 dup if endif over one succeeds", .unlocking_hex = "51", .locking_hex = "766368", .flags = bsvz.script.engine.ExecutionFlags.legacyReference(), .expected = .{ .success = true } },
        .{ .name = "row 46 if one endif over one succeeds", .unlocking_hex = "51", .locking_hex = "635168", .flags = bsvz.script.engine.ExecutionFlags.legacyReference(), .expected = .{ .success = true } },
        .{ .name = "row 47 dup if else endif over one succeeds", .unlocking_hex = "51", .locking_hex = "76636768", .flags = bsvz.script.engine.ExecutionFlags.legacyReference(), .expected = .{ .success = true } },
        .{ .name = "row 48 if one else endif over one succeeds", .unlocking_hex = "51", .locking_hex = "63516768", .flags = bsvz.script.engine.ExecutionFlags.legacyReference(), .expected = .{ .success = true } },
        .{ .name = "row 49 if else one endif over zero succeeds", .unlocking_hex = "00", .locking_hex = "63675168", .flags = bsvz.script.engine.ExecutionFlags.legacyReference(), .expected = .{ .success = true } },
        .{ .name = "dup if endif over zero leaves false result", .unlocking_hex = "00", .locking_hex = "766368", .flags = bsvz.script.engine.ExecutionFlags.legacyReference(), .expected = .{ .success = false } },
        .{ .name = "if true branch guarded by zero leaves false result", .unlocking_hex = "00", .locking_hex = "635168", .flags = bsvz.script.engine.ExecutionFlags.legacyReference(), .expected = .{ .success = false } },
        .{ .name = "dup if else endif over zero leaves false result", .unlocking_hex = "00", .locking_hex = "76636768", .flags = bsvz.script.engine.ExecutionFlags.legacyReference(), .expected = .{ .success = false } },
        .{ .name = "if else endif over zero leaves false result", .unlocking_hex = "00", .locking_hex = "63516768", .flags = bsvz.script.engine.ExecutionFlags.legacyReference(), .expected = .{ .success = false } },
        .{ .name = "notif else one endif over zero still leaves false result", .unlocking_hex = "00", .locking_hex = "64675168", .flags = bsvz.script.engine.ExecutionFlags.legacyReference(), .expected = .{ .success = false } },
    });
}

test "go direct script rows: compact op_return post-genesis rows" {
    const allocator = std.testing.allocator;
    const legacy_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    const post_genesis_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();

    try runRows(allocator, &[_]GoRow{
        .{ .name = "legacy dup if return endif errors", .unlocking_hex = "51", .locking_hex = "76636a68", .flags = legacy_flags, .expected = .{ .err = error.ReturnEncountered } },
        .{ .name = "legacy return data errors", .unlocking_hex = "51", .locking_hex = "6a0464617461", .flags = legacy_flags, .expected = .{ .err = error.ReturnEncountered } },
        .{ .name = "post-genesis dup if return endif succeeds from top stack", .unlocking_hex = "51", .locking_hex = "76636a68", .flags = post_genesis_flags, .expected = .{ .success = true } },
        .{ .name = "post-genesis return data succeeds from top stack", .unlocking_hex = "51", .locking_hex = "6a0464617461", .flags = post_genesis_flags, .expected = .{ .success = true } },
    });
}

test "go direct script rows: legacy versus post-genesis multiple else" {
    const allocator = std.testing.allocator;
    const legacy_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    const post_genesis_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();

    try runRows(allocator, &[_]GoRow{
        .{ .name = "legacy multiple else inverts execution when if branch is false", .unlocking_hex = "00", .locking_hex = "63006751670068", .flags = legacy_flags, .expected = .{ .success = true } },
        .{ .name = "post-genesis multiple else is unbalanced when if branch is false", .unlocking_hex = "00", .locking_hex = "63006751670068", .flags = post_genesis_flags, .expected = .{ .err = error.UnbalancedConditionals } },
        .{ .name = "legacy multiple else inverts execution when if branch is true", .unlocking_hex = "51", .locking_hex = "635167006768", .flags = legacy_flags, .expected = .{ .success = true } },
        .{ .name = "post-genesis multiple else is unbalanced when if branch is true", .unlocking_hex = "51", .locking_hex = "635167006768", .flags = post_genesis_flags, .expected = .{ .err = error.UnbalancedConditionals } },
        .{ .name = "legacy multiple else with empty first branch still reaches final true branch", .unlocking_hex = "51", .locking_hex = "636700675168", .flags = legacy_flags, .expected = .{ .success = true } },
        .{ .name = "post-genesis multiple else with empty first branch is unbalanced", .unlocking_hex = "51", .locking_hex = "636700675168", .flags = post_genesis_flags, .expected = .{ .err = error.UnbalancedConditionals } },
    });
}

test "go direct script rows: nested else else legacy versus post-genesis" {
    const allocator = std.testing.allocator;
    const legacy_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    const post_genesis_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();

    try runRows(allocator, &[_]GoRow{
        .{ .name = "legacy nested else else succeeds for outer false path", .unlocking_hex = "00", .locking_hex = "6351636a676a676a6867516351676a675168676a68935287", .flags = legacy_flags, .expected = .{ .success = true } },
        .{ .name = "post-genesis nested else else is unbalanced for outer false path", .unlocking_hex = "00", .locking_hex = "6351636a676a676a6867516351676a675168676a68935287", .flags = post_genesis_flags, .expected = .{ .err = error.UnbalancedConditionals } },
        .{ .name = "legacy nested else else succeeds for outer true notif path", .unlocking_hex = "51", .locking_hex = "6400646a676a676a6867006451676a675168676a68935287", .flags = legacy_flags, .expected = .{ .success = true } },
        .{ .name = "post-genesis nested else else is unbalanced for outer true notif path", .unlocking_hex = "51", .locking_hex = "6400646a676a676a6867006451676a675168676a68935287", .flags = post_genesis_flags, .expected = .{ .err = error.UnbalancedConditionals } },
    });
}

test "go direct script rows: op_return in different branches" {
    const allocator = std.testing.allocator;
    const legacy_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    const post_genesis_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();

    try runRows(allocator, &[_]GoRow{
        .{ .name = "legacy branch-selected op_return still errors", .unlocking_hex = "00", .locking_hex = "636a05646174613167516a05646174613268", .flags = legacy_flags, .expected = .{ .err = error.ReturnEncountered } },
        .{ .name = "post-genesis branch-selected op_return keeps success when else branch pushes one first", .unlocking_hex = "00", .locking_hex = "636a05646174613167516a05646174613268", .flags = post_genesis_flags, .expected = .{ .success = true } },
    });
}
