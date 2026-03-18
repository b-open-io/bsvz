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
