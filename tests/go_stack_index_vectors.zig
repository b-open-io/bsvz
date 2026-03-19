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

test "go direct script rows: pick parity" {
    const allocator = std.testing.allocator;

    try runRows(allocator, bsvz.script.engine.ExecutionFlags.legacyReference(), &[_]GoRow{
        .{ .row = 435, .name = "pick with index three reads the deepest stack item", .unlocking_hex = "5100000053", .locking_hex = "79", .expected = .{ .success = true } },
        .{ .row = 436, .name = "pick with index zero duplicates the current top item", .unlocking_hex = "5100", .locking_hex = "79", .expected = .{ .success = true } },
        .{ .row = 198, .name = "pick index zero reads stack top without changing depth", .unlocking_hex = "011601150114", .locking_hex = "0079011488745387", .expected = .{ .success = true } },
        .{ .row = 199, .name = "pick index one reads second stack item", .unlocking_hex = "011601150114", .locking_hex = "5179011588745387", .expected = .{ .success = true } },
        .{ .row = 200, .name = "pick index two reads third stack item", .unlocking_hex = "011601150114", .locking_hex = "5279011688745387", .expected = .{ .success = true } },
        .{ .row = 611, .name = "pick with minimally encoded index succeeds", .unlocking_hex = "51020000", .locking_hex = "7975", .expected = .{ .success = true } },
    });

    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.minimal_data = true;

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 1262, .name = "pick rejects non-minimally encoded index under minimaldata", .unlocking_hex = "51020000", .locking_hex = "7975", .expected = .{ .err = error.MinimalData } },
    });
}

test "go direct script rows: roll parity" {
    const allocator = std.testing.allocator;

    try runRows(allocator, bsvz.script.engine.ExecutionFlags.legacyReference(), &[_]GoRow{
        .{ .row = 437, .name = "roll with index three rotates the deepest stack item to the top", .unlocking_hex = "5100000053", .locking_hex = "7a", .expected = .{ .success = true } },
        .{ .row = 438, .name = "roll with index zero removes and re-pushes the current top item", .unlocking_hex = "5100", .locking_hex = "7a", .expected = .{ .success = true } },
        .{ .row = 201, .name = "roll index zero preserves top item and reduces depth", .unlocking_hex = "011601150114", .locking_hex = "007a011488745287", .expected = .{ .success = true } },
        .{ .row = 202, .name = "roll index one rotates second stack item to the top", .unlocking_hex = "011601150114", .locking_hex = "517a011588745287", .expected = .{ .success = true } },
        .{ .row = 203, .name = "roll index two rotates third stack item to the top", .unlocking_hex = "011601150114", .locking_hex = "527a011688745287", .expected = .{ .success = true } },
        .{ .row = 612, .name = "roll with minimally encoded index succeeds", .unlocking_hex = "51020000", .locking_hex = "7a7551", .expected = .{ .success = true } },
    });

    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.minimal_data = true;

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 1263, .name = "roll rejects non-minimally encoded index under minimaldata", .unlocking_hex = "51020000", .locking_hex = "7a7551", .expected = .{ .err = error.MinimalData } },
    });
}

test "go direct script rows: stack-index invalid operations" {
    const allocator = std.testing.allocator;
    const flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 1413, .name = "pick rejects out-of-range positive index", .unlocking_hex = "51515153", .locking_hex = "79", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 1414, .name = "pick requires an index operand", .unlocking_hex = "00", .locking_hex = "7951", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 1415, .name = "roll rejects out-of-range positive index", .unlocking_hex = "51515153", .locking_hex = "7a", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 1416, .name = "roll requires an index operand", .unlocking_hex = "00", .locking_hex = "7a51", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 1417, .name = "rot requires three stack items", .unlocking_hex = "5151", .locking_hex = "7b", .expected = .{ .err = error.StackUnderflow } },
    });
}
