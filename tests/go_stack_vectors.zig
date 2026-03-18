const std = @import("std");
const bsvz = @import("bsvz");
const harness = @import("support/go_script_harness.zig");

const GoRow = struct {
    name: []const u8,
    unlocking_hex: []const u8,
    locking_hex: []const u8,
    expected: harness.Expectation,
};

fn runRows(allocator: std.mem.Allocator, rows: []const GoRow) !void {
    const flags = bsvz.script.engine.ExecutionFlags.legacyReference();
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

test "go direct stack rows: safe positive stack-shape subset" {
    const allocator = std.testing.allocator;

    try runRows(allocator, &[_]GoRow{
        .{
            .name = "row 152 ifdup leaves zero unduplicated",
            .unlocking_hex = "0073",
            .locking_hex = "7451880087",
            .expected = .{ .success = true },
        },
        .{
            .name = "row 153 ifdup duplicates one",
            .unlocking_hex = "5173",
            .locking_hex = "74528851875187",
            .expected = .{ .success = true },
        },
        .{
            .name = "row 155 drop empties stack",
            .unlocking_hex = "0075",
            .locking_hex = "740087",
            .expected = .{ .success = true },
        },
        .{
            .name = "row 423 twodrop accepts two items",
            .unlocking_hex = "0000",
            .locking_hex = "6d51",
            .expected = .{ .success = true },
        },
        .{
            .name = "row 424 twodup duplicates two items",
            .unlocking_hex = "0051",
            .locking_hex = "6e",
            .expected = .{ .success = true },
        },
        .{
            .name = "row 429 ifdup duplicates truthy item",
            .unlocking_hex = "51",
            .locking_hex = "73",
            .expected = .{ .success = true },
        },
    });
}

test "go direct stack rows: safe underflow subset" {
    const allocator = std.testing.allocator;

    try runRows(allocator, &[_]GoRow{
        .{
            .name = "row 744 ifdup underflows on empty stack",
            .unlocking_hex = "",
            .locking_hex = "73",
            .expected = .{ .err = error.StackUnderflow },
        },
        .{
            .name = "row 745 drop underflows on empty stack",
            .unlocking_hex = "",
            .locking_hex = "75",
            .expected = .{ .err = error.StackUnderflow },
        },
        .{
            .name = "row 1159 twodrop on one item errors",
            .unlocking_hex = "51",
            .locking_hex = "6d51",
            .expected = .{ .err = error.StackUnderflow },
        },
        .{
            .name = "row 1160 twodup on one item errors",
            .unlocking_hex = "51",
            .locking_hex = "6e",
            .expected = .{ .err = error.StackUnderflow },
        },
    });
}
