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
            .name = "row 422 toaltstack round-trips through fromaltstack",
            .unlocking_hex = "51",
            .locking_hex = "6b6c",
            .expected = .{ .success = true },
        },
        .{
            .name = "row 424 twodup duplicates two items",
            .unlocking_hex = "0051",
            .locking_hex = "6e",
            .expected = .{ .success = true },
        },
        .{
            .name = "row 425 threedup duplicates three stack items",
            .unlocking_hex = "000051",
            .locking_hex = "6f",
            .expected = .{ .success = true },
        },
        .{
            .name = "row 426 twoover copies the pair below the top pair",
            .unlocking_hex = "00510000",
            .locking_hex = "70",
            .expected = .{ .success = true },
        },
        .{
            .name = "row 427 tworot rotates the bottom pair to the top",
            .unlocking_hex = "005100000000",
            .locking_hex = "71",
            .expected = .{ .success = true },
        },
        .{
            .name = "row 428 twoswap exchanges the top two pairs",
            .unlocking_hex = "00510000",
            .locking_hex = "72",
            .expected = .{ .success = true },
        },
        .{
            .name = "row 429 ifdup duplicates truthy item",
            .unlocking_hex = "51",
            .locking_hex = "73",
            .expected = .{ .success = true },
        },
        .{
            .name = "row 430 depth pushes zero before a truthy tail",
            .unlocking_hex = "61",
            .locking_hex = "7451",
            .expected = .{ .success = true },
        },
        .{
            .name = "row 432 dup preserves a single truthy item",
            .unlocking_hex = "51",
            .locking_hex = "76",
            .expected = .{ .success = true },
        },
        .{
            .name = "row 433 nip drops the second stack item exactly",
            .unlocking_hex = "0051",
            .locking_hex = "77",
            .expected = .{ .success = true },
        },
        .{
            .name = "row 434 over copies the second stack item",
            .unlocking_hex = "5100",
            .locking_hex = "78",
            .expected = .{ .success = true },
        },
        .{
            .name = "row 439 rot rotates the third item to the top",
            .unlocking_hex = "510000",
            .locking_hex = "7b",
            .expected = .{ .success = true },
        },
        .{
            .name = "row 440 swap reverses the top two items",
            .unlocking_hex = "5100",
            .locking_hex = "7c",
            .expected = .{ .success = true },
        },
        .{
            .name = "row 441 tuck copies the top item below the second item",
            .unlocking_hex = "0051",
            .locking_hex = "7d",
            .expected = .{ .success = true },
        },
        .{
            .name = "row 442 size leaves a truthy length result",
            .unlocking_hex = "51",
            .locking_hex = "82",
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
            .name = "row 1401 fromaltstack underflows on empty alt stack",
            .unlocking_hex = "51",
            .locking_hex = "6c",
            .expected = .{ .err = error.AltStackUnderflow },
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
        .{
            .name = "row 1405 twoover on three items errors",
            .unlocking_hex = "515151",
            .locking_hex = "70",
            .expected = .{ .err = error.StackUnderflow },
        },
        .{
            .name = "row 1406 tworot on five items errors",
            .unlocking_hex = "5151515151",
            .locking_hex = "71",
            .expected = .{ .err = error.StackUnderflow },
        },
        .{
            .name = "row 1407 twoswap on three items errors",
            .unlocking_hex = "515151",
            .locking_hex = "72",
            .expected = .{ .err = error.StackUnderflow },
        },
        .{
            .name = "row 1418 swap requires two stack items",
            .unlocking_hex = "51",
            .locking_hex = "7c",
            .expected = .{ .err = error.StackUnderflow },
        },
    });
}
