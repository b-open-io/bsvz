const std = @import("std");
const bsvz = @import("bsvz");
const harness = @import("support/go_script_harness.zig");
const builders = @import("support/go_vector_builders.zig");

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

fn scriptHexForPushesAndOps(
    allocator: std.mem.Allocator,
    pushes: []const []const u8,
    ops: []const u8,
) ![]u8 {
    var bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer bytes.deinit(allocator);

    for (pushes) |push| try builders.appendPushData(&bytes, allocator, push);
    try bytes.appendSlice(allocator, ops);
    return builders.scriptHexFromBytes(allocator, bytes.items);
}

fn scriptNumBytes(allocator: std.mem.Allocator, value: i64) ![]u8 {
    return builders.scriptNumBytes(allocator, value);
}

test "go direct script rows: swap cat sha256 parity" {
    const allocator = std.testing.allocator;

    try runRows(allocator, bsvz.script.engine.ExecutionFlags.legacyReference(), &[_]GoRow{
        .{
            .row = 298,
            .name = "swap cat sha256 matches known hello-world digest",
            .unlocking_hex = "0568656c6c6f05776f726c64",
            .locking_hex = "7c7ea8208376118fc0230e6054e782fb31ae52ebcfd551342d8d026c209997e0127b6f7487",
            .expected = .{ .success = true },
        },
    });
}

test "go direct script rows: bitwise or parity" {
    const allocator = std.testing.allocator;
    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.strict_encoding = true;

    try harness.runCase(allocator, .{
        .name = "or with two equal byte vectors stays equal to the same vector",
        .unlocking_hex = "020100020100",
        .locking_hex = "8502010087",
        .flags = flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "or with two one-byte scalars yields one-byte true",
        .unlocking_hex = "5151",
        .locking_hex = "855187",
        .flags = flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "or with one stack item underflows",
        .unlocking_hex = "00",
        .locking_hex = "855087",
        .flags = flags,
        .expected = .{ .err = error.StackUnderflow },
    });

    try harness.runCase(allocator, .{
        .name = "or with empty stack underflows",
        .unlocking_hex = "",
        .locking_hex = "855087",
        .flags = flags,
        .expected = .{ .err = error.StackUnderflow },
    });
}

test "go direct script rows: cat parity" {
    const allocator = std.testing.allocator;
    const flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 940, .name = "cat underflows on empty stack", .unlocking_hex = "", .locking_hex = "7e0087", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 941, .name = "cat underflows with one parameter", .unlocking_hex = "0161", .locking_hex = "7e0087", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 942, .name = "cat concatenates two payloads", .unlocking_hex = "04616263640465666768", .locking_hex = "7e08616263646566676887", .expected = .{ .success = true } },
        .{ .row = 943, .name = "cat keeps two empty strings empty", .unlocking_hex = "0000", .locking_hex = "7e0087", .expected = .{ .success = true } },
        .{ .row = 944, .name = "cat with empty string on the right keeps left", .unlocking_hex = "0361626300", .locking_hex = "7e0361626387", .expected = .{ .success = true } },
        .{ .row = 945, .name = "cat with empty string on the left keeps right", .unlocking_hex = "0003646566", .locking_hex = "7e0364656687", .expected = .{ .success = true } },
    });
}

test "go direct script rows: split parity" {
    const allocator = std.testing.allocator;
    const flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    const zero = try scriptNumBytes(allocator, 0);
    defer allocator.free(zero);
    const three = try scriptNumBytes(allocator, 3);
    defer allocator.free(three);
    const four = try scriptNumBytes(allocator, 4);
    defer allocator.free(four);
    const neg_one = try scriptNumBytes(allocator, -1);
    defer allocator.free(neg_one);

    const abcdef_split_3 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        "abcdef",
        three,
    }, &[_]u8{});
    defer allocator.free(abcdef_split_3);
    const empty_split_0 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        "",
        zero,
    }, &[_]u8{});
    defer allocator.free(empty_split_0);
    const abc_split_0 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        "abc",
        zero,
    }, &[_]u8{});
    defer allocator.free(abc_split_0);
    const abc_split_3 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        "abc",
        three,
    }, &[_]u8{});
    defer allocator.free(abc_split_3);
    const abc_split_4 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        "abc",
        four,
    }, &[_]u8{});
    defer allocator.free(abc_split_4);
    const abc_split_neg1 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        "abc",
        neg_one,
    }, &[_]u8{});
    defer allocator.free(abc_split_neg1);

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 968, .name = "split underflows on empty stack", .unlocking_hex = "", .locking_hex = "7f", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 969, .name = "split underflows with one parameter", .unlocking_hex = "0161", .locking_hex = "7f", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 970, .name = "split divides abcdef at three", .unlocking_hex = abcdef_split_3, .locking_hex = "7f03646566880461626387", .expected = .{ .success = true } },
        .{ .row = 971, .name = "split on empty string at zero keeps both halves empty", .unlocking_hex = empty_split_0, .locking_hex = "7f00880087", .expected = .{ .success = true } },
        .{ .row = 972, .name = "split at zero keeps right side intact", .unlocking_hex = abc_split_0, .locking_hex = "7f03616263880087", .expected = .{ .success = true } },
        .{ .row = 973, .name = "split at payload length keeps left side intact", .unlocking_hex = abc_split_3, .locking_hex = "7f00880361626387", .expected = .{ .success = true } },
        .{ .row = 974, .name = "split rejects upper out of bounds", .unlocking_hex = abc_split_4, .locking_hex = "7f", .expected = .{ .err = error.InvalidSplitPosition } },
        .{ .row = 975, .name = "split rejects negative index", .unlocking_hex = abc_split_neg1, .locking_hex = "7f", .expected = .{ .err = error.InvalidStackIndex } },
    });
}
