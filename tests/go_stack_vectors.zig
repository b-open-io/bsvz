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
            .name = "go row 154: ifdup duplicates non-integer byte payloads",
            .unlocking_hex = "05010000000073",
            .locking_hex = "74528805010000000087",
            .expected = .{ .success = true },
        },
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
            .name = "go row 156: dup supports arithmetic without consuming the original zero",
            .unlocking_hex = "00",
            .locking_hex = "76519351880087",
            .expected = .{ .success = true },
        },
        .{
            .name = "go row 157: nip matches the exact two-item Go stack shape",
            .unlocking_hex = "0051",
            .locking_hex = "77",
            .expected = .{ .success = true },
        },
        .{
            .name = "go row 158: over preserves depth while copying the second item",
            .unlocking_hex = "5100",
            .locking_hex = "78745388",
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
            .name = "go row 431: drop reveals the pushed true tail",
            .unlocking_hex = "00",
            .locking_hex = "7551",
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
            .name = "go row 165: rot brings the third item to the top for equality",
            .unlocking_hex = "011601150114",
            .locking_hex = "7b011687",
            .expected = .{ .success = true },
        },
        .{
            .name = "go row 166: rot then drop leaves the original top item",
            .unlocking_hex = "011601150114",
            .locking_hex = "7b75011487",
            .expected = .{ .success = true },
        },
        .{
            .name = "go row 167: rot then two drops leaves the original middle item",
            .unlocking_hex = "011601150114",
            .locking_hex = "7b7575011587",
            .expected = .{ .success = true },
        },
        .{
            .name = "go row 168: rot rot cycles the stack and exposes the middle item",
            .unlocking_hex = "011601150114",
            .locking_hex = "7b7b011587",
            .expected = .{ .success = true },
        },
        .{
            .name = "go row 169: rot rot rot returns the original top item",
            .unlocking_hex = "011601150114",
            .locking_hex = "7b7b7b011487",
            .expected = .{ .success = true },
        },
        .{
            .name = "go row 170: 2rot brings the fourth item pair to the top",
            .unlocking_hex = "011901180117011601150114",
            .locking_hex = "71011887",
            .expected = .{ .success = true },
        },
        .{
            .name = "go row 171: 2rot then drop leaves the original deepest item",
            .unlocking_hex = "011901180117011601150114",
            .locking_hex = "7175011987",
            .expected = .{ .success = true },
        },
        .{
            .name = "go row 172: 2rot then 2drop leaves the original top item",
            .unlocking_hex = "011901180117011601150114",
            .locking_hex = "716d011487",
            .expected = .{ .success = true },
        },
        .{
            .name = "go row 173: 2rot then 2drop drop leaves the next item",
            .unlocking_hex = "011901180117011601150114",
            .locking_hex = "716d75011587",
            .expected = .{ .success = true },
        },
        .{
            .name = "go row 174: 2rot then two 2drops leaves the third item",
            .unlocking_hex = "011901180117011601150114",
            .locking_hex = "716d6d011687",
            .expected = .{ .success = true },
        },
        .{
            .name = "go row 175: 2rot then two 2drops and drop leaves the fourth item",
            .unlocking_hex = "011901180117011601150114",
            .locking_hex = "716d6d75011787",
            .expected = .{ .success = true },
        },
        .{
            .name = "go row 176: 2rot twice cycles the pair order",
            .unlocking_hex = "011901180117011601150114",
            .locking_hex = "7171011687",
            .expected = .{ .success = true },
        },
        .{
            .name = "go row 177: 2rot three times restores the original top item",
            .unlocking_hex = "011901180117011601150114",
            .locking_hex = "717171011487",
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
            .name = "go row 178: swap exposes the original bottom item for equality",
            .unlocking_hex = "5100",
            .locking_hex = "7c51880087",
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

test "go row 150: toaltstack and fromaltstack preserve the hidden element" {
    const allocator = std.testing.allocator;

    try runRows(allocator, &[_]GoRow{
        .{
            .name = "go row 150: toaltstack and fromaltstack preserve the hidden element",
            .unlocking_hex = "5a005b6b756c",
            .locking_hex = "93011587",
            .expected = .{ .success = true },
        },
    });
}

test "go row 151: altstack round-trip preserves byte payloads exactly" {
    const allocator = std.testing.allocator;

    try runRows(allocator, &[_]GoRow{
        .{
            .name = "go row 151: altstack round-trip preserves byte payloads exactly",
            .unlocking_hex = "0e676176696e5f7761735f686572656b5b6c",
            .locking_hex = "0e676176696e5f7761735f68657265885b87",
            .expected = .{ .success = true },
        },
    });
}

test "go row 179: tuck produces the exact three-item shape before cleanup" {
    const allocator = std.testing.allocator;

    try runRows(allocator, &[_]GoRow{
        .{
            .name = "go row 179: tuck produces the exact three-item shape before cleanup",
            .unlocking_hex = "0051",
            .locking_hex = "7d7453887c6d",
            .expected = .{ .success = true },
        },
    });
}

test "go row 180: 2dup copies both items for pairwise equality" {
    const allocator = std.testing.allocator;

    try runRows(allocator, &[_]GoRow{
        .{
            .name = "go row 180: 2dup copies both items for pairwise equality",
            .unlocking_hex = "5d5e",
            .locking_hex = "6e7b8887",
            .expected = .{ .success = true },
        },
    });
}

test "go row 182: 2over copies the lower pair for the exact sum checks" {
    const allocator = std.testing.allocator;

    try runRows(allocator, &[_]GoRow{
        .{
            .name = "go row 182: 2over copies the lower pair for the exact sum checks",
            .unlocking_hex = "51525355",
            .locking_hex = "709393588893935687",
            .expected = .{ .success = true },
        },
    });
}

test "go row 183: 2swap exchanges the top pairs before the add checks" {
    const allocator = std.testing.allocator;

    try runRows(allocator, &[_]GoRow{
        .{
            .name = "go row 183: 2swap exchanges the top pairs before the add checks",
            .unlocking_hex = "51535557",
            .locking_hex = "72935488935c87",
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
            .name = "go row 1408: ifdup underflows even with a trailing push",
            .unlocking_hex = "61",
            .locking_hex = "7351",
            .expected = .{ .err = error.StackUnderflow },
        },
        .{
            .name = "go row 1409: drop underflows even with a trailing push",
            .unlocking_hex = "61",
            .locking_hex = "7551",
            .expected = .{ .err = error.StackUnderflow },
        },
        .{
            .name = "go row 1410: dup underflows even with a trailing push",
            .unlocking_hex = "61",
            .locking_hex = "7651",
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
        .{
            .name = "go row 1158: fromaltstack underflows with no prior alt push",
            .unlocking_hex = "51",
            .locking_hex = "6c",
            .expected = .{ .err = error.AltStackUnderflow },
        },
        .{
            .name = "go row 1161: 3dup requires three stack items",
            .unlocking_hex = "5151",
            .locking_hex = "6f",
            .expected = .{ .err = error.StackUnderflow },
        },
        .{
            .name = "go row 1162: 2over requires four stack items",
            .unlocking_hex = "515151",
            .locking_hex = "70",
            .expected = .{ .err = error.StackUnderflow },
        },
        .{
            .name = "go row 1163: 2rot requires six stack items",
            .unlocking_hex = "5151515151",
            .locking_hex = "71",
            .expected = .{ .err = error.StackUnderflow },
        },
        .{
            .name = "go row 1164: 2swap requires four stack items",
            .unlocking_hex = "515151",
            .locking_hex = "72",
            .expected = .{ .err = error.StackUnderflow },
        },
        .{
            .name = "go row 1165: ifdup underflows on an empty stack even with trailing success",
            .unlocking_hex = "61",
            .locking_hex = "7351",
            .expected = .{ .err = error.StackUnderflow },
        },
        .{
            .name = "go row 1166: drop underflows on an empty stack even with trailing success",
            .unlocking_hex = "61",
            .locking_hex = "7551",
            .expected = .{ .err = error.StackUnderflow },
        },
        .{
            .name = "go row 1167: dup underflows on an empty stack even with trailing success",
            .unlocking_hex = "61",
            .locking_hex = "7651",
            .expected = .{ .err = error.StackUnderflow },
        },
        .{
            .name = "go row 1168: nip requires two stack items",
            .unlocking_hex = "51",
            .locking_hex = "77",
            .expected = .{ .err = error.StackUnderflow },
        },
        .{
            .name = "go row 1169: over requires two stack items",
            .unlocking_hex = "51",
            .locking_hex = "78",
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
        .{
            .name = "go row 1174: rot requires three stack items",
            .unlocking_hex = "5151",
            .locking_hex = "7b",
            .expected = .{ .err = error.StackUnderflow },
        },
        .{
            .name = "go row 1175: swap requires two stack items",
            .unlocking_hex = "51",
            .locking_hex = "7c",
            .expected = .{ .err = error.StackUnderflow },
        },
        .{
            .name = "go row 1176: tuck requires two stack items",
            .unlocking_hex = "51",
            .locking_hex = "7d",
            .expected = .{ .err = error.StackUnderflow },
        },
        .{
            .name = "go row 1412: over requires two stack items",
            .unlocking_hex = "51",
            .locking_hex = "78",
            .expected = .{ .err = error.StackUnderflow },
        },
        .{
            .name = "go row 770: swap underflows before trailing true push",
            .unlocking_hex = "51",
            .locking_hex = "7c51",
            .expected = .{ .err = error.StackUnderflow },
        },
        .{
            .name = "go row 772: tuck underflows on empty stack before trailing true push",
            .unlocking_hex = "61",
            .locking_hex = "7d51",
            .expected = .{ .err = error.StackUnderflow },
        },
        .{
            .name = "go row 773: tuck underflows with one stack item before trailing true push",
            .unlocking_hex = "51",
            .locking_hex = "7d51",
            .expected = .{ .err = error.StackUnderflow },
        },
    });
}

test "go row 774: tuck leaves a false top item after exact cleanup" {
    const allocator = std.testing.allocator;

    try runRows(allocator, &[_]GoRow{
        .{
            .name = "go row 774: tuck leaves a false top item after exact cleanup",
            .unlocking_hex = "5100",
            .locking_hex = "7d7453887c6d",
            .expected = .{ .success = false },
        },
    });
}
