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
        .{ .row = 159, .name = "go row 159: pick index zero reads the top item and preserves depth", .unlocking_hex = "011601150114", .locking_hex = "0079011488745387", .expected = .{ .success = true } },
        .{ .row = 160, .name = "go row 160: pick index one reads the second item and preserves depth", .unlocking_hex = "011601150114", .locking_hex = "5179011588745387", .expected = .{ .success = true } },
        .{ .row = 161, .name = "go row 161: pick index two reads the third item and preserves depth", .unlocking_hex = "011601150114", .locking_hex = "5279011688745387", .expected = .{ .success = true } },
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
        .{ .row = 162, .name = "go row 162: roll index zero preserves the top item while reducing depth", .unlocking_hex = "011601150114", .locking_hex = "007a011488745287", .expected = .{ .success = true } },
        .{ .row = 163, .name = "go row 163: roll index one rotates the second item to the top", .unlocking_hex = "011601150114", .locking_hex = "517a011588745287", .expected = .{ .success = true } },
        .{ .row = 164, .name = "go row 164: roll index two rotates the third item to the top", .unlocking_hex = "011601150114", .locking_hex = "527a011688745287", .expected = .{ .success = true } },
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
        .{ .name = "rot requires three stack items", .unlocking_hex = "5151", .locking_hex = "7b", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 754, .name = "go row 754: pick cannot reach nineteen items deep", .unlocking_hex = "011301140115", .locking_hex = "79011388745287", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 755, .name = "go row 755: pick underflows when no data items remain after nop", .unlocking_hex = "61", .locking_hex = "0079", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 760, .name = "go row 760: roll underflows when no data items remain after nop", .unlocking_hex = "61", .locking_hex = "007a", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 1170, .name = "go row 1170: pick cannot address beyond the available four items", .unlocking_hex = "51515153", .locking_hex = "79", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 1171, .name = "go row 1171: pick needs an index item even when the data stack is empty", .unlocking_hex = "00", .locking_hex = "7951", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 1172, .name = "go row 1172: roll cannot address beyond the available four items", .unlocking_hex = "51515153", .locking_hex = "7a", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 1173, .name = "go row 1173: roll needs an index item even when the data stack is empty", .unlocking_hex = "00", .locking_hex = "7a51", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 746, .name = "go row 746: dup underflows before depth can observe the stack", .unlocking_hex = "", .locking_hex = "76740087", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 756, .name = "go row 756: pick rejects a negative index", .unlocking_hex = "51", .locking_hex = "4f79", .expected = .{ .err = error.InvalidStackIndex } },
        .{ .row = 761, .name = "go row 761: roll rejects a negative index", .unlocking_hex = "51", .locking_hex = "4f7a", .expected = .{ .err = error.InvalidStackIndex } },
    });
}

test "go direct script rows: exact depth and stack-index false results" {
    const allocator = std.testing.allocator;
    const flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 9, .name = "go row 9: empty unlocking script makes depth equal zero", .unlocking_hex = "", .locking_hex = "740087", .expected = .{ .success = true } },
        .{ .row = 10, .name = "go row 10: whitespace unlocking script still makes depth equal zero", .unlocking_hex = "", .locking_hex = "740087", .expected = .{ .success = true } },
        .{ .row = 11, .name = "go row 11: more whitespace still leaves an empty stack", .unlocking_hex = "", .locking_hex = "740087", .expected = .{ .success = true } },
        .{ .row = 12, .name = "go row 12: repeated whitespace still leaves an empty stack", .unlocking_hex = "", .locking_hex = "740087", .expected = .{ .success = true } },
        .{ .row = 430, .name = "go row 430: nop in unlocking script leaves depth one", .unlocking_hex = "61", .locking_hex = "7451", .expected = .{ .success = true } },
        .{ .row = 677, .name = "go row 677: empty unlocking script leaves bare depth false", .unlocking_hex = "", .locking_hex = "74", .expected = .{ .success = false } },
        .{ .row = 678, .name = "go row 678: whitespace unlocking script still leaves bare depth false", .unlocking_hex = "", .locking_hex = "74", .expected = .{ .success = false } },
        .{ .row = 679, .name = "go row 679: more whitespace still leaves bare depth false", .unlocking_hex = "", .locking_hex = "74", .expected = .{ .success = false } },
        .{ .row = 680, .name = "go row 680: repeated whitespace still leaves bare depth false", .unlocking_hex = "", .locking_hex = "74", .expected = .{ .success = false } },
        .{ .row = 683, .name = "go row 683: nop before depth still leaves a false zero", .unlocking_hex = "", .locking_hex = "6174", .expected = .{ .success = false } },
        .{ .row = 685, .name = "go row 685: unlocking nop leaves bare depth false", .unlocking_hex = "61", .locking_hex = "74", .expected = .{ .success = false } },
        .{ .row = 687, .name = "go row 687: double nop still leaves bare depth false", .unlocking_hex = "61", .locking_hex = "6174", .expected = .{ .success = false } },
        .{ .row = 688, .name = "go row 688: depth in unlocking script alone leaves false at the seam", .unlocking_hex = "74", .locking_hex = "", .expected = .{ .success = false } },
        .{ .row = 753, .name = "go row 753: over depth equalverify leaves a false result on the wrong stack shape", .unlocking_hex = "0051", .locking_hex = "78745388", .expected = .{ .success = false } },
        .{ .row = 757, .name = "go row 757: pick zero fails equality against the wrong value", .unlocking_hex = "011301140115", .locking_hex = "0079011488745387", .expected = .{ .success = false } },
        .{ .row = 758, .name = "go row 758: pick one fails equality against the wrong value", .unlocking_hex = "011301140115", .locking_hex = "5179011588745387", .expected = .{ .success = false } },
        .{ .row = 759, .name = "go row 759: pick two fails equality against the wrong value", .unlocking_hex = "011301140115", .locking_hex = "5279011688745387", .expected = .{ .success = false } },
        .{ .row = 762, .name = "go row 762: roll zero fails equality against the wrong value", .unlocking_hex = "011301140115", .locking_hex = "007a011488745287", .expected = .{ .success = false } },
        .{ .row = 763, .name = "go row 763: roll one fails equality against the wrong value", .unlocking_hex = "011301140115", .locking_hex = "517a011588745287", .expected = .{ .success = false } },
        .{ .row = 764, .name = "go row 764: roll two fails equality against the wrong value", .unlocking_hex = "011301140115", .locking_hex = "527a011688745287", .expected = .{ .success = false } },
    });
}

test "go direct script rows: compact stack-index success operators" {
    const allocator = std.testing.allocator;
    const flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 423, .name = "go row 423: 2drop removes two stack items before pushing one", .unlocking_hex = "0000", .locking_hex = "6d51", .expected = .{ .success = true } },
        .{ .row = 424, .name = "go row 424: 2dup duplicates the top two stack items", .unlocking_hex = "0051", .locking_hex = "6e", .expected = .{ .success = true } },
        .{ .row = 425, .name = "go row 425: 3dup duplicates the top three stack items", .unlocking_hex = "000051", .locking_hex = "6f", .expected = .{ .success = true } },
        .{ .row = 426, .name = "go row 426: 2over copies the pair below the top pair", .unlocking_hex = "00510000", .locking_hex = "70", .expected = .{ .success = true } },
        .{ .row = 427, .name = "go row 427: 2rot rotates the bottom pair of three pairs to the top", .unlocking_hex = "005100000000", .locking_hex = "71", .expected = .{ .success = true } },
        .{ .row = 428, .name = "go row 428: 2swap swaps the top two pairs", .unlocking_hex = "00510000", .locking_hex = "72", .expected = .{ .success = true } },
        .{ .row = 433, .name = "go row 433: nip removes the second stack item", .unlocking_hex = "0051", .locking_hex = "77", .expected = .{ .success = true } },
        .{ .row = 434, .name = "go row 434: over copies the second stack item to the top", .unlocking_hex = "5100", .locking_hex = "78", .expected = .{ .success = true } },
        .{ .row = 439, .name = "go row 439: rot moves the third stack item to the top", .unlocking_hex = "510000", .locking_hex = "7b", .expected = .{ .success = true } },
        .{ .row = 440, .name = "go row 440: swap exchanges the top two stack items", .unlocking_hex = "5100", .locking_hex = "7c", .expected = .{ .success = true } },
        .{ .row = 441, .name = "go row 441: tuck copies the top stack item beneath the next item", .unlocking_hex = "0051", .locking_hex = "7d", .expected = .{ .success = true } },
    });
}
