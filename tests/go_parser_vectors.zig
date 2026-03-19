const std = @import("std");
const bsvz = @import("bsvz");
const harness = @import("support/go_script_harness.zig");
const builders = @import("support/go_vector_builders.zig");

const GoRow = struct {
    row: usize,
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

test "go direct parser rows: malformed pushdata lengths" {
    const allocator = std.testing.allocator;
    const flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    const rows = [_]GoRow{
        .{
            .row = 831,
            .name = "row 831 pushdata1 with not enough bytes",
            .unlocking_hex = "4c01",
            .locking_hex = "0161",
            .expected = .{ .err = error.InvalidPushData },
        },
        .{
            .row = 832,
            .name = "row 832 pushdata2 with not enough bytes",
            .unlocking_hex = "4d0200ff",
            .locking_hex = "0161",
            .expected = .{ .err = error.InvalidPushData },
        },
        .{
            .row = 833,
            .name = "row 833 pushdata4 with not enough bytes",
            .unlocking_hex = "4e03000000ffff",
            .locking_hex = "0161",
            .expected = .{ .err = error.InvalidPushData },
        },
    };

    try runRows(allocator, flags, &rows);
}

test "go direct parser rows: op_return tail scanning and result shapes" {
    const allocator = std.testing.allocator;
    const legacy_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    const post_genesis_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();

    const legacy_rows = [_]GoRow{
        .{
            .row = 129,
            .name = "row 129 skipped if does not hide top-level bad opcode after endif before genesis",
            .unlocking_hex = "00",
            .locking_hex = "636a68ba",
            .expected = .{ .err = error.UnknownOpcode },
        },
        .{
            .row = 131,
            .name = "row 131 executed op_return stops before bad opcode tail before genesis",
            .unlocking_hex = "51",
            .locking_hex = "63556a68ba",
            .expected = .{ .err = error.ReturnEncountered },
        },
        .{
            .row = 134,
            .name = "row 134 top-level op_return before bad opcode tail returns op_return before genesis",
            .unlocking_hex = "00",
            .locking_hex = "636a686aba",
            .expected = .{ .err = error.ReturnEncountered },
        },
        .{
            .row = 149,
            .name = "row 149 top-level op_return stops before bad opcode tail before genesis",
            .unlocking_hex = "51",
            .locking_hex = "6aba",
            .expected = .{ .err = error.ReturnEncountered },
        },
        .{
            .row = 150,
            .name = "row 150 skipped branch ignores op_return and bad opcode bytes before genesis",
            .unlocking_hex = "00",
            .locking_hex = "636aba6855",
            .expected = .{ .success = true },
        },
        .{
            .row = 151,
            .name = "row 151 executed branch hits op_return before skipped bad opcode before genesis",
            .unlocking_hex = "51",
            .locking_hex = "63556aba6855",
            .expected = .{ .err = error.ReturnEncountered },
        },
    };

    const post_genesis_rows = [_]GoRow{
        .{
            .row = 130,
            .name = "row 130 skipped if does not hide top-level bad opcode after endif after genesis",
            .unlocking_hex = "00",
            .locking_hex = "636a68ba",
            .expected = .{ .err = error.UnknownOpcode },
        },
        .{
            .row = 132,
            .name = "row 132 executed op_return stops before bad opcode tail after genesis",
            .unlocking_hex = "51",
            .locking_hex = "63556a68ba",
            .expected = .{ .success = true },
        },
        .{
            .row = 135,
            .name = "row 135 top-level op_return after skipped branch leaves false result after genesis",
            .unlocking_hex = "00",
            .locking_hex = "636a686aba",
            .expected = .{ .success = false },
        },
        .{
            .row = 137,
            .name = "row 137 top-level op_return preserves truthy stack result after genesis",
            .unlocking_hex = "00",
            .locking_hex = "636a68556aba",
            .expected = .{ .success = true },
        },
    };

    try runRows(allocator, legacy_flags, &legacy_rows);
    try runRows(allocator, post_genesis_flags, &post_genesis_rows);
}

test "go direct parser rows: compact if return tail families" {
    const allocator = std.testing.allocator;
    const legacy_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    const post_genesis_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();

    const legacy_rows = [_]GoRow{
        .{
            .row = 91,
            .name = "row 91 if five return errors before genesis",
            .unlocking_hex = "51",
            .locking_hex = "63556a",
            .expected = .{ .err = error.ReturnEncountered },
        },
        .{
            .row = 97,
            .name = "row 97 if five return bad opcode tail errors before genesis",
            .unlocking_hex = "51",
            .locking_hex = "63556aba",
            .expected = .{ .err = error.ReturnEncountered },
        },
        .{
            .row = 101,
            .name = "row 101 if five return bad opcode endif errors before genesis",
            .unlocking_hex = "51",
            .locking_hex = "63556aba68",
            .expected = .{ .err = error.ReturnEncountered },
        },
        .{
            .row = 107,
            .name = "row 107 if return endif then return bad opcode still errors before genesis",
            .unlocking_hex = "00",
            .locking_hex = "636a686aba",
            .expected = .{ .err = error.ReturnEncountered },
        },
        .{
            .row = 93,
            .name = "row 93 untaken if return endif trailing five succeeds before genesis",
            .unlocking_hex = "00",
            .locking_hex = "636a6855",
            .expected = .{ .success = true },
        },
        .{
            .row = 95,
            .name = "row 95 untaken if return bad opcode tail remains unbalanced before genesis",
            .unlocking_hex = "00",
            .locking_hex = "636aba",
            .expected = .{ .err = error.UnbalancedConditionals },
        },
        .{
            .row = 99,
            .name = "row 99 untaken if return bad opcode endif trailing five succeeds before genesis",
            .unlocking_hex = "00",
            .locking_hex = "636aba6855",
            .expected = .{ .success = true },
        },
        .{
            .row = 103,
            .name = "row 103 untaken if return endif exposes the bad opcode tail before genesis",
            .unlocking_hex = "00",
            .locking_hex = "636a68ba",
            .expected = .{ .err = error.UnknownOpcode },
        },
        .{
            .row = 105,
            .name = "row 105 if five return endif bad opcode tail still errors before genesis",
            .unlocking_hex = "51",
            .locking_hex = "63556a68ba",
            .expected = .{ .err = error.ReturnEncountered },
        },
        .{
            .row = 117,
            .name = "row 117 if return endif if still errors before genesis",
            .unlocking_hex = "51",
            .locking_hex = "636a6863",
            .expected = .{ .err = error.ReturnEncountered },
        },
        .{
            .row = 119,
            .name = "row 119 bare bad opcode still errors before genesis",
            .unlocking_hex = "51",
            .locking_hex = "ba",
            .expected = .{ .err = error.UnknownOpcode },
        },
        .{
            .row = 120,
            .name = "row 120 bare return bad opcode still errors before genesis",
            .unlocking_hex = "51",
            .locking_hex = "6aba",
            .expected = .{ .err = error.ReturnEncountered },
        },
        .{
            .row = 121,
            .name = "row 121 untaken if return bad opcode endif trailing five succeeds before genesis",
            .unlocking_hex = "00",
            .locking_hex = "636aba6855",
            .expected = .{ .success = true },
        },
        .{
            .row = 122,
            .name = "row 122 if five return bad opcode endif trailing five still errors before genesis",
            .unlocking_hex = "51",
            .locking_hex = "63556aba6855",
            .expected = .{ .err = error.ReturnEncountered },
        },
    };

    const post_genesis_rows = [_]GoRow{
        .{
            .row = 98,
            .name = "row 98 if five return bad opcode tail is unbalanced after genesis",
            .unlocking_hex = "51",
            .locking_hex = "63556aba",
            .expected = .{ .err = error.UnbalancedConditionals },
        },
        .{
            .row = 102,
            .name = "row 102 if five return bad opcode endif succeeds after genesis",
            .unlocking_hex = "51",
            .locking_hex = "63556aba68",
            .expected = .{ .success = true },
        },
        .{
            .row = 108,
            .name = "row 108 if return endif then return bad opcode yields false after genesis",
            .unlocking_hex = "00",
            .locking_hex = "636a686aba",
            .expected = .{ .success = false },
        },
        .{
            .row = 94,
            .name = "row 94 untaken if return endif trailing five succeeds after genesis",
            .unlocking_hex = "00",
            .locking_hex = "636a6855",
            .expected = .{ .success = true },
        },
        .{
            .row = 96,
            .name = "row 96 untaken if return bad opcode tail remains unbalanced after genesis",
            .unlocking_hex = "00",
            .locking_hex = "636aba",
            .expected = .{ .err = error.UnbalancedConditionals },
        },
        .{
            .row = 100,
            .name = "row 100 untaken if return bad opcode endif trailing five succeeds after genesis",
            .unlocking_hex = "00",
            .locking_hex = "636aba6855",
            .expected = .{ .success = true },
        },
        .{
            .row = 104,
            .name = "row 104 untaken if return endif exposes the bad opcode tail after genesis",
            .unlocking_hex = "00",
            .locking_hex = "636a68ba",
            .expected = .{ .err = error.UnknownOpcode },
        },
        .{
            .row = 106,
            .name = "row 106 if five return endif bad opcode tail succeeds after genesis",
            .unlocking_hex = "51",
            .locking_hex = "63556a68ba",
            .expected = .{ .success = true },
        },
    };

    try runRows(allocator, legacy_flags, &legacy_rows);
    try runRows(allocator, post_genesis_flags, &post_genesis_rows);
}

test "go direct parser rows: pushdata equivalence forms" {
    const allocator = std.testing.allocator;
    const flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    const repeated_z_bytes = try builders.repeatedHexByte(allocator, 74, 'z');
    defer allocator.free(repeated_z_bytes);
    const repeated_z_hex = try builders.encodeLowerAlloc(allocator, repeated_z_bytes);
    defer allocator.free(repeated_z_hex);
    const azz_payload = try std.mem.concat(allocator, u8, &[_][]const u8{ "41", repeated_z_hex });
    defer allocator.free(azz_payload);

    const row29_unlocking = try std.mem.concat(allocator, u8, &[_][]const u8{ "4b", azz_payload });
    defer allocator.free(row29_unlocking);
    const row29_locking = try std.mem.concat(allocator, u8, &[_][]const u8{ "4b", azz_payload, "87" });
    defer allocator.free(row29_locking);

    const seventy_five_bytes = try builders.repeatedHexByte(allocator, 75, 0x11);
    defer allocator.free(seventy_five_bytes);
    const seventy_five = try builders.encodeLowerAlloc(allocator, seventy_five_bytes);
    defer allocator.free(seventy_five);
    const two_fifty_five_bytes = try builders.repeatedHexByte(allocator, 255, 0x11);
    defer allocator.free(two_fifty_five_bytes);
    const two_fifty_five = try builders.encodeLowerAlloc(allocator, two_fifty_five_bytes);
    defer allocator.free(two_fifty_five);

    const pushdata1_75 = try std.mem.concat(allocator, u8, &[_][]const u8{ "4c4b", seventy_five });
    defer allocator.free(pushdata1_75);
    const direct_75_equal = try std.mem.concat(allocator, u8, &[_][]const u8{ "4b", seventy_five, "87" });
    defer allocator.free(direct_75_equal);

    const pushdata2_255 = try std.mem.concat(allocator, u8, &[_][]const u8{ "4dff00", two_fifty_five });
    defer allocator.free(pushdata2_255);
    const pushdata1_255_equal = try std.mem.concat(allocator, u8, &[_][]const u8{ "4cff", two_fifty_five, "87" });
    defer allocator.free(pushdata1_255_equal);

    const sixty_four_bytes = try builders.repeatedHexByte(allocator, 64, 0x42);
    defer allocator.free(sixty_four_bytes);
    const sixty_four = try builders.encodeLowerAlloc(allocator, sixty_four_bytes);
    defer allocator.free(sixty_four);
    const direct_64 = try std.mem.concat(allocator, u8, &[_][]const u8{ "40", sixty_four });
    defer allocator.free(direct_64);
    const pushdata1_64 = try std.mem.concat(allocator, u8, &[_][]const u8{ "4c40", sixty_four });
    defer allocator.free(pushdata1_64);
    const pushdata2_64_equal = try std.mem.concat(allocator, u8, &[_][]const u8{ "4d4000", sixty_four, "87" });
    defer allocator.free(pushdata2_64_equal);

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 27, .name = "row 27 direct one-byte push equals small integer 11", .unlocking_hex = "010b", .locking_hex = "5b87", .expected = .{ .success = true } },
        .{ .row = 28, .name = "row 28 direct two-byte push equals Az", .unlocking_hex = "02417a", .locking_hex = "02417a87", .expected = .{ .success = true } },
        .{ .row = 29, .name = "row 29 direct seventy-five-byte push stays canonical", .unlocking_hex = row29_unlocking, .locking_hex = row29_locking, .expected = .{ .success = true } },
        .{ .row = 31, .name = "row 31 pushdata1 single byte stays canonical", .unlocking_hex = "4c0107", .locking_hex = "5787", .expected = .{ .success = true } },
        .{ .row = 32, .name = "row 32 pushdata2 single byte stays canonical", .unlocking_hex = "4d010008", .locking_hex = "5887", .expected = .{ .success = true } },
        .{ .row = 33, .name = "row 33 pushdata4 single byte stays canonical", .unlocking_hex = "4e0100000009", .locking_hex = "5987", .expected = .{ .success = true } },
        .{ .row = 34, .name = "row 34 pushdata1 zero length equals op_0", .unlocking_hex = "4c00", .locking_hex = "0087", .expected = .{ .success = true } },
        .{ .row = 35, .name = "row 35 pushdata2 zero length equals op_0", .unlocking_hex = "4d0000", .locking_hex = "0087", .expected = .{ .success = true } },
        .{ .row = 36, .name = "row 36 pushdata4 zero length equals op_0", .unlocking_hex = "4e00000000", .locking_hex = "0087", .expected = .{ .success = true } },
        .{ .row = 637, .name = "row 637 direct 64-byte push equals pushdata2 64-byte push", .unlocking_hex = direct_64, .locking_hex = pushdata2_64_equal, .expected = .{ .success = true } },
        .{ .row = 641, .name = "row 641 pushdata1 64-byte push equals pushdata2 64-byte push", .unlocking_hex = pushdata1_64, .locking_hex = pushdata2_64_equal, .expected = .{ .success = true } },
        .{ .row = 648, .name = "row 648 pushdata1 of seventy-five bytes equals direct push", .unlocking_hex = pushdata1_75, .locking_hex = direct_75_equal, .expected = .{ .success = true } },
        .{ .row = 649, .name = "row 649 pushdata2 of two-hundred-fifty-five bytes equals pushdata1", .unlocking_hex = pushdata2_255, .locking_hex = pushdata1_255_equal, .expected = .{ .success = true } },
    });
}

test "go direct parser rows: codeseparator scanner sanity" {
    const allocator = std.testing.allocator;
    const flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    try runRows(allocator, flags, &[_]GoRow{
        .{
            .row = 552,
            .name = "row 552 codeseparator before op_1 preserves success shape",
            .unlocking_hex = "61",
            .locking_hex = "ab51",
            .expected = .{ .success = true },
        },
    });
}

test "go direct parser rows: compact bad-op precedence after conditionals" {
    const allocator = std.testing.allocator;
    const legacy_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    const post_genesis_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();

    try runRows(allocator, legacy_flags, &[_]GoRow{
        .{
            .row = 123,
            .name = "row 123 executed if exposes bad opcode before endif",
            .unlocking_hex = "51",
            .locking_hex = "63ba6855",
            .expected = .{ .err = error.UnknownOpcode },
        },
        .{
            .row = 125,
            .name = "row 125 untaken if hides bad opcode before endif",
            .unlocking_hex = "00",
            .locking_hex = "63ba6855",
            .expected = .{ .success = true },
        },
    });

    try runRows(allocator, post_genesis_flags, &[_]GoRow{
        .{
            .row = 124,
            .name = "row 124 executed if exposes bad opcode before endif after genesis",
            .unlocking_hex = "51",
            .locking_hex = "63ba6855",
            .expected = .{ .err = error.UnknownOpcode },
        },
        .{
            .row = 126,
            .name = "row 126 untaken if hides bad opcode before endif after genesis",
            .unlocking_hex = "00",
            .locking_hex = "63ba6855",
            .expected = .{ .success = true },
        },
        .{
            .row = 131,
            .name = "row 131 untaken if keeps verif inert in else form",
            .unlocking_hex = "00",
            .locking_hex = "6365675168",
            .expected = .{ .success = true },
        },
        .{
            .row = 133,
            .name = "row 133 untaken if keeps vernotif inert in else form",
            .unlocking_hex = "00",
            .locking_hex = "6366675168",
            .expected = .{ .success = true },
        },
        .{
            .row = 135,
            .name = "row 135 top-level ver is a bad opcode after genesis",
            .unlocking_hex = "51",
            .locking_hex = "62",
            .expected = .{ .err = error.UnknownOpcode },
        },
        .{
            .row = 136,
            .name = "row 136 top-level reserved is a bad opcode after genesis",
            .unlocking_hex = "51",
            .locking_hex = "50",
            .expected = .{ .err = error.UnknownOpcode },
        },
        .{
            .row = 137,
            .name = "row 137 top-level reserved1 is a bad opcode after genesis",
            .unlocking_hex = "51",
            .locking_hex = "89",
            .expected = .{ .err = error.UnknownOpcode },
        },
        .{
            .row = 138,
            .name = "row 138 top-level reserved2 is a bad opcode after genesis",
            .unlocking_hex = "51",
            .locking_hex = "8a",
            .expected = .{ .err = error.UnknownOpcode },
        },
        .{
            .row = 139,
            .name = "row 139 untaken if keeps ver inert before trailing five after genesis",
            .unlocking_hex = "00",
            .locking_hex = "63626855",
            .expected = .{ .success = true },
        },
        .{
            .row = 140,
            .name = "row 140 untaken if keeps reserved inert before trailing five after genesis",
            .unlocking_hex = "00",
            .locking_hex = "63506855",
            .expected = .{ .success = true },
        },
        .{
            .row = 141,
            .name = "row 141 untaken if keeps reserved1 inert before trailing five after genesis",
            .unlocking_hex = "00",
            .locking_hex = "63896855",
            .expected = .{ .success = true },
        },
        .{
            .row = 142,
            .name = "row 142 untaken if keeps reserved2 inert before trailing five after genesis",
            .unlocking_hex = "00",
            .locking_hex = "638a6855",
            .expected = .{ .success = true },
        },
    });
}

test "go direct parser rows: exact pushdata boundary equivalence" {
    const allocator = std.testing.allocator;
    const flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    const seventy_five_bytes = try builders.repeatedHexByte(allocator, 75, 0x11);
    defer allocator.free(seventy_five_bytes);
    const seventy_five = try builders.encodeLowerAlloc(allocator, seventy_five_bytes);
    defer allocator.free(seventy_five);

    const two_fifty_five_bytes = try builders.repeatedHexByte(allocator, 255, 0x11);
    defer allocator.free(two_fifty_five_bytes);
    const two_fifty_five = try builders.encodeLowerAlloc(allocator, two_fifty_five_bytes);
    defer allocator.free(two_fifty_five);

    const pushdata1_75 = try std.mem.concat(allocator, u8, &[_][]const u8{ "4c4b", seventy_five });
    defer allocator.free(pushdata1_75);
    const direct_75_equal = try std.mem.concat(allocator, u8, &[_][]const u8{ "4b", seventy_five, "87" });
    defer allocator.free(direct_75_equal);

    const pushdata2_255 = try std.mem.concat(allocator, u8, &[_][]const u8{ "4dff00", two_fifty_five });
    defer allocator.free(pushdata2_255);
    const pushdata1_255_equal = try std.mem.concat(allocator, u8, &[_][]const u8{ "4cff", two_fifty_five, "87" });
    defer allocator.free(pushdata1_255_equal);

    try runRows(allocator, flags, &[_]GoRow{
        .{
            .row = 538,
            .name = "row 538 pushdata1 of 75 bytes equals direct push",
            .unlocking_hex = pushdata1_75,
            .locking_hex = direct_75_equal,
            .expected = .{ .success = true },
        },
        .{
            .row = 539,
            .name = "row 539 pushdata2 of 255 bytes equals pushdata1",
            .unlocking_hex = pushdata2_255,
            .locking_hex = pushdata1_255_equal,
            .expected = .{ .success = true },
        },
    });
}

test "go direct parser rows: exact canonical push and small-integer equivalence" {
    const allocator = std.testing.allocator;
    const legacy_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    var minimaldata_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    minimaldata_flags.minimal_data = true;

    const row23_tail_bytes = try builders.repeatedHexByte(allocator, 74, 0x7a);
    defer allocator.free(row23_tail_bytes);
    const row23_tail = try builders.encodeLowerAlloc(allocator, row23_tail_bytes);
    defer allocator.free(row23_tail);
    const row23_payload = try std.mem.concat(allocator, u8, &[_][]const u8{
        "41",
        row23_tail,
    });
    defer allocator.free(row23_payload);
    const row23_unlocking = try std.mem.concat(allocator, u8, &[_][]const u8{ "4b", row23_payload });
    defer allocator.free(row23_unlocking);
    const row23_locking = try std.mem.concat(allocator, u8, &[_][]const u8{ "4b", row23_payload, "87" });
    defer allocator.free(row23_locking);

    try runRows(allocator, legacy_flags, &[_]GoRow{
        .{ .row = 21, .name = "row 21 canonical one-byte push equals opcode 11", .unlocking_hex = "010b", .locking_hex = "5b87", .expected = .{ .success = true } },
        .{ .row = 22, .name = "row 22 canonical two-byte push equals exact string payload", .unlocking_hex = "02417a", .locking_hex = "02417a87", .expected = .{ .success = true } },
        .{ .row = 23, .name = "row 23 canonical 75-byte push equals exact string payload", .unlocking_hex = row23_unlocking, .locking_hex = row23_locking, .expected = .{ .success = true } },
        .{ .row = 24, .name = "row 24 pushdata1 single-byte payload equals opcode 7", .unlocking_hex = "4c0107", .locking_hex = "5787", .expected = .{ .success = true } },
        .{ .row = 25, .name = "row 25 pushdata2 single-byte payload equals opcode 8", .unlocking_hex = "4d010008", .locking_hex = "5887", .expected = .{ .success = true } },
        .{ .row = 26, .name = "row 26 pushdata4 single-byte payload equals opcode 9", .unlocking_hex = "4e0100000009", .locking_hex = "5987", .expected = .{ .success = true } },
        .{ .row = 542, .name = "row 542 raw 0x81 equals op_1negate push result", .unlocking_hex = "0181", .locking_hex = "4f87", .expected = .{ .success = true } },
        .{ .row = 543, .name = "row 543 raw 0x01 equals op_1 push result", .unlocking_hex = "0101", .locking_hex = "5187", .expected = .{ .success = true } },
        .{ .row = 544, .name = "row 544 raw 0x02 equals op_2 push result", .unlocking_hex = "0102", .locking_hex = "5287", .expected = .{ .success = true } },
        .{ .row = 545, .name = "row 545 raw 0x03 equals op_3 push result", .unlocking_hex = "0103", .locking_hex = "5387", .expected = .{ .success = true } },
        .{ .row = 554, .name = "row 554 raw 0x0c equals op_12 push result", .unlocking_hex = "010c", .locking_hex = "5c87", .expected = .{ .success = true } },
        .{ .row = 555, .name = "row 555 raw 0x0d equals op_13 push result", .unlocking_hex = "010d", .locking_hex = "5d87", .expected = .{ .success = true } },
        .{ .row = 556, .name = "row 556 raw 0x0e equals op_14 push result", .unlocking_hex = "010e", .locking_hex = "5e87", .expected = .{ .success = true } },
        .{ .row = 557, .name = "row 557 raw 0x0f equals op_15 push result", .unlocking_hex = "010f", .locking_hex = "5f87", .expected = .{ .success = true } },
        .{ .row = 558, .name = "row 558 raw 0x10 equals op_16 push result", .unlocking_hex = "0110", .locking_hex = "6087", .expected = .{ .success = true } },
    });

    try runRows(allocator, minimaldata_flags, &[_]GoRow{
        .{ .row = 573, .name = "row 573 untaken branch keeps raw negative-one push inert under minimaldata", .unlocking_hex = "006301816851", .locking_hex = "", .expected = .{ .success = true } },
        .{ .row = 574, .name = "row 574 untaken branch keeps raw one-byte push inert under minimaldata", .unlocking_hex = "006301016851", .locking_hex = "", .expected = .{ .success = true } },
    });
}

test "go direct parser rows: untaken non-minimal pushes are ignored under minimaldata" {
    const allocator = std.testing.allocator;
    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.minimal_data = true;

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 687, .name = "row 687 untaken pushdata1 zero-length is ignored under minimaldata", .unlocking_hex = "00", .locking_hex = "634c006851", .expected = .{ .success = true } },
        .{ .row = 688, .name = "row 688 untaken pushdata2 zero-length is ignored under minimaldata", .unlocking_hex = "00", .locking_hex = "634d00006851", .expected = .{ .success = true } },
        .{ .row = 689, .name = "row 689 untaken pushdata4 zero-length is ignored under minimaldata", .unlocking_hex = "00", .locking_hex = "634e000000006851", .expected = .{ .success = true } },
        .{ .row = 690, .name = "row 690 untaken non-minimal negative-one encoding is ignored under minimaldata", .unlocking_hex = "00", .locking_hex = "6301816851", .expected = .{ .success = true } },
        .{ .row = 691, .name = "row 691 untaken non-minimal op_1 encoding is ignored under minimaldata", .unlocking_hex = "00", .locking_hex = "6301016851", .expected = .{ .success = true } },
        .{ .row = 692, .name = "row 692 untaken non-minimal op_2 encoding is ignored under minimaldata", .unlocking_hex = "00", .locking_hex = "6301026851", .expected = .{ .success = true } },
        .{ .row = 693, .name = "row 693 untaken non-minimal op_3 encoding is ignored under minimaldata", .unlocking_hex = "00", .locking_hex = "6301036851", .expected = .{ .success = true } },
        .{ .row = 694, .name = "row 694 untaken non-minimal op_4 encoding is ignored under minimaldata", .unlocking_hex = "00", .locking_hex = "6301046851", .expected = .{ .success = true } },
        .{ .row = 695, .name = "row 695 untaken non-minimal op_5 encoding is ignored under minimaldata", .unlocking_hex = "00", .locking_hex = "6301056851", .expected = .{ .success = true } },
        .{ .row = 696, .name = "row 696 untaken non-minimal op_6 encoding is ignored under minimaldata", .unlocking_hex = "00", .locking_hex = "6301066851", .expected = .{ .success = true } },
        .{ .row = 697, .name = "row 697 untaken non-minimal op_7 encoding is ignored under minimaldata", .unlocking_hex = "00", .locking_hex = "6301076851", .expected = .{ .success = true } },
        .{ .row = 698, .name = "row 698 untaken non-minimal op_8 encoding is ignored under minimaldata", .unlocking_hex = "00", .locking_hex = "6301086851", .expected = .{ .success = true } },
    });
}
