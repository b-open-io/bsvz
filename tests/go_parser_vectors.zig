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
        .{
            .row = 146,
            .name = "row 146 top-level op_return still leaves unbalanced conditional state after genesis",
            .unlocking_hex = "51",
            .locking_hex = "636a6863",
            .expected = .{ .err = error.UnbalancedConditionals },
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
            .row = 92,
            .name = "row 92 if five return is unbalanced after genesis",
            .unlocking_hex = "51",
            .locking_hex = "63556a",
            .expected = .{ .err = error.UnbalancedConditionals },
        },
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
            .row = 118,
            .name = "row 118 if return endif if is unbalanced after genesis",
            .unlocking_hex = "51",
            .locking_hex = "636a6863",
            .expected = .{ .err = error.UnbalancedConditionals },
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

test "go direct parser rows: untaken non-minimal pushes are ignored under minimaldata" {
    const allocator = std.testing.allocator;
    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.minimal_data = true;

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 687, .name = "row 687 untaken pushdata1 zero-length is ignored under minimaldata", .unlocking_hex = "00", .locking_hex = "634c006851", .expected = .{ .success = true } },
        .{ .row = 688, .name = "row 688 untaken pushdata2 zero-length is ignored under minimaldata", .unlocking_hex = "00", .locking_hex = "634d00006851", .expected = .{ .success = true } },
        .{ .row = 689, .name = "row 689 untaken pushdata4 zero-length is ignored under minimaldata", .unlocking_hex = "00", .locking_hex = "634e000000006851", .expected = .{ .success = true } },
        .{ .row = 690, .name = "row 690 untaken non-minimal negative-one encoding is ignored under minimaldata", .unlocking_hex = "00", .locking_hex = "6301816851", .expected = .{ .success = true } },
    });
}
