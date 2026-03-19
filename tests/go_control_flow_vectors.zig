const std = @import("std");
const bsvz = @import("bsvz");
const harness = @import("support/go_script_harness.zig");

const GoRow = struct {
    row: ?usize = null,
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

fn repeatedElseElseSha1Chain(allocator: std.mem.Allocator, leading_opcode_hex: []const u8) ![]u8 {
    const suffix = "681468ca4fec736264c13b859bac43d5173df687168287";
    const repeated = "6767a7";
    const total_len = leading_opcode_hex.len + 2 + (19 * repeated.len) + suffix.len;
    const hex = try allocator.alloc(u8, total_len);
    errdefer allocator.free(hex);

    var cursor: usize = 0;
    @memcpy(hex[cursor .. cursor + leading_opcode_hex.len], leading_opcode_hex);
    cursor += leading_opcode_hex.len;
    @memcpy(hex[cursor .. cursor + 2], "a7");
    cursor += 2;
    for (0..19) |_| {
        @memcpy(hex[cursor .. cursor + repeated.len], repeated);
        cursor += repeated.len;
    }
    @memcpy(hex[cursor .. cursor + suffix.len], suffix);
    cursor += suffix.len;

    std.debug.assert(cursor == total_len);
    return hex;
}

test "go direct control-flow rows: compact op_return and sigpushonly" {
    const allocator = std.testing.allocator;

    const legacy_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    const post_genesis_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();
    var post_genesis_sigpushonly_flags = post_genesis_flags;
    post_genesis_sigpushonly_flags.sig_push_only = true;

    try runRows(allocator, &[_]GoRow{
        .{
            .name = "return before genesis errors",
            .unlocking_hex = "51",
            .locking_hex = "6a",
            .flags = legacy_flags,
            .expected = .{ .err = error.ReturnEncountered },
        },
        .{
            .name = "false stack plus return before genesis errors",
            .unlocking_hex = "00",
            .locking_hex = "6a",
            .flags = legacy_flags,
            .expected = .{ .err = error.ReturnEncountered },
        },
        .{
            .name = "return after genesis succeeds with true top stack",
            .unlocking_hex = "51",
            .locking_hex = "6a",
            .flags = post_genesis_flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "return after genesis yields false with false top stack",
            .unlocking_hex = "00",
            .locking_hex = "6a",
            .flags = post_genesis_flags,
            .expected = .{ .success = false },
        },
        .{
            .name = "unlocking script op_return is sigpushonly violation after genesis",
            .unlocking_hex = "6a",
            .locking_hex = "51",
            .flags = post_genesis_sigpushonly_flags,
            .expected = .{ .err = error.SigPushOnly },
        },
        .{
            .name = "return if before genesis errors",
            .unlocking_hex = "51",
            .locking_hex = "6a63",
            .flags = legacy_flags,
            .expected = .{ .err = error.ReturnEncountered },
        },
        .{
            .name = "return if after genesis succeeds",
            .unlocking_hex = "51",
            .locking_hex = "6a63",
            .flags = post_genesis_flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "return bad opcode tail before genesis errors",
            .unlocking_hex = "51",
            .locking_hex = "6aba",
            .flags = legacy_flags,
            .expected = .{ .err = error.ReturnEncountered },
        },
        .{
            .name = "return bad opcode tail after genesis succeeds",
            .unlocking_hex = "51",
            .locking_hex = "6aba",
            .flags = post_genesis_flags,
            .expected = .{ .success = true },
        },
        .{
            .row = 92,
            .name = "row 92 post-genesis return leaves the selected if unbalanced",
            .unlocking_hex = "51",
            .locking_hex = "63556a",
            .flags = post_genesis_flags,
            .expected = .{ .err = error.UnbalancedConditionals },
        },
    });
}

test "go direct control-flow rows: exact compact return seam families" {
    const allocator = std.testing.allocator;

    const legacy_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    const post_genesis_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();

    try runRows(allocator, &[_]GoRow{
        .{
            .name = "row 76 untaken if branch ignores return before genesis",
            .unlocking_hex = "00",
            .locking_hex = "636a6851",
            .flags = legacy_flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "row 77 untaken if branch ignores return after genesis",
            .unlocking_hex = "00",
            .locking_hex = "636a6851",
            .flags = post_genesis_flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "row 82 unlocking-script return errors before genesis",
            .unlocking_hex = "6a",
            .locking_hex = "51",
            .flags = legacy_flags,
            .expected = .{ .err = error.ReturnEncountered },
        },
        .{
            .name = "row 83 unlocking-script return succeeds after genesis",
            .unlocking_hex = "6a",
            .locking_hex = "51",
            .flags = post_genesis_flags,
            .expected = .{ .success = true },
        },
        .{
            .name = "row 107 if return endif return bad-op tail errors before genesis",
            .unlocking_hex = "00",
            .locking_hex = "636a686aba",
            .flags = legacy_flags,
            .expected = .{ .err = error.ReturnEncountered },
        },
        .{
            .name = "row 108 if return endif return bad-op tail yields false after genesis",
            .unlocking_hex = "00",
            .locking_hex = "636a686aba",
            .flags = post_genesis_flags,
            .expected = .{ .success = false },
        },
        .{
            .row = 109,
            .name = "row 109 if return endif five return bad-op tail errors before genesis",
            .unlocking_hex = "00",
            .locking_hex = "636a68556aba",
            .flags = legacy_flags,
            .expected = .{ .err = error.ReturnEncountered },
        },
        .{
            .row = 110,
            .name = "row 110 if return endif five return bad-op tail stays true after genesis",
            .unlocking_hex = "00",
            .locking_hex = "636a68556aba",
            .flags = post_genesis_flags,
            .expected = .{ .success = true },
        },
        .{
            .row = 111,
            .name = "row 111 taken if return endif five return bad-op tail errors before genesis",
            .unlocking_hex = "51",
            .locking_hex = "636a68556aba",
            .flags = legacy_flags,
            .expected = .{ .err = error.ReturnEncountered },
        },
        .{
            .row = 112,
            .name = "row 112 taken if return endif five return bad-op tail yields false after genesis",
            .unlocking_hex = "51",
            .locking_hex = "636a68556aba",
            .flags = post_genesis_flags,
            .expected = .{ .success = false },
        },
        .{
            .row = 113,
            .name = "row 113 if five return endif five return bad-op tail errors before genesis",
            .unlocking_hex = "51",
            .locking_hex = "63556a68556aba",
            .flags = legacy_flags,
            .expected = .{ .err = error.ReturnEncountered },
        },
        .{
            .row = 114,
            .name = "row 114 if five return endif five return bad-op tail stays true after genesis",
            .unlocking_hex = "51",
            .locking_hex = "63556a68556aba",
            .flags = post_genesis_flags,
            .expected = .{ .success = true },
        },
        .{
            .row = 115,
            .name = "row 115 if five return endif five return if errors before genesis",
            .unlocking_hex = "51",
            .locking_hex = "63556a68556a63",
            .flags = legacy_flags,
            .expected = .{ .err = error.ReturnEncountered },
        },
        .{
            .row = 116,
            .name = "row 116 post-genesis trailing if stays truthy after return handling",
            .unlocking_hex = "51",
            .locking_hex = "63556a68556a63",
            .flags = post_genesis_flags,
            .expected = .{ .success = true },
        },
    });
}

test "go direct script rows: false control-flow result shapes" {
    const allocator = std.testing.allocator;

    try runRows(allocator, &[_]GoRow{
        .{ .name = "row 36 dup if endif over one succeeds", .unlocking_hex = "51", .locking_hex = "766368", .flags = bsvz.script.engine.ExecutionFlags.legacyReference(), .expected = .{ .success = true } },
        .{ .name = "row 37 if one endif over one succeeds", .unlocking_hex = "51", .locking_hex = "635168", .flags = bsvz.script.engine.ExecutionFlags.legacyReference(), .expected = .{ .success = true } },
        .{ .name = "row 38 dup if else endif over one succeeds", .unlocking_hex = "51", .locking_hex = "76636768", .flags = bsvz.script.engine.ExecutionFlags.legacyReference(), .expected = .{ .success = true } },
        .{ .name = "row 39 if one else endif over one succeeds", .unlocking_hex = "51", .locking_hex = "63516768", .flags = bsvz.script.engine.ExecutionFlags.legacyReference(), .expected = .{ .success = true } },
        .{ .name = "row 40 if else one endif over zero succeeds", .unlocking_hex = "00", .locking_hex = "63675168", .flags = bsvz.script.engine.ExecutionFlags.legacyReference(), .expected = .{ .success = true } },
        .{ .name = "dup if endif over zero leaves false result", .unlocking_hex = "00", .locking_hex = "766368", .flags = bsvz.script.engine.ExecutionFlags.legacyReference(), .expected = .{ .success = false } },
        .{ .name = "if true branch guarded by zero leaves false result", .unlocking_hex = "00", .locking_hex = "635168", .flags = bsvz.script.engine.ExecutionFlags.legacyReference(), .expected = .{ .success = false } },
        .{ .name = "dup if else endif over zero leaves false result", .unlocking_hex = "00", .locking_hex = "76636768", .flags = bsvz.script.engine.ExecutionFlags.legacyReference(), .expected = .{ .success = false } },
        .{ .name = "if else endif over zero leaves false result", .unlocking_hex = "00", .locking_hex = "63516768", .flags = bsvz.script.engine.ExecutionFlags.legacyReference(), .expected = .{ .success = false } },
        .{ .name = "notif else one endif over zero still leaves false result", .unlocking_hex = "00", .locking_hex = "64675168", .flags = bsvz.script.engine.ExecutionFlags.legacyReference(), .expected = .{ .success = false } },
    });
}

test "go direct script rows: exact nested conditionals" {
    const allocator = std.testing.allocator;
    const legacy_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    const post_genesis_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();

    try runRows(allocator, &[_]GoRow{
        .{ .name = "row 41 nested if if takes the inner true branch", .unlocking_hex = "5151", .locking_hex = "63635167006868", .flags = legacy_flags, .expected = .{ .success = true } },
        .{ .name = "row 42 nested if if takes the inner false branch", .unlocking_hex = "5100", .locking_hex = "63635167006868", .flags = legacy_flags, .expected = .{ .success = true } },
        .{ .name = "row 43 nested if else if succeeds before genesis", .unlocking_hex = "5151", .locking_hex = "63635167006867630067516868", .flags = legacy_flags, .expected = .{ .success = true } },
        .{ .name = "row 44 nested if else if still succeeds after genesis", .unlocking_hex = "5151", .locking_hex = "63635167006867630067516868", .flags = post_genesis_flags, .expected = .{ .success = true } },
        .{ .name = "row 45 nested multiple else is unbalanced after genesis", .unlocking_hex = "5151", .locking_hex = "636351670067516867630067516868", .flags = post_genesis_flags, .expected = .{ .err = error.UnbalancedConditionals } },
        .{ .name = "row 46 nested multiple else succeeds before genesis", .unlocking_hex = "5151", .locking_hex = "636351670067516867630067516868", .flags = legacy_flags, .expected = .{ .success = true } },
        .{ .name = "row 47 nested if else if succeeds when both conditions are false", .unlocking_hex = "0000", .locking_hex = "63635167006867630067516868", .flags = legacy_flags, .expected = .{ .success = true } },
        .{ .name = "row 48 nested notif if succeeds when outer notif is not taken", .unlocking_hex = "5100", .locking_hex = "64635167006868", .flags = legacy_flags, .expected = .{ .success = true } },
        .{ .name = "row 49 nested notif if succeeds when inner if is taken", .unlocking_hex = "5151", .locking_hex = "64635167006868", .flags = legacy_flags, .expected = .{ .success = true } },
        .{ .name = "row 50 nested notif else if succeeds before genesis", .unlocking_hex = "5100", .locking_hex = "64635167006867630067516868", .flags = legacy_flags, .expected = .{ .success = true } },
        .{ .name = "row 51 nested notif else if succeeds on the alternate path", .unlocking_hex = "0051", .locking_hex = "64635167006867630067516868", .flags = legacy_flags, .expected = .{ .success = true } },
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
        .{ .row = 53, .name = "row 53 legacy multiple else inverts execution when if branch is false", .unlocking_hex = "00", .locking_hex = "63006751670068", .flags = legacy_flags, .expected = .{ .success = true } },
        .{ .row = 54, .name = "row 54 legacy multiple else succeeds when the first branch is taken", .unlocking_hex = "51", .locking_hex = "635167006768", .flags = legacy_flags, .expected = .{ .success = true } },
        .{ .row = 55, .name = "row 55 legacy multiple else with add and equal yields true", .unlocking_hex = "51", .locking_hex = "63516700675168935287", .flags = legacy_flags, .expected = .{ .success = true } },
        .{ .row = 57, .name = "row 57 post-genesis multiple else is unbalanced when if branch is false", .unlocking_hex = "00", .locking_hex = "63006751670068", .flags = post_genesis_flags, .expected = .{ .err = error.UnbalancedConditionals } },
        .{ .row = 58, .name = "row 58 post-genesis multiple else is unbalanced when the first branch is taken", .unlocking_hex = "51", .locking_hex = "635167006768", .flags = post_genesis_flags, .expected = .{ .err = error.UnbalancedConditionals } },
        .{ .row = 59, .name = "row 59 post-genesis empty first branch is unbalanced", .unlocking_hex = "51", .locking_hex = "636700675168", .flags = post_genesis_flags, .expected = .{ .err = error.UnbalancedConditionals } },
        .{ .row = 60, .name = "row 60 post-genesis multiple else add and equal is unbalanced", .unlocking_hex = "51", .locking_hex = "63516700675168935287", .flags = post_genesis_flags, .expected = .{ .err = error.UnbalancedConditionals } },
    });
}

test "go direct script rows: exact multiple else with notif" {
    const allocator = std.testing.allocator;
    const legacy_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    const post_genesis_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();

    try runRows(allocator, &[_]GoRow{
        .{ .row = 62, .name = "row 62 legacy notif multiple else inverts execution when notif is not taken", .unlocking_hex = "51", .locking_hex = "64006751670068", .flags = legacy_flags, .expected = .{ .success = true } },
        .{ .row = 63, .name = "row 63 legacy notif multiple else succeeds when the first branch is taken", .unlocking_hex = "00", .locking_hex = "645167006768", .flags = legacy_flags, .expected = .{ .success = true } },
        .{ .row = 64, .name = "row 64 legacy notif empty first branch still reaches the final true branch", .unlocking_hex = "00", .locking_hex = "646700675168", .flags = legacy_flags, .expected = .{ .success = true } },
        .{ .row = 65, .name = "row 65 legacy notif multiple else with add and equal yields true", .unlocking_hex = "00", .locking_hex = "64516700675168935287", .flags = legacy_flags, .expected = .{ .success = true } },
        .{ .row = 67, .name = "row 67 post-genesis notif multiple else is unbalanced when notif is not taken", .unlocking_hex = "51", .locking_hex = "64006751670068", .flags = post_genesis_flags, .expected = .{ .err = error.UnbalancedConditionals } },
        .{ .row = 68, .name = "row 68 post-genesis notif multiple else is unbalanced when the first branch is taken", .unlocking_hex = "00", .locking_hex = "645167006768", .flags = post_genesis_flags, .expected = .{ .err = error.UnbalancedConditionals } },
        .{ .row = 69, .name = "row 69 post-genesis notif empty first branch is unbalanced", .unlocking_hex = "00", .locking_hex = "646700675168", .flags = post_genesis_flags, .expected = .{ .err = error.UnbalancedConditionals } },
        .{ .row = 70, .name = "row 70 post-genesis notif multiple else add and equal is unbalanced", .unlocking_hex = "00", .locking_hex = "64516700675168935287", .flags = post_genesis_flags, .expected = .{ .err = error.UnbalancedConditionals } },
    });
}

test "go direct script rows: nested else else legacy versus post-genesis" {
    const allocator = std.testing.allocator;
    const legacy_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    const post_genesis_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();

    try runRows(allocator, &[_]GoRow{
        .{ .name = "row 72 legacy nested else else succeeds for outer false path", .unlocking_hex = "00", .locking_hex = "6351636a676a676a6867516351676a675168676a68935287", .flags = legacy_flags, .expected = .{ .success = true } },
        .{ .name = "row 74 post-genesis nested else else is unbalanced for outer false path", .unlocking_hex = "00", .locking_hex = "6351636a676a676a6867516351676a675168676a68935287", .flags = post_genesis_flags, .expected = .{ .err = error.UnbalancedConditionals } },
        .{ .name = "row 73 legacy nested else else succeeds for outer true notif path", .unlocking_hex = "51", .locking_hex = "6400646a676a676a6867006451676a675168676a68935287", .flags = legacy_flags, .expected = .{ .success = true } },
        .{ .name = "row 75 post-genesis nested else else is unbalanced for outer true notif path", .unlocking_hex = "51", .locking_hex = "6400646a676a676a6867006451676a675168676a68935287", .flags = post_genesis_flags, .expected = .{ .err = error.UnbalancedConditionals } },
    });
}

test "go direct script rows: malformed conditional sequences" {
    const allocator = std.testing.allocator;
    const flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    try runRows(allocator, &[_]GoRow{
        .{ .name = "row 874 endif alone is unbalanced", .unlocking_hex = "51", .locking_hex = "68", .flags = flags, .expected = .{ .err = error.UnbalancedConditionals } },
        .{ .name = "row 875 else endif is unbalanced", .unlocking_hex = "51", .locking_hex = "6768", .flags = flags, .expected = .{ .err = error.UnbalancedConditionals } },
        .{ .name = "row 876 endif else is unbalanced", .unlocking_hex = "51", .locking_hex = "6867", .flags = flags, .expected = .{ .err = error.UnbalancedConditionals } },
        .{ .name = "row 877 endif else if is unbalanced", .unlocking_hex = "51", .locking_hex = "686763", .flags = flags, .expected = .{ .err = error.UnbalancedConditionals } },
        .{ .name = "row 878 if else endif else is unbalanced", .unlocking_hex = "51", .locking_hex = "63676867", .flags = flags, .expected = .{ .err = error.UnbalancedConditionals } },
        .{ .name = "row 879 if else endif else endif is unbalanced", .unlocking_hex = "51", .locking_hex = "6367686768", .flags = flags, .expected = .{ .err = error.UnbalancedConditionals } },
        .{ .name = "row 880 if endif endif is unbalanced", .unlocking_hex = "51", .locking_hex = "636868", .flags = flags, .expected = .{ .err = error.UnbalancedConditionals } },
    });
}

test "go direct script rows: exact conditional bad-op and verify rows" {
    const allocator = std.testing.allocator;
    const post_genesis_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();
    const legacy_flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    try runRows(allocator, &[_]GoRow{
        .{ .row = 127, .name = "row 127 executed verif in if branch is a bad opcode after genesis", .unlocking_hex = "51", .locking_hex = "6365675168", .flags = post_genesis_flags, .expected = .{ .err = error.UnknownOpcode } },
        .{ .row = 128, .name = "row 128 multiple else with verif tail is unbalanced after genesis", .unlocking_hex = "51", .locking_hex = "636751676568", .flags = post_genesis_flags, .expected = .{ .err = error.UnbalancedConditionals } },
        .{ .row = 147, .name = "row 147 verify succeeds on a truthy top stack item", .unlocking_hex = "5151", .locking_hex = "69", .flags = legacy_flags, .expected = .{ .success = true } },
    });
}

test "go direct script rows: compact exact return and seam rows" {
    const allocator = std.testing.allocator;
    const legacy_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    const post_genesis_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();

    try runRows(allocator, &[_]GoRow{
        .{ .name = "row 883 dup if return endif errors before genesis", .unlocking_hex = "51", .locking_hex = "76636a68", .flags = legacy_flags, .expected = .{ .err = error.ReturnEncountered } },
        .{ .name = "row 884 dup if return endif succeeds after genesis", .unlocking_hex = "51", .locking_hex = "76636a68", .flags = post_genesis_flags, .expected = .{ .success = true } },
        .{ .name = "row 886 return data errors before genesis", .unlocking_hex = "51", .locking_hex = "6a0464617461", .flags = legacy_flags, .expected = .{ .err = error.ReturnEncountered } },
        .{ .name = "row 887 return data succeeds after genesis", .unlocking_hex = "51", .locking_hex = "6a0464617461", .flags = post_genesis_flags, .expected = .{ .success = true } },
        .{ .name = "row 888 if endif cannot span scripts before genesis", .unlocking_hex = "0063", .locking_hex = "6a6851", .flags = legacy_flags, .expected = .{ .err = error.UnbalancedConditionals } },
        .{ .name = "row 889 if endif cannot span scripts after genesis", .unlocking_hex = "0063", .locking_hex = "6a6851", .flags = post_genesis_flags, .expected = .{ .err = error.UnbalancedConditionals } },
        .{ .name = "row 890 untaken if return leaves final one after genesis", .unlocking_hex = "00", .locking_hex = "63006a6851", .flags = post_genesis_flags, .expected = .{ .success = true } },
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

test "go direct script rows: exact repeated else else sha1 chains" {
    const allocator = std.testing.allocator;
    const legacy_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    const post_genesis_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();

    const if_chain = try repeatedElseElseSha1Chain(allocator, "63");
    defer allocator.free(if_chain);
    const notif_chain = try repeatedElseElseSha1Chain(allocator, "64");
    defer allocator.free(notif_chain);

    try runRows(allocator, &[_]GoRow{
        .{ .row = 56, .name = "row 56 legacy repeated else else sha1 chain under if succeeds", .unlocking_hex = "0051", .locking_hex = if_chain, .flags = legacy_flags, .expected = .{ .success = true } },
        .{ .row = 61, .name = "row 61 post-genesis repeated else else sha1 chain under if is unbalanced", .unlocking_hex = "0051", .locking_hex = if_chain, .flags = post_genesis_flags, .expected = .{ .err = error.UnbalancedConditionals } },
        .{ .row = 66, .name = "row 66 legacy repeated else else sha1 chain under notif succeeds", .unlocking_hex = "0000", .locking_hex = notif_chain, .flags = legacy_flags, .expected = .{ .success = true } },
        .{ .row = 71, .name = "row 71 post-genesis repeated else else sha1 chain under notif is unbalanced", .unlocking_hex = "0000", .locking_hex = notif_chain, .flags = post_genesis_flags, .expected = .{ .err = error.UnbalancedConditionals } },
    });
}

test "go direct script rows: untaken if branch ignores opcode bytes across the reserved tail" {
    const allocator = std.testing.allocator;
    const flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    var row_index: usize = 321;
    while (row_index <= 372) : (row_index += 1) {
        const opcode_byte: u8 = @intCast(0xcc + (row_index - 321));
        var locking_bytes = [_]u8{
            @intFromEnum(bsvz.script.opcode.Opcode.OP_IF),
            opcode_byte,
            @intFromEnum(bsvz.script.opcode.Opcode.OP_ELSE),
            @intFromEnum(bsvz.script.opcode.Opcode.OP_1),
            @intFromEnum(bsvz.script.opcode.Opcode.OP_ENDIF),
        };
        const locking_hex_storage = try allocator.alloc(u8, locking_bytes.len * 2);
        defer allocator.free(locking_hex_storage);
        const locking_hex = try bsvz.primitives.hex.encodeLower(&locking_bytes, locking_hex_storage);
        const name = try std.fmt.allocPrint(allocator, "go row {d}: untaken if branch ignores opcode 0x{x:0>2}", .{ row_index, opcode_byte });
        defer allocator.free(name);

        try harness.runCase(allocator, .{
            .name = name,
            .unlocking_hex = "00",
            .locking_hex = locking_hex,
            .flags = flags,
            .expected = .{ .success = true },
        });
    }
}
