const std = @import("std");
const bsvz = @import("bsvz");
const harness = @import("support/go_script_harness.zig");

test "go direct script-pair rows: control flow cannot span scripts" {
    const allocator = std.testing.allocator;
    const flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    try harness.runCase(allocator, .{
        .name = "if endif cannot span unlocking and locking scripts",
        .unlocking_hex = "5163",
        .locking_hex = "5168",
        .flags = flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });

    try harness.runCase(allocator, .{
        .name = "opening conditional in unlocking script remains unbalanced",
        .unlocking_hex = "51630068",
        .locking_hex = "5168",
        .flags = flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });

    try harness.runCase(allocator, .{
        .name = "else branch cannot begin in unlocking script and end in locking script",
        .unlocking_hex = "51670068",
        .locking_hex = "51",
        .flags = flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });

    try harness.runCase(allocator, .{
        .name = "notif branch cannot remain open across script boundary",
        .unlocking_hex = "0064",
        .locking_hex = "017b",
        .flags = flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });
}

test "go direct script-pair rows: op_return seam behavior" {
    const allocator = std.testing.allocator;
    const legacy_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    const post_genesis_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();

    try harness.runCase(allocator, .{
        .name = "post-genesis if return bad opcode endif is still ok when return is taken",
        .unlocking_hex = "51",
        .locking_hex = "63556aba68",
        .flags = post_genesis_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "legacy if return endif bad opcode tail is still bad opcode when branch is not taken",
        .unlocking_hex = "00",
        .locking_hex = "636a68ba",
        .flags = legacy_flags,
        .expected = .{ .err = error.UnknownOpcode },
    });

    try harness.runCase(allocator, .{
        .name = "post-genesis if return endif bad opcode tail is still bad opcode when branch is not taken",
        .unlocking_hex = "00",
        .locking_hex = "636a68ba",
        .flags = post_genesis_flags,
        .expected = .{ .err = error.UnknownOpcode },
    });

    try harness.runCase(allocator, .{
        .name = "pre-genesis taken if return endif followed by taken return still errors",
        .unlocking_hex = "51",
        .locking_hex = "63556a68556aba",
        .flags = legacy_flags,
        .expected = .{ .err = error.ReturnEncountered },
    });

    try harness.runCase(allocator, .{
        .name = "post-genesis taken if return endif followed by taken return is still ok",
        .unlocking_hex = "51",
        .locking_hex = "63556a68556aba",
        .flags = post_genesis_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "legacy if return bad opcode endif tail is still bad opcode when branch is not taken",
        .unlocking_hex = "00",
        .locking_hex = "636a68ba55",
        .flags = legacy_flags,
        .expected = .{ .err = error.UnknownOpcode },
    });

    try harness.runCase(allocator, .{
        .name = "legacy taken if return bad opcode endif tail still errors",
        .unlocking_hex = "51",
        .locking_hex = "63556aba6855",
        .flags = legacy_flags,
        .expected = .{ .err = error.ReturnEncountered },
    });

    try harness.runCase(allocator, .{
        .name = "pre-genesis unlocking op_return is still an op_return error",
        .unlocking_hex = "6a",
        .locking_hex = "51",
        .flags = legacy_flags,
        .expected = .{ .err = error.ReturnEncountered },
    });

    try harness.runCase(allocator, .{
        .name = "post-genesis unlocking op_return can still satisfy a simple lock",
        .unlocking_hex = "6a",
        .locking_hex = "51",
        .flags = post_genesis_flags,
        .expected = .{ .success = true },
    });

    var push_only_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();
    push_only_flags.sig_push_only = true;

    try harness.runCase(allocator, .{
        .name = "sigpushonly rejects op_return in unlocking script after genesis",
        .unlocking_hex = "6a",
        .locking_hex = "51",
        .flags = push_only_flags,
        .expected = .{ .err = error.SigPushOnly },
    });

    try harness.runCase(allocator, .{
        .name = "pre-genesis locking op_return still errors with true unlocking stack top",
        .unlocking_hex = "51",
        .locking_hex = "6a",
        .flags = legacy_flags,
        .expected = .{ .err = error.ReturnEncountered },
    });

    try harness.runCase(allocator, .{
        .name = "pre-genesis locking op_return still errors with false unlocking stack top",
        .unlocking_hex = "00",
        .locking_hex = "6a",
        .flags = legacy_flags,
        .expected = .{ .err = error.ReturnEncountered },
    });

    try harness.runCase(allocator, .{
        .name = "post-genesis locking op_return preserves a true unlocking stack top",
        .unlocking_hex = "51",
        .locking_hex = "6a",
        .flags = post_genesis_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "post-genesis locking op_return preserves a false unlocking stack top",
        .unlocking_hex = "00",
        .locking_hex = "6a",
        .flags = post_genesis_flags,
        .expected = .{ .success = false },
    });

    try harness.runCase(allocator, .{
        .name = "pre-genesis return only works if not executed across the script seam",
        .unlocking_hex = "00",
        .locking_hex = "636a6851",
        .flags = legacy_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "post-genesis return only works if not executed across the script seam",
        .unlocking_hex = "00",
        .locking_hex = "636a6851",
        .flags = post_genesis_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "pre-genesis taken branch return still errors across the script seam",
        .unlocking_hex = "51",
        .locking_hex = "76636a68",
        .flags = legacy_flags,
        .expected = .{ .err = error.ReturnEncountered },
    });

    try harness.runCase(allocator, .{
        .name = "post-genesis taken branch return keeps the true stack top across the script seam",
        .unlocking_hex = "51",
        .locking_hex = "76636a68",
        .flags = post_genesis_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "pre-genesis locking return if still errors",
        .unlocking_hex = "51",
        .locking_hex = "6a63",
        .flags = legacy_flags,
        .expected = .{ .err = error.ReturnEncountered },
    });

    try harness.runCase(allocator, .{
        .name = "post-genesis locking return if short-circuits to success",
        .unlocking_hex = "51",
        .locking_hex = "6a63",
        .flags = post_genesis_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "pre-genesis locking return bad opcode tail still errors",
        .unlocking_hex = "51",
        .locking_hex = "6aba",
        .flags = legacy_flags,
        .expected = .{ .err = error.ReturnEncountered },
    });

    try harness.runCase(allocator, .{
        .name = "post-genesis locking return bad opcode tail still succeeds",
        .unlocking_hex = "51",
        .locking_hex = "6aba",
        .flags = post_genesis_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "if return without endif stays unbalanced when branch is not taken",
        .unlocking_hex = "00",
        .locking_hex = "636a",
        .flags = legacy_flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });

    try harness.runCase(allocator, .{
        .name = "if return without endif stays unbalanced after genesis when branch is not taken",
        .unlocking_hex = "00",
        .locking_hex = "636a",
        .flags = post_genesis_flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });

    try harness.runCase(allocator, .{
        .name = "pre-genesis taken if return still errors before endif",
        .unlocking_hex = "51",
        .locking_hex = "63556a",
        .flags = legacy_flags,
        .expected = .{ .err = error.ReturnEncountered },
    });

    try harness.runCase(allocator, .{
        .name = "if return endif tail succeeds when branch is not taken",
        .unlocking_hex = "00",
        .locking_hex = "636a6855",
        .flags = legacy_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "if return endif tail succeeds after genesis when branch is not taken",
        .unlocking_hex = "00",
        .locking_hex = "636a6855",
        .flags = post_genesis_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "if return bad opcode tail without endif stays unbalanced when branch is not taken",
        .unlocking_hex = "00",
        .locking_hex = "636aba",
        .flags = legacy_flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });

    try harness.runCase(allocator, .{
        .name = "if return bad opcode tail without endif stays unbalanced after genesis when branch is not taken",
        .unlocking_hex = "00",
        .locking_hex = "636aba",
        .flags = post_genesis_flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });

    try harness.runCase(allocator, .{
        .name = "pre-genesis taken if return bad opcode tail still errors",
        .unlocking_hex = "51",
        .locking_hex = "63556aba",
        .flags = legacy_flags,
        .expected = .{ .err = error.ReturnEncountered },
    });

    try harness.runCase(allocator, .{
        .name = "post-genesis taken if return bad opcode tail remains unbalanced",
        .unlocking_hex = "51",
        .locking_hex = "63556aba",
        .flags = post_genesis_flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });

    try harness.runCase(allocator, .{
        .name = "if return bad opcode endif tail succeeds when branch is not taken",
        .unlocking_hex = "00",
        .locking_hex = "636aba6855",
        .flags = legacy_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "if return bad opcode endif tail succeeds after genesis when branch is not taken",
        .unlocking_hex = "00",
        .locking_hex = "636aba6855",
        .flags = post_genesis_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "row 109 if return endif then five return bad opcode still errors before genesis",
        .unlocking_hex = "00",
        .locking_hex = "636a68556aba",
        .flags = legacy_flags,
        .expected = .{ .err = error.ReturnEncountered },
    });

    try harness.runCase(allocator, .{
        .name = "row 110 if return endif then five return bad opcode succeeds after genesis",
        .unlocking_hex = "00",
        .locking_hex = "636a68556aba",
        .flags = post_genesis_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "row 111 if return endif then five return bad opcode still errors with a truthy unlock before genesis",
        .unlocking_hex = "51",
        .locking_hex = "636a68556aba",
        .flags = legacy_flags,
        .expected = .{ .err = error.ReturnEncountered },
    });

    try harness.runCase(allocator, .{
        .name = "row 112 if return endif then five return bad opcode yields false after genesis",
        .unlocking_hex = "51",
        .locking_hex = "636a68556aba",
        .flags = post_genesis_flags,
        .expected = .{ .success = false },
    });

    try harness.runCase(allocator, .{
        .name = "row 115 if five return endif then five return if still errors before genesis",
        .unlocking_hex = "51",
        .locking_hex = "63556a68556a63",
        .flags = legacy_flags,
        .expected = .{ .err = error.ReturnEncountered },
    });
}

test "go direct script-pair rows: stack and conditional state do not cross the seam" {
    const allocator = std.testing.allocator;
    const flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    try harness.runCase(allocator, .{
        .name = "altstack is not shared between unlocking and locking scripts",
        .unlocking_hex = "516b",
        .locking_hex = "6c",
        .flags = flags,
        .expected = .{ .err = error.AltStackUnderflow },
    });

    try harness.runCase(allocator, .{
        .name = "taken unlocking conditional cannot satisfy locking endif",
        .unlocking_hex = "516368",
        .locking_hex = "68",
        .flags = flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });

    try harness.runCase(allocator, .{
        .name = "skipped if return endif still leaves success path after genesis",
        .unlocking_hex = "00",
        .locking_hex = "636a6851",
        .flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv(),
        .expected = .{ .success = true },
    });

    const post_genesis_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();

    try harness.runCase(allocator, .{
        .name = "altstack is not shared between unlocking and locking scripts even with trailing success op",
        .unlocking_hex = "516b",
        .locking_hex = "6c51",
        .flags = flags,
        .expected = .{ .err = error.AltStackUnderflow },
    });

    try harness.runCase(allocator, .{
        .name = "if endif cannot span script pair even with return in locking script pre-genesis",
        .unlocking_hex = "0063",
        .locking_hex = "6a6851",
        .flags = flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });

    try harness.runCase(allocator, .{
        .name = "if endif cannot span script pair even with return in locking script post-genesis",
        .unlocking_hex = "0063",
        .locking_hex = "6a6851",
        .flags = post_genesis_flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });

    try harness.runCase(allocator, .{
        .name = "skipped if return endif tail still succeeds after genesis",
        .unlocking_hex = "00",
        .locking_hex = "63006a6851",
        .flags = post_genesis_flags,
        .expected = .{ .success = true },
    });
}
