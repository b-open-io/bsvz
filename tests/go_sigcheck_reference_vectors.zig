const std = @import("std");
const bsvz = @import("bsvz");
const harness = @import("support/go_reference_harness.zig");

const corpus_path = "../go-sdk/script/interpreter/data/script_tests.json";

const DynamicRow = struct {
    index: usize,
    input_amount: i64 = 0,
    unlocking_asm: []const u8,
    locking_asm: []const u8,
    flags_text: []const u8,
    expected_text: []const u8,
};

const QualifiedRow = struct {
    dynamic: DynamicRow,
    flags: bsvz.script.engine.ExecutionFlags,
    expected: harness.Expectation,
};

const SkipReason = enum {
    meta_or_nonstandard_row,
    non_sigcheck_row,
    unsupported_flags_or_expectation_gap,
};

fn accessOrRequire(rel_path: []const u8) !void {
    try std.fs.cwd().access(rel_path, .{});
}

fn containsToken(script_asm: []const u8, needle: []const u8) bool {
    var iter = std.mem.tokenizeScalar(u8, script_asm, ' ');
    while (iter.next()) |token| {
        if (std.mem.eql(u8, token, needle)) return true;
    }
    return false;
}

fn rowHasSigcheck(row: DynamicRow) bool {
    return containsToken(row.unlocking_asm, "CHECKSIG") or
        containsToken(row.unlocking_asm, "CHECKSIGVERIFY") or
        containsToken(row.locking_asm, "CHECKSIG") or
        containsToken(row.locking_asm, "CHECKSIGVERIFY");
}

fn parseFlags(text: []const u8) ?bsvz.script.engine.ExecutionFlags {
    const has_post_genesis = std.mem.indexOf(u8, text, "UTXO_AFTER_GENESIS") != null;
    var flags = if (has_post_genesis)
        bsvz.script.engine.ExecutionFlags.postGenesisBsv()
    else
        bsvz.script.engine.ExecutionFlags.legacyReference();

    var parts = std.mem.splitScalar(u8, text, ',');
    while (parts.next()) |raw_part| {
        const part = std.mem.trim(u8, raw_part, " \t\r\n");
        if (part.len == 0) continue;
        if (std.mem.eql(u8, part, "P2SH")) continue;
        if (std.mem.eql(u8, part, "UTXO_AFTER_GENESIS")) continue;
        if (std.mem.eql(u8, part, "STRICTENC")) {
            flags.strict_encoding = true;
            continue;
        }
        if (std.mem.eql(u8, part, "DERSIG")) {
            flags.der_signatures = true;
            continue;
        }
        if (std.mem.eql(u8, part, "LOW_S")) {
            flags.low_s = true;
            continue;
        }
        if (std.mem.eql(u8, part, "NULLFAIL")) {
            flags.null_fail = true;
            continue;
        }
        if (std.mem.eql(u8, part, "SIGHASH_FORKID")) {
            flags.enable_sighash_forkid = true;
            flags.verify_bip143_sighash = true;
            continue;
        }
        if (std.mem.eql(u8, part, "CLEANSTACK")) {
            flags.clean_stack = true;
            continue;
        }
        if (std.mem.eql(u8, part, "MINIMALIF")) {
            flags.minimal_if = true;
            continue;
        }
        return null;
    }
    return flags;
}

fn parseExpected(text: []const u8) ?harness.Expectation {
    if (std.mem.eql(u8, text, "OK")) return .{ .success = true };
    if (std.mem.eql(u8, text, "EVAL_FALSE")) return .{ .success = false };
    if (std.mem.eql(u8, text, "SIG_DER")) return .{ .err = error.InvalidSignatureEncoding };
    if (std.mem.eql(u8, text, "PUBKEYTYPE")) return .{ .err = error.InvalidPublicKeyEncoding };
    if (std.mem.eql(u8, text, "SIG_HASHTYPE")) return .{ .err = error.InvalidSigHashType };
    if (std.mem.eql(u8, text, "ILLEGAL_FORKID")) return .{ .err = error.IllegalForkId };
    if (std.mem.eql(u8, text, "NULLFAIL")) return .{ .err = error.NullFail };
    if (std.mem.eql(u8, text, "INVALID_STACK_OPERATION")) return .{ .err = error.StackUnderflow };
    if (std.mem.eql(u8, text, "SIG_HIGH_S")) return .{ .err = error.HighS };
    if (std.mem.eql(u8, text, "EQUALVERIFY")) return .{ .success = false };
    if (std.mem.eql(u8, text, "CHECKSIGVERIFY")) return .{ .success = false };
    if (std.mem.eql(u8, text, "MINIMALIF")) return .{ .err = error.MinimalIf };
    if (std.mem.eql(u8, text, "CLEANSTACK")) return .{ .err = error.CleanStack };
    return null;
}

fn classifyRow(index: usize, value: std.json.Value) union(enum) {
    qualified: QualifiedRow,
    skip: SkipReason,
} {
    if (value != .array) return .{ .skip = .meta_or_nonstandard_row };
    const items = value.array.items;
    if (items.len < 4 or items.len > 6) return .{ .skip = .meta_or_nonstandard_row };

    var item_offset: usize = 0;
    var input_amount: i64 = 0;
    if (items[0] == .array) {
        const amount_items = items[0].array.items;
        if (amount_items.len == 0 or amount_items[0] != .float) return .{ .skip = .meta_or_nonstandard_row };
        input_amount = @intFromFloat(amount_items[0].float * 100_000_000.0);
        item_offset = 1;
    }

    if (items.len < item_offset + 4 or items.len > item_offset + 5) return .{ .skip = .meta_or_nonstandard_row };
    if (items[item_offset] != .string or items[item_offset + 1] != .string or items[item_offset + 2] != .string or items[item_offset + 3] != .string) {
        return .{ .skip = .meta_or_nonstandard_row };
    }

    const row = DynamicRow{
        .index = index,
        .input_amount = input_amount,
        .unlocking_asm = items[item_offset].string,
        .locking_asm = items[item_offset + 1].string,
        .flags_text = items[item_offset + 2].string,
        .expected_text = items[item_offset + 3].string,
    };
    if (!rowHasSigcheck(row)) return .{ .skip = .non_sigcheck_row };
    const flags = parseFlags(row.flags_text) orelse return .{ .skip = .unsupported_flags_or_expectation_gap };
    const expected = parseExpected(row.expected_text) orelse return .{ .skip = .unsupported_flags_or_expectation_gap };
    return .{ .qualified = .{
        .dynamic = row,
        .flags = flags,
        .expected = expected,
    } };
}

fn runDynamicRow(allocator: std.mem.Allocator, qualified: QualifiedRow) !void {
    try harness.runCase(allocator, .{
        .name = "go sigcheck reference row",
        .unlocking_asm = qualified.dynamic.unlocking_asm,
        .locking_asm = qualified.dynamic.locking_asm,
        .flags = qualified.flags,
        .expected = qualified.expected,
        .output_value = qualified.dynamic.input_amount,
    });
}

test "filtered go sigcheck reference rows execute through bsvz" {
    const allocator = std.testing.allocator;
    try accessOrRequire(corpus_path);

    const file = try std.fs.cwd().readFileAlloc(allocator, corpus_path, 8 * 1024 * 1024);
    defer allocator.free(file);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, file, .{});
    defer parsed.deinit();

    if (parsed.value != .array) return error.InvalidEncoding;

    var executed: usize = 0;
    var skipped: usize = 0;
    var skipped_meta_or_nonstandard_row: usize = 0;
    var skipped_non_sigcheck_row: usize = 0;
    var skipped_unsupported_flags_or_expectation_gap: usize = 0;

    for (parsed.value.array.items, 0..) |value, index| {
        switch (classifyRow(index, value)) {
            .skip => |reason| {
                skipped += 1;
                switch (reason) {
                    .meta_or_nonstandard_row => skipped_meta_or_nonstandard_row += 1,
                    .non_sigcheck_row => skipped_non_sigcheck_row += 1,
                    .unsupported_flags_or_expectation_gap => skipped_unsupported_flags_or_expectation_gap += 1,
                }
                continue;
            },
            .qualified => |qualified| runDynamicRow(allocator, qualified) catch |err| {
                const row = qualified.dynamic;
                std.debug.print(
                    "filtered go sigcheck row {} failed\n  unlocking: {s}\n  locking: {s}\n  flags: {s}\n  expected: {s}\n",
                    .{ row.index, row.unlocking_asm, row.locking_asm, row.flags_text, row.expected_text },
                );
                return err;
            },
        }
        executed += 1;
    }

    std.debug.print("filtered go sigcheck rows executed={}, skipped={}\n", .{ executed, skipped });
    std.debug.print(
        "filtered go sigcheck skip reasons: meta/nonstandard={}, non-sigcheck-row={}, unsupported-flags-or-expectation-gap={}\n",
        .{
            skipped_meta_or_nonstandard_row,
            skipped_non_sigcheck_row,
            skipped_unsupported_flags_or_expectation_gap,
        },
    );
    try std.testing.expectEqual(@as(usize, 80), executed);
    try std.testing.expectEqual(@as(usize, 1419), skipped);
    try std.testing.expectEqual(
        skipped,
        skipped_meta_or_nonstandard_row +
            skipped_non_sigcheck_row +
            skipped_unsupported_flags_or_expectation_gap,
    );
}

test "exact go sigcheck dynamic reference rows execute through bsvz" {
    const allocator = std.testing.allocator;
    try accessOrRequire(corpus_path);

    const file = try std.fs.cwd().readFileAlloc(allocator, corpus_path, 8 * 1024 * 1024);
    defer allocator.free(file);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, file, .{});
    defer parsed.deinit();

    if (parsed.value != .array) return error.InvalidEncoding;

    const rows = [_]struct { row: usize }{
        .{ .row = 655 },
        .{ .row = 668 },
        .{ .row = 669 },
        .{ .row = 670 },
        .{ .row = 671 },
        .{ .row = 672 },
        .{ .row = 673 },
        .{ .row = 674 },
        .{ .row = 675 },
        .{ .row = 1320 },
        .{ .row = 1321 },
        .{ .row = 1322 },
        .{ .row = 1323 },
        .{ .row = 1324 },
        .{ .row = 1325 },
        .{ .row = 1335 },
        .{ .row = 1345 },
        .{ .row = 1372 },
        .{ .row = 1400 },
        .{ .row = 1406 },
        .{ .row = 1407 },
        .{ .row = 1411 },
        .{ .row = 1412 },
        .{ .row = 1413 },
        .{ .row = 1417 },
        .{ .row = 1418 },
        .{ .row = 1495 },
    };

    for (rows) |row_ref| {
        const qualified = switch (classifyRow(row_ref.row, parsed.value.array.items[row_ref.row])) {
            .qualified => |qualified| qualified,
            .skip => {
                std.debug.print("go exact sigcheck row {} no longer qualifies for direct import\n", .{row_ref.row});
                return error.InvalidEncoding;
            },
        };
        const row = qualified.dynamic;
        runDynamicRow(allocator, qualified) catch |err| {
            std.debug.print(
                "go exact sigcheck row {} failed\n  unlocking: {s}\n  locking: {s}\n  flags: {s}\n  expected: {s}\n",
                .{ row.index, row.unlocking_asm, row.locking_asm, row.flags_text, row.expected_text },
            );
            return err;
        };
    }
}

test "exact go sigcheck reference rows execute through bsvz" {
    const allocator = std.testing.allocator;
    const flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    const ExactRow = struct {
        row: ?usize = null,
        name: []const u8,
        unlocking_asm: []const u8,
        locking_asm: []const u8,
        flags: bsvz.script.engine.ExecutionFlags,
        expected: harness.Expectation,
    };

    const rows = [_]ExactRow{
        .{
            .row = 1336,
            .name = "row 1336 p2pk with too much r padding under dersig",
            .unlocking_asm = "0x47 0x304402200060558477337b9022e70534f1fea71a318caf836812465a2509931c5e7c4987022078ec32bd50ac9e03a349ba953dfd9fe1c8d2dd8bdb1d38ddca844d3d5c78c11801",
            .locking_asm = "0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 CHECKSIG",
            .flags = blk: {
                var f = bsvz.script.engine.ExecutionFlags.legacyReference();
                f.der_signatures = true;
                break :blk f;
            },
            .expected = .{ .err = error.InvalidSignatureEncoding },
        },
        .{
            .row = 1337,
            .name = "row 1337 p2pk with too much s padding but no dersig",
            .unlocking_asm = "0x48 0x304502202de8c03fc525285c9c535631019a5f2af7c6454fa9eb392a3756a4917c420edd02210046130bf2baf7cfc065067c8b9e33a066d9c15edcea9feb0ca2d233e3597925b401",
            .locking_asm = "0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 CHECKSIG",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .row = 1338,
            .name = "row 1338 p2pk with too much s padding under dersig",
            .unlocking_asm = "0x48 0x304502202de8c03fc525285c9c535631019a5f2af7c6454fa9eb392a3756a4917c420edd02210046130bf2baf7cfc065067c8b9e33a066d9c15edcea9feb0ca2d233e3597925b401",
            .locking_asm = "0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 CHECKSIG",
            .flags = blk: {
                var f = bsvz.script.engine.ExecutionFlags.legacyReference();
                f.der_signatures = true;
                break :blk f;
            },
            .expected = .{ .err = error.InvalidSignatureEncoding },
        },
        .{
            .row = 1340,
            .name = "row 1340 p2pk with too little r padding under dersig",
            .unlocking_asm = "0x47 0x30440220d7a0417c3f6d1a15094d1cf2a3378ca0503eb8a57630953a9e2987e21ddd0a6502207a6266d686c99090920249991d3d42065b6d43eb70187b219c0db82e4f94d1a201",
            .locking_asm = "0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 CHECKSIG",
            .flags = blk: {
                var f = bsvz.script.engine.ExecutionFlags.legacyReference();
                f.der_signatures = true;
                break :blk f;
            },
            .expected = .{ .err = error.InvalidSignatureEncoding },
        },
        .{
            .row = 1339,
            .name = "row 1339 p2pk with too little r padding but no dersig",
            .unlocking_asm = "0x47 0x30440220d7a0417c3f6d1a15094d1cf2a3378ca0503eb8a57630953a9e2987e21ddd0a6502207a6266d686c99090920249991d3d42065b6d43eb70187b219c0db82e4f94d1a201",
            .locking_asm = "0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 CHECKSIG",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .row = 1341,
            .name = "row 1341 p2pk not with bad sig too much r padding but no dersig",
            .unlocking_asm = "0x47 0x30440220005ece1335e7f757a1a1f476a7fb5bd90964e8a022489f890614a04acfb734c002206c12b8294a6513c7710e8c82d3c23d75cdbfe83200eb7efb495701958501a5d601",
            .locking_asm = "0x21 0x03363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640 CHECKSIG NOT",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .row = 1343,
            .name = "row 1343 p2pk not with too much r padding but no dersig",
            .unlocking_asm = "0x47 0x30440220005ece1335e7f657a1a1f476a7fb5bd90964e8a022489f890614a04acfb734c002206c12b8294a6513c7710e8c82d3c23d75cdbfe83200eb7efb495701958501a5d601",
            .locking_asm = "0x21 0x03363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640 CHECKSIG NOT",
            .flags = flags,
            .expected = .{ .success = false },
        },
        .{
            .row = 1346,
            .name = "row 1346 bip66 example 1 with dersig",
            .unlocking_asm = "0x47 0x30440220d7a0417c3f6d1a15094d1cf2a3378ca0503eb8a57630953a9e2987e21ddd0a6502207a6266d686c99090920249991d3d42065b6d43eb70187b219c0db82e4f94d1a201",
            .locking_asm = "0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 CHECKSIG",
            .flags = blk: {
                var f = bsvz.script.engine.ExecutionFlags.legacyReference();
                f.der_signatures = true;
                break :blk f;
            },
            .expected = .{ .err = error.InvalidSignatureEncoding },
        },
        .{
            .row = 1347,
            .name = "row 1347 bip66 example 2 without dersig",
            .unlocking_asm = "0x47 0x304402208e43c0b91f7c1e5bc58e41c8185f8a6086e111b0090187968a86f2822462d3c902200a58f4076b1133b18ff1dc83ee51676e44c60cc608d9534e0df5ace0424fc0be01",
            .locking_asm = "0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 CHECKSIG NOT",
            .flags = flags,
            .expected = .{ .success = false },
        },
        .{
            .row = 1348,
            .name = "row 1348 bip66 example 2 with dersig",
            .unlocking_asm = "0x47 0x304402208e43c0b91f7c1e5bc58e41c8185f8a6086e111b0090187968a86f2822462d3c902200a58f4076b1133b18ff1dc83ee51676e44c60cc608d9534e0df5ace0424fc0be01",
            .locking_asm = "0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 CHECKSIG NOT",
            .flags = blk: {
                var f = bsvz.script.engine.ExecutionFlags.legacyReference();
                f.der_signatures = true;
                break :blk f;
            },
            .expected = .{ .err = error.InvalidSignatureEncoding },
        },
        .{
            .row = 1349,
            .name = "row 1349 empty signature against checksig without dersig",
            .unlocking_asm = "0",
            .locking_asm = "0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 CHECKSIG",
            .flags = flags,
            .expected = .{ .success = false },
        },
        .{
            .row = 1350,
            .name = "row 1350 empty signature against checksig with dersig",
            .unlocking_asm = "0",
            .locking_asm = "0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 CHECKSIG",
            .flags = blk: {
                var f = bsvz.script.engine.ExecutionFlags.legacyReference();
                f.der_signatures = true;
                break :blk f;
            },
            .expected = .{ .success = false },
        },
        .{
            .row = 1351,
            .name = "row 1351 empty signature against checksig not without dersig",
            .unlocking_asm = "0",
            .locking_asm = "0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 CHECKSIG NOT",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .row = 1352,
            .name = "row 1352 empty signature against checksig not with dersig",
            .unlocking_asm = "0",
            .locking_asm = "0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 CHECKSIG NOT",
            .flags = blk: {
                var f = bsvz.script.engine.ExecutionFlags.legacyReference();
                f.der_signatures = true;
                break :blk f;
            },
            .expected = .{ .success = true },
        },
        .{
            .row = 1353,
            .name = "row 1353 nonnull der-compliant signature under checksig not with dersig",
            .unlocking_asm = "0x09 0x300602010102010101",
            .locking_asm = "0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 CHECKSIG NOT",
            .flags = blk: {
                var f = bsvz.script.engine.ExecutionFlags.legacyReference();
                f.der_signatures = true;
                break :blk f;
            },
            .expected = .{ .success = true },
        },
        .{
            .row = 1354,
            .name = "row 1354 empty signature under checksig not with dersig nullfail",
            .unlocking_asm = "0",
            .locking_asm = "0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 CHECKSIG NOT",
            .flags = blk: {
                var f = bsvz.script.engine.ExecutionFlags.legacyReference();
                f.der_signatures = true;
                f.null_fail = true;
                break :blk f;
            },
            .expected = .{ .success = true },
        },
        .{
            .row = 1355,
            .name = "row 1355 bip66 example 4 with dersig and nullfail",
            .unlocking_asm = "0x09 0x300602010102010101",
            .locking_asm = "0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 CHECKSIG NOT",
            .flags = blk: {
                var f = bsvz.script.engine.ExecutionFlags.legacyReference();
                f.der_signatures = true;
                f.null_fail = true;
                break :blk f;
            },
            .expected = .{ .err = error.NullFail },
        },
        .{
            .row = 1357,
            .name = "row 1357 bip66 example 5 with dersig",
            .unlocking_asm = "1",
            .locking_asm = "0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 CHECKSIG",
            .flags = blk: {
                var f = bsvz.script.engine.ExecutionFlags.legacyReference();
                f.der_signatures = true;
                break :blk f;
            },
            .expected = .{ .err = error.InvalidSignatureEncoding },
        },
        .{
            .row = 1356,
            .name = "row 1356 bip66 example 5 without dersig",
            .unlocking_asm = "1",
            .locking_asm = "0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 CHECKSIG",
            .flags = flags,
            .expected = .{ .success = false },
        },
        .{
            .row = 1359,
            .name = "row 1359 bip66 example 6 with dersig",
            .unlocking_asm = "1",
            .locking_asm = "0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 CHECKSIG NOT",
            .flags = blk: {
                var f = bsvz.script.engine.ExecutionFlags.legacyReference();
                f.der_signatures = true;
                break :blk f;
            },
            .expected = .{ .err = error.InvalidSignatureEncoding },
        },
        .{
            .row = 1358,
            .name = "row 1358 bip66 example 6 without dersig",
            .unlocking_asm = "1",
            .locking_asm = "0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 CHECKSIG NOT",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .row = 1374,
            .name = "row 1374 p2pk with high s but no low_s",
            .unlocking_asm = "0x48 0x304502203e4516da7253cf068effec6b95c41221c0cf3a8e6ccb8cbf1725b562e9afde2c022100ab1e3da73d67e32045a20e0b999e049978ea8d6ee5480d485fcf2ce0d03b2ef001",
            .locking_asm = "0x21 0x03363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640 CHECKSIG",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .row = 1373,
            .name = "row 1373 p2pk with multibyte hashtype under dersig",
            .unlocking_asm = "0x48 0x304402203e4516da7253cf068effec6b95c41221c0cf3a8e6ccb8cbf1725b562e9afde2c022054e1c258c2981cdfba5df1f46661fb6541c44f77ca0092f3600331abfffb12510101",
            .locking_asm = "0x21 0x03363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640 CHECKSIG",
            .flags = blk: {
                var f = bsvz.script.engine.ExecutionFlags.legacyReference();
                f.der_signatures = true;
                break :blk f;
            },
            .expected = .{ .err = error.InvalidSignatureEncoding },
        },
        .{
            .row = 1375,
            .name = "row 1375 p2pk with high s under low_s",
            .unlocking_asm = "0x48 0x304502203e4516da7253cf068effec6b95c41221c0cf3a8e6ccb8cbf1725b562e9afde2c022100ab1e3da73d67e32045a20e0b999e049978ea8d6ee5480d485fcf2ce0d03b2ef001",
            .locking_asm = "0x21 0x03363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640 CHECKSIG",
            .flags = blk: {
                var f = bsvz.script.engine.ExecutionFlags.legacyReference();
                f.low_s = true;
                break :blk f;
            },
            .expected = .{ .err = error.HighS },
        },
        .{
            .row = 1376,
            .name = "row 1376 p2pk with hybrid pubkey but no strictenc",
            .unlocking_asm = "0x47 0x3044022057292e2d4dfe775becdd0a9e6547997c728cdf35390f6a017da56d654d374e4902206b643be2fc53763b4e284845bfea2c597d2dc7759941dce937636c9d341b71ed01",
            .locking_asm = "0x41 0x0679be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8 CHECKSIG",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .row = 1378,
            .name = "row 1378 p2pk not with hybrid pubkey but no strictenc",
            .unlocking_asm = "0x47 0x30440220035d554e3153c14950c9993f41c496607a8e24093db0595be7bf875cf64fcf1f02204731c8c4e5daf15e706cec19cdd8f2c5b1d05490e11dab8465ed426569b6e92101",
            .locking_asm = "0x41 0x0679be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8 CHECKSIG NOT",
            .flags = flags,
            .expected = .{ .success = false },
        },
        .{
            .row = 1380,
            .name = "row 1380 p2pk not with invalid hybrid pubkey but no strictenc",
            .unlocking_asm = "0x47 0x30440220035d554e3153c04950c9993f41c496607a8e24093db0595be7bf875cf64fcf1f02204731c8c4e5daf15e706cec19cdd8f2c5b1d05490e11dab8465ed426569b6e92101",
            .locking_asm = "0x41 0x0679be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8 CHECKSIG NOT",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .row = 1385,
            .name = "row 1385 p2pk with undefined hashtype but no strictenc",
            .unlocking_asm = "0x47 0x304402206177d513ec2cda444c021a1f4f656fc4c72ba108ae063e157eb86dc3575784940220666fc66702815d0e5413bb9b1df22aed44f5f1efb8b99d41dd5dc9a5be6d205205",
            .locking_asm = "0x41 0x048282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f5150811f8a8098557dfe45e8256e830b60ace62d613ac2f7b17bed31b6eaff6e26caf CHECKSIG",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .row = 1387,
            .name = "row 1387 p2pkh with invalid sighashtype but no strictenc",
            .unlocking_asm = "0x47 0x30440220647a83507454f15f85f7e24de6e70c9d7b1d4020c71d0e53f4412425487e1dde022015737290670b4ab17b6783697a88ddd581c2d9c9efe26a59ac213076fc67f53021 0x41 0x0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
            .locking_asm = "DUP HASH160 0x14 0x91b24bf9f5288532960ac687abb035127b1d28a5 EQUALVERIFY CHECKSIG",
            .flags = flags,
            .expected = .{ .success = true },
        },
        .{
            .row = 1391,
            .name = "row 1391 p2pk not with invalid sig and undefined hashtype but no strictenc",
            .unlocking_asm = "0x47 0x304402207409b5b320296e5e2136a7b281a7f803028ca4ca44e2b83eebd46932677725de02202d4eea1c8d3c98e6f42614f54764e6e5e6542e213eb4d079737e9a8b6e9812ec05",
            .locking_asm = "0x41 0x048282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f5150811f8a8098557dfe45e8256e830b60ace62d613ac2f7b17bed31b6eaff6e26caf CHECKSIG NOT",
            .flags = flags,
            .expected = .{ .success = true },
        },
    };

    for (rows) |row| {
        try harness.runCase(allocator, .{
            .name = row.name,
            .unlocking_asm = row.unlocking_asm,
            .locking_asm = row.locking_asm,
            .flags = row.flags,
            .expected = row.expected,
        });
    }
}
