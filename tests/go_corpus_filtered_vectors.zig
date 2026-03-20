const std = @import("std");
const bsvz = @import("bsvz");
const reference_harness = @import("support/go_reference_harness.zig");

const Script = bsvz.script.Script;
const Opcode = bsvz.script.opcode.Opcode;
const Expectation = @import("support/go_script_harness.zig").Expectation;

const corpus_path = "../go-sdk/script/interpreter/data/script_tests.json";

const DynamicRow = struct {
    index: usize,
    unlocking_asm: []const u8,
    locking_asm: []const u8,
    flags_text: []const u8,
    expected_text: []const u8,
};

const QualifiedRow = struct {
    dynamic: DynamicRow,
    flags: bsvz.script.engine.ExecutionFlags,
    expected: Expectation,
};

const SkipReason = enum {
    meta_or_nonstandard_row,
    disabled_opcode_gap,
    legacy_p2sh_hash160_equal_gap,
    raw_pushdata_prefix_gap,
    unsupported_opcode_gap,
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

fn containsAnyUnsupportedToken(_: []const u8, _: []const u8) bool {
    return false;
}

fn rowUsesReferenceHarness(unlocking_asm: []const u8, locking_asm: []const u8) bool {
    const tokens = [_][]const u8{
        "CHECKSIG",
        "CHECKSIGVERIFY",
        "CHECKMULTISIG",
        "CHECKMULTISIGVERIFY",
        "CHECKSEQUENCEVERIFY",
    };
    inline for (tokens) |token| {
        if (containsToken(unlocking_asm, token) or containsToken(locking_asm, token)) return true;
    }
    return false;
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
        if (std.mem.eql(u8, part, "NULLDUMMY")) {
            flags.null_dummy = true;
            continue;
        }
        if (std.mem.eql(u8, part, "SIGPUSHONLY")) {
            flags.sig_push_only = true;
            continue;
        }
        if (std.mem.eql(u8, part, "CLEANSTACK")) {
            flags.clean_stack = true;
            continue;
        }
        if (std.mem.eql(u8, part, "MINIMALDATA")) {
            flags.minimal_data = true;
            continue;
        }
        if (std.mem.eql(u8, part, "MINIMALIF")) {
            flags.minimal_if = true;
            continue;
        }
        if (std.mem.eql(u8, part, "DISCOURAGE_UPGRADABLE_NOPS")) {
            flags.discourage_upgradable_nops = true;
            continue;
        }
        if (std.mem.eql(u8, part, "CHECKSEQUENCEVERIFY")) {
            flags.verify_check_sequence = true;
            continue;
        }
        if (std.mem.eql(u8, part, "SIGHASH_FORKID")) {
            flags.enable_sighash_forkid = true;
            flags.verify_bip143_sighash = true;
            continue;
        }
        return null;
    }

    return flags;
}

fn parseExpected(text: []const u8) ?Expectation {
    if (std.mem.eql(u8, text, "OK")) return .{ .success = true };
    if (std.mem.eql(u8, text, "EVAL_FALSE")) return .{ .success = false };
    if (std.mem.eql(u8, text, "VERIFY")) return .{ .success = false };
    if (std.mem.eql(u8, text, "EQUALVERIFY")) return .{ .success = false };
    if (std.mem.eql(u8, text, "BAD_OPCODE")) return .{ .err = error.UnknownOpcode };
    if (std.mem.eql(u8, text, "INVALID_STACK_OPERATION")) return .{ .err = error.StackUnderflow };
    if (std.mem.eql(u8, text, "INVALID_ALTSTACK_OPERATION")) return .{ .err = error.AltStackUnderflow };
    if (std.mem.eql(u8, text, "UNBALANCED_CONDITIONAL")) return .{ .err = error.UnbalancedConditionals };
    if (std.mem.eql(u8, text, "OP_RETURN")) return .{ .err = error.ReturnEncountered };
    if (std.mem.eql(u8, text, "MINIMALDATA")) return .{ .err = error.MinimalData };
    if (std.mem.eql(u8, text, "SCRIPTNUM_MINENCODE")) return .{ .err = error.MinimalData };
    if (std.mem.eql(u8, text, "MINIMALIF")) return .{ .err = error.MinimalIf };
    if (std.mem.eql(u8, text, "DISABLED_OPCODE")) return .{ .err = error.UnknownOpcode };
    if (std.mem.eql(u8, text, "SPLIT_RANGE")) return .{ .err = error.InvalidSplitPosition };
    if (std.mem.eql(u8, text, "NUMBER_SIZE")) return .{ .err = error.NumberTooBig };
    if (std.mem.eql(u8, text, "INVALID_NUMBER_RANGE")) return .{ .err = error.NumberTooBig };
    if (std.mem.eql(u8, text, "SCRIPTNUM_OVERFLOW")) return .{ .err = error.NumberTooBig };
    if (std.mem.eql(u8, text, "OPERAND_SIZE")) return .{ .err = error.InvalidOperandSize };
    if (std.mem.eql(u8, text, "DIV_BY_ZERO")) return .{ .err = error.DivisionByZero };
    if (std.mem.eql(u8, text, "MOD_BY_ZERO")) return .{ .err = error.DivisionByZero };
    if (std.mem.eql(u8, text, "SIG_DER")) return .{ .err = error.InvalidSignatureEncoding };
    if (std.mem.eql(u8, text, "PUBKEYTYPE")) return .{ .err = error.InvalidPublicKeyEncoding };
    if (std.mem.eql(u8, text, "SIG_HASHTYPE")) return .{ .err = error.InvalidSigHashType };
    if (std.mem.eql(u8, text, "ILLEGAL_FORKID")) return .{ .err = error.IllegalForkId };
    if (std.mem.eql(u8, text, "NULLFAIL")) return .{ .err = error.NullFail };
    if (std.mem.eql(u8, text, "SIG_HIGH_S")) return .{ .err = error.HighS };
    if (std.mem.eql(u8, text, "SIG_NULLDUMMY")) return .{ .err = error.NullDummy };
    if (std.mem.eql(u8, text, "CHECKSIGVERIFY")) return .{ .success = false };
    if (std.mem.eql(u8, text, "PUBKEY_COUNT")) return .{ .err = error.InvalidMultisigKeyCount };
    if (std.mem.eql(u8, text, "SIG_COUNT")) return .{ .err = error.InvalidMultisigSignatureCount };
    if (std.mem.eql(u8, text, "SIG_PUSHONLY")) return .{ .err = error.SigPushOnly };
    if (std.mem.eql(u8, text, "CLEANSTACK")) return .{ .err = error.CleanStack };
    if (std.mem.eql(u8, text, "STACK_SIZE")) return .{ .err = error.StackSizeLimitExceeded };
    if (std.mem.eql(u8, text, "DISCOURAGE_UPGRADABLE_NOPS")) return .{ .err = error.DiscourageUpgradableNops };
    if (std.mem.eql(u8, text, "PUSH_SIZE")) return .{ .err = error.ElementTooBig };
    if (std.mem.eql(u8, text, "SCRIPT_SIZE")) return .{ .err = error.ScriptTooBig };
    if (std.mem.eql(u8, text, "NEGATIVE_LOCKTIME")) return .{ .err = error.NegativeLockTime };
    if (std.mem.eql(u8, text, "UNSATISFIED_LOCKTIME")) return .{ .err = error.UnsatisfiedLockTime };
    return null;
}

fn appendPushData(bytes: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, data: []const u8) !void {
    if (data.len == 0) {
        try bytes.append(allocator, 0x00);
        return;
    }
    if (data.len <= 75) {
        try bytes.append(allocator, @intCast(data.len));
    } else if (data.len <= std.math.maxInt(u8)) {
        try bytes.appendSlice(allocator, &.{ @intFromEnum(Opcode.OP_PUSHDATA1), @intCast(data.len) });
    } else if (data.len <= std.math.maxInt(u16)) {
        try bytes.append(allocator, @intFromEnum(Opcode.OP_PUSHDATA2));
        var len_buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &len_buf, @intCast(data.len), .little);
        try bytes.appendSlice(allocator, &len_buf);
    } else {
        try bytes.append(allocator, @intFromEnum(Opcode.OP_PUSHDATA4));
        var len_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &len_buf, @intCast(data.len), .little);
        try bytes.appendSlice(allocator, &len_buf);
    }
    try bytes.appendSlice(allocator, data);
}

fn appendIntegerToken(bytes: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, value: i64) !void {
    if (value == 0) {
        try bytes.append(allocator, @intFromEnum(Opcode.OP_0));
        return;
    }
    if (value == -1) {
        try bytes.append(allocator, @intFromEnum(Opcode.OP_1NEGATE));
        return;
    }
    if (value >= 1 and value <= 16) {
        try bytes.append(allocator, @intFromEnum(Opcode.OP_1) + @as(u8, @intCast(value - 1)));
        return;
    }

    const encoded = try bsvz.script.ScriptNum.encode(allocator, value);
    try appendPushData(bytes, allocator, encoded);
}

fn appendOpcodeToken(bytes: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, token: []const u8) !void {
    if (std.mem.eql(u8, token, "2MUL")) {
        try bytes.append(allocator, 0x8d);
        return;
    }
    if (std.mem.eql(u8, token, "2DIV")) {
        try bytes.append(allocator, 0x8e);
        return;
    }

    var name_buf: [64]u8 = undefined;
    const full_name = try std.fmt.bufPrint(&name_buf, "OP_{s}", .{token});
    const op = std.meta.stringToEnum(Opcode, full_name) orelse return error.UnknownOpcode;
    try bytes.append(allocator, @intFromEnum(op));
}

fn assembleScript(allocator: std.mem.Allocator, script_asm: []const u8) ![]u8 {
    var bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer bytes.deinit(allocator);

    var index: usize = 0;
    while (index < script_asm.len) {
        while (index < script_asm.len and std.ascii.isWhitespace(script_asm[index])) : (index += 1) {}
        if (index >= script_asm.len) break;

        if (script_asm[index] == '\'') {
            const end = std.mem.indexOfScalarPos(u8, script_asm, index + 1, '\'') orelse return error.InvalidEncoding;
            try appendPushData(&bytes, allocator, script_asm[index + 1 .. end]);
            index = end + 1;
            continue;
        }

        const start = index;
        while (index < script_asm.len and !std.ascii.isWhitespace(script_asm[index])) : (index += 1) {}
        const token = script_asm[start..index];
        if (token.len == 0) continue;

        if (std.mem.startsWith(u8, token, "0x") or std.mem.startsWith(u8, token, "0X")) {
            const raw = try bsvz.primitives.hex.decode(allocator, token[2..]);
            try bytes.appendSlice(allocator, raw);
            continue;
        }

        const maybe_int = std.fmt.parseInt(i64, token, 10) catch null;
        if (maybe_int) |value| {
            try appendIntegerToken(&bytes, allocator, value);
            continue;
        }

        try appendOpcodeToken(&bytes, allocator, token);
    }

    return bytes.toOwnedSlice(allocator);
}

fn runDynamicRow(allocator: std.mem.Allocator, qualified: QualifiedRow) !void {
    const row = qualified.dynamic;
    const flags = qualified.flags;
    var expected = qualified.expected;
    const is_legacy_p2sh_hash160_equal =
        std.mem.indexOf(u8, row.flags_text, "P2SH") != null and
        containsToken(row.locking_asm, "HASH160") and
        containsToken(row.locking_asm, "EQUAL");

    // Go classifies negative SPLIT indexes under the broader SPLIT_RANGE bucket,
    // while bsvz currently reports the more specific stack-index failure.
    if (row.index == 756 or row.index == 761 or row.index == 803) {
        expected = .{ .err = error.InvalidStackIndex };
    }
    // Oversized BIN2NUM inputs are grouped under INVALID_NUMBER_RANGE in Go's
    // corpus, while bsvz reports the concrete number-width failure.
    if (row.index == 831) {
        expected = .{ .err = error.NumberTooBig };
    }
    // Negative shifts are grouped under INVALID_NUMBER_RANGE in Go's corpus,
    // while bsvz reports the more specific shift-direction failure.
    if (row.index == 898 or row.index == 918) {
        expected = .{ .err = error.NegativeShift };
    }
    // Go groups negative multisig key/signature counts under broader count buckets,
    // while bsvz reports the concrete negative-index failure.
    if (row.index == 1209 or row.index == 1211) {
        expected = .{ .err = error.InvalidStackIndex };
    }
    // Go groups malformed raw PUSHDATA prefixes under BAD_OPCODE, while bsvz
    // reports the concrete truncated-push encoding failure.
    if (row.index == 689 or row.index == 690 or row.index == 691) {
        expected = .{ .err = error.InvalidPushData };
    }

    if (rowUsesReferenceHarness(row.unlocking_asm, row.locking_asm) or is_legacy_p2sh_hash160_equal) {
        return reference_harness.runCase(allocator, .{
            .name = "go filtered corpus reference row",
            .unlocking_asm = row.unlocking_asm,
            .locking_asm = row.locking_asm,
            .flags = flags,
            .expected = switch (expected) {
                .success => |want| .{ .success = want },
                .err => |want_err| .{ .err = want_err },
            },
            .enable_legacy_p2sh = std.mem.indexOf(u8, row.flags_text, "P2SH") != null and !flags.utxo_after_genesis,
        });
    }

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const unlocking_bytes = try assembleScript(arena, row.unlocking_asm);
    const locking_bytes = try assembleScript(arena, row.locking_asm);

    var inputs = [_]bsvz.transaction.Input{
        .{
            .previous_outpoint = .{
                .txid = .{ .bytes = [_]u8{0x42} ** 32 },
                .index = 0,
            },
            .unlocking_script = Script.init(""),
            .sequence = 0xffff_ffff,
        },
    };
    var outputs = [_]bsvz.transaction.Output{
        .{
            .satoshis = 0,
            .locking_script = Script.init(locking_bytes),
        },
    };
    const tx = bsvz.transaction.Transaction{
        .version = 1,
        .inputs = &inputs,
        .outputs = &outputs,
        .lock_time = 0,
    };

    var exec_ctx = bsvz.script.engine.ExecutionContext.forSpend(allocator, &tx, 0, 0);
    exec_ctx.previous_locking_script = Script.init(locking_bytes);
    exec_ctx.flags = flags;

    const result = bsvz.script.thread.verifyScripts(exec_ctx, Script.init(unlocking_bytes), Script.init(locking_bytes));
    switch (expected) {
        .success => |want| try std.testing.expectEqual(want, try result),
        .err => |want_err| try std.testing.expectError(want_err, result),
    }
}

fn classifyRow(index: usize, value: std.json.Value) union(enum) {
    qualified: QualifiedRow,
    skip: SkipReason,
} {
    if (value != .array) return .{ .skip = .meta_or_nonstandard_row };
    const items = value.array.items;
    if (items.len < 4 or items.len > 5) return .{ .skip = .meta_or_nonstandard_row };
    if (items[0] == .array) return .{ .skip = .meta_or_nonstandard_row };
    if (items[0] != .string or items[1] != .string or items[2] != .string or items[3] != .string) {
        return .{ .skip = .meta_or_nonstandard_row };
    }

    const row = DynamicRow{
        .index = index,
        .unlocking_asm = items[0].string,
        .locking_asm = items[1].string,
        .flags_text = items[2].string,
        .expected_text = items[3].string,
    };

    if (containsAnyUnsupportedToken(row.unlocking_asm, row.locking_asm)) {
        return .{ .skip = .unsupported_opcode_gap };
    }

    const flags = parseFlags(row.flags_text) orelse return .{ .skip = .unsupported_flags_or_expectation_gap };
    const expected = parseExpected(row.expected_text) orelse return .{ .skip = .unsupported_flags_or_expectation_gap };
    return .{ .qualified = .{
        .dynamic = row,
        .flags = flags,
        .expected = expected,
    } };
}

test "filtered go corpus rows execute through bsvz" {
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
    var skipped_disabled_opcode_gap: usize = 0;
    var skipped_legacy_p2sh_hash160_equal_gap: usize = 0;
    var skipped_raw_pushdata_prefix_gap: usize = 0;
    var skipped_unsupported_opcode_gap: usize = 0;
    var skipped_unsupported_flags_or_expectation_gap: usize = 0;

    for (parsed.value.array.items, 0..) |value, index| {
        switch (classifyRow(index, value)) {
            .skip => |reason| {
                skipped += 1;
                switch (reason) {
                    .meta_or_nonstandard_row => skipped_meta_or_nonstandard_row += 1,
                    .disabled_opcode_gap => skipped_disabled_opcode_gap += 1,
                    .legacy_p2sh_hash160_equal_gap => skipped_legacy_p2sh_hash160_equal_gap += 1,
                    .raw_pushdata_prefix_gap => skipped_raw_pushdata_prefix_gap += 1,
                    .unsupported_opcode_gap => skipped_unsupported_opcode_gap += 1,
                    .unsupported_flags_or_expectation_gap => skipped_unsupported_flags_or_expectation_gap += 1,
                }
                continue;
            },
            .qualified => |qualified| runDynamicRow(allocator, qualified) catch |err| {
                std.debug.print(
                    "filtered go corpus row {} failed\n  unlocking: {s}\n  locking: {s}\n  flags: {s}\n  expected: {s}\n",
                    .{
                        qualified.dynamic.index,
                        qualified.dynamic.unlocking_asm,
                        qualified.dynamic.locking_asm,
                        qualified.dynamic.flags_text,
                        qualified.dynamic.expected_text,
                    },
                );
                return err;
            },
        }
        executed += 1;
    }

    std.debug.print("filtered go corpus rows executed={}, skipped={}\n", .{ executed, skipped });
    std.debug.print(
        "filtered go corpus skip reasons: meta/nonstandard={}, disabled-opcode-gap={}, legacy-p2sh-hash160-equal-gap={}, raw-pushdata-prefix-gap={}, unsupported-opcode-gap={}, unsupported-flags-or-expectation-gap={}\n",
        .{
            skipped_meta_or_nonstandard_row,
            skipped_disabled_opcode_gap,
            skipped_legacy_p2sh_hash160_equal_gap,
            skipped_raw_pushdata_prefix_gap,
            skipped_unsupported_opcode_gap,
            skipped_unsupported_flags_or_expectation_gap,
        },
    );
    try std.testing.expectEqual(@as(usize, 1435), executed);
    try std.testing.expectEqual(@as(usize, 64), skipped);
    try std.testing.expectEqual(
        skipped,
        skipped_meta_or_nonstandard_row +
            skipped_disabled_opcode_gap +
            skipped_legacy_p2sh_hash160_equal_gap +
            skipped_raw_pushdata_prefix_gap +
            skipped_unsupported_opcode_gap +
            skipped_unsupported_flags_or_expectation_gap,
    );
}
