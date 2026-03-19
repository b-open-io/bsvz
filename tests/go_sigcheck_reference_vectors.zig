const std = @import("std");
const bsvz = @import("bsvz");
const harness = @import("support/go_reference_harness.zig");

const corpus_path = "../go-sdk/script/interpreter/data/script_tests.json";

const DynamicRow = struct {
    index: usize,
    unlocking_asm: []const u8,
    locking_asm: []const u8,
    flags_text: []const u8,
    expected_text: []const u8,
};

fn accessOrSkip(rel_path: []const u8) !void {
    std.fs.cwd().access(rel_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
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
    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    var parts = std.mem.splitScalar(u8, text, ',');
    while (parts.next()) |raw_part| {
        const part = std.mem.trim(u8, raw_part, " \t\r\n");
        if (part.len == 0) continue;
        if (std.mem.eql(u8, part, "P2SH")) continue;
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
        return null;
    }
    return flags;
}

fn parseExpected(text: []const u8) ?harness.Expectation {
    if (std.mem.eql(u8, text, "SIG_DER")) return .{ .err = error.InvalidSignatureEncoding };
    if (std.mem.eql(u8, text, "PUBKEYTYPE")) return .{ .err = error.InvalidPublicKeyEncoding };
    if (std.mem.eql(u8, text, "SIG_HASHTYPE")) return .{ .err = error.InvalidSigHashType };
    if (std.mem.eql(u8, text, "ILLEGAL_FORKID")) return .{ .err = error.IllegalForkId };
    if (std.mem.eql(u8, text, "NULLFAIL")) return .{ .err = error.NullFail };
    if (std.mem.eql(u8, text, "INVALID_STACK_OPERATION")) return .{ .err = error.StackUnderflow };
    if (std.mem.eql(u8, text, "SIG_HIGH_S")) return .{ .err = error.HighS };
    return null;
}

fn rowFromJson(index: usize, value: std.json.Value) ?DynamicRow {
    if (value != .array) return null;
    const items = value.array.items;
    if (items.len < 4 or items.len > 5) return null;
    if (items[0] == .array) return null;
    if (items[0] != .string or items[1] != .string or items[2] != .string or items[3] != .string) return null;

    const row = DynamicRow{
        .index = index,
        .unlocking_asm = items[0].string,
        .locking_asm = items[1].string,
        .flags_text = items[2].string,
        .expected_text = items[3].string,
    };
    if (!rowHasSigcheck(row)) return null;
    _ = parseFlags(row.flags_text) orelse return null;
    _ = parseExpected(row.expected_text) orelse return null;
    return row;
}

fn runDynamicRow(allocator: std.mem.Allocator, row: DynamicRow) !void {
    try harness.runCase(allocator, .{
        .name = "go sigcheck reference row",
        .unlocking_asm = row.unlocking_asm,
        .locking_asm = row.locking_asm,
        .flags = parseFlags(row.flags_text).?,
        .expected = parseExpected(row.expected_text).?,
    });
}

test "filtered go sigcheck reference rows execute through bsvz" {
    const allocator = std.testing.allocator;
    try accessOrSkip(corpus_path);

    const file = try std.fs.cwd().readFileAlloc(allocator, corpus_path, 8 * 1024 * 1024);
    defer allocator.free(file);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, file, .{});
    defer parsed.deinit();

    if (parsed.value != .array) return error.InvalidEncoding;

    var executed: usize = 0;
    var skipped: usize = 0;

    for (parsed.value.array.items, 0..) |value, index| {
        const row = rowFromJson(index, value) orelse {
            skipped += 1;
            continue;
        };
        runDynamicRow(allocator, row) catch |err| {
            std.debug.print(
                "filtered go sigcheck row {} failed\n  unlocking: {s}\n  locking: {s}\n  flags: {s}\n  expected: {s}\n",
                .{ row.index, row.unlocking_asm, row.locking_asm, row.flags_text, row.expected_text },
            );
            return err;
        };
        executed += 1;
    }

    std.debug.print("filtered go sigcheck rows executed={}, skipped={}\n", .{ executed, skipped });
    try std.testing.expect(executed >= 25);
}
