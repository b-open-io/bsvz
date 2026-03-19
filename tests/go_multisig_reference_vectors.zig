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

fn rowHasMultisig(row: DynamicRow) bool {
    return containsToken(row.unlocking_asm, "CHECKMULTISIG") or
        containsToken(row.unlocking_asm, "CHECKMULTISIGVERIFY") or
        containsToken(row.locking_asm, "CHECKMULTISIG") or
        containsToken(row.locking_asm, "CHECKMULTISIGVERIFY");
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
        if (std.mem.eql(u8, part, "NULLDUMMY")) {
            flags.null_dummy = true;
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
    if (std.mem.eql(u8, text, "SIG_NULLDUMMY")) return .{ .err = error.NullDummy };
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
    if (!rowHasMultisig(row)) return null;
    _ = parseFlags(row.flags_text) orelse return null;
    _ = parseExpected(row.expected_text) orelse return null;
    return row;
}

fn runDynamicRow(allocator: std.mem.Allocator, row: DynamicRow) !void {
    try harness.runCase(allocator, .{
        .name = "go multisig reference row",
        .unlocking_asm = row.unlocking_asm,
        .locking_asm = row.locking_asm,
        .flags = parseFlags(row.flags_text).?,
        .expected = parseExpected(row.expected_text).?,
    });
}

test "filtered go multisig reference rows execute through bsvz" {
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
                "filtered go multisig row {} failed\n  unlocking: {s}\n  locking: {s}\n  flags: {s}\n  expected: {s}\n",
                .{ row.index, row.unlocking_asm, row.locking_asm, row.flags_text, row.expected_text },
            );
            return err;
        };
        executed += 1;
    }

    std.debug.print("filtered go multisig rows executed={}, skipped={}\n", .{ executed, skipped });
    try std.testing.expect(executed >= 15);
}

test "exact go multisig reference rows execute through bsvz" {
    const allocator = std.testing.allocator;

    const ExactRow = struct {
        row: usize,
        name: []const u8,
        unlocking_asm: []const u8,
        locking_asm: []const u8,
        flags: bsvz.script.engine.ExecutionFlags,
        expected: harness.Expectation,
    };

    const relaxed = bsvz.script.engine.ExecutionFlags.legacyReference();
    var dersig = relaxed;
    dersig.der_signatures = true;
    var dersig_nullfail = dersig;
    dersig_nullfail.null_fail = true;
    var dersig_nullfail_nulldummy = dersig_nullfail;
    dersig_nullfail_nulldummy.null_dummy = true;

    const rows = [_]ExactRow{
        .{
            .row = 1307,
            .name = "row 1307 strict multisig not with first pubkey invalid",
            .unlocking_asm = "0 0x47 0x3044022044dc17b0887c161bb67ba9635bf758735bdde503e4b0a0987f587f14a4e1143d022009a215772d49a85dae40d8ca03955af26ad3978a0ff965faa12915e9586249a501 0x47 0x3044022044dc17b0887c161bb67ba9635bf758735bdde503e4b0a0987f587f14a4e1143d022009a215772d49a85dae40d8ca03955af26ad3978a0ff965faa12915e9586249a501",
            .locking_asm = "2 0x21 0x02865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac0 0 2 CHECKMULTISIG NOT",
            .flags = blk: {
                var f = bsvz.script.engine.ExecutionFlags.legacyReference();
                f.strict_encoding = true;
                break :blk f;
            },
            .expected = .{ .err = error.InvalidPublicKeyEncoding },
        },
        .{
            .row = 1308,
            .name = "row 1308 strict multisig not with first signature invalid",
            .unlocking_asm = "0 0x47 0x3044022044dc17b0887c161bb67ba9635bf758735bdde503e4b0a0987f587f14a4e1143d022009a215772d49a85dae40d8ca03955af26ad3978a0ff965faa12915e9586249a501 1",
            .locking_asm = "2 0x21 0x02865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac0 0x21 0x02865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac0 2 CHECKMULTISIG NOT",
            .flags = blk: {
                var f = bsvz.script.engine.ExecutionFlags.legacyReference();
                f.strict_encoding = true;
                break :blk f;
            },
            .expected = .{ .err = error.InvalidSignatureEncoding },
        },
        .{
            .row = 1309,
            .name = "row 1309 strict 2-of-3 multisig with parse-error signature",
            .unlocking_asm = "0 0x47 0x304402205451ce65ad844dbb978b8bdedf5082e33b43cae8279c30f2c74d9e9ee49a94f802203fe95a7ccf74da7a232ee523ef4a53cb4d14bdd16289680cdb97a63819b8f42f01 0x46 0x304402205451ce65ad844dbb978b8bdedf5082e33b43cae8279c30f2c74d9e9ee49a94f802203fe95a7ccf74da7a232ee523ef4a53cb4d14bdd16289680cdb97a63819b8f42f",
            .locking_asm = "2 0x21 0x02a673638cb9587cb68ea08dbef685c6f2d2a751a8b3c6f2a7e9a4999e6e4bfaf5 0x21 0x02a673638cb9587cb68ea08dbef685c6f2d2a751a8b3c6f2a7e9a4999e6e4bfaf5 0x21 0x02a673638cb9587cb68ea08dbef685c6f2d2a751a8b3c6f2a7e9a4999e6e4bfaf5 3 CHECKMULTISIG",
            .flags = blk: {
                var f = bsvz.script.engine.ExecutionFlags.legacyReference();
                f.strict_encoding = true;
                break :blk f;
            },
            .expected = .{ .err = error.InvalidSignatureEncoding },
        },
        .{
            .row = 1360,
            .name = "row 1360 bip66 example 7 without dersig",
            .unlocking_asm = "0 0x47 0x30440220cae00b1444babfbf6071b0ba8707f6bd373da3df494d6e74119b0430c5db810502205d5231b8c5939c8ff0c82242656d6e06edb073d42af336c99fe8837c36ea39d501 0x47 0x3044022027c2714269ca5aeecc4d70edc88ba5ee0e3da4986e9216028f489ab4f1b8efce022022bd545b4951215267e4c5ceabd4c5350331b2e4a0b6494c56f361fa5a57a1a201",
            .locking_asm = "2 0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 0x21 0x03363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640 2 CHECKMULTISIG",
            .flags = relaxed,
            .expected = .{ .success = true },
        },
        .{
            .row = 1361,
            .name = "row 1361 bip66 example 7 with dersig",
            .unlocking_asm = "0 0x47 0x30440220cae00b1444babfbf6071b0ba8707f6bd373da3df494d6e74119b0430c5db810502205d5231b8c5939c8ff0c82242656d6e06edb073d42af336c99fe8837c36ea39d501 0x47 0x3044022027c2714269ca5aeecc4d70edc88ba5ee0e3da4986e9216028f489ab4f1b8efce022022bd545b4951215267e4c5ceabd4c5350331b2e4a0b6494c56f361fa5a57a1a201",
            .locking_asm = "2 0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 0x21 0x03363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640 2 CHECKMULTISIG",
            .flags = blk: {
                var f = bsvz.script.engine.ExecutionFlags.legacyReference();
                f.der_signatures = true;
                break :blk f;
            },
            .expected = .{ .err = error.InvalidSignatureEncoding },
        },
        .{
            .row = 1362,
            .name = "row 1362 bip66 example 8 without dersig",
            .unlocking_asm = "0 0x47 0x30440220b119d67d389315308d1745f734a51ff3ec72e06081e84e236fdf9dc2f5d2a64802204b04e3bc38674c4422ea317231d642b56dc09d214a1ecbbf16ecca01ed996e2201 0x47 0x3044022079ea80afd538d9ada421b5101febeb6bc874e01dde5bca108c1d0479aec339a4022004576db8f66130d1df686ccf00935703689d69cf539438da1edab208b0d63c4801",
            .locking_asm = "2 0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 0x21 0x03363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640 2 CHECKMULTISIG NOT",
            .flags = relaxed,
            .expected = .{ .success = false },
        },
        .{
            .row = 1363,
            .name = "row 1363 bip66 example 8 with dersig",
            .unlocking_asm = "0 0x47 0x30440220b119d67d389315308d1745f734a51ff3ec72e06081e84e236fdf9dc2f5d2a64802204b04e3bc38674c4422ea317231d642b56dc09d214a1ecbbf16ecca01ed996e2201 0x47 0x3044022079ea80afd538d9ada421b5101febeb6bc874e01dde5bca108c1d0479aec339a4022004576db8f66130d1df686ccf00935703689d69cf539438da1edab208b0d63c4801",
            .locking_asm = "2 0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 0x21 0x03363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640 2 CHECKMULTISIG NOT",
            .flags = blk: {
                var f = bsvz.script.engine.ExecutionFlags.legacyReference();
                f.der_signatures = true;
                break :blk f;
            },
            .expected = .{ .err = error.InvalidSignatureEncoding },
        },
        .{
            .row = 1364,
            .name = "row 1364 bip66 example 9 without dersig",
            .unlocking_asm = "0 0 0x47 0x3044022081aa9d436f2154e8b6d600516db03d78de71df685b585a9807ead4210bd883490220534bb6bdf318a419ac0749660b60e78d17d515558ef369bf872eff405b676b2e01",
            .locking_asm = "2 0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 0x21 0x03363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640 2 CHECKMULTISIG",
            .flags = relaxed,
            .expected = .{ .success = false },
        },
        .{
            .row = 1365,
            .name = "row 1365 bip66 example 9 with dersig",
            .unlocking_asm = "0 0 0x47 0x3044022081aa9d436f2154e8b6d600516db03d78de71df685b585a9807ead4210bd883490220534bb6bdf318a419ac0749660b60e78d17d515558ef369bf872eff405b676b2e01",
            .locking_asm = "2 0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 0x21 0x03363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640 2 CHECKMULTISIG",
            .flags = blk: {
                var f = bsvz.script.engine.ExecutionFlags.legacyReference();
                f.der_signatures = true;
                break :blk f;
            },
            .expected = .{ .err = error.InvalidSignatureEncoding },
        },
        .{
            .row = 1366,
            .name = "row 1366 bip66 example 10 without dersig",
            .unlocking_asm = "0 0 0x47 0x30440220da6f441dc3b4b2c84cfa8db0cd5b34ed92c9e01686de5a800d40498b70c0dcac02207c2cf91b0c32b860c4cd4994be36cfb84caf8bb7c3a8e4d96a31b2022c5299c501",
            .locking_asm = "2 0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 0x21 0x03363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640 2 CHECKMULTISIG NOT",
            .flags = relaxed,
            .expected = .{ .success = true },
        },
        .{
            .row = 1367,
            .name = "row 1367 bip66 example 10 with dersig",
            .unlocking_asm = "0 0 0x47 0x30440220da6f441dc3b4b2c84cfa8db0cd5b34ed92c9e01686de5a800d40498b70c0dcac02207c2cf91b0c32b860c4cd4994be36cfb84caf8bb7c3a8e4d96a31b2022c5299c501",
            .locking_asm = "2 0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 0x21 0x03363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640 2 CHECKMULTISIG NOT",
            .flags = blk: {
                var f = bsvz.script.engine.ExecutionFlags.legacyReference();
                f.der_signatures = true;
                break :blk f;
            },
            .expected = .{ .err = error.InvalidSignatureEncoding },
        },
        .{
            .row = 1368,
            .name = "row 1368 bip66 example 11 without dersig",
            .unlocking_asm = "0 0x47 0x30440220cae00b1444babfbf6071b0ba8707f6bd373da3df494d6e74119b0430c5db810502205d5231b8c5939c8ff0c82242656d6e06edb073d42af336c99fe8837c36ea39d501 0",
            .locking_asm = "2 0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 0x21 0x03363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640 2 CHECKMULTISIG",
            .flags = relaxed,
            .expected = .{ .success = false },
        },
        .{
            .row = 1369,
            .name = "row 1369 bip66 example 11 with dersig",
            .unlocking_asm = "0 0x47 0x30440220cae00b1444babfbf6071b0ba8707f6bd373da3df494d6e74119b0430c5db810502205d5231b8c5939c8ff0c82242656d6e06edb073d42af336c99fe8837c36ea39d501 0",
            .locking_asm = "2 0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 0x21 0x03363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640 2 CHECKMULTISIG",
            .flags = dersig,
            .expected = .{ .success = false },
        },
        .{
            .row = 1370,
            .name = "row 1370 bip66 example 12 without dersig",
            .unlocking_asm = "0 0x47 0x30440220b119d67d389315308d1745f734a51ff3ec72e06081e84e236fdf9dc2f5d2a64802204b04e3bc38674c4422ea317231d642b56dc09d214a1ecbbf16ecca01ed996e2201 0",
            .locking_asm = "2 0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 0x21 0x03363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640 2 CHECKMULTISIG NOT",
            .flags = relaxed,
            .expected = .{ .success = true },
        },
        .{
            .row = 1371,
            .name = "row 1371 bip66 example 12 with dersig",
            .unlocking_asm = "0 0x47 0x30440220b119d67d389315308d1745f734a51ff3ec72e06081e84e236fdf9dc2f5d2a64802204b04e3bc38674c4422ea317231d642b56dc09d214a1ecbbf16ecca01ed996e2201 0",
            .locking_asm = "2 0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 0x21 0x03363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640 2 CHECKMULTISIG NOT",
            .flags = dersig,
            .expected = .{ .success = true },
        },
        .{
            .row = 1382,
            .name = "row 1382 1-of-2 multisig with unchecked hybrid pubkey and no strictenc",
            .unlocking_asm = "0 0x47 0x304402202e79441ad1baf5a07fb86bae3753184f6717d9692680947ea8b6e8b777c69af1022079a262e13d868bb5a0964fefe3ba26942e1b0669af1afb55ef3344bc9d4fc4c401",
            .locking_asm = "1 0x41 0x0679be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8 0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 2 CHECKMULTISIG",
            .flags = relaxed,
            .expected = .{ .success = true },
        },
        .{
            .row = 1383,
            .name = "row 1383 1-of-2 multisig with unchecked hybrid pubkey under strictenc",
            .unlocking_asm = "0 0x47 0x304402202e79441ad1baf5a07fb86bae3753184f6717d9692680947ea8b6e8b777c69af1022079a262e13d868bb5a0964fefe3ba26942e1b0669af1afb55ef3344bc9d4fc4c401",
            .locking_asm = "1 0x41 0x0679be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8 0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 2 CHECKMULTISIG",
            .flags = blk: {
                var f = bsvz.script.engine.ExecutionFlags.legacyReference();
                f.strict_encoding = true;
                break :blk f;
            },
            .expected = .{ .success = true },
        },
        .{
            .row = 1485,
            .name = "row 1485 bip66 and nullfail compliant under dersig",
            .unlocking_asm = "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
            .locking_asm = "0x01 0x14 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0x01 0x14 CHECKMULTISIG NOT",
            .flags = dersig,
            .expected = .{ .success = true },
        },
        .{
            .row = 1486,
            .name = "row 1486 bip66 and nullfail compliant under dersig nullfail",
            .unlocking_asm = "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
            .locking_asm = "0x01 0x14 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0x01 0x14 CHECKMULTISIG NOT",
            .flags = dersig_nullfail,
            .expected = .{ .success = true },
        },
        .{
            .row = 1487,
            .name = "row 1487 nonzero dummy is still ok without nulldummy",
            .unlocking_asm = "1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
            .locking_asm = "0x01 0x14 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0x01 0x14 CHECKMULTISIG NOT",
            .flags = dersig_nullfail,
            .expected = .{ .success = true },
        },
        .{
            .row = 1488,
            .name = "row 1488 nonzero dummy trips nulldummy",
            .unlocking_asm = "1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
            .locking_asm = "0x01 0x14 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0x01 0x14 CHECKMULTISIG NOT",
            .flags = dersig_nullfail_nulldummy,
            .expected = .{ .err = error.NullDummy },
        },
        .{
            .row = 1489,
            .name = "row 1489 bip66 compliant but not nullfail compliant under dersig",
            .unlocking_asm = "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0x09 0x300602010102010101",
            .locking_asm = "0x01 0x14 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0x01 0x14 CHECKMULTISIG NOT",
            .flags = dersig,
            .expected = .{ .success = true },
        },
        .{
            .row = 1490,
            .name = "row 1490 bip66 compliant but not nullfail compliant under nullfail",
            .unlocking_asm = "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0x09 0x300602010102010101",
            .locking_asm = "0x01 0x14 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0x01 0x14 CHECKMULTISIG NOT",
            .flags = dersig_nullfail,
            .expected = .{ .err = error.NullFail },
        },
        .{
            .row = 1491,
            .name = "row 1491 leading invalid signature is tolerated without nullfail",
            .unlocking_asm = "0 0x09 0x300602010102010101 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
            .locking_asm = "0x01 0x14 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0x01 0x14 CHECKMULTISIG NOT",
            .flags = dersig,
            .expected = .{ .success = true },
        },
        .{
            .row = 1492,
            .name = "row 1492 leading invalid signature trips nullfail",
            .unlocking_asm = "0 0x09 0x300602010102010101 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
            .locking_asm = "0x01 0x14 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0x01 0x14 CHECKMULTISIG NOT",
            .flags = dersig_nullfail,
            .expected = .{ .err = error.NullFail },
        },
    };

    for (rows) |row| {
        harness.runCase(allocator, .{
            .name = row.name,
            .unlocking_asm = row.unlocking_asm,
            .locking_asm = row.locking_asm,
            .flags = row.flags,
            .expected = row.expected,
        }) catch |err| {
            std.debug.print(
                "exact go multisig reference row {} failed\n  name: {s}\n  unlocking: {s}\n  locking: {s}\n",
                .{ row.row, row.name, row.unlocking_asm, row.locking_asm },
            );
            return err;
        };
    }
}
