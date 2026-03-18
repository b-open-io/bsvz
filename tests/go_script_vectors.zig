const std = @import("std");
const bsvz = @import("bsvz");
const harness = @import("support/go_script_harness.zig");
const builders = @import("support/go_vector_builders.zig");

const GoRow = struct {
    row: ?usize = null,
    name: []const u8,
    unlocking_hex: []const u8,
    locking_hex: []const u8,
    expected: harness.Expectation,
};

fn scriptHexForPushesAndOps(
    allocator: std.mem.Allocator,
    pushes: []const []const u8,
    ops: []const u8,
) ![]u8 {
    var bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer bytes.deinit(allocator);

    for (pushes) |push| try builders.appendPushData(&bytes, allocator, push);
    try bytes.appendSlice(allocator, ops);
    return builders.scriptHexFromBytes(allocator, bytes.items);
}

fn scriptNumBytes(allocator: std.mem.Allocator, value: i64) ![]u8 {
    return builders.scriptNumBytes(allocator, value);
}

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

test "go direct checkmultisig rows: nullfail and nulldummy matrix" {
    const allocator = std.testing.allocator;

    const empty_case = try builders.buildSyntheticCheckmultisigNotHexes(allocator, 0x00, null);
    defer allocator.free(empty_case.unlocking_hex);
    defer allocator.free(empty_case.locking_hex);

    var dersig_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    dersig_flags.der_signatures = true;

    try harness.runCase(allocator, .{
        .name = "20-of-20 not all-empty signatures with dersig",
        .unlocking_hex = empty_case.unlocking_hex,
        .locking_hex = empty_case.locking_hex,
        .flags = dersig_flags,
        .expected = .{ .success = true },
    });

    var nullfail_flags = dersig_flags;
    nullfail_flags.null_fail = true;

    try harness.runCase(allocator, .{
        .name = "20-of-20 not all-empty signatures with dersig and nullfail",
        .unlocking_hex = empty_case.unlocking_hex,
        .locking_hex = empty_case.locking_hex,
        .flags = nullfail_flags,
        .expected = .{ .success = true },
    });

    const nonzero_dummy_case = try builders.buildSyntheticCheckmultisigNotHexes(allocator, 0x51, null);
    defer allocator.free(nonzero_dummy_case.unlocking_hex);
    defer allocator.free(nonzero_dummy_case.locking_hex);

    try harness.runCase(allocator, .{
        .name = "20-of-20 not nonzero dummy with nullfail but no nulldummy",
        .unlocking_hex = nonzero_dummy_case.unlocking_hex,
        .locking_hex = nonzero_dummy_case.locking_hex,
        .flags = nullfail_flags,
        .expected = .{ .success = true },
    });

    var nulldummy_flags = nullfail_flags;
    nulldummy_flags.null_dummy = true;

    try harness.runCase(allocator, .{
        .name = "20-of-20 not nonzero dummy with nulldummy precedence",
        .unlocking_hex = nonzero_dummy_case.unlocking_hex,
        .locking_hex = nonzero_dummy_case.locking_hex,
        .flags = nulldummy_flags,
        .expected = .{ .err = error.NullDummy },
    });

    const nonempty_sig_case = try builders.buildSyntheticCheckmultisigNotHexes(allocator, 0x00, 19);
    defer allocator.free(nonempty_sig_case.unlocking_hex);
    defer allocator.free(nonempty_sig_case.locking_hex);

    try harness.runCase(allocator, .{
        .name = "20-of-20 not non-null der-compliant invalid signature with dersig",
        .unlocking_hex = nonempty_sig_case.unlocking_hex,
        .locking_hex = nonempty_sig_case.locking_hex,
        .flags = dersig_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "20-of-20 not non-null der-compliant invalid signature with nullfail",
        .unlocking_hex = nonempty_sig_case.unlocking_hex,
        .locking_hex = nonempty_sig_case.locking_hex,
        .flags = nullfail_flags,
        .expected = .{ .err = error.NullFail },
    });

    const leading_nonempty_sig_case = try builders.buildSyntheticCheckmultisigNotHexes(allocator, 0x00, 0);
    defer allocator.free(leading_nonempty_sig_case.unlocking_hex);
    defer allocator.free(leading_nonempty_sig_case.locking_hex);

    try harness.runCase(allocator, .{
        .name = "20-of-20 not leading non-null der-compliant invalid signature with dersig",
        .unlocking_hex = leading_nonempty_sig_case.unlocking_hex,
        .locking_hex = leading_nonempty_sig_case.locking_hex,
        .flags = dersig_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "20-of-20 not leading non-null der-compliant invalid signature with nullfail",
        .unlocking_hex = leading_nonempty_sig_case.unlocking_hex,
        .locking_hex = leading_nonempty_sig_case.locking_hex,
        .flags = nullfail_flags,
        .expected = .{ .err = error.NullFail },
    });
}

test "go direct checkmultisig rows: strict evaluation order" {
    const allocator = std.testing.allocator;

    var strict_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    strict_flags.strict_encoding = true;

    try harness.runCase(allocator, .{
        .name = "2-of-2 checkmultisig not errors on first checked invalid pubkey",
        .unlocking_hex =
            "00"
            ++ "09" ++ "300602010102010101"
            ++ "09" ++ "300602010102010101",
        .locking_hex =
            "52"
            ++ "21" ++ "02865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac0"
            ++ "00"
            ++ "52"
            ++ "ae91",
        .flags = strict_flags,
        .expected = .{ .err = error.InvalidPublicKeyEncoding },
    });

    try harness.runCase(allocator, .{
        .name = "2-of-2 checkmultisig not errors on first checked malformed signature",
        .unlocking_hex =
            "00"
            ++ "09" ++ "300602010102010101"
            ++ "51",
        .locking_hex =
            "52"
            ++ "21" ++ "02865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac0"
            ++ "21" ++ "02865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac0"
            ++ "52"
            ++ "ae91",
        .flags = strict_flags,
        .expected = .{ .err = error.InvalidSignatureEncoding },
    });
}

test "go direct script rows: checkmultisig zero count parity" {
    const allocator = std.testing.allocator;

    try runRows(allocator, bsvz.script.engine.ExecutionFlags.legacyReference(), &[_]GoRow{
        .{ .row = 565, .name = "checkmultisig allows zero keys and zero sigs", .unlocking_hex = "", .locking_hex = "000000ae69740087", .expected = .{ .success = true } },
        .{ .row = 566, .name = "checkmultisigverify allows zero keys and zero sigs", .unlocking_hex = "", .locking_hex = "000000af740087", .expected = .{ .success = true } },
        .{ .row = 567, .name = "checkmultisig ignores keys when zero sigs are required", .unlocking_hex = "", .locking_hex = "00000051ae69740087", .expected = .{ .success = true } },
        .{ .row = 568, .name = "checkmultisigverify ignores keys when zero sigs are required", .unlocking_hex = "", .locking_hex = "00000051af740087", .expected = .{ .success = true } },
    });

    const cases = [_]struct {
        row: usize,
        name: []const u8,
        key_count: usize,
        verify: bool,
    }{
        .{ .row = 594, .name = "checkmultisigverify with one key and zero sigs succeeds", .key_count = 1, .verify = true },
        .{ .row = 595, .name = "checkmultisigverify with two keys and zero sigs succeeds", .key_count = 2, .verify = true },
        .{ .row = 596, .name = "checkmultisigverify with three keys and zero sigs succeeds", .key_count = 3, .verify = true },
        .{ .row = 613, .name = "checkmultisigverify with twenty keys and zero sigs succeeds", .key_count = 20, .verify = true },
    };

    for (cases) |case| {
        var bytes: std.ArrayListUnmanaged(u8) = .empty;
        defer bytes.deinit(allocator);

        try bytes.append(allocator, @intFromEnum(bsvz.script.opcode.Opcode.OP_0));
        try bytes.append(allocator, @intFromEnum(bsvz.script.opcode.Opcode.OP_0));

        for (0..case.key_count) |index| {
            const key_byte: u8 = @intCast('a' + index);
            try bytes.append(allocator, 0x01);
            try bytes.append(allocator, key_byte);
        }

        if (case.key_count >= 1 and case.key_count <= 16) {
            try bytes.append(allocator, @intFromEnum(@as(bsvz.script.opcode.Opcode, @enumFromInt(
                @intFromEnum(bsvz.script.opcode.Opcode.OP_1) + @as(u8, @intCast(case.key_count - 1)),
            ))));
        } else {
            const count_num = try bsvz.script.ScriptNum.encode(allocator, @as(i64, @intCast(case.key_count)));
            defer allocator.free(count_num);
            try builders.appendPushData(&bytes, allocator, count_num);
        }

        try bytes.append(allocator, if (case.verify)
            @intFromEnum(bsvz.script.opcode.Opcode.OP_CHECKMULTISIGVERIFY)
        else
            @intFromEnum(bsvz.script.opcode.Opcode.OP_CHECKMULTISIG));
        if (!case.verify) {
            try bytes.append(allocator, @intFromEnum(bsvz.script.opcode.Opcode.OP_VERIFY));
        }
        try bytes.append(allocator, @intFromEnum(bsvz.script.opcode.Opcode.OP_DEPTH));
        try bytes.append(allocator, @intFromEnum(bsvz.script.opcode.Opcode.OP_0));
        try bytes.append(allocator, @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL));

        const locking_hex = try builders.scriptHexFromBytes(allocator, bytes.items);
        defer allocator.free(locking_hex);

        try harness.runCase(allocator, .{
            .name = case.name,
            .unlocking_hex = "",
            .locking_hex = locking_hex,
            .flags = bsvz.script.engine.ExecutionFlags.legacyReference(),
            .expected = .{ .success = true },
        });
    }
}

test "go direct script rows: executed and skipped disabled opcode precedence" {
    const allocator = std.testing.allocator;
    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.strict_encoding = true;

    try harness.runCase(allocator, .{
        .name = "executed vernotif remains a bad opcode",
        .unlocking_hex = "51",
        .locking_hex = "6366675168",
        .flags = flags,
        .expected = .{ .err = error.UnknownOpcode },
    });

    var post_genesis_flags = flags;
    post_genesis_flags.utxo_after_genesis = true;

    try harness.runCase(allocator, .{
        .name = "multiple else beats later vernotif after genesis",
        .unlocking_hex = "51",
        .locking_hex = "636751676668",
        .flags = post_genesis_flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });

    try harness.runCase(allocator, .{
        .name = "skipped disabled opcode in untaken branch is still ok",
        .unlocking_hex = "00",
        .locking_hex = "63ec675168",
        .flags = flags,
        .expected = .{ .success = true },
    });
}

test "go direct script rows: bin2num parity" {
    const allocator = std.testing.allocator;
    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.strict_encoding = true;

    const max_i32 = try scriptNumBytes(allocator, 2_147_483_647);
    defer allocator.free(max_i32);
    const neg_max_i32 = try scriptNumBytes(allocator, -2_147_483_647);
    defer allocator.free(neg_max_i32);
    const one = try scriptNumBytes(allocator, 1);
    defer allocator.free(one);
    const positive_983041 = try scriptNumBytes(allocator, 983_041);
    defer allocator.free(positive_983041);
    const negative_983041 = try scriptNumBytes(allocator, -983_041);
    defer allocator.free(negative_983041);

    const oversized_hex = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        max_i32,
        &[_]u8{ 0xff, 0xff, 0xff, 0xff, 0x00 },
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_BIN2NUM),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(oversized_hex);
    try harness.runCase(allocator, .{
        .name = "bin2num oversized argument is invalid number range",
        .unlocking_hex = oversized_hex,
        .locking_hex = "",
        .flags = flags,
        .expected = .{ .err = error.NumberTooBig },
    });

    const noncanonical_max_hex = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        neg_max_i32,
        &[_]u8{ 0xff, 0xff, 0xff, 0x7f, 0x80 },
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_BIN2NUM),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(noncanonical_max_hex);
    try harness.runCase(allocator, .{
        .name = "bin2num noncanonical max size negative argument is ok",
        .unlocking_hex = noncanonical_max_hex,
        .locking_hex = "",
        .flags = flags,
        .expected = .{ .success = true },
    });

    const significant_zero_hex = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        positive_983041,
        &[_]u8{ 0x01, 0x00, 0x0f, 0x00, 0x00 },
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_BIN2NUM),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(significant_zero_hex);
    try harness.runCase(allocator, .{
        .name = "bin2num retains significant zero bytes for positive values",
        .unlocking_hex = significant_zero_hex,
        .locking_hex = "",
        .flags = flags,
        .expected = .{ .success = true },
    });

    const significant_zero_negative_hex = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        negative_983041,
        &[_]u8{ 0x01, 0x00, 0x0f, 0x00, 0x80 },
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_BIN2NUM),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(significant_zero_negative_hex);
    try harness.runCase(allocator, .{
        .name = "bin2num retains significant zero bytes for negative values",
        .unlocking_hex = significant_zero_negative_hex,
        .locking_hex = "",
        .flags = flags,
        .expected = .{ .success = true },
    });

    const one_hex = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        one,
        &[_]u8{ 0x01, 0x00, 0x00, 0x00, 0x00 },
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_BIN2NUM),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(one_hex);
    try harness.runCase(allocator, .{
        .name = "bin2num normalizes trailing zero bytes down to one",
        .unlocking_hex = one_hex,
        .locking_hex = "",
        .flags = flags,
        .expected = .{ .success = true },
    });
}

test "go direct script rows: pick parity" {
    const allocator = std.testing.allocator;

    try runRows(allocator, bsvz.script.engine.ExecutionFlags.legacyReference(), &[_]GoRow{
        .{ .row = 198, .name = "pick index zero reads stack top without changing depth", .unlocking_hex = "011601150114", .locking_hex = "0079011488745387", .expected = .{ .success = true } },
        .{ .row = 199, .name = "pick index one reads second stack item", .unlocking_hex = "011601150114", .locking_hex = "5179011588745387", .expected = .{ .success = true } },
        .{ .row = 200, .name = "pick index two reads third stack item", .unlocking_hex = "011601150114", .locking_hex = "5279011688745387", .expected = .{ .success = true } },
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
        .{ .row = 201, .name = "roll index zero preserves top item and reduces depth", .unlocking_hex = "011601150114", .locking_hex = "007a011488745287", .expected = .{ .success = true } },
        .{ .row = 202, .name = "roll index one rotates second stack item to the top", .unlocking_hex = "011601150114", .locking_hex = "517a011588745287", .expected = .{ .success = true } },
        .{ .row = 203, .name = "roll index two rotates third stack item to the top", .unlocking_hex = "011601150114", .locking_hex = "527a011688745287", .expected = .{ .success = true } },
        .{ .row = 612, .name = "roll with minimally encoded index succeeds", .unlocking_hex = "51020000", .locking_hex = "7a7551", .expected = .{ .success = true } },
    });

    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.minimal_data = true;

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 1263, .name = "roll rejects non-minimally encoded index under minimaldata", .unlocking_hex = "51020000", .locking_hex = "7a7551", .expected = .{ .err = error.MinimalData } },
    });
}

test "go direct script rows: swap cat sha256 parity" {
    const allocator = std.testing.allocator;

    try runRows(allocator, bsvz.script.engine.ExecutionFlags.legacyReference(), &[_]GoRow{
        .{
            .row = 298,
            .name = "swap cat sha256 matches known hello-world digest",
            .unlocking_hex = "0568656c6c6f05776f726c64",
            .locking_hex = "7c7ea8208376118fc0230e6054e782fb31ae52ebcfd551342d8d026c209997e0127b6f7487",
            .expected = .{ .success = true },
        },
    });
}

test "go direct script rows: bitwise or parity" {
    const allocator = std.testing.allocator;
    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.strict_encoding = true;

    try harness.runCase(allocator, .{
        .name = "or with two equal byte vectors stays equal to the same vector",
        .unlocking_hex = "020100020100",
        .locking_hex = "8502010087",
        .flags = flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "or with two one-byte scalars yields one-byte true",
        .unlocking_hex = "5151",
        .locking_hex = "855187",
        .flags = flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "or with one stack item underflows",
        .unlocking_hex = "00",
        .locking_hex = "855087",
        .flags = flags,
        .expected = .{ .err = error.StackUnderflow },
    });

    try harness.runCase(allocator, .{
        .name = "or with empty stack underflows",
        .unlocking_hex = "",
        .locking_hex = "855087",
        .flags = flags,
        .expected = .{ .err = error.StackUnderflow },
    });
}

test "go direct script rows: size parity" {
    const allocator = std.testing.allocator;
    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.strict_encoding = true;

    const size_rows = [_]struct {
        row: usize,
        name: []const u8,
        value: i64,
        locking_hex: []const u8,
    }{
        .{ .row = 223, .name = "size of zero is zero bytes", .value = 0, .locking_hex = "820087" },
        .{ .row = 224, .name = "size of one is one byte", .value = 1, .locking_hex = "825187" },
        .{ .row = 225, .name = "size of 127 is one byte", .value = 127, .locking_hex = "825187" },
        .{ .row = 226, .name = "size of 128 is two bytes", .value = 128, .locking_hex = "825287" },
        .{ .row = 227, .name = "size of 32767 is two bytes", .value = 32_767, .locking_hex = "825287" },
        .{ .row = 228, .name = "size of 32768 is three bytes", .value = 32_768, .locking_hex = "825387" },
        .{ .row = 229, .name = "size of 8388607 is three bytes", .value = 8_388_607, .locking_hex = "825387" },
        .{ .row = 230, .name = "size of 8388608 is four bytes", .value = 8_388_608, .locking_hex = "825487" },
        .{ .row = 231, .name = "size of 2147483647 is four bytes", .value = 2_147_483_647, .locking_hex = "825487" },
        .{ .row = 232, .name = "size of 2147483648 is five bytes", .value = 2_147_483_648, .locking_hex = "825587" },
        .{ .row = 233, .name = "size of 549755813887 is five bytes", .value = 549_755_813_887, .locking_hex = "825587" },
        .{ .row = 234, .name = "size of 549755813888 is six bytes", .value = 549_755_813_888, .locking_hex = "825687" },
        .{ .row = 235, .name = "size of int64 max is eight bytes", .value = 9_223_372_036_854_775_807, .locking_hex = "825887" },
        .{ .row = 236, .name = "size of negative one is one byte", .value = -1, .locking_hex = "825187" },
        .{ .row = 237, .name = "size of negative 127 is one byte", .value = -127, .locking_hex = "825187" },
        .{ .row = 238, .name = "size of negative 128 is two bytes", .value = -128, .locking_hex = "825287" },
        .{ .row = 239, .name = "size of negative 32767 is two bytes", .value = -32_767, .locking_hex = "825287" },
        .{ .row = 240, .name = "size of negative 32768 is three bytes", .value = -32_768, .locking_hex = "825387" },
        .{ .row = 241, .name = "size of negative 8388607 is three bytes", .value = -8_388_607, .locking_hex = "825387" },
        .{ .row = 242, .name = "size of negative 8388608 is four bytes", .value = -8_388_608, .locking_hex = "825487" },
        .{ .row = 243, .name = "size of negative 2147483647 is four bytes", .value = -2_147_483_647, .locking_hex = "825487" },
        .{ .row = 244, .name = "size of negative 2147483648 is five bytes", .value = -2_147_483_648, .locking_hex = "825587" },
        .{ .row = 245, .name = "size of negative 549755813887 is five bytes", .value = -549_755_813_887, .locking_hex = "825587" },
        .{ .row = 246, .name = "size of negative 549755813888 is six bytes", .value = -549_755_813_888, .locking_hex = "825687" },
        .{ .row = 247, .name = "size of negative int64 max is eight bytes", .value = -9_223_372_036_854_775_807, .locking_hex = "825887" },
    };

    for (size_rows) |case| {
        const push = try scriptNumBytes(allocator, case.value);
        defer allocator.free(push);
        const unlocking_hex = try scriptHexForPushesAndOps(allocator, &[_][]const u8{push}, &[_]u8{});
        defer allocator.free(unlocking_hex);

        try harness.runCase(allocator, .{
            .name = case.name,
            .unlocking_hex = unlocking_hex,
            .locking_hex = case.locking_hex,
            .flags = flags,
            .expected = .{ .success = true },
        });
    }

    const push_32767 = try scriptNumBytes(allocator, 32_767);
    defer allocator.free(push_32767);
    var script_num_2147483648 = try bsvz.script.ScriptNum.fromValue(allocator, @as(i128, 2_147_483_648));
    defer script_num_2147483648.deinit();
    const push_2147483648 = try script_num_2147483648.encodeOwned(allocator);
    defer allocator.free(push_2147483648);
    const push_neg_8388608 = try scriptNumBytes(allocator, -8_388_608);
    defer allocator.free(push_neg_8388608);
    const size_two_hex = try scriptHexForPushesAndOps(allocator, &[_][]const u8{push_32767}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_SIZE),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_2),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(size_two_hex);
    const size_five_hex = try scriptHexForPushesAndOps(allocator, &[_][]const u8{push_2147483648}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_SIZE),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_5),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(size_five_hex);
    const size_four_hex = try scriptHexForPushesAndOps(allocator, &[_][]const u8{push_neg_8388608}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_SIZE),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_4),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(size_four_hex);

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 185, .name = "size of one-byte canonical positive number is one", .unlocking_hex = "51", .locking_hex = "825187", .expected = .{ .success = true } },
        .{ .row = 186, .name = "size of one-byte minimally encoded 127 is one", .unlocking_hex = "017f", .locking_hex = "825187", .expected = .{ .success = true } },
        .{ .row = 188, .name = "size of 32767 is two bytes", .unlocking_hex = size_two_hex, .locking_hex = "", .expected = .{ .success = true } },
        .{ .row = 197, .name = "size of one-byte minimally encoded negative one is one", .unlocking_hex = "4f", .locking_hex = "825187", .expected = .{ .success = true } },
        .{ .row = 198, .name = "size of one-byte minimally encoded negative 127 is one", .unlocking_hex = "01ff", .locking_hex = "825187", .expected = .{ .success = true } },
        .{ .row = 193, .name = "size of 2147483648 is five bytes", .unlocking_hex = size_five_hex, .locking_hex = "", .expected = .{ .success = true } },
        .{ .row = 203, .name = "size of -8388608 is four bytes", .unlocking_hex = size_four_hex, .locking_hex = "", .expected = .{ .success = true } },
        .{ .row = 209, .name = "size of alphabet payload is twenty six", .unlocking_hex = "1a6162636465666768696a6b6c6d6e6f707172737475767778797a", .locking_hex = "82011a87", .expected = .{ .success = true } },
        .{ .row = 210, .name = "size does not consume its argument", .unlocking_hex = "012a", .locking_hex = "825188012a87", .expected = .{ .success = true } },
        .{ .row = 848, .name = "size with one stack item underflows at equal", .unlocking_hex = "61", .locking_hex = "8251", .expected = .{ .err = error.StackUnderflow } },
    });
}

test "go direct script rows: skipped disabled opcode exact row" {
    const allocator = std.testing.allocator;
    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.strict_encoding = true;

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 353, .name = "if disabled opcode in untaken branch remains ok", .unlocking_hex = "00", .locking_hex = "63ec675168", .expected = .{ .success = true } },
    });

    try harness.runCase(allocator, .{
        .name = "if disabled 2div in untaken branch remains ok after genesis",
        .unlocking_hex = "5200",
        .locking_hex = "639668",
        .flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv(),
        .expected = .{ .success = true },
    });
}

test "go direct script rows: small integer opcode push sanity" {
    const allocator = std.testing.allocator;

    try runRows(allocator, bsvz.script.engine.ExecutionFlags.legacyReference(), &[_]GoRow{
        .{ .row = 552, .name = "op_10 pushes byte 0x0a", .unlocking_hex = "010a", .locking_hex = "5a87", .expected = .{ .success = true } },
    });
}

test "go direct script rows: boolean and minmaxwithin parity" {
    const allocator = std.testing.allocator;

    const push_neg_2147483647 = try scriptNumBytes(allocator, -2_147_483_647);
    defer allocator.free(push_neg_2147483647);
    const push_pos_2147483647 = try scriptNumBytes(allocator, 2_147_483_647);
    defer allocator.free(push_pos_2147483647);
    const push_neg_100 = try scriptNumBytes(allocator, -100);
    defer allocator.free(push_neg_100);
    const push_pos_100 = try scriptNumBytes(allocator, 100);
    defer allocator.free(push_pos_100);
    const push_eleven = try scriptNumBytes(allocator, 11);
    defer allocator.free(push_eleven);
    const push_zero = try scriptNumBytes(allocator, 0);
    defer allocator.free(push_zero);
    const push_neg_one = try scriptNumBytes(allocator, -1);
    defer allocator.free(push_neg_one);

    const within_315_hex = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        push_zero,
        push_neg_2147483647,
        push_pos_2147483647,
    }, &[_]u8{});
    defer allocator.free(within_315_hex);
    const within_316_hex = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        push_neg_one,
        push_neg_100,
        push_pos_100,
    }, &[_]u8{});
    defer allocator.free(within_316_hex);
    const within_317_hex = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        push_eleven,
        push_neg_100,
        push_pos_100,
    }, &[_]u8{});
    defer allocator.free(within_317_hex);
    const within_318_hex = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        push_neg_2147483647,
        push_neg_100,
        push_pos_100,
    }, &[_]u8{});
    defer allocator.free(within_318_hex);
    const within_319_hex = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        push_pos_2147483647,
        push_neg_100,
        push_pos_100,
    }, &[_]u8{});
    defer allocator.free(within_319_hex);

    try runRows(allocator, bsvz.script.engine.ExecutionFlags.legacyReference(), &[_]GoRow{
        .{ .row = 271, .name = "booland with true and true stays true", .unlocking_hex = "51519a", .locking_hex = "61", .expected = .{ .success = true } },
        .{ .row = 272, .name = "booland with true and false becomes true after not", .unlocking_hex = "51009a", .locking_hex = "91", .expected = .{ .success = true } },
        .{ .row = 273, .name = "booland with false and true becomes true after not", .unlocking_hex = "00519a", .locking_hex = "91", .expected = .{ .success = true } },
        .{ .row = 274, .name = "booland with false and false becomes true after not", .unlocking_hex = "00009a", .locking_hex = "91", .expected = .{ .success = true } },
        .{ .row = 275, .name = "booland with sixteen and seventeen stays true", .unlocking_hex = "6001119a", .locking_hex = "61", .expected = .{ .success = true } },
        .{ .row = 276, .name = "boolor with true and true stays true", .unlocking_hex = "51519b", .locking_hex = "61", .expected = .{ .success = true } },
        .{ .row = 277, .name = "boolor with true and false stays true", .unlocking_hex = "51009b", .locking_hex = "61", .expected = .{ .success = true } },
        .{ .row = 278, .name = "boolor with false and true stays true", .unlocking_hex = "00519b", .locking_hex = "61", .expected = .{ .success = true } },
        .{ .row = 279, .name = "boolor with false and false becomes true after not", .unlocking_hex = "00009b", .locking_hex = "91", .expected = .{ .success = true } },
        .{ .row = 280, .name = "boolor with sixteen and seventeen stays true", .unlocking_hex = "6001119b", .locking_hex = "61", .expected = .{ .success = true } },
        .{ .row = 313, .name = "within includes lower bound and excludes upper bound", .unlocking_hex = "000051", .locking_hex = "a5", .expected = .{ .success = true } },
        .{ .row = 314, .name = "within rejects upper bound and not makes it true", .unlocking_hex = "510051", .locking_hex = "a591", .expected = .{ .success = true } },
        .{ .row = 315, .name = "within accepts zero inside full int32 range", .unlocking_hex = within_315_hex, .locking_hex = "a5", .expected = .{ .success = true } },
        .{ .row = 316, .name = "within accepts negative one inside negative hundred to positive hundred", .unlocking_hex = within_316_hex, .locking_hex = "a5", .expected = .{ .success = true } },
        .{ .row = 317, .name = "within accepts eleven inside negative hundred to positive hundred", .unlocking_hex = within_317_hex, .locking_hex = "a5", .expected = .{ .success = true } },
        .{ .row = 318, .name = "within rejects very negative value and not makes it true", .unlocking_hex = within_318_hex, .locking_hex = "a591", .expected = .{ .success = true } },
        .{ .row = 319, .name = "within rejects very positive value and not makes it true", .unlocking_hex = within_319_hex, .locking_hex = "a591", .expected = .{ .success = true } },
        .{ .row = 534, .name = "booland treats negative one as true", .unlocking_hex = "4f4f9a", .locking_hex = "61", .expected = .{ .success = true } },
        .{ .row = 535, .name = "boolor treats negative one as true", .unlocking_hex = "4f009b", .locking_hex = "61", .expected = .{ .success = true } },
        .{ .row = 545, .name = "within rejects matching upper bound on negative one", .unlocking_hex = "4f4f00", .locking_hex = "a5", .expected = .{ .success = true } },
        .{ .row = 623, .name = "booland with false and non-minimal false shape still drops to true tail", .unlocking_hex = "00020000", .locking_hex = "9a7551", .expected = .{ .success = true } },
        .{ .row = 624, .name = "booland with reversed operands still drops to true tail", .unlocking_hex = "02000000", .locking_hex = "9a7551", .expected = .{ .success = true } },
        .{ .row = 625, .name = "boolor with false and non-minimal false shape still drops to true tail", .unlocking_hex = "00020000", .locking_hex = "9b7551", .expected = .{ .success = true } },
        .{ .row = 626, .name = "boolor with reversed operands still drops to true tail", .unlocking_hex = "02000000", .locking_hex = "9b7551", .expected = .{ .success = true } },
        .{ .row = 641, .name = "min with false and non-minimal false shape still drops to true tail", .unlocking_hex = "00020000", .locking_hex = "a37551", .expected = .{ .success = true } },
        .{ .row = 643, .name = "max with false and non-minimal false shape still drops to true tail", .unlocking_hex = "00020000", .locking_hex = "a47551", .expected = .{ .success = true } },
        .{ .row = 645, .name = "within with non-minimal false lower bound still drops to true tail", .unlocking_hex = "0200000000", .locking_hex = "a57551", .expected = .{ .success = true } },
        .{ .row = 646, .name = "within with non-minimal false upper bound still drops to true tail", .unlocking_hex = "0002000000", .locking_hex = "a57551", .expected = .{ .success = true } },
        .{ .row = 647, .name = "within with non-minimal false tested value still drops to true tail", .unlocking_hex = "0000020000", .locking_hex = "a57551", .expected = .{ .success = true } },
    });
}
