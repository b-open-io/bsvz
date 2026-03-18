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

fn numericOpDrop1Hex(allocator: std.mem.Allocator, op: bsvz.script.opcode.Opcode) ![]u8 {
    return builders.scriptHexFromBytes(allocator, &[_]u8{
        @intFromEnum(op),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_DROP),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_1),
    });
}

fn expectMinimalDataUnary(
    allocator: std.mem.Allocator,
    flags: bsvz.script.engine.ExecutionFlags,
    op: bsvz.script.opcode.Opcode,
    name: []const u8,
) !void {
    const locking_hex = try numericOpDrop1Hex(allocator, op);
    defer allocator.free(locking_hex);

    try harness.runCase(allocator, .{
        .name = name,
        .unlocking_hex = "020000",
        .locking_hex = locking_hex,
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });
}

fn expectMinimalDataBinary(
    allocator: std.mem.Allocator,
    flags: bsvz.script.engine.ExecutionFlags,
    op: bsvz.script.opcode.Opcode,
    name_left: []const u8,
    name_right: []const u8,
) !void {
    const locking_hex = try numericOpDrop1Hex(allocator, op);
    defer allocator.free(locking_hex);

    try harness.runCase(allocator, .{
        .name = name_left,
        .unlocking_hex = "00020000",
        .locking_hex = locking_hex,
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });

    try harness.runCase(allocator, .{
        .name = name_right,
        .unlocking_hex = "02000000",
        .locking_hex = locking_hex,
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });
}

fn scriptHexForOps(allocator: std.mem.Allocator, ops: []const bsvz.script.opcode.Opcode) ![]u8 {
    return builders.scriptHexForOps(allocator, ops);
}

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

test "go direct script rows: minimaldata push forms" {
    const allocator = std.testing.allocator;

    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.minimal_data = true;

    try harness.runCase(allocator, .{
        .name = "empty vector minimally represented by op_0",
        .unlocking_hex = "4c00",
        .locking_hex = "7551",
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });

    try harness.runCase(allocator, .{
        .name = "negative one minimally represented by op_1negate",
        .unlocking_hex = "0181",
        .locking_hex = "7551",
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });

    try harness.runCase(allocator, .{
        .name = "one minimally represented by op_1",
        .unlocking_hex = "0101",
        .locking_hex = "7551",
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });

    const direct_smallint_cases = [_]struct {
        name: []const u8,
        unlocking_hex: []const u8,
    }{
        .{ .name = "two minimally represented by op_2", .unlocking_hex = "0102" },
        .{ .name = "three minimally represented by op_3", .unlocking_hex = "0103" },
        .{ .name = "four minimally represented by op_4", .unlocking_hex = "0104" },
        .{ .name = "five minimally represented by op_5", .unlocking_hex = "0105" },
        .{ .name = "six minimally represented by op_6", .unlocking_hex = "0106" },
        .{ .name = "seven minimally represented by op_7", .unlocking_hex = "0107" },
        .{ .name = "eight minimally represented by op_8", .unlocking_hex = "0108" },
        .{ .name = "nine minimally represented by op_9", .unlocking_hex = "0109" },
        .{ .name = "ten minimally represented by op_10", .unlocking_hex = "010a" },
        .{ .name = "eleven minimally represented by op_11", .unlocking_hex = "010b" },
        .{ .name = "twelve minimally represented by op_12", .unlocking_hex = "010c" },
        .{ .name = "thirteen minimally represented by op_13", .unlocking_hex = "010d" },
        .{ .name = "fourteen minimally represented by op_14", .unlocking_hex = "010e" },
        .{ .name = "fifteen minimally represented by op_15", .unlocking_hex = "010f" },
        .{ .name = "sixteen minimally represented by op_16", .unlocking_hex = "0110" },
    };

    inline for (direct_smallint_cases) |case| {
        try harness.runCase(allocator, .{
            .name = case.name,
            .unlocking_hex = case.unlocking_hex,
            .locking_hex = "7551",
            .flags = flags,
            .expected = .{ .err = error.MinimalData },
        });
    }

    const push_72 = try std.mem.concat(allocator, u8, &[_][]const u8{
        "4c48",
        "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
    });
    defer allocator.free(push_72);

    try harness.runCase(allocator, .{
        .name = "pushdata1 of 72 bytes is non-minimal",
        .unlocking_hex = push_72,
        .locking_hex = "7551",
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });
}

test "go direct script rows: minimaldata numeric arguments" {
    const allocator = std.testing.allocator;

    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.minimal_data = true;

    const locking_not_drop_1 = try builders.scriptHexFromBytes(allocator, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NOT),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_DROP),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_1),
    });
    defer allocator.free(locking_not_drop_1);

    try harness.runCase(allocator, .{
        .name = "numeric minimaldata rejects direct-pushed zero",
        .unlocking_hex = "0100",
        .locking_hex = locking_not_drop_1,
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });

    try harness.runCase(allocator, .{
        .name = "numeric minimaldata rejects negative zero",
        .unlocking_hex = "0180",
        .locking_hex = locking_not_drop_1,
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });

    try expectMinimalDataUnary(allocator, flags, .OP_1ADD, "1add rejects non-minimal operand");
    try expectMinimalDataUnary(allocator, flags, .OP_1SUB, "1sub rejects non-minimal operand");
    try expectMinimalDataUnary(allocator, flags, .OP_NEGATE, "negate rejects non-minimal operand");
    try expectMinimalDataUnary(allocator, flags, .OP_ABS, "abs rejects non-minimal operand");
    try expectMinimalDataUnary(allocator, flags, .OP_0NOTEQUAL, "0notequal rejects non-minimal operand");

    const locking_pick_drop = try builders.scriptHexFromBytes(allocator, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_PICK),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_DROP),
    });
    defer allocator.free(locking_pick_drop);

    try harness.runCase(allocator, .{
        .name = "pick rejects non-minimal numeric index",
        .unlocking_hex = "51020000",
        .locking_hex = locking_pick_drop,
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });

    const locking_roll_drop_1 = try builders.scriptHexFromBytes(allocator, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_ROLL),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_DROP),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_1),
    });
    defer allocator.free(locking_roll_drop_1);

    try harness.runCase(allocator, .{
        .name = "roll rejects non-minimal numeric index",
        .unlocking_hex = "51020000",
        .locking_hex = locking_roll_drop_1,
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });

    try expectMinimalDataBinary(
        allocator,
        flags,
        .OP_ADD,
        "add rejects non-minimal left operand",
        "add rejects non-minimal right operand",
    );
    try expectMinimalDataBinary(
        allocator,
        flags,
        .OP_SUB,
        "sub rejects non-minimal left operand",
        "sub rejects non-minimal right operand",
    );
    try expectMinimalDataBinary(
        allocator,
        flags,
        .OP_BOOLAND,
        "booland rejects non-minimal left operand",
        "booland rejects non-minimal right operand",
    );
    try expectMinimalDataBinary(
        allocator,
        flags,
        .OP_BOOLOR,
        "boolor rejects non-minimal left operand",
        "boolor rejects non-minimal right operand",
    );
    try expectMinimalDataBinary(
        allocator,
        flags,
        .OP_NUMEQUAL,
        "numequal rejects non-minimal left operand",
        "numequal rejects non-minimal right operand",
    );

    const locking_numequalverify_1 = try builders.scriptHexFromBytes(allocator, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NUMEQUALVERIFY),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_1),
    });
    defer allocator.free(locking_numequalverify_1);

    try harness.runCase(allocator, .{
        .name = "numequalverify rejects non-minimal operand",
        .unlocking_hex = "00020000",
        .locking_hex = locking_numequalverify_1,
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });

    try expectMinimalDataBinary(
        allocator,
        flags,
        .OP_NUMNOTEQUAL,
        "numnotequal rejects non-minimal left operand",
        "numnotequal rejects non-minimal right operand",
    );
    try expectMinimalDataBinary(
        allocator,
        flags,
        .OP_LESSTHAN,
        "lessthan rejects non-minimal left operand",
        "lessthan rejects non-minimal right operand",
    );
    try expectMinimalDataBinary(
        allocator,
        flags,
        .OP_GREATERTHAN,
        "greaterthan rejects non-minimal left operand",
        "greaterthan rejects non-minimal right operand",
    );
    try expectMinimalDataBinary(
        allocator,
        flags,
        .OP_LESSTHANOREQUAL,
        "lessthanorequal rejects non-minimal left operand",
        "lessthanorequal rejects non-minimal right operand",
    );
    try expectMinimalDataBinary(
        allocator,
        flags,
        .OP_GREATERTHANOREQUAL,
        "greaterthanorequal rejects non-minimal left operand",
        "greaterthanorequal rejects non-minimal right operand",
    );
    try expectMinimalDataBinary(
        allocator,
        flags,
        .OP_MIN,
        "min rejects non-minimal left operand",
        "min rejects non-minimal right operand",
    );
    try expectMinimalDataBinary(
        allocator,
        flags,
        .OP_MAX,
        "max rejects non-minimal left operand",
        "max rejects non-minimal right operand",
    );

    const locking_within_drop_1 = try numericOpDrop1Hex(allocator, .OP_WITHIN);
    defer allocator.free(locking_within_drop_1);

    try harness.runCase(allocator, .{
        .name = "within rejects non-minimal operand",
        .unlocking_hex = "0200000000",
        .locking_hex = locking_within_drop_1,
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });

    try harness.runCase(allocator, .{
        .name = "within rejects non-minimal middle operand",
        .unlocking_hex = "0002000000",
        .locking_hex = locking_within_drop_1,
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });

    try harness.runCase(allocator, .{
        .name = "within rejects non-minimal top operand",
        .unlocking_hex = "0000020000",
        .locking_hex = locking_within_drop_1,
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });
}

test "go direct script rows: minimaldata multisig counts" {
    const allocator = std.testing.allocator;

    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.minimal_data = true;

    const checkmultisig_drop_1 = try scriptHexForOps(allocator, &[_]bsvz.script.opcode.Opcode{
        .OP_CHECKMULTISIG,
        .OP_DROP,
        .OP_1,
    });
    defer allocator.free(checkmultisig_drop_1);

    try harness.runCase(allocator, .{
        .name = "checkmultisig rejects non-minimal key count",
        .unlocking_hex = "0000020000",
        .locking_hex = checkmultisig_drop_1,
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });

    try harness.runCase(allocator, .{
        .name = "checkmultisig rejects non-minimal signature count",
        .unlocking_hex = "0002000000",
        .locking_hex = checkmultisig_drop_1,
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });

    try harness.runCase(allocator, .{
        .name = "checkmultisig rejects non-minimal signature count with one pubkey",
        .unlocking_hex = "000200000051",
        .locking_hex = checkmultisig_drop_1,
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });

    const checkmultisigverify_1 = try scriptHexForOps(allocator, &[_]bsvz.script.opcode.Opcode{
        .OP_CHECKMULTISIGVERIFY,
        .OP_1,
    });
    defer allocator.free(checkmultisigverify_1);

    try harness.runCase(allocator, .{
        .name = "checkmultisigverify rejects non-minimal key count",
        .unlocking_hex = "0000020000",
        .locking_hex = checkmultisigverify_1,
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });

    try harness.runCase(allocator, .{
        .name = "checkmultisigverify rejects non-minimal signature count",
        .unlocking_hex = "0002000000",
        .locking_hex = checkmultisigverify_1,
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });
}

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
        .name = "legacy if return bad opcode endif tail is ok when branch is not taken",
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
        .name = "post-genesis taken if return remains unbalanced without endif",
        .unlocking_hex = "51",
        .locking_hex = "63556a",
        .flags = post_genesis_flags,
        .expected = .{ .err = error.UnbalancedConditionals },
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
}

test "go direct script rows: false control-flow result shapes" {
    const allocator = std.testing.allocator;

    try runRows(allocator, bsvz.script.engine.ExecutionFlags.legacyReference(), &[_]GoRow{
        .{ .row = 851, .name = "dup if endif over zero leaves false result", .unlocking_hex = "00", .locking_hex = "766368", .expected = .{ .success = false } },
        .{ .row = 852, .name = "if true branch guarded by zero leaves false result", .unlocking_hex = "00", .locking_hex = "635168", .expected = .{ .success = false } },
        .{ .row = 853, .name = "dup if else endif over zero leaves false result", .unlocking_hex = "00", .locking_hex = "76636768", .expected = .{ .success = false } },
        .{ .row = 854, .name = "if else endif over zero leaves false result", .unlocking_hex = "00", .locking_hex = "63516768", .expected = .{ .success = false } },
        .{ .row = 855, .name = "notif else one endif over zero still leaves false result", .unlocking_hex = "00", .locking_hex = "64675168", .expected = .{ .success = false } },
    });
}

test "go direct script rows: compact op_return post-genesis rows" {
    const allocator = std.testing.allocator;
    const legacy_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    const post_genesis_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();

    try runRows(allocator, legacy_flags, &[_]GoRow{
        .{ .row = 883, .name = "legacy dup if return endif errors", .unlocking_hex = "51", .locking_hex = "76636a68", .expected = .{ .err = error.ReturnEncountered } },
        .{ .row = 886, .name = "legacy return data errors", .unlocking_hex = "51", .locking_hex = "6a0464617461", .expected = .{ .err = error.ReturnEncountered } },
    });

    try runRows(allocator, post_genesis_flags, &[_]GoRow{
        .{ .row = 884, .name = "post-genesis dup if return endif succeeds from top stack", .unlocking_hex = "51", .locking_hex = "76636a68", .expected = .{ .success = true } },
        .{ .row = 887, .name = "post-genesis return data succeeds from top stack", .unlocking_hex = "51", .locking_hex = "6a0464617461", .expected = .{ .success = true } },
    });
}

test "go direct script rows: legacy versus post-genesis multiple else" {
    const allocator = std.testing.allocator;
    const legacy_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    const post_genesis_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();

    try harness.runCase(allocator, .{
        .name = "legacy multiple else inverts execution when if branch is false",
        .unlocking_hex = "00",
        .locking_hex = "63006751670068",
        .flags = legacy_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "post-genesis multiple else is unbalanced when if branch is false",
        .unlocking_hex = "00",
        .locking_hex = "63006751670068",
        .flags = post_genesis_flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });

    try harness.runCase(allocator, .{
        .name = "legacy multiple else inverts execution when if branch is true",
        .unlocking_hex = "51",
        .locking_hex = "635167006768",
        .flags = legacy_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "post-genesis multiple else is unbalanced when if branch is true",
        .unlocking_hex = "51",
        .locking_hex = "635167006768",
        .flags = post_genesis_flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });

    try harness.runCase(allocator, .{
        .name = "legacy multiple else with empty first branch still reaches final true branch",
        .unlocking_hex = "51",
        .locking_hex = "636700675168",
        .flags = legacy_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "post-genesis multiple else with empty first branch is unbalanced",
        .unlocking_hex = "51",
        .locking_hex = "636700675168",
        .flags = post_genesis_flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });
}

test "go direct script rows: nested else else legacy versus post-genesis" {
    const allocator = std.testing.allocator;
    const legacy_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    const post_genesis_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();

    try harness.runCase(allocator, .{
        .name = "legacy nested else else succeeds for outer false path",
        .unlocking_hex = "00",
        .locking_hex = "6351636a676a676a6867516351676a675168676a68935287",
        .flags = legacy_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "post-genesis nested else else is unbalanced for outer false path",
        .unlocking_hex = "00",
        .locking_hex = "6351636a676a676a6867516351676a675168676a68935287",
        .flags = post_genesis_flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });

    try harness.runCase(allocator, .{
        .name = "legacy nested else else succeeds for outer true notif path",
        .unlocking_hex = "51",
        .locking_hex = "6400646a676a676a6867006451676a675168676a68935287",
        .flags = legacy_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "post-genesis nested else else is unbalanced for outer true notif path",
        .unlocking_hex = "51",
        .locking_hex = "6400646a676a676a6867006451676a675168676a68935287",
        .flags = post_genesis_flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });
}

test "go direct script rows: op_return in different branches" {
    const allocator = std.testing.allocator;
    const legacy_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    const post_genesis_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();

    try harness.runCase(allocator, .{
        .name = "legacy branch-selected op_return still errors",
        .unlocking_hex = "00",
        .locking_hex = "636a05646174613167516a05646174613268",
        .flags = legacy_flags,
        .expected = .{ .err = error.ReturnEncountered },
    });

    try harness.runCase(allocator, .{
        .name = "post-genesis branch-selected op_return keeps success when else branch pushes one first",
        .unlocking_hex = "00",
        .locking_hex = "636a05646174613167516a05646174613268",
        .flags = post_genesis_flags,
        .expected = .{ .success = true },
    });
}

test "go direct script-pair rows: stack and conditional state do not cross the seam" {
    const allocator = std.testing.allocator;
    const legacy_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    const post_genesis_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();

    try harness.runCase(allocator, .{
        .name = "altstack is not shared between unlocking and locking scripts",
        .unlocking_hex = "516b",
        .locking_hex = "6c51",
        .flags = legacy_flags,
        .expected = .{ .err = error.AltStackUnderflow },
    });

    try harness.runCase(allocator, .{
        .name = "if endif cannot span script pair even with return in locking script pre-genesis",
        .unlocking_hex = "0063",
        .locking_hex = "6a6851",
        .flags = legacy_flags,
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

test "go direct script rows: minimaldata not parity" {
    const allocator = std.testing.allocator;
    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.minimal_data = true;

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 1249, .name = "not rejects explicit zero push", .unlocking_hex = "0100", .locking_hex = "917551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1250, .name = "not rejects non-minimal zero push", .unlocking_hex = "020000", .locking_hex = "917551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1251, .name = "not rejects negative zero push", .unlocking_hex = "0180", .locking_hex = "917551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1252, .name = "not rejects non-minimal negative zero push", .unlocking_hex = "020080", .locking_hex = "917551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1253, .name = "not rejects non-minimal positive five push", .unlocking_hex = "020500", .locking_hex = "917551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1254, .name = "not rejects longer non-minimal positive five push", .unlocking_hex = "03050000", .locking_hex = "917551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1255, .name = "not rejects non-minimal negative five push", .unlocking_hex = "020580", .locking_hex = "917551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1256, .name = "not rejects longer non-minimal negative five push", .unlocking_hex = "03050080", .locking_hex = "917551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1257, .name = "not rejects non-minimal ffff encoding", .unlocking_hex = "03ff7f80", .locking_hex = "917551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1258, .name = "not rejects non-minimal ff7f encoding", .unlocking_hex = "03ff7f00", .locking_hex = "917551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1259, .name = "not rejects non-minimal ffffff encoding", .unlocking_hex = "04ffff7f80", .locking_hex = "917551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1260, .name = "not rejects non-minimal ffff7f encoding", .unlocking_hex = "04ffff7f00", .locking_hex = "917551", .expected = .{ .err = error.MinimalData } },
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

test "go direct script rows: minimaldata ignored in untaken branches" {
    const allocator = std.testing.allocator;
    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.minimal_data = true;

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 570, .name = "non-minimal pusdata1 is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "634c006851", .expected = .{ .success = true } },
        .{ .row = 571, .name = "non-minimal pusdata2 is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "634d00006851", .expected = .{ .success = true } },
        .{ .row = 572, .name = "non-minimal pusdata4 is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "634e000000006851", .expected = .{ .success = true } },
        .{ .row = 573, .name = "1negate-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "6301816851", .expected = .{ .success = true } },
        .{ .row = 574, .name = "op_1-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "6301016851", .expected = .{ .success = true } },
        .{ .row = 575, .name = "op_2-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "6301026851", .expected = .{ .success = true } },
        .{ .row = 576, .name = "op_3-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "6301036851", .expected = .{ .success = true } },
        .{ .row = 577, .name = "op_4-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "6301046851", .expected = .{ .success = true } },
        .{ .row = 578, .name = "op_5-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "6301056851", .expected = .{ .success = true } },
        .{ .row = 579, .name = "op_6-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "6301066851", .expected = .{ .success = true } },
        .{ .row = 580, .name = "op_7-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "6301076851", .expected = .{ .success = true } },
        .{ .row = 581, .name = "op_8-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "6301086851", .expected = .{ .success = true } },
        .{ .row = 582, .name = "op_9-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "6301096851", .expected = .{ .success = true } },
        .{ .row = 583, .name = "op_10-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "63010a6851", .expected = .{ .success = true } },
        .{ .row = 584, .name = "op_11-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "63010b6851", .expected = .{ .success = true } },
        .{ .row = 585, .name = "op_12-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "63010c6851", .expected = .{ .success = true } },
        .{ .row = 586, .name = "op_13-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "63010d6851", .expected = .{ .success = true } },
        .{ .row = 587, .name = "op_14-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "63010e6851", .expected = .{ .success = true } },
        .{ .row = 588, .name = "op_15-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "63010f6851", .expected = .{ .success = true } },
        .{ .row = 589, .name = "op_16-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "6301106851", .expected = .{ .success = true } },
    });
}

test "go direct script rows: minimaldata non-minimal unlocking pushes can still satisfy a simple lock" {
    const allocator = std.testing.allocator;
    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.minimal_data = true;

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 591, .name = "non-minimal zero push still satisfies simple lock", .unlocking_hex = "0100", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 592, .name = "negative zero push still satisfies simple lock", .unlocking_hex = "0180", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 593, .name = "non-minimal minus one push still satisfies simple lock", .unlocking_hex = "020180", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 594, .name = "non-minimal one push still satisfies simple lock", .unlocking_hex = "020100", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 595, .name = "non-minimal two push still satisfies simple lock", .unlocking_hex = "020200", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 596, .name = "non-minimal three push still satisfies simple lock", .unlocking_hex = "020300", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 597, .name = "non-minimal four push still satisfies simple lock", .unlocking_hex = "020400", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 598, .name = "non-minimal five push still satisfies simple lock", .unlocking_hex = "020500", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 599, .name = "non-minimal six push still satisfies simple lock", .unlocking_hex = "020600", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 600, .name = "non-minimal seven push still satisfies simple lock", .unlocking_hex = "020700", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 601, .name = "non-minimal eight push still satisfies simple lock", .unlocking_hex = "020800", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 602, .name = "non-minimal nine push still satisfies simple lock", .unlocking_hex = "020900", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 603, .name = "non-minimal ten push still satisfies simple lock", .unlocking_hex = "020a00", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 604, .name = "non-minimal eleven push still satisfies simple lock", .unlocking_hex = "020b00", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 605, .name = "non-minimal twelve push still satisfies simple lock", .unlocking_hex = "020c00", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 606, .name = "non-minimal thirteen push still satisfies simple lock", .unlocking_hex = "020d00", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 607, .name = "non-minimal fourteen push still satisfies simple lock", .unlocking_hex = "020e00", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 608, .name = "non-minimal fifteen push still satisfies simple lock", .unlocking_hex = "020f00", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 609, .name = "non-minimal sixteen push still satisfies simple lock", .unlocking_hex = "021000", .locking_hex = "51", .expected = .{ .success = true } },
    });
}

test "go direct script rows: minimaldata push form boundaries" {
    const allocator = std.testing.allocator;
    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.minimal_data = true;

    const push72 = try builders.repeatedHexByte(allocator, 72, 0x11);
    defer allocator.free(push72);
    const push255 = try builders.repeatedHexByte(allocator, 255, 0x11);
    defer allocator.free(push255);
    const push256 = try builders.repeatedHexByte(allocator, 256, 0x11);
    defer allocator.free(push256);

    var row1245_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer row1245_bytes.deinit(allocator);
    try row1245_bytes.append(allocator, @intFromEnum(bsvz.script.opcode.Opcode.OP_PUSHDATA1));
    try row1245_bytes.append(allocator, 0x48);
    try row1245_bytes.appendSlice(allocator, push72);
    try row1245_bytes.appendSlice(allocator, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_DROP),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_1),
    });
    const row1245_hex = try builders.scriptHexFromBytes(allocator, row1245_bytes.items);
    defer allocator.free(row1245_hex);

    var row1246_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer row1246_bytes.deinit(allocator);
    try row1246_bytes.append(allocator, @intFromEnum(bsvz.script.opcode.Opcode.OP_PUSHDATA2));
    try row1246_bytes.appendSlice(allocator, &[_]u8{ 0xff, 0x00 });
    try row1246_bytes.appendSlice(allocator, push255);
    try row1246_bytes.appendSlice(allocator, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_DROP),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_1),
    });
    const row1246_hex = try builders.scriptHexFromBytes(allocator, row1246_bytes.items);
    defer allocator.free(row1246_hex);

    var row1247_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer row1247_bytes.deinit(allocator);
    try row1247_bytes.append(allocator, @intFromEnum(bsvz.script.opcode.Opcode.OP_PUSHDATA4));
    try row1247_bytes.appendSlice(allocator, &[_]u8{ 0x00, 0x01, 0x00, 0x00 });
    try row1247_bytes.appendSlice(allocator, push256);
    try row1247_bytes.appendSlice(allocator, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_DROP),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_1),
    });
    const row1247_hex = try builders.scriptHexFromBytes(allocator, row1247_bytes.items);
    defer allocator.free(row1247_hex);

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 1227, .name = "minimaldata rejects pusdata1 empty vector", .unlocking_hex = "", .locking_hex = "4c007551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1228, .name = "minimaldata rejects explicit -1 push", .unlocking_hex = "", .locking_hex = "01817551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1229, .name = "minimaldata rejects explicit 1 push", .unlocking_hex = "", .locking_hex = "01017551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1238, .name = "minimaldata rejects explicit 10 push", .unlocking_hex = "", .locking_hex = "010a7551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1245, .name = "minimaldata rejects pusdata1 of 72 bytes", .unlocking_hex = "", .locking_hex = row1245_hex, .expected = .{ .err = error.MinimalData } },
        .{ .row = 1246, .name = "minimaldata rejects pusdata2 of 255 bytes", .unlocking_hex = "", .locking_hex = row1246_hex, .expected = .{ .err = error.MinimalData } },
        .{ .row = 1247, .name = "minimaldata rejects pusdata4 of 256 bytes", .unlocking_hex = "", .locking_hex = row1247_hex, .expected = .{ .err = error.MinimalData } },
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

test "go direct script rows: minimaldata numeric argument matrix" {
    const allocator = std.testing.allocator;
    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.minimal_data = true;

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 1264, .name = "1add rejects non-minimal operand", .unlocking_hex = "020000", .locking_hex = "8b7551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1265, .name = "1sub rejects non-minimal operand", .unlocking_hex = "020000", .locking_hex = "8c7551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1266, .name = "negate rejects non-minimal operand", .unlocking_hex = "020000", .locking_hex = "8f7551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1267, .name = "abs rejects non-minimal operand", .unlocking_hex = "020000", .locking_hex = "907551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1268, .name = "not exact minimaldata matrix row", .unlocking_hex = "020000", .locking_hex = "917551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1269, .name = "0notequal rejects non-minimal operand", .unlocking_hex = "020000", .locking_hex = "927551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1270, .name = "add rejects non-minimal left operand", .unlocking_hex = "00020000", .locking_hex = "937551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1271, .name = "add rejects non-minimal right operand", .unlocking_hex = "02000000", .locking_hex = "937551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1272, .name = "sub rejects non-minimal left operand", .unlocking_hex = "00020000", .locking_hex = "947551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1273, .name = "sub rejects non-minimal right operand", .unlocking_hex = "02000000", .locking_hex = "947551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1274, .name = "booland exact minimaldata matrix left row", .unlocking_hex = "00020000", .locking_hex = "9a7551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1275, .name = "booland exact minimaldata matrix right row", .unlocking_hex = "02000000", .locking_hex = "9a7551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1276, .name = "boolor exact minimaldata matrix left row", .unlocking_hex = "00020000", .locking_hex = "9b7551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1277, .name = "boolor exact minimaldata matrix right row", .unlocking_hex = "02000000", .locking_hex = "9b7551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1278, .name = "numequal rejects non-minimal left operand", .unlocking_hex = "00020000", .locking_hex = "9c7551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1279, .name = "numequal rejects non-minimal right operand", .unlocking_hex = "02000051", .locking_hex = "9c7551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1280, .name = "numequalverify rejects non-minimal left operand", .unlocking_hex = "00020000", .locking_hex = "9d51", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1281, .name = "numequalverify rejects non-minimal right operand", .unlocking_hex = "02000000", .locking_hex = "9d51", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1282, .name = "numnotequal rejects non-minimal left operand", .unlocking_hex = "00020000", .locking_hex = "9e7551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1283, .name = "numnotequal rejects non-minimal right operand", .unlocking_hex = "02000000", .locking_hex = "9e7551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1284, .name = "lessthan rejects non-minimal left operand", .unlocking_hex = "00020000", .locking_hex = "9f7551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1285, .name = "lessthan rejects non-minimal right operand", .unlocking_hex = "02000000", .locking_hex = "9f7551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1286, .name = "greaterthan rejects non-minimal left operand", .unlocking_hex = "00020000", .locking_hex = "a07551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1287, .name = "greaterthan rejects non-minimal right operand", .unlocking_hex = "02000000", .locking_hex = "a07551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1288, .name = "lessthanorequal rejects non-minimal left operand", .unlocking_hex = "00020000", .locking_hex = "a17551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1289, .name = "lessthanorequal rejects non-minimal right operand", .unlocking_hex = "02000000", .locking_hex = "a17551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1290, .name = "greaterthanorequal rejects non-minimal left operand", .unlocking_hex = "00020000", .locking_hex = "a27551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1291, .name = "greaterthanorequal rejects non-minimal right operand", .unlocking_hex = "02000000", .locking_hex = "a27551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1292, .name = "min rejects non-minimal left operand", .unlocking_hex = "00020000", .locking_hex = "a37551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1293, .name = "min rejects non-minimal right operand", .unlocking_hex = "02000000", .locking_hex = "a37551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1294, .name = "max rejects non-minimal left operand", .unlocking_hex = "00020000", .locking_hex = "a47551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1295, .name = "max rejects non-minimal right operand", .unlocking_hex = "02000000", .locking_hex = "a47551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1296, .name = "within rejects non-minimal tested value", .unlocking_hex = "0200000000", .locking_hex = "a57551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1297, .name = "within rejects non-minimal lower bound", .unlocking_hex = "0002000000", .locking_hex = "a57551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1298, .name = "within rejects non-minimal upper bound", .unlocking_hex = "0000020000", .locking_hex = "a57551", .expected = .{ .err = error.MinimalData } },
    });
}
