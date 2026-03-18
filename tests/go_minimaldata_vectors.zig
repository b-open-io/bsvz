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

    try expectMinimalDataBinary(allocator, flags, .OP_ADD, "add rejects non-minimal left operand", "add rejects non-minimal right operand");
    try expectMinimalDataBinary(allocator, flags, .OP_SUB, "sub rejects non-minimal left operand", "sub rejects non-minimal right operand");
    try expectMinimalDataBinary(allocator, flags, .OP_BOOLAND, "booland rejects non-minimal left operand", "booland rejects non-minimal right operand");
    try expectMinimalDataBinary(allocator, flags, .OP_BOOLOR, "boolor rejects non-minimal left operand", "boolor rejects non-minimal right operand");
    try expectMinimalDataBinary(allocator, flags, .OP_NUMEQUAL, "numequal rejects non-minimal left operand", "numequal rejects non-minimal right operand");

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

    try expectMinimalDataBinary(allocator, flags, .OP_NUMNOTEQUAL, "numnotequal rejects non-minimal left operand", "numnotequal rejects non-minimal right operand");
    try expectMinimalDataBinary(allocator, flags, .OP_LESSTHAN, "lessthan rejects non-minimal left operand", "lessthan rejects non-minimal right operand");
    try expectMinimalDataBinary(allocator, flags, .OP_GREATERTHAN, "greaterthan rejects non-minimal left operand", "greaterthan rejects non-minimal right operand");
    try expectMinimalDataBinary(allocator, flags, .OP_LESSTHANOREQUAL, "lessthanorequal rejects non-minimal left operand", "lessthanorequal rejects non-minimal right operand");
    try expectMinimalDataBinary(allocator, flags, .OP_GREATERTHANOREQUAL, "greaterthanorequal rejects non-minimal left operand", "greaterthanorequal rejects non-minimal right operand");
    try expectMinimalDataBinary(allocator, flags, .OP_MIN, "min rejects non-minimal left operand", "min rejects non-minimal right operand");
    try expectMinimalDataBinary(allocator, flags, .OP_MAX, "max rejects non-minimal left operand", "max rejects non-minimal right operand");

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
