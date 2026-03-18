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
        .{ .row = 264, .name = "not over zero leaves truthy result", .unlocking_hex = "0091", .locking_hex = "61", .expected = .{ .success = true } },
        .{ .row = 265, .name = "not over one becomes zero", .unlocking_hex = "5191", .locking_hex = "0087", .expected = .{ .success = true } },
        .{ .row = 266, .name = "not over eleven becomes zero", .unlocking_hex = "5b91", .locking_hex = "0087", .expected = .{ .success = true } },
        .{ .row = 267, .name = "zeronotequal over zero becomes zero", .unlocking_hex = "0092", .locking_hex = "0087", .expected = .{ .success = true } },
        .{ .row = 268, .name = "zeronotequal over one stays one", .unlocking_hex = "5192", .locking_hex = "5187", .expected = .{ .success = true } },
        .{ .row = 269, .name = "zeronotequal over eleven stays one", .unlocking_hex = "5b92", .locking_hex = "5187", .expected = .{ .success = true } },
        .{ .row = 270, .name = "zeronotequal over negative one stays one", .unlocking_hex = "4f92", .locking_hex = "5187", .expected = .{ .success = true } },
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

test "go direct script rows: boolean underflow parity" {
    const allocator = std.testing.allocator;

    try runRows(allocator, bsvz.script.engine.ExecutionFlags.legacyReference(), &[_]GoRow{
        .{ .row = 1430, .name = "not underflows with empty stack", .unlocking_hex = "", .locking_hex = "91", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 1431, .name = "zeronotequal underflows with empty stack", .unlocking_hex = "", .locking_hex = "92", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 1435, .name = "booland underflows with one stack item", .unlocking_hex = "51", .locking_hex = "9a", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 1436, .name = "boolor underflows with one stack item", .unlocking_hex = "51", .locking_hex = "9b", .expected = .{ .err = error.StackUnderflow } },
    });
}
