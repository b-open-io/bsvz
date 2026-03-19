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
        row: ?usize = null,
        name: []const u8,
        value: i64,
        locking_hex: []const u8,
    }{
        .{ .name = "size of zero is zero bytes", .value = 0, .locking_hex = "820087" },
        .{ .row = 224, .name = "size of one is one byte", .value = 1, .locking_hex = "825187" },
        .{ .row = 225, .name = "size of 127 is one byte", .value = 127, .locking_hex = "825187" },
        .{ .name = "size of 128 is two bytes", .value = 128, .locking_hex = "825287" },
        .{ .row = 227, .name = "size of 32767 is two bytes", .value = 32_767, .locking_hex = "825287" },
        .{ .row = 228, .name = "size of 32768 is three bytes", .value = 32_768, .locking_hex = "825387" },
        .{ .row = 229, .name = "size of 8388607 is three bytes", .value = 8_388_607, .locking_hex = "825387" },
        .{ .row = 230, .name = "size of 8388608 is four bytes", .value = 8_388_608, .locking_hex = "825487" },
        .{ .row = 231, .name = "size of 2147483647 is four bytes", .value = 2_147_483_647, .locking_hex = "825487" },
        .{ .name = "size of 2147483648 is five bytes", .value = 2_147_483_648, .locking_hex = "825587" },
        .{ .row = 233, .name = "size of 549755813887 is five bytes", .value = 549_755_813_887, .locking_hex = "825587" },
        .{ .row = 234, .name = "size of 549755813888 is six bytes", .value = 549_755_813_888, .locking_hex = "825687" },
        .{ .row = 235, .name = "size of int64 max is eight bytes", .value = 9_223_372_036_854_775_807, .locking_hex = "825887" },
        .{ .name = "size of negative one is one byte", .value = -1, .locking_hex = "825187" },
        .{ .row = 237, .name = "size of negative 127 is one byte", .value = -127, .locking_hex = "825187" },
        .{ .row = 238, .name = "size of negative 128 is two bytes", .value = -128, .locking_hex = "825287" },
        .{ .row = 239, .name = "size of negative 32767 is two bytes", .value = -32_767, .locking_hex = "825287" },
        .{ .row = 240, .name = "size of negative 32768 is three bytes", .value = -32_768, .locking_hex = "825387" },
        .{ .row = 241, .name = "size of negative 8388607 is three bytes", .value = -8_388_607, .locking_hex = "825387" },
        .{ .row = 242, .name = "size of negative 8388608 is four bytes", .value = -8_388_608, .locking_hex = "825487" },
        .{ .row = 243, .name = "size of negative 2147483647 is four bytes", .value = -2_147_483_647, .locking_hex = "825487" },
        .{ .name = "size of negative 2147483648 is five bytes", .value = -2_147_483_648, .locking_hex = "825587" },
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

    const push_8388608 = try scriptNumBytes(allocator, 8_388_608);
    defer allocator.free(push_8388608);
    const size_8388608_hex = try scriptHexForPushesAndOps(allocator, &[_][]const u8{push_8388608}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_SIZE),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_4),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(size_8388608_hex);

    const push_2147483647 = try scriptNumBytes(allocator, 2_147_483_647);
    defer allocator.free(push_2147483647);
    const size_2147483647_hex = try scriptHexForPushesAndOps(allocator, &[_][]const u8{push_2147483647}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_SIZE),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_4),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(size_2147483647_hex);

    var script_num_549755813887 = try bsvz.script.ScriptNum.fromValue(allocator, @as(i128, 549_755_813_887));
    defer script_num_549755813887.deinit();
    const push_549755813887 = try script_num_549755813887.encodeOwned(allocator);
    defer allocator.free(push_549755813887);
    const size_549755813887_hex = try scriptHexForPushesAndOps(allocator, &[_][]const u8{push_549755813887}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_SIZE),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_5),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(size_549755813887_hex);

    var script_num_i64_max = try bsvz.script.ScriptNum.fromValue(allocator, @as(i128, std.math.maxInt(i64)));
    defer script_num_i64_max.deinit();
    const push_i64_max = try script_num_i64_max.encodeOwned(allocator);
    defer allocator.free(push_i64_max);
    const size_i64_max_hex = try scriptHexForPushesAndOps(allocator, &[_][]const u8{push_i64_max}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_SIZE),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_8),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(size_i64_max_hex);

    const push_neg_128 = try scriptNumBytes(allocator, -128);
    defer allocator.free(push_neg_128);
    const size_neg_128_hex = try scriptHexForPushesAndOps(allocator, &[_][]const u8{push_neg_128}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_SIZE),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_2),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(size_neg_128_hex);

    const push_neg_32767 = try scriptNumBytes(allocator, -32_767);
    defer allocator.free(push_neg_32767);
    const size_neg_32767_hex = try scriptHexForPushesAndOps(allocator, &[_][]const u8{push_neg_32767}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_SIZE),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_2),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(size_neg_32767_hex);

    const push_neg_32768 = try scriptNumBytes(allocator, -32_768);
    defer allocator.free(push_neg_32768);
    const size_neg_32768_hex = try scriptHexForPushesAndOps(allocator, &[_][]const u8{push_neg_32768}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_SIZE),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_3),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(size_neg_32768_hex);

    const push_neg_8388607 = try scriptNumBytes(allocator, -8_388_607);
    defer allocator.free(push_neg_8388607);
    const size_neg_8388607_hex = try scriptHexForPushesAndOps(allocator, &[_][]const u8{push_neg_8388607}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_SIZE),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_3),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(size_neg_8388607_hex);

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 185, .name = "size of one-byte canonical positive number is one", .unlocking_hex = "51", .locking_hex = "825187", .expected = .{ .success = true } },
        .{ .row = 186, .name = "size of one-byte minimally encoded 127 is one", .unlocking_hex = "017f", .locking_hex = "825187", .expected = .{ .success = true } },
        .{ .row = 187, .name = "size of positive one hundred twenty eight is two bytes", .unlocking_hex = "028000", .locking_hex = "825287", .expected = .{ .success = true } },
        .{ .row = 188, .name = "size of 32767 is two bytes", .unlocking_hex = size_two_hex, .locking_hex = "", .expected = .{ .success = true } },
        .{ .row = 189, .name = "size of positive thirty two thousand seven hundred sixty eight is three bytes", .unlocking_hex = "03008000", .locking_hex = "825387", .expected = .{ .success = true } },
        .{ .row = 190, .name = "size of positive eight million three hundred eighty eight thousand six hundred seven is three bytes", .unlocking_hex = "03ffff7f", .locking_hex = "825387", .expected = .{ .success = true } },
        .{ .name = "size of positive eight million three hundred eighty eight thousand six hundred eight is four bytes", .unlocking_hex = size_8388608_hex, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "size of positive max int32 is four bytes", .unlocking_hex = size_2147483647_hex, .locking_hex = "", .expected = .{ .success = true } },
        .{ .row = 197, .name = "size of one-byte minimally encoded negative one is one", .unlocking_hex = "4f", .locking_hex = "825187", .expected = .{ .success = true } },
        .{ .row = 198, .name = "size of one-byte minimally encoded negative 127 is one", .unlocking_hex = "01ff", .locking_hex = "825187", .expected = .{ .success = true } },
        .{ .row = 199, .name = "size of negative one hundred twenty eight is two bytes", .unlocking_hex = size_neg_128_hex, .locking_hex = "", .expected = .{ .success = true } },
        .{ .row = 200, .name = "size of negative thirty two thousand seven hundred sixty seven is two bytes", .unlocking_hex = size_neg_32767_hex, .locking_hex = "", .expected = .{ .success = true } },
        .{ .row = 201, .name = "size of negative thirty two thousand seven hundred sixty eight is three bytes", .unlocking_hex = size_neg_32768_hex, .locking_hex = "", .expected = .{ .success = true } },
        .{ .row = 202, .name = "size of negative eight million three hundred eighty eight thousand six hundred seven is three bytes", .unlocking_hex = size_neg_8388607_hex, .locking_hex = "", .expected = .{ .success = true } },
        .{ .row = 193, .name = "size of 2147483648 is five bytes", .unlocking_hex = size_five_hex, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "size of positive five hundred forty nine billion seven hundred fifty five million eight hundred thirteen thousand eight hundred eighty seven is five bytes", .unlocking_hex = size_549755813887_hex, .locking_hex = "", .expected = .{ .success = true } },
        .{ .row = 195, .name = "size of positive five hundred forty nine billion seven hundred fifty five million eight hundred thirteen thousand eight hundred eighty eight is six bytes", .unlocking_hex = "06000000008000", .locking_hex = "825687", .expected = .{ .success = true } },
        .{ .name = "size of positive int64 max is eight bytes", .unlocking_hex = size_i64_max_hex, .locking_hex = "", .expected = .{ .success = true } },
        .{ .row = 203, .name = "size of -8388608 is four bytes", .unlocking_hex = size_four_hex, .locking_hex = "", .expected = .{ .success = true } },
        .{ .row = 204, .name = "size of negative max int32 is four bytes", .unlocking_hex = "04ffffffff", .locking_hex = "825487", .expected = .{ .success = true } },
        .{ .row = 205, .name = "size of negative two billion one hundred forty seven million four hundred eighty three thousand six hundred forty eight is five bytes", .unlocking_hex = "050000008080", .locking_hex = "825587", .expected = .{ .success = true } },
        .{ .row = 206, .name = "size of negative five hundred forty nine billion seven hundred fifty five million eight hundred thirteen thousand eight hundred eighty seven is five bytes", .unlocking_hex = "05ffffffffff", .locking_hex = "825587", .expected = .{ .success = true } },
        .{ .row = 207, .name = "size of negative five hundred forty nine billion seven hundred fifty five million eight hundred thirteen thousand eight hundred eighty eight is six bytes", .unlocking_hex = "06000000008080", .locking_hex = "825687", .expected = .{ .success = true } },
        .{ .row = 208, .name = "size of negative int64 max is eight bytes", .unlocking_hex = "08ffffffffffffffff", .locking_hex = "825887", .expected = .{ .success = true } },
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
        .{ .row = 222, .name = "not over zero leaves a truthy nop tail", .unlocking_hex = "0091", .locking_hex = "61", .expected = .{ .success = true } },
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
        .{ .name = "boolor with false and true stays true", .unlocking_hex = "00519b", .locking_hex = "61", .expected = .{ .success = true } },
        .{ .name = "boolor with false and false becomes true after not", .unlocking_hex = "00009b", .locking_hex = "91", .expected = .{ .success = true } },
        .{ .name = "boolor with sixteen and seventeen stays true", .unlocking_hex = "6001119b", .locking_hex = "61", .expected = .{ .success = true } },
        .{ .row = 313, .name = "within includes lower bound and excludes upper bound", .unlocking_hex = "000051", .locking_hex = "a5", .expected = .{ .success = true } },
        .{ .row = 314, .name = "within rejects upper bound and not makes it true", .unlocking_hex = "510051", .locking_hex = "a591", .expected = .{ .success = true } },
        .{ .row = 315, .name = "within accepts zero inside full int32 range", .unlocking_hex = within_315_hex, .locking_hex = "a5", .expected = .{ .success = true } },
        .{ .row = 316, .name = "within accepts negative one inside negative hundred to positive hundred", .unlocking_hex = within_316_hex, .locking_hex = "a5", .expected = .{ .success = true } },
        .{ .row = 317, .name = "within accepts eleven inside negative hundred to positive hundred", .unlocking_hex = within_317_hex, .locking_hex = "a5", .expected = .{ .success = true } },
        .{ .row = 318, .name = "within rejects very negative value and not makes it true", .unlocking_hex = within_318_hex, .locking_hex = "a591", .expected = .{ .success = true } },
        .{ .row = 319, .name = "within rejects very positive value and not makes it true", .unlocking_hex = within_319_hex, .locking_hex = "a591", .expected = .{ .success = true } },
        .{ .name = "booland treats negative one as true", .unlocking_hex = "4f4f9a", .locking_hex = "61", .expected = .{ .success = true } },
        .{ .row = 535, .name = "boolor treats negative one as true", .unlocking_hex = "4f009b", .locking_hex = "61", .expected = .{ .success = true } },
        .{ .name = "within rejects matching upper bound on negative one", .unlocking_hex = "4f4f00", .locking_hex = "a5", .expected = .{ .success = true } },
        .{ .row = 623, .name = "booland with false and non-minimal false shape still drops to true tail", .unlocking_hex = "00020000", .locking_hex = "9a7551", .expected = .{ .success = true } },
        .{ .row = 624, .name = "booland with reversed operands still drops to true tail", .unlocking_hex = "02000000", .locking_hex = "9a7551", .expected = .{ .success = true } },
        .{ .row = 625, .name = "boolor with false and non-minimal false shape still drops to true tail", .unlocking_hex = "00020000", .locking_hex = "9b7551", .expected = .{ .success = true } },
        .{ .row = 626, .name = "boolor with reversed operands still drops to true tail", .unlocking_hex = "02000000", .locking_hex = "9b7551", .expected = .{ .success = true } },
        .{ .row = 627, .name = "numequal with false and non-minimal false shape still drops to true tail", .unlocking_hex = "00020000", .locking_hex = "9c7551", .expected = .{ .success = true } },
        .{ .row = 628, .name = "numequal with non-minimal false and one still drops to true tail", .unlocking_hex = "0200000051", .locking_hex = "9c7551", .expected = .{ .success = true } },
        .{ .row = 629, .name = "numequalverify with false and non-minimal false shape still passes", .unlocking_hex = "00020000", .locking_hex = "9d51", .expected = .{ .success = true } },
        .{ .row = 630, .name = "numequalverify with reversed false operands still passes", .unlocking_hex = "0200000000", .locking_hex = "9d51", .expected = .{ .success = true } },
        .{ .row = 631, .name = "numnotequal with false and non-minimal false shape still drops to true tail", .unlocking_hex = "00020000", .locking_hex = "9e7551", .expected = .{ .success = true } },
        .{ .row = 632, .name = "numnotequal with reversed false operands still drops to true tail", .unlocking_hex = "0200000000", .locking_hex = "9e7551", .expected = .{ .success = true } },
        .{ .row = 633, .name = "lessthan with false and non-minimal false shape still drops to true tail", .unlocking_hex = "00020000", .locking_hex = "9f7551", .expected = .{ .success = true } },
        .{ .row = 634, .name = "lessthan with reversed false operands still drops to true tail", .unlocking_hex = "0200000000", .locking_hex = "9f7551", .expected = .{ .success = true } },
        .{ .row = 635, .name = "greaterthan with false and non-minimal false shape still drops to true tail", .unlocking_hex = "00020000", .locking_hex = "a07551", .expected = .{ .success = true } },
        .{ .row = 636, .name = "greaterthan with reversed false operands still drops to true tail", .unlocking_hex = "0200000000", .locking_hex = "a07551", .expected = .{ .success = true } },
        .{ .name = "lessthanorequal with false and non-minimal false shape still drops to true tail", .unlocking_hex = "00020000", .locking_hex = "a17551", .expected = .{ .success = true } },
        .{ .row = 638, .name = "lessthanorequal with reversed false operands still drops to true tail", .unlocking_hex = "0200000000", .locking_hex = "a17551", .expected = .{ .success = true } },
        .{ .row = 639, .name = "greaterthanorequal with false and non-minimal false shape still drops to true tail", .unlocking_hex = "00020000", .locking_hex = "a27551", .expected = .{ .success = true } },
        .{ .row = 640, .name = "greaterthanorequal with reversed false operands still drops to true tail", .unlocking_hex = "0200000000", .locking_hex = "a27551", .expected = .{ .success = true } },
        .{ .name = "min with false and non-minimal false shape still drops to true tail", .unlocking_hex = "00020000", .locking_hex = "a37551", .expected = .{ .success = true } },
        .{ .row = 642, .name = "min with reversed false operands still drops to true tail", .unlocking_hex = "0200000000", .locking_hex = "a37551", .expected = .{ .success = true } },
        .{ .row = 643, .name = "max with false and non-minimal false shape still drops to true tail", .unlocking_hex = "00020000", .locking_hex = "a47551", .expected = .{ .success = true } },
        .{ .row = 644, .name = "max with reversed false operands still drops to true tail", .unlocking_hex = "0200000000", .locking_hex = "a47551", .expected = .{ .success = true } },
        .{ .row = 645, .name = "within with non-minimal false lower bound still drops to true tail", .unlocking_hex = "0200000000", .locking_hex = "a57551", .expected = .{ .success = true } },
        .{ .row = 646, .name = "within with non-minimal false upper bound still drops to true tail", .unlocking_hex = "0002000000", .locking_hex = "a57551", .expected = .{ .success = true } },
        .{ .row = 647, .name = "within with non-minimal false tested value still drops to true tail", .unlocking_hex = "0000020000", .locking_hex = "a57551", .expected = .{ .success = true } },
    });
}

test "go direct script rows: comparison and minmax exact rows" {
    const allocator = std.testing.allocator;
    const flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    const neg_eleven = try scriptNumBytes(allocator, -11);
    defer allocator.free(neg_eleven);
    const neg_ten = try scriptNumBytes(allocator, -10);
    defer allocator.free(neg_ten);
    const hundred = try scriptNumBytes(allocator, 100);
    defer allocator.free(hundred);
    const neg_hundred = try scriptNumBytes(allocator, -100);
    defer allocator.free(neg_hundred);
    const max_i32 = try scriptNumBytes(allocator, 2_147_483_647);
    defer allocator.free(max_i32);
    const neg_max_i32 = try scriptNumBytes(allocator, -2_147_483_647);
    defer allocator.free(neg_max_i32);

    const add_chain = try scriptHexForPushesAndOps(allocator, &[_][]const u8{}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_11),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_10),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_1),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_ADD),
    });
    defer allocator.free(add_chain);

    const eq_lock = try scriptHexForPushesAndOps(allocator, &[_][]const u8{}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NUMEQUAL),
    });
    defer allocator.free(eq_lock);
    const eqverify_lock = try scriptHexForPushesAndOps(allocator, &[_][]const u8{}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NUMEQUALVERIFY),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_1),
    });
    defer allocator.free(eqverify_lock);
    const notequal_not_lock = try scriptHexForPushesAndOps(allocator, &[_][]const u8{}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NUMNOTEQUAL),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NOT),
    });
    defer allocator.free(notequal_not_lock);
    const notequal_lock = try scriptHexForPushesAndOps(allocator, &[_][]const u8{}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NUMNOTEQUAL),
    });
    defer allocator.free(notequal_lock);
    const lt_not_lock = try scriptHexForPushesAndOps(allocator, &[_][]const u8{}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_LESSTHAN),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NOT),
    });
    defer allocator.free(lt_not_lock);
    const lt_lock = try scriptHexForPushesAndOps(allocator, &[_][]const u8{}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_LESSTHAN),
    });
    defer allocator.free(lt_lock);
    const gt_lock = try scriptHexForPushesAndOps(allocator, &[_][]const u8{}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_GREATERTHAN),
    });
    defer allocator.free(gt_lock);
    const gt_not_lock = try scriptHexForPushesAndOps(allocator, &[_][]const u8{}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_GREATERTHAN),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NOT),
    });
    defer allocator.free(gt_not_lock);
    const lte_lock = try scriptHexForPushesAndOps(allocator, &[_][]const u8{}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_LESSTHANOREQUAL),
    });
    defer allocator.free(lte_lock);
    const lte_not_lock = try scriptHexForPushesAndOps(allocator, &[_][]const u8{}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_LESSTHANOREQUAL),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NOT),
    });
    defer allocator.free(lte_not_lock);
    const gte_lock = try scriptHexForPushesAndOps(allocator, &[_][]const u8{}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_GREATERTHANOREQUAL),
    });
    defer allocator.free(gte_lock);
    const gte_not_lock = try scriptHexForPushesAndOps(allocator, &[_][]const u8{}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_GREATERTHANOREQUAL),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NOT),
    });
    defer allocator.free(gte_not_lock);
    const min_zero_eq_lock = try scriptHexForPushesAndOps(allocator, &[_][]const u8{}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_MIN),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_0),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NUMEQUAL),
    });
    defer allocator.free(min_zero_eq_lock);
    const min_negone_eq_lock = try scriptHexForPushesAndOps(allocator, &[_][]const u8{}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_MIN),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_1NEGATE),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NUMEQUAL),
    });
    defer allocator.free(min_negone_eq_lock);
    const min_negmax_eq_lock = try scriptHexForPushesAndOps(allocator, &[_][]const u8{neg_max_i32}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_MIN),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NUMEQUAL),
    });
    defer allocator.free(min_negmax_eq_lock);
    const max_maxi32_eq_lock = try scriptHexForPushesAndOps(allocator, &[_][]const u8{max_i32}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_MAX),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NUMEQUAL),
    });
    defer allocator.free(max_maxi32_eq_lock);
    const max_100_eq_lock = try scriptHexForPushesAndOps(allocator, &[_][]const u8{hundred}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_MAX),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NUMEQUAL),
    });
    defer allocator.free(max_100_eq_lock);
    const max_zero_eq_lock = try scriptHexForPushesAndOps(allocator, &[_][]const u8{}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_MAX),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_0),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NUMEQUAL),
    });
    defer allocator.free(max_zero_eq_lock);
    const max_one_eq_lock = try scriptHexForPushesAndOps(allocator, &[_][]const u8{}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_MAX),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_1),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NUMEQUAL),
    });
    defer allocator.free(max_one_eq_lock);
    const within_zero_lock = try scriptHexForPushesAndOps(allocator, &[_][]const u8{}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_WITHIN),
    });
    defer allocator.free(within_zero_lock);

    const neg11_11 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{neg_eleven}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_11),
    });
    defer allocator.free(neg11_11);
    const neg11_neg10 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{ neg_eleven, neg_ten }, &[_]u8{});
    defer allocator.free(neg11_neg10);
    const zero_negmax = try scriptHexForPushesAndOps(allocator, &[_][]const u8{neg_max_i32}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_0),
    });
    defer allocator.free(zero_negmax);
    const maxi32_zero = try scriptHexForPushesAndOps(allocator, &[_][]const u8{max_i32}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_0),
    });
    defer allocator.free(maxi32_zero);
    const zero_hundred = try scriptHexForPushesAndOps(allocator, &[_][]const u8{hundred}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_0),
    });
    defer allocator.free(zero_hundred);
    const neghundred_zero = try scriptHexForPushesAndOps(allocator, &[_][]const u8{neg_hundred}, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_0),
    });
    defer allocator.free(neghundred_zero);

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 281, .name = "numequal matches add-chain result", .unlocking_hex = add_chain, .locking_hex = eq_lock, .expected = .{ .success = true } },
        .{ .row = 282, .name = "numequalverify matches add-chain result", .unlocking_hex = add_chain, .locking_hex = eqverify_lock, .expected = .{ .success = true } },
        .{ .row = 283, .name = "numnotequal not over equal values becomes true", .unlocking_hex = add_chain, .locking_hex = notequal_not_lock, .expected = .{ .success = true } },
        .{ .row = 284, .name = "numnotequal over unequal values stays true", .unlocking_hex = "5f5a510193", .locking_hex = notequal_lock, .expected = .{ .success = true } },
        .{ .row = 285, .name = "lessthan not over greater values becomes true", .unlocking_hex = "5b5a", .locking_hex = lt_not_lock, .expected = .{ .success = true } },
        .{ .row = 286, .name = "lessthan not over equal values becomes true", .unlocking_hex = "5454", .locking_hex = lt_not_lock, .expected = .{ .success = true } },
        .{ .row = 287, .name = "lessthan over ascending values stays true", .unlocking_hex = "5a5b", .locking_hex = lt_lock, .expected = .{ .success = true } },
        .{ .row = 288, .name = "lessthan over negative and positive stays true", .unlocking_hex = neg11_11, .locking_hex = lt_lock, .expected = .{ .success = true } },
        .{ .row = 289, .name = "lessthan over negative ascending values stays true", .unlocking_hex = neg11_neg10, .locking_hex = lt_lock, .expected = .{ .success = true } },
        .{ .row = 290, .name = "greaterthan over descending values stays true", .unlocking_hex = "5b5a", .locking_hex = gt_lock, .expected = .{ .success = true } },
        .{ .row = 291, .name = "greaterthan not over equal values becomes true", .unlocking_hex = "5454", .locking_hex = gt_not_lock, .expected = .{ .success = true } },
        .{ .row = 292, .name = "greaterthan not over ascending values becomes true", .unlocking_hex = "5a5b", .locking_hex = gt_not_lock, .expected = .{ .success = true } },
        .{ .row = 293, .name = "greaterthan not over negative and positive becomes true", .unlocking_hex = neg11_11, .locking_hex = gt_not_lock, .expected = .{ .success = true } },
        .{ .row = 294, .name = "greaterthan not over negative ascending becomes true", .unlocking_hex = neg11_neg10, .locking_hex = gt_not_lock, .expected = .{ .success = true } },
        .{ .name = "greaterthan over descending values stays true", .unlocking_hex = "5b5a", .locking_hex = gt_lock, .expected = .{ .success = true } },
        .{ .name = "greaterthan not over equal values becomes true", .unlocking_hex = "5454", .locking_hex = gt_not_lock, .expected = .{ .success = true } },
        .{ .name = "greaterthan not over ascending values becomes true", .unlocking_hex = "5a5b", .locking_hex = gt_not_lock, .expected = .{ .success = true } },
        .{ .name = "greaterthan not over negative and positive becomes true", .unlocking_hex = neg11_11, .locking_hex = gt_not_lock, .expected = .{ .success = true } },
        .{ .name = "greaterthan not over negative ascending becomes true", .unlocking_hex = neg11_neg10, .locking_hex = gt_not_lock, .expected = .{ .success = true } },
        .{ .name = "lessthanorequal not over descending becomes true", .unlocking_hex = "5b5a", .locking_hex = lte_not_lock, .expected = .{ .success = true } },
        .{ .name = "lessthanorequal over equal values stays true", .unlocking_hex = "5454", .locking_hex = lte_lock, .expected = .{ .success = true } },
        .{ .name = "lessthanorequal over ascending values stays true", .unlocking_hex = "5a5b", .locking_hex = lte_lock, .expected = .{ .success = true } },
        .{ .name = "lessthanorequal over negative and positive stays true", .unlocking_hex = neg11_11, .locking_hex = lte_lock, .expected = .{ .success = true } },
        .{ .name = "lessthanorequal over negative ascending stays true", .unlocking_hex = neg11_neg10, .locking_hex = lte_lock, .expected = .{ .success = true } },
        .{ .name = "greaterthanorequal over descending stays true", .unlocking_hex = "5b5a", .locking_hex = gte_lock, .expected = .{ .success = true } },
        .{ .name = "greaterthanorequal over equal values stays true", .unlocking_hex = "5454", .locking_hex = gte_lock, .expected = .{ .success = true } },
        .{ .name = "greaterthanorequal not over ascending becomes true", .unlocking_hex = "5a5b", .locking_hex = gte_not_lock, .expected = .{ .success = true } },
        .{ .name = "greaterthanorequal not over negative and positive becomes true", .unlocking_hex = neg11_11, .locking_hex = gte_not_lock, .expected = .{ .success = true } },
        .{ .name = "greaterthanorequal not over negative ascending becomes true", .unlocking_hex = neg11_neg10, .locking_hex = gte_not_lock, .expected = .{ .success = true } },
        .{ .name = "min of one and zero is zero", .unlocking_hex = "5100", .locking_hex = min_zero_eq_lock, .expected = .{ .success = true } },
        .{ .row = 295, .name = "lessthanorequal not over descending becomes true", .unlocking_hex = "5b5a", .locking_hex = lte_not_lock, .expected = .{ .success = true } },
        .{ .row = 296, .name = "lessthanorequal over equal values stays true", .unlocking_hex = "5454", .locking_hex = lte_lock, .expected = .{ .success = true } },
        .{ .row = 297, .name = "lessthanorequal over ascending values stays true", .unlocking_hex = "5a5b", .locking_hex = lte_lock, .expected = .{ .success = true } },
        .{ .name = "lessthanorequal over negative and positive stays true", .unlocking_hex = neg11_11, .locking_hex = lte_lock, .expected = .{ .success = true } },
        .{ .name = "lessthanorequal over negative ascending stays true", .unlocking_hex = neg11_neg10, .locking_hex = lte_lock, .expected = .{ .success = true } },
        .{ .name = "greaterthanorequal over descending stays true", .unlocking_hex = "5b5a", .locking_hex = gte_lock, .expected = .{ .success = true } },
        .{ .name = "greaterthanorequal over equal values stays true", .unlocking_hex = "5454", .locking_hex = gte_lock, .expected = .{ .success = true } },
        .{ .name = "greaterthanorequal not over ascending becomes true", .unlocking_hex = "5a5b", .locking_hex = gte_not_lock, .expected = .{ .success = true } },
        .{ .row = 303, .name = "greaterthanorequal not over negative and positive becomes true", .unlocking_hex = neg11_11, .locking_hex = gte_not_lock, .expected = .{ .success = true } },
        .{ .row = 304, .name = "greaterthanorequal not over negative ascending becomes true", .unlocking_hex = neg11_neg10, .locking_hex = gte_not_lock, .expected = .{ .success = true } },
        .{ .row = 305, .name = "min of one and zero is zero", .unlocking_hex = "5100", .locking_hex = min_zero_eq_lock, .expected = .{ .success = true } },
        .{ .row = 306, .name = "min of zero and one is zero", .unlocking_hex = "0051", .locking_hex = min_zero_eq_lock, .expected = .{ .success = true } },
        .{ .row = 307, .name = "min of negative one and zero is negative one", .unlocking_hex = "4f00", .locking_hex = min_negone_eq_lock, .expected = .{ .success = true } },
        .{ .row = 308, .name = "min of zero and negative max int32 is negative max int32", .unlocking_hex = zero_negmax, .locking_hex = min_negmax_eq_lock, .expected = .{ .success = true } },
        .{ .row = 309, .name = "max of int32 max and zero is int32 max", .unlocking_hex = maxi32_zero, .locking_hex = max_maxi32_eq_lock, .expected = .{ .success = true } },
        .{ .row = 310, .name = "max of zero and hundred is hundred", .unlocking_hex = zero_hundred, .locking_hex = max_100_eq_lock, .expected = .{ .success = true } },
        .{ .row = 311, .name = "max of negative hundred and zero is zero", .unlocking_hex = neghundred_zero, .locking_hex = max_zero_eq_lock, .expected = .{ .success = true } },
        .{ .row = 312, .name = "max of zero and negative max int32 is zero", .unlocking_hex = zero_negmax, .locking_hex = max_zero_eq_lock, .expected = .{ .success = true } },
        .{ .row = 408, .name = "bytewise unequal one and zero-padded one become true after not", .unlocking_hex = "51", .locking_hex = "0201008791", .expected = .{ .success = true } },
        .{ .row = 409, .name = "numerically equal one and zero-padded one stay true", .unlocking_hex = "51", .locking_hex = "0201009c", .expected = .{ .success = true } },
        .{ .row = 410, .name = "numequal accepts minimally and non-minimally encoded eleven", .unlocking_hex = "5b", .locking_hex = "4c030b00009c", .expected = .{ .success = true } },
        .{ .row = 416, .name = "numequal accepts larger positive values with significant zero bytes", .unlocking_hex = "03100000", .locking_hex = "04100000009c", .expected = .{ .success = true } },
        .{ .row = 536, .name = "numequal over zero and zero stays true", .unlocking_hex = "0000", .locking_hex = eq_lock, .expected = .{ .success = true } },
        .{ .name = "numequalverify over zero and zero stays true", .unlocking_hex = "0000", .locking_hex = eqverify_lock, .expected = .{ .success = true } },
        .{ .name = "numnotequal over negative one and zero stays true", .unlocking_hex = "4f00", .locking_hex = notequal_lock, .expected = .{ .success = true } },
        .{ .name = "lessthan over negative one and zero stays true", .unlocking_hex = "4f00", .locking_hex = lt_lock, .expected = .{ .success = true } },
        .{ .name = "greaterthan over one and zero stays true", .unlocking_hex = "5100", .locking_hex = gt_lock, .expected = .{ .success = true } },
        .{ .name = "lessthanorequal over zero and zero stays true", .unlocking_hex = "0000", .locking_hex = lte_lock, .expected = .{ .success = true } },
        .{ .name = "greaterthanorequal over zero and zero stays true", .unlocking_hex = "0000", .locking_hex = gte_lock, .expected = .{ .success = true } },
        .{ .name = "min over negative one and zero stays negative one", .unlocking_hex = "4f00", .locking_hex = min_negone_eq_lock, .expected = .{ .success = true } },
        .{ .name = "max over one and zero stays one", .unlocking_hex = "5100", .locking_hex = max_one_eq_lock, .expected = .{ .success = true } },
    });
}

test "go direct script rows: boolean underflow parity" {
    const allocator = std.testing.allocator;

    try runRows(allocator, bsvz.script.engine.ExecutionFlags.legacyReference(), &[_]GoRow{
        .{ .row = 1428, .name = "negate underflows with empty stack", .unlocking_hex = "61", .locking_hex = "8f51", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 1429, .name = "abs underflows with empty stack", .unlocking_hex = "61", .locking_hex = "9051", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 1430, .name = "not underflows with empty stack", .unlocking_hex = "", .locking_hex = "91", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 1431, .name = "zeronotequal underflows with empty stack", .unlocking_hex = "", .locking_hex = "92", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 1432, .name = "add underflows with one stack item", .unlocking_hex = "51", .locking_hex = "93", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 1433, .name = "sub underflows with one stack item", .unlocking_hex = "51", .locking_hex = "94", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 1435, .name = "booland underflows with one stack item", .unlocking_hex = "51", .locking_hex = "9a", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 1436, .name = "boolor underflows with one stack item", .unlocking_hex = "51", .locking_hex = "9b", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 1437, .name = "numequal underflows with one stack item", .unlocking_hex = "51", .locking_hex = "9c", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 1438, .name = "numequalverify underflows with one stack item", .unlocking_hex = "51", .locking_hex = "9d51", .expected = .{ .err = error.StackUnderflow } },
    });
}

test "go direct script rows: compact boolean and arithmetic result shapes" {
    const allocator = std.testing.allocator;

    try runRows(allocator, bsvz.script.engine.ExecutionFlags.legacyReference(), &[_]GoRow{
        .{ .row = 528, .name = "abs over negative one leaves a truthy result", .unlocking_hex = "4f90", .locking_hex = "", .expected = .{ .success = true } },
        .{ .row = 529, .name = "not over zero leaves a truthy result", .unlocking_hex = "0091", .locking_hex = "", .expected = .{ .success = true } },
        .{ .row = 530, .name = "zeronotequal over negative one leaves a truthy result", .unlocking_hex = "4f92", .locking_hex = "", .expected = .{ .success = true } },
        .{ .row = 532, .name = "add over one and zero leaves a truthy result", .unlocking_hex = "510093", .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "sub over one and zero leaves a truthy result", .unlocking_hex = "510094", .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "within over negative one in negative one to zero leaves a truthy result", .unlocking_hex = "4f4f00a5", .locking_hex = "", .expected = .{ .success = true } },
    });
}
