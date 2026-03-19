const std = @import("std");
const bsvz = @import("bsvz");
const harness = @import("support/go_script_harness.zig");
const builders = @import("support/go_vector_builders.zig");

const GoRow = struct {
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
        .name = "go row 824: bin2num underflows on empty stack",
        .unlocking_hex = "",
        .locking_hex = "810087",
        .flags = flags,
        .expected = .{ .err = error.StackUnderflow },
    });

    try harness.runCase(allocator, .{
        .name = "bin2num normalizes trailing zero bytes down to one",
        .unlocking_hex = one_hex,
        .locking_hex = "",
        .flags = flags,
        .expected = .{ .success = true },
    });
}

test "go direct script rows: bin2num canonical rows" {
    const allocator = std.testing.allocator;
    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.strict_encoding = true;

    const neg_forty_two = try scriptNumBytes(allocator, -42);
    defer allocator.free(neg_forty_two);
    const max_i32 = try scriptNumBytes(allocator, 2_147_483_647);
    defer allocator.free(max_i32);
    const neg_max_i32 = try scriptNumBytes(allocator, -2_147_483_647);
    defer allocator.free(neg_max_i32);

    const zero_case = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        &[_]u8{},
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_BIN2NUM),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_0),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(zero_case);
    const one_case = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        &[_]u8{0x01},
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_BIN2NUM),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_1),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(one_case);
    const neg42_case = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        neg_forty_two,
        &[_]u8{ 0x2a, 0x80 },
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_BIN2NUM),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(neg42_case);
    const noncanonical_zero_case = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        &[_]u8{0x00},
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_BIN2NUM),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_0),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(noncanonical_zero_case);
    const max_i32_case = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        max_i32,
        &[_]u8{ 0xff, 0xff, 0xff, 0x7f },
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_BIN2NUM),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(max_i32_case);
    const neg_max_i32_case = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        neg_max_i32,
        &[_]u8{ 0xff, 0xff, 0xff, 0xff },
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_BIN2NUM),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(neg_max_i32_case);

    try runRows(allocator, flags, &[_]GoRow{
        .{ .name = "go row 825: bin2num canonical zero stays zero", .unlocking_hex = zero_case, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "go row 826: bin2num canonical one-byte positive stays one", .unlocking_hex = one_case, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "go row 827: bin2num canonical negative forty-two stays negative forty-two", .unlocking_hex = neg42_case, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "go row 828: bin2num non-canonical zero still decodes to zero", .unlocking_hex = noncanonical_zero_case, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "go row 829: bin2num canonical max int32 stays max int32", .unlocking_hex = max_i32_case, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "go row 830: bin2num canonical negative max int32 stays negative max int32", .unlocking_hex = neg_max_i32_case, .locking_hex = "", .expected = .{ .success = true } },
    });
}

test "go direct script rows: bin2num exact corpus rows" {
    const allocator = std.testing.allocator;
    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.strict_encoding = true;

    const pos_one = try scriptNumBytes(allocator, 1);
    defer allocator.free(pos_one);
    const pos_254 = try scriptNumBytes(allocator, 254);
    defer allocator.free(pos_254);
    const neg_five = try scriptNumBytes(allocator, -5);
    defer allocator.free(neg_five);
    const pos_128 = try scriptNumBytes(allocator, 128);
    defer allocator.free(pos_128);
    const neg_128 = try scriptNumBytes(allocator, -128);
    defer allocator.free(neg_128);
    const pos_15 = try scriptNumBytes(allocator, 15);
    defer allocator.free(pos_15);
    const neg_15 = try scriptNumBytes(allocator, -15);
    defer allocator.free(neg_15);
    const pos_8388609 = try scriptNumBytes(allocator, 8_388_609);
    defer allocator.free(pos_8388609);
    const neg_8388609 = try scriptNumBytes(allocator, -8_388_609);
    defer allocator.free(neg_8388609);

    const row833 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        pos_one,
        &[_]u8{ 0x01, 0x00, 0x00, 0x00, 0x00 },
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_BIN2NUM),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(row833);
    const row834 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        pos_254,
        &[_]u8{ 0xfe, 0x00, 0x00, 0x00, 0x00 },
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_BIN2NUM),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(row834);
    const row835 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        neg_five,
        &[_]u8{ 0x05, 0x00, 0x00, 0x00, 0x80 },
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_BIN2NUM),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(row835);
    const row836 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        pos_128,
        &[_]u8{ 0x80, 0x00, 0x00 },
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_BIN2NUM),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(row836);
    const row837 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        neg_128,
        &[_]u8{ 0x80, 0x00, 0x80 },
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_BIN2NUM),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(row837);
    const row838 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        pos_128,
        &[_]u8{ 0x80, 0x00 },
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_BIN2NUM),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(row838);
    const row839 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        neg_128,
        &[_]u8{ 0x80, 0x80 },
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_BIN2NUM),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(row839);
    const row840 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        pos_15,
        &[_]u8{ 0x0f, 0x00, 0x00 },
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_BIN2NUM),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(row840);
    const row841 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        neg_15,
        &[_]u8{ 0x0f, 0x00, 0x80 },
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_BIN2NUM),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(row841);
    const row842 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        pos_15,
        &[_]u8{ 0x0f, 0x00 },
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_BIN2NUM),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(row842);
    const row843 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        neg_15,
        &[_]u8{ 0x0f, 0x80 },
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_BIN2NUM),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(row843);
    const row844 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        pos_8388609,
        &[_]u8{ 0x01, 0x00, 0x80, 0x00, 0x00 },
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_BIN2NUM),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(row844);
    const row845 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        neg_8388609,
        &[_]u8{ 0x01, 0x00, 0x80, 0x00, 0x80 },
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_BIN2NUM),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(row845);

    try runRows(allocator, flags, &[_]GoRow{
        .{ .name = "go row 833: bin2num normalizes positive one with trailing zeros", .unlocking_hex = row833, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "go row 834: bin2num normalizes positive two hundred fifty four with trailing zeros", .unlocking_hex = row834, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "go row 835: bin2num relocates sign bit for negative five", .unlocking_hex = row835, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "go row 836: bin2num retains padding when msb is set for positive one hundred twenty eight", .unlocking_hex = row836, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "go row 837: bin2num retains padding when msb is set for negative one hundred twenty eight", .unlocking_hex = row837, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "go row 838: bin2num canonical two-byte positive one hundred twenty eight stays positive", .unlocking_hex = row838, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "go row 839: bin2num canonical two-byte negative one hundred twenty eight stays negative", .unlocking_hex = row839, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "go row 840: bin2num trims unnecessary positive padding when msb is not set", .unlocking_hex = row840, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "go row 841: bin2num trims unnecessary negative padding when msb is not set", .unlocking_hex = row841, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "go row 842: bin2num canonical two-byte positive fifteen stays positive", .unlocking_hex = row842, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "go row 843: bin2num canonical two-byte negative fifteen stays negative", .unlocking_hex = row843, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "go row 844: bin2num retains significant zero bytes for large positive values", .unlocking_hex = row844, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "go row 845: bin2num retains significant zero bytes for large negative values", .unlocking_hex = row845, .locking_hex = "", .expected = .{ .success = true } },
    });
}

test "go direct script rows: num2bin parity" {
    const allocator = std.testing.allocator;
    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.strict_encoding = true;

    const size_zero = try scriptNumBytes(allocator, 0);
    defer allocator.free(size_zero);
    const size_one = try scriptNumBytes(allocator, 1);
    defer allocator.free(size_one);
    const size_two = try scriptNumBytes(allocator, 2);
    defer allocator.free(size_two);
    const size_three = try scriptNumBytes(allocator, 3);
    defer allocator.free(size_three);
    const size_four = try scriptNumBytes(allocator, 4);
    defer allocator.free(size_four);
    const size_seven = try scriptNumBytes(allocator, 7);
    defer allocator.free(size_seven);
    const size_ten = try scriptNumBytes(allocator, 10);
    defer allocator.free(size_ten);
    const size_520 = try scriptNumBytes(allocator, 520);
    defer allocator.free(size_520);
    const size_521 = try scriptNumBytes(allocator, 521);
    defer allocator.free(size_521);
    const neg_three = try scriptNumBytes(allocator, -3);
    defer allocator.free(neg_three);
    const zero_num = try scriptNumBytes(allocator, 0);
    defer allocator.free(zero_num);
    const one_num = try scriptNumBytes(allocator, 1);
    defer allocator.free(one_num);
    const neg_forty_two = try scriptNumBytes(allocator, -42);
    defer allocator.free(neg_forty_two);
    const neg_zero = &[_]u8{0x80};
    const shrink_source = &[_]u8{ 0xab, 0xcd, 0xef, 0x42, 0x80 };

    const zero_zero = try scriptHexForPushesAndOps(allocator, &[_][]const u8{ zero_num, size_zero }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NUM2BIN),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_0),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(zero_zero);
    const zero_one = try scriptHexForPushesAndOps(allocator, &[_][]const u8{ zero_num, size_one }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NUM2BIN),
        0x01,
        0x00,
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(zero_one);
    const zero_seven = try scriptHexForPushesAndOps(allocator, &[_][]const u8{ zero_num, size_seven }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NUM2BIN),
        0x07,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(zero_seven);
    const one_one = try scriptHexForPushesAndOps(allocator, &[_][]const u8{ one_num, size_one }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NUM2BIN),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_1),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(one_one);
    const neg42_one = try scriptHexForPushesAndOps(allocator, &[_][]const u8{ neg_forty_two, size_one }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NUM2BIN),
        0x01,
        0xaa,
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(neg42_one);
    const neg42_two = try scriptHexForPushesAndOps(allocator, &[_][]const u8{ neg_forty_two, size_two }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NUM2BIN),
        0x02,
        0x2a,
        0x80,
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(neg42_two);
    const neg42_ten = try scriptHexForPushesAndOps(allocator, &[_][]const u8{ neg_forty_two, size_ten }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NUM2BIN),
        0x0a,
        0x2a,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x80,
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(neg42_ten);
    const neg42_520 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{ neg_forty_two, size_520 }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NUM2BIN),
    });
    defer allocator.free(neg42_520);
    const neg42_521 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{ neg_forty_two, size_521 }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NUM2BIN),
    });
    defer allocator.free(neg42_521);
    const neg42_neg3 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{ neg_forty_two, neg_three }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NUM2BIN),
    });
    defer allocator.free(neg42_neg3);
    const shrink_case = try scriptHexForPushesAndOps(allocator, &[_][]const u8{ shrink_source, size_four }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NUM2BIN),
        0x04,
        0xab,
        0xcd,
        0xef,
        0xc2,
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(shrink_case);
    const neg_zero_zero = try scriptHexForPushesAndOps(allocator, &[_][]const u8{ neg_zero, size_zero }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NUM2BIN),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_0),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(neg_zero_zero);
    const neg_zero_three = try scriptHexForPushesAndOps(allocator, &[_][]const u8{ neg_zero, size_three }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NUM2BIN),
        0x03,
        0x00,
        0x00,
        0x00,
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(neg_zero_three);

    try harness.runCase(allocator, .{
        .name = "go row 808: num2bin underflows on empty stack",
        .unlocking_hex = "",
        .locking_hex = "800087",
        .flags = flags,
        .expected = .{ .err = error.StackUnderflow },
    });

    try harness.runCase(allocator, .{
        .name = "go row 809: num2bin underflows with one parameter",
        .unlocking_hex = "00",
        .locking_hex = "800087",
        .flags = flags,
        .expected = .{ .err = error.StackUnderflow },
    });

    try runRows(allocator, flags, &[_]GoRow{
        .{ .name = "go row 810: num2bin canonical zero at size zero stays empty", .unlocking_hex = zero_zero, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "go row 811: num2bin zero-extends zero to one byte", .unlocking_hex = zero_one, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "go row 812: num2bin zero-extends zero to seven bytes", .unlocking_hex = zero_seven, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "go row 813: num2bin canonical one at size one stays one", .unlocking_hex = one_one, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "go row 814: num2bin canonical negative forty-two at size one stays canonical", .unlocking_hex = neg42_one, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "go row 815: num2bin canonical negative forty-two at size two extends sign", .unlocking_hex = neg42_two, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "go row 816: num2bin canonical negative forty-two at size ten materializes padding", .unlocking_hex = neg42_ten, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "go row 817: num2bin allows pushing exactly five hundred twenty bytes", .unlocking_hex = neg42_520, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "go row 818: num2bin rejects pushing five hundred twenty one bytes", .unlocking_hex = neg42_521, .locking_hex = "", .expected = .{ .err = error.NumberTooBig } },
        .{ .name = "go row 819: num2bin rejects negative sizes", .unlocking_hex = neg42_neg3, .locking_hex = "", .expected = .{ .err = error.InvalidStackIndex } },
        .{ .name = "go row 820: num2bin shrinks value bytes while preserving sign bit", .unlocking_hex = shrink_case, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "go row 821: num2bin normalizes negative zero to empty at size zero", .unlocking_hex = neg_zero_zero, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "go row 822: num2bin normalizes negative zero to zero bytes at larger size", .unlocking_hex = neg_zero_three, .locking_hex = "", .expected = .{ .success = true } },
    });
}
