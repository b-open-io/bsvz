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
        .name = "bin2num normalizes trailing zero bytes down to one",
        .unlocking_hex = one_hex,
        .locking_hex = "",
        .flags = flags,
        .expected = .{ .success = true },
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
        0x01, 0x00,
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(zero_one);
    const zero_seven = try scriptHexForPushesAndOps(allocator, &[_][]const u8{ zero_num, size_seven }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NUM2BIN),
        0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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
        0x01, 0xaa,
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(neg42_one);
    const neg42_two = try scriptHexForPushesAndOps(allocator, &[_][]const u8{ neg_forty_two, size_two }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NUM2BIN),
        0x02, 0x2a, 0x80,
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(neg42_two);
    const neg42_ten = try scriptHexForPushesAndOps(allocator, &[_][]const u8{ neg_forty_two, size_ten }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NUM2BIN),
        0x0a, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
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
        0x04, 0xab, 0xcd, 0xef, 0xc2,
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
        0x03, 0x00, 0x00, 0x00,
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(neg_zero_three);

    try harness.runCase(allocator, .{
        .name = "num2bin underflows on empty stack",
        .unlocking_hex = "",
        .locking_hex = "800087",
        .flags = flags,
        .expected = .{ .err = error.StackUnderflow },
    });

    try harness.runCase(allocator, .{
        .name = "num2bin underflows with one parameter",
        .unlocking_hex = "00",
        .locking_hex = "800087",
        .flags = flags,
        .expected = .{ .err = error.StackUnderflow },
    });

    try runRows(allocator, flags, &[_]GoRow{
        .{ .name = "num2bin canonical zero at size zero stays empty", .unlocking_hex = zero_zero, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "num2bin zero-extends zero to one byte", .unlocking_hex = zero_one, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "num2bin zero-extends zero to seven bytes", .unlocking_hex = zero_seven, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "num2bin canonical one at size one stays one", .unlocking_hex = one_one, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "num2bin canonical negative forty-two at size one stays canonical", .unlocking_hex = neg42_one, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "num2bin canonical negative forty-two at size two extends sign", .unlocking_hex = neg42_two, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "num2bin canonical negative forty-two at size ten materializes padding", .unlocking_hex = neg42_ten, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "num2bin allows pushing exactly five hundred twenty bytes", .unlocking_hex = neg42_520, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "num2bin rejects pushing five hundred twenty one bytes", .unlocking_hex = neg42_521, .locking_hex = "", .expected = .{ .err = error.NumberTooBig } },
        .{ .name = "num2bin rejects negative sizes", .unlocking_hex = neg42_neg3, .locking_hex = "", .expected = .{ .err = error.InvalidStackIndex } },
        .{ .name = "num2bin shrinks value bytes while preserving sign bit", .unlocking_hex = shrink_case, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "num2bin normalizes negative zero to empty at size zero", .unlocking_hex = neg_zero_zero, .locking_hex = "", .expected = .{ .success = true } },
        .{ .name = "num2bin normalizes negative zero to zero bytes at larger size", .unlocking_hex = neg_zero_three, .locking_hex = "", .expected = .{ .success = true } },
    });
}
