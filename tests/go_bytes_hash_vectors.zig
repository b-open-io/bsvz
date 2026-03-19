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

fn scriptHexForPushesAndOps(
    allocator: std.mem.Allocator,
    pushes: []const []const u8,
    ops: []const u8,
) ![]u8 {
    var bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer bytes.deinit(allocator);

    for (pushes) |push| {
        if (push.len <= 75) {
            try bytes.append(allocator, @intCast(push.len));
        } else if (push.len <= 0xff) {
            try bytes.append(allocator, 0x4c);
            try bytes.append(allocator, @intCast(push.len));
        } else if (push.len <= 0xffff) {
            try bytes.append(allocator, 0x4d);
            try bytes.append(allocator, @intCast(push.len & 0xff));
            try bytes.append(allocator, @intCast((push.len >> 8) & 0xff));
        } else {
            return error.InvalidPushData;
        }
        try bytes.appendSlice(allocator, push);
    }
    try bytes.appendSlice(allocator, ops);
    return builders.scriptHexFromBytes(allocator, bytes.items);
}

fn scriptNumBytes(allocator: std.mem.Allocator, value: i64) ![]u8 {
    return builders.scriptNumBytes(allocator, value);
}

fn decodeHexBytes(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    return bsvz.primitives.hex.decode(allocator, hex);
}

fn scriptHexWithOpsPushOps(
    allocator: std.mem.Allocator,
    prefix_ops: []const bsvz.script.opcode.Opcode,
    push_data: []const u8,
    suffix_ops: []const bsvz.script.opcode.Opcode,
) ![]u8 {
    var bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer bytes.deinit(allocator);

    for (prefix_ops) |op| {
        try bytes.append(allocator, @intFromEnum(op));
    }
    try builders.appendPushData(&bytes, allocator, push_data);
    for (suffix_ops) |op| {
        try bytes.append(allocator, @intFromEnum(op));
    }

    return builders.scriptHexFromBytes(allocator, bytes.items);
}

fn scriptHexWithOpsPushdata1Ops(
    allocator: std.mem.Allocator,
    prefix_ops: []const bsvz.script.opcode.Opcode,
    push_data: []const u8,
    suffix_ops: []const bsvz.script.opcode.Opcode,
) ![]u8 {
    var bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer bytes.deinit(allocator);

    for (prefix_ops) |op| {
        try bytes.append(allocator, @intFromEnum(op));
    }
    try bytes.append(allocator, @intFromEnum(bsvz.script.opcode.Opcode.OP_PUSHDATA1));
    try bytes.append(allocator, @intCast(push_data.len));
    try bytes.appendSlice(allocator, push_data);
    for (suffix_ops) |op| {
        try bytes.append(allocator, @intFromEnum(op));
    }

    return builders.scriptHexFromBytes(allocator, bytes.items);
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

test "go direct script rows: cat parity" {
    const allocator = std.testing.allocator;
    const flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 790, .name = "go row 790: cat with empty left operand keeps the right payload", .unlocking_hex = "0003646566", .locking_hex = "7e0364656687", .expected = .{ .success = true } },
        .{ .row = 940, .name = "cat underflows on empty stack", .unlocking_hex = "", .locking_hex = "7e0087", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 941, .name = "cat underflows with one parameter", .unlocking_hex = "0161", .locking_hex = "7e0087", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 942, .name = "cat concatenates two payloads", .unlocking_hex = "04616263640465666768", .locking_hex = "7e08616263646566676887", .expected = .{ .success = true } },
        .{ .row = 943, .name = "cat keeps two empty strings empty", .unlocking_hex = "0000", .locking_hex = "7e0087", .expected = .{ .success = true } },
        .{ .name = "cat with empty string on the right keeps left", .unlocking_hex = "0361626300", .locking_hex = "7e0361626387", .expected = .{ .success = true } },
        .{ .row = 945, .name = "cat with empty string on the left keeps right", .unlocking_hex = "0003646566", .locking_hex = "7e0364656687", .expected = .{ .success = true } },
    });
}

test "go direct script rows: cat max length parity" {
    const allocator = std.testing.allocator;
    const flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    const left_145 = try builders.repeatedHexByte(allocator, 145, 'a');
    defer allocator.free(left_145);
    const right_375 = try builders.repeatedHexByte(allocator, 375, 'b');
    defer allocator.free(right_375);
    const joined_520 = try allocator.alloc(u8, 520);
    defer allocator.free(joined_520);
    @memcpy(joined_520[0..145], left_145);
    @memcpy(joined_520[145..], right_375);

    const cat_520 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        left_145,
        right_375,
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_CAT),
    });
    defer allocator.free(cat_520);
    const cat_520_eq = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        joined_520,
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(cat_520_eq);

    const cat_empty_left = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        &[_]u8{},
        joined_520,
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_CAT),
    });
    defer allocator.free(cat_empty_left);
    const cat_empty_left_eq = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        joined_520,
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(cat_empty_left_eq);

    const cat_empty_right = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        joined_520,
        &[_]u8{},
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_CAT),
    });
    defer allocator.free(cat_empty_right);
    const cat_empty_right_eq = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        joined_520,
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(cat_empty_right_eq);

    const oversized_cat = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        &[_]u8{'a'},
        joined_520,
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_CAT),
    });
    defer allocator.free(oversized_cat);

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 791, .name = "go row 791: cat concatenates to the maximum script element size", .unlocking_hex = cat_520, .locking_hex = cat_520_eq, .expected = .{ .success = true } },
        .{ .row = 792, .name = "go row 792: cat with empty left operand keeps maximum-sized right operand", .unlocking_hex = cat_empty_left, .locking_hex = cat_empty_left_eq, .expected = .{ .success = true } },
        .{ .row = 793, .name = "go row 793: cat with empty right operand keeps maximum-sized left operand", .unlocking_hex = cat_empty_right, .locking_hex = cat_empty_right_eq, .expected = .{ .success = true } },
        .{ .row = 794, .name = "go row 794: cat rejects oversized result above the maximum script element size", .unlocking_hex = oversized_cat, .locking_hex = "", .expected = .{ .err = error.ElementTooBig } },
    });
}

test "go direct script rows: split parity" {
    const allocator = std.testing.allocator;
    const flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    const zero = try scriptNumBytes(allocator, 0);
    defer allocator.free(zero);
    const three = try scriptNumBytes(allocator, 3);
    defer allocator.free(three);
    const four = try scriptNumBytes(allocator, 4);
    defer allocator.free(four);
    const neg_one = try scriptNumBytes(allocator, -1);
    defer allocator.free(neg_one);

    const abcdef_split_3 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        "abcdef",
        three,
    }, &[_]u8{});
    defer allocator.free(abcdef_split_3);
    const empty_split_0 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        "",
        zero,
    }, &[_]u8{});
    defer allocator.free(empty_split_0);
    const abc_split_0 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        "abc",
        zero,
    }, &[_]u8{});
    defer allocator.free(abc_split_0);
    const abc_split_3 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        "abc",
        three,
    }, &[_]u8{});
    defer allocator.free(abc_split_3);
    const abc_split_4 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        "abc",
        four,
    }, &[_]u8{});
    defer allocator.free(abc_split_4);
    const abc_split_neg1 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        "abc",
        neg_one,
    }, &[_]u8{});
    defer allocator.free(abc_split_neg1);

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 796, .name = "go row 796: split underflows on an empty stack", .unlocking_hex = "", .locking_hex = "7f", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 797, .name = "go row 797: split underflows with only one parameter", .unlocking_hex = "0161", .locking_hex = "7f", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 798, .name = "go row 798: split divides abcdef at index three", .unlocking_hex = "0661626364656653", .locking_hex = "7f03646566880361626387", .expected = .{ .success = true } },
        .{ .row = 799, .name = "go row 799: split on empty string at zero keeps both halves empty", .unlocking_hex = "0000", .locking_hex = "7f00880087", .expected = .{ .success = true } },
        .{ .row = 800, .name = "go row 800: split at zero keeps the right side intact", .unlocking_hex = "0361626300", .locking_hex = "7f03616263880087", .expected = .{ .success = true } },
        .{ .row = 801, .name = "go row 801: split at payload length keeps the left side intact", .unlocking_hex = "0361626353", .locking_hex = "7f00880361626387", .expected = .{ .success = true } },
        .{ .row = 802, .name = "go row 802: split rejects an index above payload length", .unlocking_hex = "0361626354", .locking_hex = "7f", .expected = .{ .err = error.InvalidSplitPosition } },
        .{ .row = 803, .name = "go row 803: split rejects a negative index", .unlocking_hex = "036162634f", .locking_hex = "7f", .expected = .{ .err = error.InvalidStackIndex } },
        .{ .row = 968, .name = "split underflows on empty stack", .unlocking_hex = "", .locking_hex = "7f", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 969, .name = "split underflows with one parameter", .unlocking_hex = "0161", .locking_hex = "7f", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 970, .name = "split divides abcdef at three", .unlocking_hex = abcdef_split_3, .locking_hex = "7f03646566880461626387", .expected = .{ .success = true } },
        .{ .row = 971, .name = "split on empty string at zero keeps both halves empty", .unlocking_hex = empty_split_0, .locking_hex = "7f00880087", .expected = .{ .success = true } },
        .{ .row = 972, .name = "split at zero keeps right side intact", .unlocking_hex = abc_split_0, .locking_hex = "7f03616263880087", .expected = .{ .success = true } },
        .{ .row = 973, .name = "split at payload length keeps left side intact", .unlocking_hex = abc_split_3, .locking_hex = "7f00880361626387", .expected = .{ .success = true } },
        .{ .row = 974, .name = "split rejects upper out of bounds", .unlocking_hex = abc_split_4, .locking_hex = "7f", .expected = .{ .err = error.InvalidSplitPosition } },
        .{ .row = 975, .name = "split rejects negative index", .unlocking_hex = abc_split_neg1, .locking_hex = "7f", .expected = .{ .err = error.InvalidStackIndex } },
    });
}

test "go direct script rows: split max length parity" {
    const allocator = std.testing.allocator;
    const flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    const left_145 = try builders.repeatedHexByte(allocator, 145, 'a');
    defer allocator.free(left_145);
    const right_375 = try builders.repeatedHexByte(allocator, 375, 'b');
    defer allocator.free(right_375);
    const joined_520 = try allocator.alloc(u8, 520);
    defer allocator.free(joined_520);
    @memcpy(joined_520[0..145], left_145);
    @memcpy(joined_520[145..], right_375);
    const split_zero = try scriptNumBytes(allocator, 0);
    defer allocator.free(split_zero);
    const split_145 = try scriptNumBytes(allocator, 145);
    defer allocator.free(split_145);
    const split_520 = try scriptNumBytes(allocator, 520);
    defer allocator.free(split_520);

    const split_mid = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        joined_520,
        split_145,
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_SPLIT),
    });
    defer allocator.free(split_mid);
    const split_mid_eq = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        right_375,
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUALVERIFY),
    });
    defer allocator.free(split_mid_eq);
    const split_mid_tail = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        left_145,
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(split_mid_tail);

    const split_zero_case = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        joined_520,
        split_zero,
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_SPLIT),
    });
    defer allocator.free(split_zero_case);
    const split_zero_eq = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        joined_520,
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUALVERIFY),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_0),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(split_zero_eq);

    const split_full_case = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        joined_520,
        split_520,
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_SPLIT),
    });
    defer allocator.free(split_full_case);
    const split_full_eq = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        &[_]u8{},
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUALVERIFY),
    });
    defer allocator.free(split_full_eq);
    const split_full_tail = try scriptHexForPushesAndOps(allocator, &[_][]const u8{
        joined_520,
    }, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_EQUAL),
    });
    defer allocator.free(split_full_tail);
    const split_mid_lock = try std.mem.concat(allocator, u8, &[_][]const u8{ split_mid_eq, split_mid_tail });
    defer allocator.free(split_mid_lock);
    const split_full_lock = try std.mem.concat(allocator, u8, &[_][]const u8{ split_full_eq, split_full_tail });
    defer allocator.free(split_full_lock);

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 804, .name = "go row 804: split divides a maximum-sized element at an interior boundary", .unlocking_hex = split_mid, .locking_hex = split_mid_lock, .expected = .{ .success = true } },
        .{ .row = 805, .name = "go row 805: split at zero keeps the full right half and empty left half", .unlocking_hex = split_zero_case, .locking_hex = split_zero_eq, .expected = .{ .success = true } },
        .{ .row = 806, .name = "go row 806: split at full length keeps the full left half and empty right half", .unlocking_hex = split_full_case, .locking_hex = split_full_lock, .expected = .{ .success = true } },
    });
}

test "go direct script rows: size parity" {
    const allocator = std.testing.allocator;
    const flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    const zero = try scriptNumBytes(allocator, 0);
    defer allocator.free(zero);
    const pos_128 = try scriptNumBytes(allocator, 128);
    defer allocator.free(pos_128);
    const pos_2147483648 = try scriptNumBytes(allocator, 2_147_483_648);
    defer allocator.free(pos_2147483648);
    const neg_one = try scriptNumBytes(allocator, -1);
    defer allocator.free(neg_one);
    const neg_2147483648 = try scriptNumBytes(allocator, -2_147_483_648);
    defer allocator.free(neg_2147483648);
    const forty_two = try scriptNumBytes(allocator, 42);
    defer allocator.free(forty_two);
    const one = try scriptNumBytes(allocator, 1);
    defer allocator.free(one);
    const two = try scriptNumBytes(allocator, 2);
    defer allocator.free(two);
    const five = try scriptNumBytes(allocator, 5);
    defer allocator.free(five);
    const twenty_six = try scriptNumBytes(allocator, 26);
    defer allocator.free(twenty_six);

    const unlock_zero = try scriptHexForPushesAndOps(allocator, &[_][]const u8{zero}, &[_]u8{});
    defer allocator.free(unlock_zero);
    const unlock_128 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{pos_128}, &[_]u8{});
    defer allocator.free(unlock_128);
    const unlock_2147483648 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{pos_2147483648}, &[_]u8{});
    defer allocator.free(unlock_2147483648);
    const unlock_neg_one = try scriptHexForPushesAndOps(allocator, &[_][]const u8{neg_one}, &[_]u8{});
    defer allocator.free(unlock_neg_one);
    const unlock_neg_2147483648 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{neg_2147483648}, &[_]u8{});
    defer allocator.free(unlock_neg_2147483648);
    const unlock_alpha = try scriptHexForPushesAndOps(allocator, &[_][]const u8{"abcdefghijklmnopqrstuvwxyz"}, &[_]u8{});
    defer allocator.free(unlock_alpha);
    const unlock_42 = try scriptHexForPushesAndOps(allocator, &[_][]const u8{forty_two}, &[_]u8{});
    defer allocator.free(unlock_42);

    const size_eq_0 = try scriptHexWithOpsPushOps(allocator, &[_]bsvz.script.opcode.Opcode{.OP_SIZE}, zero, &[_]bsvz.script.opcode.Opcode{.OP_EQUAL});
    defer allocator.free(size_eq_0);
    const size_eq_2 = try scriptHexWithOpsPushOps(allocator, &[_]bsvz.script.opcode.Opcode{.OP_SIZE}, two, &[_]bsvz.script.opcode.Opcode{.OP_EQUAL});
    defer allocator.free(size_eq_2);
    const size_eq_5 = try scriptHexWithOpsPushOps(allocator, &[_]bsvz.script.opcode.Opcode{.OP_SIZE}, five, &[_]bsvz.script.opcode.Opcode{.OP_EQUAL});
    defer allocator.free(size_eq_5);
    const size_eq_1 = try scriptHexWithOpsPushOps(allocator, &[_]bsvz.script.opcode.Opcode{.OP_SIZE}, one, &[_]bsvz.script.opcode.Opcode{.OP_EQUAL});
    defer allocator.free(size_eq_1);
    const size_eq_26 = try scriptHexWithOpsPushOps(allocator, &[_]bsvz.script.opcode.Opcode{.OP_SIZE}, twenty_six, &[_]bsvz.script.opcode.Opcode{.OP_EQUAL});
    defer allocator.free(size_eq_26);
    const size_preserves_arg = try scriptHexWithOpsPushOps(
        allocator,
        &[_]bsvz.script.opcode.Opcode{ .OP_SIZE, .OP_1, .OP_EQUALVERIFY },
        forty_two,
        &[_]bsvz.script.opcode.Opcode{.OP_EQUAL},
    );
    defer allocator.free(size_preserves_arg);
    const size_underflow = try scriptHexWithOpsPushOps(allocator, &[_]bsvz.script.opcode.Opcode{.OP_SIZE}, one, &[_]bsvz.script.opcode.Opcode{});
    defer allocator.free(size_underflow);

    try runRows(allocator, flags, &[_]GoRow{
        .{ .name = "go row 223: size of zero is zero bytes", .unlocking_hex = unlock_zero, .locking_hex = size_eq_0, .expected = .{ .success = true } },
        .{ .name = "go row 226: size of 128 is two bytes", .unlocking_hex = unlock_128, .locking_hex = size_eq_2, .expected = .{ .success = true } },
        .{ .name = "go row 232: size of 2147483648 is five bytes", .unlocking_hex = unlock_2147483648, .locking_hex = size_eq_5, .expected = .{ .success = true } },
        .{ .name = "go row 236: size of -1 is one byte", .unlocking_hex = unlock_neg_one, .locking_hex = size_eq_1, .expected = .{ .success = true } },
        .{ .name = "go row 244: size of -2147483648 is five bytes", .unlocking_hex = unlock_neg_2147483648, .locking_hex = size_eq_5, .expected = .{ .success = true } },
        .{ .name = "go row 248: size of alphabet payload is twenty-six", .unlocking_hex = unlock_alpha, .locking_hex = size_eq_26, .expected = .{ .success = true } },
        .{ .name = "go row 250: size does not consume its argument", .unlocking_hex = unlock_42, .locking_hex = size_preserves_arg, .expected = .{ .success = true } },
        .{ .name = "go row 1035: size underflows on empty stack after nop", .unlocking_hex = "61", .locking_hex = size_underflow, .expected = .{ .err = error.StackUnderflow } },
    });
}

test "go direct script rows: exact hash vectors" {
    const allocator = std.testing.allocator;
    const flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    const ripe_empty = try decodeHexBytes(allocator, "9c1185a5c5e9fc54612808977ee8f548b2258d31");
    defer allocator.free(ripe_empty);
    const ripe_a = try decodeHexBytes(allocator, "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe");
    defer allocator.free(ripe_a);
    const ripe_alpha = try decodeHexBytes(allocator, "f71c27109c692c1b56bbdceb5b9d2865b3708dbc");
    defer allocator.free(ripe_alpha);
    const sha1_empty = try decodeHexBytes(allocator, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    defer allocator.free(sha1_empty);
    const sha1_a = try decodeHexBytes(allocator, "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8");
    defer allocator.free(sha1_a);
    const sha1_alpha = try decodeHexBytes(allocator, "32d10c7b8cf96570ca04ce37f2a19d84240d3a89");
    defer allocator.free(sha1_alpha);
    const sha256_empty = try decodeHexBytes(allocator, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    defer allocator.free(sha256_empty);
    const sha256_a = try decodeHexBytes(allocator, "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb");
    defer allocator.free(sha256_a);
    const sha256_alpha = try decodeHexBytes(allocator, "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73");
    defer allocator.free(sha256_alpha);
    const hash160_empty = try decodeHexBytes(allocator, "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb");
    defer allocator.free(hash160_empty);
    const hash160_a = try decodeHexBytes(allocator, "994355199e516ff76c4fa4aab39337b9d84cf12b");
    defer allocator.free(hash160_a);
    const hash160_alpha = try decodeHexBytes(allocator, "c286a1af0947f58d1ad787385b1c2c4a976f9e71");
    defer allocator.free(hash160_alpha);
    const hash256_empty = try decodeHexBytes(allocator, "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456");
    defer allocator.free(hash256_empty);
    const hash256_a = try decodeHexBytes(allocator, "bf5d3affb73efd2ec6c36ad3112dd933efed63c4e1cbffcfa88e2759c144f2d8");
    defer allocator.free(hash256_a);
    const hash256_alpha = try decodeHexBytes(allocator, "ca139bc10c2f660da42666f72e89a225936fc60f193c161124a672050c434671");
    defer allocator.free(hash256_alpha);

    const ripemd160_eq_empty = try scriptHexWithOpsPushOps(allocator, &[_]bsvz.script.opcode.Opcode{.OP_RIPEMD160}, ripe_empty, &[_]bsvz.script.opcode.Opcode{.OP_EQUAL});
    defer allocator.free(ripemd160_eq_empty);
    const ripemd160_eq_a = try scriptHexWithOpsPushOps(allocator, &[_]bsvz.script.opcode.Opcode{.OP_RIPEMD160}, ripe_a, &[_]bsvz.script.opcode.Opcode{.OP_EQUAL});
    defer allocator.free(ripemd160_eq_a);
    const ripemd160_eq_alpha = try scriptHexWithOpsPushOps(allocator, &[_]bsvz.script.opcode.Opcode{.OP_RIPEMD160}, ripe_alpha, &[_]bsvz.script.opcode.Opcode{.OP_EQUAL});
    defer allocator.free(ripemd160_eq_alpha);
    const sha1_eq_empty = try scriptHexWithOpsPushOps(allocator, &[_]bsvz.script.opcode.Opcode{.OP_SHA1}, sha1_empty, &[_]bsvz.script.opcode.Opcode{.OP_EQUAL});
    defer allocator.free(sha1_eq_empty);
    const sha1_eq_a = try scriptHexWithOpsPushOps(allocator, &[_]bsvz.script.opcode.Opcode{.OP_SHA1}, sha1_a, &[_]bsvz.script.opcode.Opcode{.OP_EQUAL});
    defer allocator.free(sha1_eq_a);
    const sha1_eq_alpha = try scriptHexWithOpsPushOps(allocator, &[_]bsvz.script.opcode.Opcode{.OP_SHA1}, sha1_alpha, &[_]bsvz.script.opcode.Opcode{.OP_EQUAL});
    defer allocator.free(sha1_eq_alpha);
    const sha256_eq_empty = try scriptHexWithOpsPushOps(allocator, &[_]bsvz.script.opcode.Opcode{.OP_SHA256}, sha256_empty, &[_]bsvz.script.opcode.Opcode{.OP_EQUAL});
    defer allocator.free(sha256_eq_empty);
    const sha256_eq_a = try scriptHexWithOpsPushOps(allocator, &[_]bsvz.script.opcode.Opcode{.OP_SHA256}, sha256_a, &[_]bsvz.script.opcode.Opcode{.OP_EQUAL});
    defer allocator.free(sha256_eq_a);
    const sha256_eq_alpha = try scriptHexWithOpsPushOps(allocator, &[_]bsvz.script.opcode.Opcode{.OP_SHA256}, sha256_alpha, &[_]bsvz.script.opcode.Opcode{.OP_EQUAL});
    defer allocator.free(sha256_eq_alpha);
    const hash160_eq_empty = try scriptHexWithOpsPushOps(allocator, &[_]bsvz.script.opcode.Opcode{ .OP_NOP, .OP_HASH160 }, hash160_empty, &[_]bsvz.script.opcode.Opcode{.OP_EQUAL});
    defer allocator.free(hash160_eq_empty);
    const hash160_eq_a = try scriptHexWithOpsPushOps(allocator, &[_]bsvz.script.opcode.Opcode{.OP_HASH160}, hash160_a, &[_]bsvz.script.opcode.Opcode{ .OP_NOP, .OP_EQUAL });
    defer allocator.free(hash160_eq_a);
    const hash160_eq_alpha = try scriptHexWithOpsPushdata1Ops(allocator, &[_]bsvz.script.opcode.Opcode{.OP_HASH160}, hash160_alpha, &[_]bsvz.script.opcode.Opcode{.OP_EQUAL});
    defer allocator.free(hash160_eq_alpha);
    const hash256_eq_empty = try scriptHexWithOpsPushOps(allocator, &[_]bsvz.script.opcode.Opcode{.OP_HASH256}, hash256_empty, &[_]bsvz.script.opcode.Opcode{.OP_EQUAL});
    defer allocator.free(hash256_eq_empty);
    const hash256_eq_a = try scriptHexWithOpsPushOps(allocator, &[_]bsvz.script.opcode.Opcode{.OP_HASH256}, hash256_a, &[_]bsvz.script.opcode.Opcode{.OP_EQUAL});
    defer allocator.free(hash256_eq_a);
    const hash256_eq_alpha = try scriptHexWithOpsPushdata1Ops(allocator, &[_]bsvz.script.opcode.Opcode{.OP_HASH256}, hash256_alpha, &[_]bsvz.script.opcode.Opcode{.OP_EQUAL});
    defer allocator.free(hash256_eq_alpha);
    const dup_hash160_swap_sha256_ripemd160_equal = try builders.scriptHexForOps(allocator, &[_]bsvz.script.opcode.Opcode{
        .OP_DUP,
        .OP_HASH160,
        .OP_SWAP,
        .OP_SHA256,
        .OP_RIPEMD160,
        .OP_EQUAL,
    });
    defer allocator.free(dup_hash160_swap_sha256_ripemd160_equal);
    const dup_hash256_swap_sha256_sha256_equal = try builders.scriptHexForOps(allocator, &[_]bsvz.script.opcode.Opcode{
        .OP_DUP,
        .OP_HASH256,
        .OP_SWAP,
        .OP_SHA256,
        .OP_SHA256,
        .OP_EQUAL,
    });
    defer allocator.free(dup_hash256_swap_sha256_sha256_equal);

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 325, .name = "go row 325: ripemd160 of empty string", .unlocking_hex = "00", .locking_hex = ripemd160_eq_empty, .expected = .{ .success = true } },
        .{ .row = 326, .name = "go row 326: ripemd160 of a", .unlocking_hex = "0161", .locking_hex = ripemd160_eq_a, .expected = .{ .success = true } },
        .{ .row = 327, .name = "go row 327: ripemd160 of alphabet", .unlocking_hex = "1a6162636465666768696a6b6c6d6e6f707172737475767778797a", .locking_hex = ripemd160_eq_alpha, .expected = .{ .success = true } },
        .{ .row = 328, .name = "go row 328: sha1 of empty string", .unlocking_hex = "00", .locking_hex = sha1_eq_empty, .expected = .{ .success = true } },
        .{ .row = 329, .name = "go row 329: sha1 of a", .unlocking_hex = "0161", .locking_hex = sha1_eq_a, .expected = .{ .success = true } },
        .{ .row = 330, .name = "go row 330: sha1 of alphabet", .unlocking_hex = "1a6162636465666768696a6b6c6d6e6f707172737475767778797a", .locking_hex = sha1_eq_alpha, .expected = .{ .success = true } },
        .{ .row = 331, .name = "go row 331: sha256 of empty string", .unlocking_hex = "00", .locking_hex = sha256_eq_empty, .expected = .{ .success = true } },
        .{ .row = 332, .name = "go row 332: sha256 of a", .unlocking_hex = "0161", .locking_hex = sha256_eq_a, .expected = .{ .success = true } },
        .{ .row = 333, .name = "go row 333: sha256 of alphabet", .unlocking_hex = "1a6162636465666768696a6b6c6d6e6f707172737475767778797a", .locking_hex = sha256_eq_alpha, .expected = .{ .success = true } },
        .{ .row = 334, .name = "go row 334: hash160 matches sha256 then ripemd160", .unlocking_hex = "00", .locking_hex = dup_hash160_swap_sha256_ripemd160_equal, .expected = .{ .success = true } },
        .{ .row = 335, .name = "go row 335: hash256 matches double sha256", .unlocking_hex = "00", .locking_hex = dup_hash256_swap_sha256_sha256_equal, .expected = .{ .success = true } },
        .{ .row = 336, .name = "go row 336: hash160 of empty string with leading nop", .unlocking_hex = "00", .locking_hex = hash160_eq_empty, .expected = .{ .success = true } },
        .{ .row = 337, .name = "go row 337: hash160 of a with trailing nop", .unlocking_hex = "0161", .locking_hex = hash160_eq_a, .expected = .{ .success = true } },
        .{ .row = 338, .name = "go row 338: hash160 of alphabet with explicit pushdata1 digest push", .unlocking_hex = "1a6162636465666768696a6b6c6d6e6f707172737475767778797a", .locking_hex = hash160_eq_alpha, .expected = .{ .success = true } },
        .{ .row = 339, .name = "go row 339: hash256 of empty string", .unlocking_hex = "00", .locking_hex = hash256_eq_empty, .expected = .{ .success = true } },
        .{ .row = 340, .name = "go row 340: hash256 of a", .unlocking_hex = "0161", .locking_hex = hash256_eq_a, .expected = .{ .success = true } },
        .{ .row = 341, .name = "go row 341: hash256 of alphabet with explicit pushdata1 digest push", .unlocking_hex = "1a6162636465666768696a6b6c6d6e6f707172737475767778797a", .locking_hex = hash256_eq_alpha, .expected = .{ .success = true } },
    });
}

test "go direct script rows: compact hash result shapes" {
    const allocator = std.testing.allocator;
    const flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    const ripemd160_only = try builders.scriptHexForOps(allocator, &[_]bsvz.script.opcode.Opcode{.OP_RIPEMD160});
    defer allocator.free(ripemd160_only);
    const sha1_only = try builders.scriptHexForOps(allocator, &[_]bsvz.script.opcode.Opcode{.OP_SHA1});
    defer allocator.free(sha1_only);
    const sha256_only = try builders.scriptHexForOps(allocator, &[_]bsvz.script.opcode.Opcode{.OP_SHA256});
    defer allocator.free(sha256_only);
    const hash160_only = try builders.scriptHexForOps(allocator, &[_]bsvz.script.opcode.Opcode{.OP_HASH160});
    defer allocator.free(hash160_only);
    const hash256_only = try builders.scriptHexForOps(allocator, &[_]bsvz.script.opcode.Opcode{.OP_HASH256});
    defer allocator.free(hash256_only);

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 466, .name = "go row 466: ripemd160 of raw zero leaves a truthy digest", .unlocking_hex = "00", .locking_hex = ripemd160_only, .expected = .{ .success = true } },
        .{ .row = 467, .name = "go row 467: sha1 of raw zero leaves a truthy digest", .unlocking_hex = "00", .locking_hex = sha1_only, .expected = .{ .success = true } },
        .{ .row = 468, .name = "go row 468: sha256 of raw zero leaves a truthy digest", .unlocking_hex = "00", .locking_hex = sha256_only, .expected = .{ .success = true } },
        .{ .row = 469, .name = "go row 469: hash160 of raw zero leaves a truthy digest", .unlocking_hex = "00", .locking_hex = hash160_only, .expected = .{ .success = true } },
        .{ .row = 470, .name = "go row 470: hash256 of raw zero leaves a truthy digest", .unlocking_hex = "00", .locking_hex = hash256_only, .expected = .{ .success = true } },
        .{ .row = 1124, .name = "go row 1124: nop then ripemd160 underflows", .unlocking_hex = "61", .locking_hex = ripemd160_only, .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 1125, .name = "go row 1125: nop then sha1 underflows", .unlocking_hex = "61", .locking_hex = sha1_only, .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 1126, .name = "go row 1126: nop then sha256 underflows", .unlocking_hex = "61", .locking_hex = sha256_only, .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 1127, .name = "go row 1127: nop then hash160 underflows", .unlocking_hex = "61", .locking_hex = hash160_only, .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 1128, .name = "go row 1128: nop then hash256 underflows", .unlocking_hex = "61", .locking_hex = hash256_only, .expected = .{ .err = error.StackUnderflow } },
    });
}
