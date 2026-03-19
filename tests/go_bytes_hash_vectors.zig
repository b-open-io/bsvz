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
        .{ .row = 944, .name = "cat with empty string on the right keeps left", .unlocking_hex = "0361626300", .locking_hex = "7e0361626387", .expected = .{ .success = true } },
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
        .{ .row = 798, .name = "go row 798: split divides abcdef at index three", .unlocking_hex = "0661626364656653", .locking_hex = "7f03646566880361626387", .expected = .{ .success = true } },
        .{ .row = 799, .name = "go row 799: split on empty string at zero keeps both halves empty", .unlocking_hex = "0000", .locking_hex = "7f00880087", .expected = .{ .success = true } },
        .{ .row = 800, .name = "go row 800: split at zero keeps the right side intact", .unlocking_hex = "0361626300", .locking_hex = "7f03616263880087", .expected = .{ .success = true } },
        .{ .row = 801, .name = "go row 801: split at payload length keeps the left side intact", .unlocking_hex = "0361626353", .locking_hex = "7f00880361626387", .expected = .{ .success = true } },
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
