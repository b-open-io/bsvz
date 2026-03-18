const std = @import("std");
const bsvz = @import("bsvz");
const harness = @import("support/go_script_harness.zig");

const Opcode = bsvz.script.opcode.Opcode;

const GoRow = struct {
    row: usize,
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

fn encodeLowerAlloc(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, bytes.len * 2);
    return try bsvz.primitives.hex.encodeLower(bytes, out);
}

fn scriptHexFromBytes(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    return encodeLowerAlloc(allocator, bytes);
}

fn appendAsmInt(
    bytes: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    value: i64,
) !void {
    switch (value) {
        0 => try bytes.append(allocator, @intFromEnum(Opcode.OP_0)),
        -1 => try bytes.append(allocator, @intFromEnum(Opcode.OP_1NEGATE)),
        1...16 => |small| {
            const op_value = @intFromEnum(Opcode.OP_1) + @as(u8, @intCast(small - 1));
            try bytes.append(allocator, op_value);
        },
        else => {
            const encoded = try bsvz.script.ScriptNum.encode(allocator, value);
            defer allocator.free(encoded);

            if (encoded.len > 75) return error.InvalidPushData;
            try bytes.append(allocator, @intCast(encoded.len));
            try bytes.appendSlice(allocator, encoded);
        },
    }
}

fn scriptHexForAsmIntsAndOps(
    allocator: std.mem.Allocator,
    ints: []const i64,
    ops: []const Opcode,
) ![]u8 {
    var bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer bytes.deinit(allocator);

    for (ints) |value| try appendAsmInt(&bytes, allocator, value);
    for (ops) |op| try bytes.append(allocator, @intFromEnum(op));

    return scriptHexFromBytes(allocator, bytes.items);
}

test "go numeric rows: exact stack-shape result rows" {
    const allocator = std.testing.allocator;

    try runRows(allocator, bsvz.script.engine.ExecutionFlags.legacyReference(), &[_]GoRow{
        .{ .row = 191, .name = "go row 191: ifdup over zero preserves false stack shape", .unlocking_hex = "0073", .locking_hex = "7451880087", .expected = .{ .success = true } },
        .{ .row = 192, .name = "go row 192: ifdup over one duplicates true value", .unlocking_hex = "5173", .locking_hex = "74528851885187", .expected = .{ .success = true } },
        .{ .row = 194, .name = "go row 194: drop over zero leaves empty depth", .unlocking_hex = "0075", .locking_hex = "740087", .expected = .{ .success = true } },
        .{ .row = 196, .name = "go row 196: nip drops the second stack item", .unlocking_hex = "0051", .locking_hex = "77", .expected = .{ .success = true } },
        .{ .row = 217, .name = "go row 217: swap reverses the top two items", .unlocking_hex = "5100", .locking_hex = "7c51880087", .expected = .{ .success = true } },
    });
}

test "go numeric rows: exact arithmetic result rows" {
    const allocator = std.testing.allocator;
    const flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    const row252_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ 2, -2 }, &[_]Opcode{.OP_ADD});
    defer allocator.free(row252_unlocking);
    const row252_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{0}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row252_locking);

    const row254_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ -1, -1 }, &[_]Opcode{.OP_ADD});
    defer allocator.free(row254_unlocking);
    const row254_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{-2}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row254_locking);

    const row259_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{111}, &[_]Opcode{.OP_1SUB});
    defer allocator.free(row259_unlocking);
    const row259_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{110}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row259_locking);

    const row263_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{-16}, &[_]Opcode{.OP_ABS});
    defer allocator.free(row263_unlocking);
    const row263_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{-16}, &[_]Opcode{ .OP_NEGATE, .OP_EQUAL });
    defer allocator.free(row263_locking);

    const row322_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{2_147_483_647}, &[_]Opcode{ .OP_DUP, .OP_ADD });
    defer allocator.free(row322_unlocking);
    const row322_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{4_294_967_294}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row322_locking);

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 252, .name = "go row 252: add cancels positive and negative operands", .unlocking_hex = row252_unlocking, .locking_hex = row252_locking, .expected = .{ .success = true } },
        .{ .row = 254, .name = "go row 254: add keeps negative totals exact", .unlocking_hex = row254_unlocking, .locking_hex = row254_locking, .expected = .{ .success = true } },
        .{ .row = 259, .name = "go row 259: 1sub decrements exactly", .unlocking_hex = row259_unlocking, .locking_hex = row259_locking, .expected = .{ .success = true } },
        .{ .row = 263, .name = "go row 263: abs matches negate of negative operand", .unlocking_hex = row263_unlocking, .locking_hex = row263_locking, .expected = .{ .success = true } },
        .{ .row = 322, .name = "go row 322: dup add supports greater-than-32-bit equality", .unlocking_hex = row322_unlocking, .locking_hex = row322_locking, .expected = .{ .success = true } },
    });
}

test "go numeric rows: exact division result rows" {
    const allocator = std.testing.allocator;
    const flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    const row976_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ 0, 123 }, &[_]Opcode{.OP_DIV});
    defer allocator.free(row976_unlocking);
    const row976_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{0}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row976_locking);

    const row978_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ 1, 1 }, &[_]Opcode{ .OP_DIV, .OP_DEPTH });
    defer allocator.free(row978_unlocking);
    const row978_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{1}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row978_locking);

    const row981_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ 2_147_483_647, 1 }, &[_]Opcode{.OP_DIV});
    defer allocator.free(row981_unlocking);
    const row981_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{2_147_483_647}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row981_locking);

    const row982_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ 1, 2_147_483_647 }, &[_]Opcode{.OP_DIV});
    defer allocator.free(row982_unlocking);
    const row982_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{0}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row982_locking);

    const row983_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ 2_147_483_647, 2_147_483_647 }, &[_]Opcode{.OP_DIV});
    defer allocator.free(row983_unlocking);
    const row983_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{1}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row983_locking);

    const row984_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ -2_147_483_647, 1 }, &[_]Opcode{.OP_DIV});
    defer allocator.free(row984_unlocking);
    const row984_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{-2_147_483_647}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row984_locking);

    const row985_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ -1, 2_147_483_647 }, &[_]Opcode{.OP_DIV});
    defer allocator.free(row985_unlocking);
    const row985_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{0}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row985_locking);

    const row986_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ -2_147_483_647, 2_147_483_647 }, &[_]Opcode{.OP_DIV});
    defer allocator.free(row986_unlocking);
    const row986_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{-1}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row986_locking);

    const row987_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ 2_147_483_647, -1 }, &[_]Opcode{.OP_DIV});
    defer allocator.free(row987_unlocking);
    const row987_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{-2_147_483_647}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row987_locking);

    const row988_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ 1, -2_147_483_647 }, &[_]Opcode{.OP_DIV});
    defer allocator.free(row988_unlocking);
    const row988_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{0}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row988_locking);

    const row989_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ 2_147_483_647, -2_147_483_647 }, &[_]Opcode{.OP_DIV});
    defer allocator.free(row989_unlocking);
    const row989_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{-1}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row989_locking);

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 976, .name = "go row 976: div by larger positive denominator yields zero", .unlocking_hex = row976_unlocking, .locking_hex = row976_locking, .expected = .{ .success = true } },
        .{ .row = 977, .name = "go row 977: div rejects divide by zero", .unlocking_hex = "02ff0100", .locking_hex = "96", .expected = .{ .err = error.DivisionByZero } },
        .{ .row = 978, .name = "go row 978: div leaves one stack item after depth check", .unlocking_hex = row978_unlocking, .locking_hex = row978_locking, .expected = .{ .success = true } },
        .{ .row = 979, .name = "go row 979: div requires two operands for one", .unlocking_hex = "51", .locking_hex = "96", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 980, .name = "go row 980: div requires two operands for zero", .unlocking_hex = "00", .locking_hex = "96", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 981, .name = "go row 981: div preserves max int32 when dividing by one", .unlocking_hex = row981_unlocking, .locking_hex = row981_locking, .expected = .{ .success = true } },
        .{ .row = 982, .name = "go row 982: div truncates one over max int32 to zero", .unlocking_hex = row982_unlocking, .locking_hex = row982_locking, .expected = .{ .success = true } },
        .{ .row = 983, .name = "go row 983: div of equal max int32 values yields one", .unlocking_hex = row983_unlocking, .locking_hex = row983_locking, .expected = .{ .success = true } },
        .{ .row = 984, .name = "go row 984: div preserves negative max int32 by one", .unlocking_hex = row984_unlocking, .locking_hex = row984_locking, .expected = .{ .success = true } },
        .{ .row = 985, .name = "go row 985: div truncates negative one over max int32 to zero", .unlocking_hex = row985_unlocking, .locking_hex = row985_locking, .expected = .{ .success = true } },
        .{ .row = 986, .name = "go row 986: div of negative max int32 by max int32 yields negative one", .unlocking_hex = row986_unlocking, .locking_hex = row986_locking, .expected = .{ .success = true } },
        .{ .row = 987, .name = "go row 987: div of max int32 by negative one yields negative max int32", .unlocking_hex = row987_unlocking, .locking_hex = row987_locking, .expected = .{ .success = true } },
        .{ .row = 988, .name = "go row 988: div truncates one over negative max int32 to zero", .unlocking_hex = row988_unlocking, .locking_hex = row988_locking, .expected = .{ .success = true } },
        .{ .row = 989, .name = "go row 989: div of max int32 by negative max int32 yields negative one", .unlocking_hex = row989_unlocking, .locking_hex = row989_locking, .expected = .{ .success = true } },
    });
}

test "go numeric rows: exact modulo result rows" {
    const allocator = std.testing.allocator;
    const flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    const row998_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ 1, 1 }, &[_]Opcode{.OP_MOD});
    defer allocator.free(row998_unlocking);
    const row998_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{0}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row998_locking);

    const row999_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ -1, 1 }, &[_]Opcode{.OP_MOD});
    defer allocator.free(row999_unlocking);
    const row999_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{0}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row999_locking);

    const row1000_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ 1, -1 }, &[_]Opcode{.OP_MOD});
    defer allocator.free(row1000_unlocking);
    const row1000_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{0}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row1000_locking);

    const row1001_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ -1, -1 }, &[_]Opcode{.OP_MOD});
    defer allocator.free(row1001_unlocking);
    const row1001_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{0}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row1001_locking);

    const row1002_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ 82, 23 }, &[_]Opcode{.OP_MOD});
    defer allocator.free(row1002_unlocking);
    const row1002_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{13}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row1002_locking);

    const row1003_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ 8, -3 }, &[_]Opcode{.OP_MOD});
    defer allocator.free(row1003_unlocking);
    const row1003_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{2}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row1003_locking);

    const row1004_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ -71, 13 }, &[_]Opcode{.OP_MOD});
    defer allocator.free(row1004_unlocking);
    const row1004_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{-6}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row1004_locking);

    const row1005_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ -110, -31 }, &[_]Opcode{.OP_MOD});
    defer allocator.free(row1005_unlocking);
    const row1005_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{-17}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row1005_locking);

    const row1006_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ 0, 1 }, &[_]Opcode{.OP_MOD});
    defer allocator.free(row1006_unlocking);
    const row1006_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{0}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row1006_locking);

    const row1011_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ 2_147_483_647, 123 }, &[_]Opcode{.OP_MOD});
    defer allocator.free(row1011_unlocking);
    const row1011_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{79}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row1011_locking);

    const row1012_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ 123, 2_147_483_647 }, &[_]Opcode{.OP_MOD});
    defer allocator.free(row1012_unlocking);
    const row1012_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{123}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row1012_locking);

    const row1013_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ 2_147_483_647, 2_147_483_647 }, &[_]Opcode{.OP_MOD});
    defer allocator.free(row1013_unlocking);
    const row1013_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{0}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row1013_locking);

    const row1014_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ -2_147_483_647, 123 }, &[_]Opcode{.OP_MOD});
    defer allocator.free(row1014_unlocking);
    const row1014_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{-79}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row1014_locking);

    const row1015_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ -123, 2_147_483_647 }, &[_]Opcode{.OP_MOD});
    defer allocator.free(row1015_unlocking);
    const row1015_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{-123}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row1015_locking);

    const row1016_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ -2_147_483_647, 2_147_483_647 }, &[_]Opcode{.OP_MOD});
    defer allocator.free(row1016_unlocking);
    const row1016_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{0}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row1016_locking);

    const row1017_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ 2_147_483_647, -123 }, &[_]Opcode{.OP_MOD});
    defer allocator.free(row1017_unlocking);
    const row1017_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{79}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row1017_locking);

    const row1018_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ 123, -2_147_483_647 }, &[_]Opcode{.OP_MOD});
    defer allocator.free(row1018_unlocking);
    const row1018_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{123}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row1018_locking);

    const row1019_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ 2_147_483_647, -2_147_483_647 }, &[_]Opcode{.OP_MOD});
    defer allocator.free(row1019_unlocking);
    const row1019_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{0}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row1019_locking);

    const row1020_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ -2_147_483_647, -123 }, &[_]Opcode{.OP_MOD});
    defer allocator.free(row1020_unlocking);
    const row1020_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{-79}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row1020_locking);

    const row1021_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ -123, -2_147_483_647 }, &[_]Opcode{.OP_MOD});
    defer allocator.free(row1021_unlocking);
    const row1021_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{-123}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row1021_locking);

    const row1022_unlocking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{ -2_147_483_647, -2_147_483_647 }, &[_]Opcode{.OP_MOD});
    defer allocator.free(row1022_unlocking);
    const row1022_locking = try scriptHexForAsmIntsAndOps(allocator, &[_]i64{0}, &[_]Opcode{.OP_EQUAL});
    defer allocator.free(row1022_locking);

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 998, .name = "go row 998: mod of one by one yields zero", .unlocking_hex = row998_unlocking, .locking_hex = row998_locking, .expected = .{ .success = true } },
        .{ .row = 999, .name = "go row 999: mod of negative one by one yields zero", .unlocking_hex = row999_unlocking, .locking_hex = row999_locking, .expected = .{ .success = true } },
        .{ .row = 1000, .name = "go row 1000: mod of one by negative one yields zero", .unlocking_hex = row1000_unlocking, .locking_hex = row1000_locking, .expected = .{ .success = true } },
        .{ .row = 1001, .name = "go row 1001: mod of negative one by negative one yields zero", .unlocking_hex = row1001_unlocking, .locking_hex = row1001_locking, .expected = .{ .success = true } },
        .{ .row = 1002, .name = "go row 1002: mod keeps positive remainder", .unlocking_hex = row1002_unlocking, .locking_hex = row1002_locking, .expected = .{ .success = true } },
        .{ .row = 1003, .name = "go row 1003: mod truncates toward zero for negative divisor", .unlocking_hex = row1003_unlocking, .locking_hex = row1003_locking, .expected = .{ .success = true } },
        .{ .row = 1004, .name = "go row 1004: mod keeps negative remainder sign of numerator", .unlocking_hex = row1004_unlocking, .locking_hex = row1004_locking, .expected = .{ .success = true } },
        .{ .row = 1005, .name = "go row 1005: mod keeps negative remainder with both operands negative", .unlocking_hex = row1005_unlocking, .locking_hex = row1005_locking, .expected = .{ .success = true } },
        .{ .row = 1006, .name = "go row 1006: mod of zero by one yields zero", .unlocking_hex = row1006_unlocking, .locking_hex = row1006_locking, .expected = .{ .success = true } },
        .{ .row = 1007, .name = "go row 1007: mod rejects modulo by zero", .unlocking_hex = "5100", .locking_hex = "97", .expected = .{ .err = error.DivisionByZero } },
        .{ .row = 1010, .name = "go row 1010: mod requires two operands", .unlocking_hex = "00", .locking_hex = "97", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 1011, .name = "go row 1011: mod keeps positive boundary remainder", .unlocking_hex = row1011_unlocking, .locking_hex = row1011_locking, .expected = .{ .success = true } },
        .{ .row = 1012, .name = "go row 1012: mod with smaller dividend keeps dividend", .unlocking_hex = row1012_unlocking, .locking_hex = row1012_locking, .expected = .{ .success = true } },
        .{ .row = 1013, .name = "go row 1013: mod of equal positive max int32 values yields zero", .unlocking_hex = row1013_unlocking, .locking_hex = row1013_locking, .expected = .{ .success = true } },
        .{ .row = 1014, .name = "go row 1014: mod keeps negative boundary remainder", .unlocking_hex = row1014_unlocking, .locking_hex = row1014_locking, .expected = .{ .success = true } },
        .{ .row = 1015, .name = "go row 1015: mod keeps negative smaller dividend", .unlocking_hex = row1015_unlocking, .locking_hex = row1015_locking, .expected = .{ .success = true } },
        .{ .row = 1016, .name = "go row 1016: mod of negative max int32 by positive max int32 yields zero", .unlocking_hex = row1016_unlocking, .locking_hex = row1016_locking, .expected = .{ .success = true } },
        .{ .row = 1017, .name = "go row 1017: mod keeps positive remainder with negative divisor", .unlocking_hex = row1017_unlocking, .locking_hex = row1017_locking, .expected = .{ .success = true } },
        .{ .row = 1018, .name = "go row 1018: mod with smaller positive dividend and negative divisor keeps dividend", .unlocking_hex = row1018_unlocking, .locking_hex = row1018_locking, .expected = .{ .success = true } },
        .{ .row = 1019, .name = "go row 1019: mod of positive max int32 by negative max int32 yields zero", .unlocking_hex = row1019_unlocking, .locking_hex = row1019_locking, .expected = .{ .success = true } },
        .{ .row = 1020, .name = "go row 1020: mod keeps negative remainder with both divisor and dividend negative", .unlocking_hex = row1020_unlocking, .locking_hex = row1020_locking, .expected = .{ .success = true } },
        .{ .row = 1021, .name = "go row 1021: mod keeps negative smaller dividend against negative divisor", .unlocking_hex = row1021_unlocking, .locking_hex = row1021_locking, .expected = .{ .success = true } },
        .{ .row = 1022, .name = "go row 1022: mod of equal negative max int32 values yields zero", .unlocking_hex = row1022_unlocking, .locking_hex = row1022_locking, .expected = .{ .success = true } },
        .{ .row = 1023, .name = "go row 1023: mod rejects positive five-byte numerator", .unlocking_hex = "05000000008051", .locking_hex = "97", .expected = .{ .err = error.NumberTooBig } },
        .{ .row = 1024, .name = "go row 1024: mod rejects positive five-byte denominator", .unlocking_hex = "51050000000080", .locking_hex = "97", .expected = .{ .err = error.NumberTooBig } },
        .{ .row = 1025, .name = "go row 1025: mod rejects negative five-byte numerator", .unlocking_hex = "0500000000808051", .locking_hex = "97", .expected = .{ .err = error.NumberTooBig } },
        .{ .row = 1026, .name = "go row 1026: mod rejects negative five-byte denominator", .unlocking_hex = "5105000000008080", .locking_hex = "97", .expected = .{ .err = error.NumberTooBig } },
    });
}

test "go numeric rows: exact stack underflow result rows" {
    const allocator = std.testing.allocator;

    try runRows(allocator, bsvz.script.engine.ExecutionFlags.legacyReference(), &[_]GoRow{
        .{ .row = 1402, .name = "go row 1402: 2drop requires two stack items", .unlocking_hex = "51", .locking_hex = "6d51", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 1411, .name = "go row 1411: nip requires two stack items", .unlocking_hex = "51", .locking_hex = "77", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 1417, .name = "go row 1417: rot requires three stack items", .unlocking_hex = "5151", .locking_hex = "7b", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 1419, .name = "go row 1419: tuck requires two stack items", .unlocking_hex = "51", .locking_hex = "7d", .expected = .{ .err = error.StackUnderflow } },
    });
}
