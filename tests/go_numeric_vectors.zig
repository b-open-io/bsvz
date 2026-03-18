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

test "go numeric rows: exact stack underflow result rows" {
    const allocator = std.testing.allocator;

    try runRows(allocator, bsvz.script.engine.ExecutionFlags.legacyReference(), &[_]GoRow{
        .{ .row = 1402, .name = "go row 1402: 2drop requires two stack items", .unlocking_hex = "51", .locking_hex = "6d51", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 1411, .name = "go row 1411: nip requires two stack items", .unlocking_hex = "51", .locking_hex = "77", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 1417, .name = "go row 1417: rot requires three stack items", .unlocking_hex = "5151", .locking_hex = "7b", .expected = .{ .err = error.StackUnderflow } },
        .{ .row = 1419, .name = "go row 1419: tuck requires two stack items", .unlocking_hex = "51", .locking_hex = "7d", .expected = .{ .err = error.StackUnderflow } },
    });
}
