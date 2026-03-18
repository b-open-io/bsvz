const std = @import("std");
const bsvz = @import("bsvz");
const harness = @import("support/go_script_harness.zig");

const nonempty_invalid_der_signature = [_]u8{
    0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01,
};

const GoRow = struct {
    name: []const u8,
    unlocking_hex: []const u8,
    locking_hex: []const u8,
    expected: harness.Expectation,
};

fn encodeLowerAlloc(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, bytes.len * 2);
    return try bsvz.primitives.hex.encodeLower(bytes, out);
}

fn buildSyntheticCheckmultisigNotHexes(
    allocator: std.mem.Allocator,
    dummy_opcode: u8,
    nonempty_sig_index: ?usize,
) !struct { unlocking_hex: []u8, locking_hex: []u8 } {
    var unlocking_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer unlocking_bytes.deinit(allocator);
    var locking_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer locking_bytes.deinit(allocator);

    try unlocking_bytes.append(allocator, dummy_opcode);
    for (0..20) |index| {
        if (nonempty_sig_index != null and nonempty_sig_index.? == index) {
            try unlocking_bytes.append(allocator, nonempty_invalid_der_signature.len);
            try unlocking_bytes.appendSlice(allocator, &nonempty_invalid_der_signature);
        } else {
            try unlocking_bytes.append(allocator, 0x00);
        }
    }

    try locking_bytes.appendSlice(allocator, &[_]u8{ 0x01, 0x14 });
    for (0..20) |_| try locking_bytes.append(allocator, 0x51);
    try locking_bytes.appendSlice(allocator, &[_]u8{
        0x01,
        0x14,
        @intFromEnum(bsvz.script.opcode.Opcode.OP_CHECKMULTISIG),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NOT),
    });

    return .{
        .unlocking_hex = try encodeLowerAlloc(allocator, unlocking_bytes.items),
        .locking_hex = try encodeLowerAlloc(allocator, locking_bytes.items),
    };
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

test "go multisig rows: nullfail and nulldummy matrix" {
    const allocator = std.testing.allocator;

    const empty_case = try buildSyntheticCheckmultisigNotHexes(allocator, 0x00, null);
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

    const nonzero_dummy_case = try buildSyntheticCheckmultisigNotHexes(allocator, 0x51, null);
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

    const trailing_nonempty_sig_case = try buildSyntheticCheckmultisigNotHexes(allocator, 0x00, 19);
    defer allocator.free(trailing_nonempty_sig_case.unlocking_hex);
    defer allocator.free(trailing_nonempty_sig_case.locking_hex);

    try harness.runCase(allocator, .{
        .name = "20-of-20 not trailing non-null der-compliant invalid signature with dersig",
        .unlocking_hex = trailing_nonempty_sig_case.unlocking_hex,
        .locking_hex = trailing_nonempty_sig_case.locking_hex,
        .flags = dersig_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "20-of-20 not trailing non-null der-compliant invalid signature with nullfail",
        .unlocking_hex = trailing_nonempty_sig_case.unlocking_hex,
        .locking_hex = trailing_nonempty_sig_case.locking_hex,
        .flags = nullfail_flags,
        .expected = .{ .err = error.NullFail },
    });

    const leading_nonempty_sig_case = try buildSyntheticCheckmultisigNotHexes(allocator, 0x00, 0);
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

test "go multisig rows: strict evaluation order" {
    const allocator = std.testing.allocator;

    var strict_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    strict_flags.strict_encoding = true;

    try runRows(allocator, strict_flags, &[_]GoRow{
        .{
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
            .expected = .{ .err = error.InvalidPublicKeyEncoding },
        },
        .{
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
            .expected = .{ .err = error.InvalidSignatureEncoding },
        },
    });
}

test "go multisig rows: zero-count parity" {
    const allocator = std.testing.allocator;
    const flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    try runRows(allocator, flags, &[_]GoRow{
        .{ .name = "checkmultisig allows zero keys and zero sigs", .unlocking_hex = "", .locking_hex = "000000ae69740087", .expected = .{ .success = true } },
        .{ .name = "checkmultisigverify allows zero keys and zero sigs", .unlocking_hex = "", .locking_hex = "000000af740087", .expected = .{ .success = true } },
        .{ .name = "checkmultisig ignores keys when zero sigs are required", .unlocking_hex = "", .locking_hex = "00000051ae69740087", .expected = .{ .success = true } },
        .{ .name = "checkmultisigverify ignores keys when zero sigs are required", .unlocking_hex = "", .locking_hex = "00000051af740087", .expected = .{ .success = true } },
    });
}
