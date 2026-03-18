const std = @import("std");
const bsvz = @import("bsvz");
const harness = @import("support/go_script_harness.zig");

const nonempty_invalid_der_signature = [_]u8{
    0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01,
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

test "go direct checksig rows: bip66 example 4 nullfail matrix" {
    const allocator = std.testing.allocator;
    const locking_hex =
        "21"
        ++ "038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508"
        ++ "ac91";

    var base_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    base_flags.der_signatures = true;

    try harness.runCase(allocator, .{
        .name = "empty signature with dersig",
        .unlocking_hex = "00",
        .locking_hex = locking_hex,
        .flags = base_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "non-null der-compliant invalid signature with dersig",
        .unlocking_hex = "09300602010102010101",
        .locking_hex = locking_hex,
        .flags = base_flags,
        .expected = .{ .success = true },
    });

    var nullfail_flags = base_flags;
    nullfail_flags.null_fail = true;

    try harness.runCase(allocator, .{
        .name = "empty signature with dersig and nullfail",
        .unlocking_hex = "00",
        .locking_hex = locking_hex,
        .flags = nullfail_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "non-null der-compliant invalid signature with dersig and nullfail",
        .unlocking_hex = "09300602010102010101",
        .locking_hex = locking_hex,
        .flags = nullfail_flags,
        .expected = .{ .err = error.NullFail },
    });
}

test "go direct checksig rows: additional bip66 result shapes" {
    const allocator = std.testing.allocator;
    const locking_hex =
        "21"
        ++ "038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508"
        ++ "ac";

    var relaxed_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    relaxed_flags.der_signatures = false;

    var dersig_flags = relaxed_flags;
    dersig_flags.der_signatures = true;

    try harness.runCase(allocator, .{
        .name = "bip66 example 2 with dersig",
        .unlocking_hex = "47304402208e43c0b91f7c1e5bc58e41c8185f8a6086e111b0090187968a86f2822462d3c902200a58f4076b1133b18ff1dc83ee51676e44c60cc608d9534e0df5ace0424fc0be01",
        .locking_hex = locking_hex ++ "91",
        .flags = dersig_flags,
        .expected = .{ .err = error.InvalidSignatureEncoding },
    });

    try harness.runCase(allocator, .{
        .name = "bip66 example 3 without dersig",
        .unlocking_hex = "00",
        .locking_hex = locking_hex,
        .flags = relaxed_flags,
        .expected = .{ .success = false },
    });

    try harness.runCase(allocator, .{
        .name = "bip66 example 3 with dersig",
        .unlocking_hex = "00",
        .locking_hex = locking_hex,
        .flags = dersig_flags,
        .expected = .{ .success = false },
    });

    try harness.runCase(allocator, .{
        .name = "bip66 example 5 without dersig",
        .unlocking_hex = "51",
        .locking_hex = locking_hex,
        .flags = relaxed_flags,
        .expected = .{ .success = false },
    });

    try harness.runCase(allocator, .{
        .name = "bip66 example 5 with dersig",
        .unlocking_hex = "51",
        .locking_hex = locking_hex,
        .flags = dersig_flags,
        .expected = .{ .err = error.InvalidSignatureEncoding },
    });
}

test "go direct checksig rows: padding-related dersig policy rows" {
    const allocator = std.testing.allocator;

    var relaxed_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    relaxed_flags.der_signatures = false;

    var dersig_flags = relaxed_flags;
    dersig_flags.der_signatures = true;

    try harness.runCase(allocator, .{
        .name = "p2pk checksig not bad sig with too much r padding without dersig",
        .unlocking_hex = "4730440220005ece1335e7f757a1a1f476a7fb5bd90964e8a022489f890614a04acfb734c002206c12b8294a6513c7710e8c82d3c23d75cdbfe83200eb7efb495701958501a5d601",
        .locking_hex =
            "21"
            ++ "03363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640"
            ++ "ac91",
        .flags = relaxed_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "p2pk checksig not bad sig with too much r padding with dersig",
        .unlocking_hex = "4730440220005ece1335e7f757a1a1f476a7fb5bd90964e8a022489f890614a04acfb734c002206c12b8294a6513c7710e8c82d3c23d75cdbfe83200eb7efb495701958501a5d601",
        .locking_hex =
            "21"
            ++ "03363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640"
            ++ "ac91",
        .flags = dersig_flags,
        .expected = .{ .err = error.InvalidSignatureEncoding },
    });

    try harness.runCase(allocator, .{
        .name = "p2pk checksig too little r padding with dersig",
        .unlocking_hex = "4730440220d7a0417c3f6d1a15094d1cf2a3378ca0503eb8a57630953a9e2987e21ddd0a6502207a6266d686c99090920249991d3d42065b6d43eb70187b219c0db82e4f94d1a201",
        .locking_hex =
            "21"
            ++ "038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508"
            ++ "ac",
        .flags = dersig_flags,
        .expected = .{ .err = error.InvalidSignatureEncoding },
    });
}

test "go direct checkmultisig rows: nullfail and nulldummy matrix" {
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

    const nonempty_sig_case = try buildSyntheticCheckmultisigNotHexes(allocator, 0x00, 19);
    defer allocator.free(nonempty_sig_case.unlocking_hex);
    defer allocator.free(nonempty_sig_case.locking_hex);

    try harness.runCase(allocator, .{
        .name = "20-of-20 not non-null der-compliant invalid signature with dersig",
        .unlocking_hex = nonempty_sig_case.unlocking_hex,
        .locking_hex = nonempty_sig_case.locking_hex,
        .flags = dersig_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "20-of-20 not non-null der-compliant invalid signature with nullfail",
        .unlocking_hex = nonempty_sig_case.unlocking_hex,
        .locking_hex = nonempty_sig_case.locking_hex,
        .flags = nullfail_flags,
        .expected = .{ .err = error.NullFail },
    });
}
