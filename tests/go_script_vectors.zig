const std = @import("std");
const bsvz = @import("bsvz");
const harness = @import("support/go_script_harness.zig");

const nonempty_invalid_der_signature = [_]u8{
    0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01,
};

const GoRow = struct {
    row: ?usize = null,
    name: []const u8,
    unlocking_hex: []const u8,
    locking_hex: []const u8,
    expected: harness.Expectation,
};

fn encodeLowerAlloc(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, bytes.len * 2);
    return try bsvz.primitives.hex.encodeLower(bytes, out);
}

fn scriptHexFromBytes(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    return encodeLowerAlloc(allocator, bytes);
}

fn numericOpDrop1Hex(allocator: std.mem.Allocator, op: bsvz.script.opcode.Opcode) ![]u8 {
    return scriptHexFromBytes(allocator, &[_]u8{
        @intFromEnum(op),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_DROP),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_1),
    });
}

fn expectMinimalDataUnary(
    allocator: std.mem.Allocator,
    flags: bsvz.script.engine.ExecutionFlags,
    op: bsvz.script.opcode.Opcode,
    name: []const u8,
) !void {
    const locking_hex = try numericOpDrop1Hex(allocator, op);
    defer allocator.free(locking_hex);

    try harness.runCase(allocator, .{
        .name = name,
        .unlocking_hex = "020000",
        .locking_hex = locking_hex,
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });
}

fn expectMinimalDataBinary(
    allocator: std.mem.Allocator,
    flags: bsvz.script.engine.ExecutionFlags,
    op: bsvz.script.opcode.Opcode,
    name_left: []const u8,
    name_right: []const u8,
) !void {
    const locking_hex = try numericOpDrop1Hex(allocator, op);
    defer allocator.free(locking_hex);

    try harness.runCase(allocator, .{
        .name = name_left,
        .unlocking_hex = "00020000",
        .locking_hex = locking_hex,
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });

    try harness.runCase(allocator, .{
        .name = name_right,
        .unlocking_hex = "02000000",
        .locking_hex = locking_hex,
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });
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

fn scriptHexForOps(allocator: std.mem.Allocator, ops: []const bsvz.script.opcode.Opcode) ![]u8 {
    var bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer bytes.deinit(allocator);
    for (ops) |op| try bytes.append(allocator, @intFromEnum(op));
    return scriptHexFromBytes(allocator, bytes.items);
}

fn appendPushData(
    bytes: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    data: []const u8,
) !void {
    if (data.len <= 75) {
        try bytes.append(allocator, @intCast(data.len));
    } else unreachable;
    try bytes.appendSlice(allocator, data);
}

fn scriptHexForPushesAndOps(
    allocator: std.mem.Allocator,
    pushes: []const []const u8,
    ops: []const u8,
) ![]u8 {
    var bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer bytes.deinit(allocator);

    for (pushes) |push| try appendPushData(&bytes, allocator, push);
    try bytes.appendSlice(allocator, ops);
    return scriptHexFromBytes(allocator, bytes.items);
}

fn scriptNumBytes(allocator: std.mem.Allocator, value: i64) ![]u8 {
    return bsvz.script.ScriptNum.encode(allocator, value);
}

fn repeatedHexByte(allocator: std.mem.Allocator, count: usize, byte: u8) ![]u8 {
    const bytes = try allocator.alloc(u8, count);
    @memset(bytes, byte);
    return bytes;
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
        .name = "bip66 example 1 with dersig",
        .unlocking_hex = "4730440220d7a0417c3f6d1a15094d1cf2a3378ca0503eb8a57630953a9e2987e21ddd0a6502207a6266d686c99090920249991d3d42065b6d43eb70187b219c0db82e4f94d1a201",
        .locking_hex = locking_hex,
        .flags = dersig_flags,
        .expected = .{ .err = error.InvalidSignatureEncoding },
    });

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

    try harness.runCase(allocator, .{
        .name = "bip66 example 6 without dersig",
        .unlocking_hex = "51",
        .locking_hex = locking_hex ++ "91",
        .flags = relaxed_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "bip66 example 6 with dersig",
        .unlocking_hex = "51",
        .locking_hex = locking_hex ++ "91",
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

    try harness.runCase(allocator, .{
        .name = "p2pk checksig too much r padding with dersig",
        .unlocking_hex = "47304402200060558477337b9022e70534f1fea71a318caf836812465a2509931c5e7c4987022078ec32bd50ac9e03a349ba953dfd9fe1c8d2dd8bdb1d38ddca844d3d5c78c11801",
        .locking_hex =
            "21"
            ++ "038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508"
            ++ "ac",
        .flags = dersig_flags,
        .expected = .{ .err = error.InvalidSignatureEncoding },
    });

    try harness.runCase(allocator, .{
        .name = "p2pk checksig too much s padding with dersig",
        .unlocking_hex = "48304502202de8c03fc525285c9c535631019a5f2af7c6454fa9eb392a3756a4917c420edd02210046130bf2baf7cfc065067c8b9e33a066d9c15edcea9feb0ca2d233e3597925b401",
        .locking_hex =
            "21"
            ++ "038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508"
            ++ "ac",
        .flags = dersig_flags,
        .expected = .{ .err = error.InvalidSignatureEncoding },
    });
}

test "go direct checksig rows: malformed dersig matrix" {
    const allocator = std.testing.allocator;
    const locking_hex = "00ac91";

    var dersig_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    dersig_flags.der_signatures = true;

    const cases = [_]struct {
        name: []const u8,
        unlocking_hex: []const u8,
    }{
        .{
            .name = "overly long signature is invalid under dersig",
            .unlocking_hex = "4a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        },
        .{
            .name = "missing s is invalid under dersig",
            .unlocking_hex = "24302202200000000000000000000000000000000000000000000000000000000000000000",
        },
        .{
            .name = "invalid s length is invalid under dersig",
            .unlocking_hex = "273024021077777777777777777777777777777777020a7777777777777777777777777777777701",
        },
        .{
            .name = "non-integer r is invalid under dersig",
            .unlocking_hex = "27302403107777777777777777777777777777777702107777777777777777777777777777777701",
        },
        .{
            .name = "non-integer s is invalid under dersig",
            .unlocking_hex = "27302402107777777777777777777777777777777703107777777777777777777777777777777701",
        },
        .{
            .name = "zero-length r is invalid under dersig",
            .unlocking_hex = "173014020002107777777777777777777777777777777701",
        },
        .{
            .name = "zero-length s is invalid under dersig",
            .unlocking_hex = "173014021077777777777777777777777777777777020001",
        },
        .{
            .name = "negative s is invalid under dersig",
            .unlocking_hex = "27302402107777777777777777777777777777777702108777777777777777777777777777777701",
        },
    };

    inline for (cases) |case| {
        try harness.runCase(allocator, .{
            .name = case.name,
            .unlocking_hex = case.unlocking_hex,
            .locking_hex = locking_hex,
            .flags = dersig_flags,
            .expected = .{ .err = error.InvalidSignatureEncoding },
        });
    }
}

test "go direct script rows: sighash policy gates" {
    const allocator = std.testing.allocator;

    const checksig_not_locking_hex =
        "21"
        ++ "02865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac0"
        ++ "ac91";

    var legacy_strict = bsvz.script.engine.ExecutionFlags.legacyReference();
    legacy_strict.strict_encoding = true;

    try harness.runCase(allocator, .{
        .name = "checksig not rejects illegal forkid under legacy strict policy",
        .unlocking_hex = "09300602010102010141",
        .locking_hex = checksig_not_locking_hex,
        .flags = legacy_strict,
        .expected = .{ .err = error.IllegalForkId },
    });

    var forkid_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();
    forkid_flags.der_signatures = true;

    try harness.runCase(allocator, .{
        .name = "checksig not accepts forkid under forkid policy",
        .unlocking_hex = "09300602010102010141",
        .locking_hex = checksig_not_locking_hex,
        .flags = forkid_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "checksig not rejects invalid sighash type under legacy strict policy",
        .unlocking_hex = "09300602010102010105",
        .locking_hex = checksig_not_locking_hex,
        .flags = legacy_strict,
        .expected = .{ .err = error.InvalidSigHashType },
    });

    try harness.runCase(allocator, .{
        .name = "p2pk rejects invalid forkid under legacy strict policy",
        .unlocking_hex = "4730440220368d68340dfbebf99d5ec87d77fba899763e466c0a7ab2fa0221fb868ab0f3ef0220266c1a52a8e5b7b597613b80cf53814d3925dfb6715dce712c8e7a25e63a044041",
        .locking_hex =
            "41"
            ++ "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
            ++ "ac",
        .flags = legacy_strict,
        .expected = .{ .err = error.IllegalForkId },
    });

    try harness.runCase(allocator, .{
        .name = "p2pkh rejects invalid sighash type under legacy strict policy",
        .unlocking_hex =
            "4730440220647a83507454f15f85f7e24de6e70c9d7b1d4020c71d0e53f4412425487e1dde022015737290670b4ab17b6783697a88ddd581c2d9c9efe26a59ac213076fc67f53021"
            ++ "41"
            ++ "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        .locking_hex =
            "76"
            ++ "a9"
            ++ "14"
            ++ "91b24bf9f5288532960ac687abb035127b1d28a5"
            ++ "88"
            ++ "ac",
        .flags = legacy_strict,
        .expected = .{ .err = error.InvalidSigHashType },
    });

    const checkmultisig_not_locking_hex =
        "51"
        ++ "21"
        ++ "02865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac0"
        ++ "51"
        ++ "ae91";

    try harness.runCase(allocator, .{
        .name = "checkmultisig not rejects illegal forkid under legacy strict policy",
        .unlocking_hex = "0009300602010102010141",
        .locking_hex = checkmultisig_not_locking_hex,
        .flags = legacy_strict,
        .expected = .{ .err = error.IllegalForkId },
    });

    try harness.runCase(allocator, .{
        .name = "checkmultisig not accepts forkid under forkid policy",
        .unlocking_hex = "0009300602010102010141",
        .locking_hex = checkmultisig_not_locking_hex,
        .flags = forkid_flags,
        .expected = .{ .success = true },
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

test "go direct checkmultisig rows: strict evaluation order" {
    const allocator = std.testing.allocator;

    var strict_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    strict_flags.strict_encoding = true;

    try harness.runCase(allocator, .{
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
        .flags = strict_flags,
        .expected = .{ .err = error.InvalidPublicKeyEncoding },
    });

    try harness.runCase(allocator, .{
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
        .flags = strict_flags,
        .expected = .{ .err = error.InvalidSignatureEncoding },
    });
}

test "go direct script rows: minimaldata push forms" {
    const allocator = std.testing.allocator;

    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.minimal_data = true;

    try harness.runCase(allocator, .{
        .name = "empty vector minimally represented by op_0",
        .unlocking_hex = "4c00",
        .locking_hex = "7551",
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });

    try harness.runCase(allocator, .{
        .name = "negative one minimally represented by op_1negate",
        .unlocking_hex = "0181",
        .locking_hex = "7551",
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });

    try harness.runCase(allocator, .{
        .name = "one minimally represented by op_1",
        .unlocking_hex = "0101",
        .locking_hex = "7551",
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });

    const direct_smallint_cases = [_]struct {
        name: []const u8,
        unlocking_hex: []const u8,
    }{
        .{ .name = "two minimally represented by op_2", .unlocking_hex = "0102" },
        .{ .name = "three minimally represented by op_3", .unlocking_hex = "0103" },
        .{ .name = "four minimally represented by op_4", .unlocking_hex = "0104" },
        .{ .name = "five minimally represented by op_5", .unlocking_hex = "0105" },
        .{ .name = "six minimally represented by op_6", .unlocking_hex = "0106" },
        .{ .name = "seven minimally represented by op_7", .unlocking_hex = "0107" },
        .{ .name = "eight minimally represented by op_8", .unlocking_hex = "0108" },
        .{ .name = "nine minimally represented by op_9", .unlocking_hex = "0109" },
        .{ .name = "ten minimally represented by op_10", .unlocking_hex = "010a" },
        .{ .name = "eleven minimally represented by op_11", .unlocking_hex = "010b" },
        .{ .name = "twelve minimally represented by op_12", .unlocking_hex = "010c" },
        .{ .name = "thirteen minimally represented by op_13", .unlocking_hex = "010d" },
        .{ .name = "fourteen minimally represented by op_14", .unlocking_hex = "010e" },
        .{ .name = "fifteen minimally represented by op_15", .unlocking_hex = "010f" },
        .{ .name = "sixteen minimally represented by op_16", .unlocking_hex = "0110" },
    };

    inline for (direct_smallint_cases) |case| {
        try harness.runCase(allocator, .{
            .name = case.name,
            .unlocking_hex = case.unlocking_hex,
            .locking_hex = "7551",
            .flags = flags,
            .expected = .{ .err = error.MinimalData },
        });
    }

    const push_72 = try std.mem.concat(allocator, u8, &[_][]const u8{
        "4c48",
        "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
    });
    defer allocator.free(push_72);

    try harness.runCase(allocator, .{
        .name = "pushdata1 of 72 bytes is non-minimal",
        .unlocking_hex = push_72,
        .locking_hex = "7551",
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });
}

test "go direct script rows: minimaldata numeric arguments" {
    const allocator = std.testing.allocator;

    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.minimal_data = true;

    const locking_not_drop_1 = try scriptHexFromBytes(allocator, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NOT),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_DROP),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_1),
    });
    defer allocator.free(locking_not_drop_1);

    try harness.runCase(allocator, .{
        .name = "numeric minimaldata rejects direct-pushed zero",
        .unlocking_hex = "0100",
        .locking_hex = locking_not_drop_1,
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });

    try harness.runCase(allocator, .{
        .name = "numeric minimaldata rejects negative zero",
        .unlocking_hex = "0180",
        .locking_hex = locking_not_drop_1,
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });

    try expectMinimalDataUnary(allocator, flags, .OP_1ADD, "1add rejects non-minimal operand");
    try expectMinimalDataUnary(allocator, flags, .OP_1SUB, "1sub rejects non-minimal operand");
    try expectMinimalDataUnary(allocator, flags, .OP_NEGATE, "negate rejects non-minimal operand");
    try expectMinimalDataUnary(allocator, flags, .OP_ABS, "abs rejects non-minimal operand");
    try expectMinimalDataUnary(allocator, flags, .OP_0NOTEQUAL, "0notequal rejects non-minimal operand");

    const locking_pick_drop = try scriptHexFromBytes(allocator, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_PICK),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_DROP),
    });
    defer allocator.free(locking_pick_drop);

    try harness.runCase(allocator, .{
        .name = "pick rejects non-minimal numeric index",
        .unlocking_hex = "51020000",
        .locking_hex = locking_pick_drop,
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });

    const locking_roll_drop_1 = try scriptHexFromBytes(allocator, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_ROLL),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_DROP),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_1),
    });
    defer allocator.free(locking_roll_drop_1);

    try harness.runCase(allocator, .{
        .name = "roll rejects non-minimal numeric index",
        .unlocking_hex = "51020000",
        .locking_hex = locking_roll_drop_1,
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });

    try expectMinimalDataBinary(
        allocator,
        flags,
        .OP_ADD,
        "add rejects non-minimal left operand",
        "add rejects non-minimal right operand",
    );
    try expectMinimalDataBinary(
        allocator,
        flags,
        .OP_SUB,
        "sub rejects non-minimal left operand",
        "sub rejects non-minimal right operand",
    );
    try expectMinimalDataBinary(
        allocator,
        flags,
        .OP_BOOLAND,
        "booland rejects non-minimal left operand",
        "booland rejects non-minimal right operand",
    );
    try expectMinimalDataBinary(
        allocator,
        flags,
        .OP_BOOLOR,
        "boolor rejects non-minimal left operand",
        "boolor rejects non-minimal right operand",
    );
    try expectMinimalDataBinary(
        allocator,
        flags,
        .OP_NUMEQUAL,
        "numequal rejects non-minimal left operand",
        "numequal rejects non-minimal right operand",
    );

    const locking_numequalverify_1 = try scriptHexFromBytes(allocator, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NUMEQUALVERIFY),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_1),
    });
    defer allocator.free(locking_numequalverify_1);

    try harness.runCase(allocator, .{
        .name = "numequalverify rejects non-minimal operand",
        .unlocking_hex = "00020000",
        .locking_hex = locking_numequalverify_1,
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });

    try expectMinimalDataBinary(
        allocator,
        flags,
        .OP_NUMNOTEQUAL,
        "numnotequal rejects non-minimal left operand",
        "numnotequal rejects non-minimal right operand",
    );
    try expectMinimalDataBinary(
        allocator,
        flags,
        .OP_LESSTHAN,
        "lessthan rejects non-minimal left operand",
        "lessthan rejects non-minimal right operand",
    );
    try expectMinimalDataBinary(
        allocator,
        flags,
        .OP_GREATERTHAN,
        "greaterthan rejects non-minimal left operand",
        "greaterthan rejects non-minimal right operand",
    );
    try expectMinimalDataBinary(
        allocator,
        flags,
        .OP_LESSTHANOREQUAL,
        "lessthanorequal rejects non-minimal left operand",
        "lessthanorequal rejects non-minimal right operand",
    );
    try expectMinimalDataBinary(
        allocator,
        flags,
        .OP_GREATERTHANOREQUAL,
        "greaterthanorequal rejects non-minimal left operand",
        "greaterthanorequal rejects non-minimal right operand",
    );
    try expectMinimalDataBinary(
        allocator,
        flags,
        .OP_MIN,
        "min rejects non-minimal left operand",
        "min rejects non-minimal right operand",
    );
    try expectMinimalDataBinary(
        allocator,
        flags,
        .OP_MAX,
        "max rejects non-minimal left operand",
        "max rejects non-minimal right operand",
    );

    const locking_within_drop_1 = try numericOpDrop1Hex(allocator, .OP_WITHIN);
    defer allocator.free(locking_within_drop_1);

    try harness.runCase(allocator, .{
        .name = "within rejects non-minimal operand",
        .unlocking_hex = "0200000000",
        .locking_hex = locking_within_drop_1,
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });

    try harness.runCase(allocator, .{
        .name = "within rejects non-minimal middle operand",
        .unlocking_hex = "0002000000",
        .locking_hex = locking_within_drop_1,
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });

    try harness.runCase(allocator, .{
        .name = "within rejects non-minimal top operand",
        .unlocking_hex = "0000020000",
        .locking_hex = locking_within_drop_1,
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });
}

test "go direct script rows: minimaldata multisig counts" {
    const allocator = std.testing.allocator;

    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.minimal_data = true;

    const checkmultisig_drop_1 = try scriptHexForOps(allocator, &[_]bsvz.script.opcode.Opcode{
        .OP_CHECKMULTISIG,
        .OP_DROP,
        .OP_1,
    });
    defer allocator.free(checkmultisig_drop_1);

    try harness.runCase(allocator, .{
        .name = "checkmultisig rejects non-minimal key count",
        .unlocking_hex = "0000020000",
        .locking_hex = checkmultisig_drop_1,
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });

    try harness.runCase(allocator, .{
        .name = "checkmultisig rejects non-minimal signature count",
        .unlocking_hex = "0002000000",
        .locking_hex = checkmultisig_drop_1,
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });

    try harness.runCase(allocator, .{
        .name = "checkmultisig rejects non-minimal signature count with one pubkey",
        .unlocking_hex = "000200000051",
        .locking_hex = checkmultisig_drop_1,
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });

    const checkmultisigverify_1 = try scriptHexForOps(allocator, &[_]bsvz.script.opcode.Opcode{
        .OP_CHECKMULTISIGVERIFY,
        .OP_1,
    });
    defer allocator.free(checkmultisigverify_1);

    try harness.runCase(allocator, .{
        .name = "checkmultisigverify rejects non-minimal key count",
        .unlocking_hex = "0000020000",
        .locking_hex = checkmultisigverify_1,
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });

    try harness.runCase(allocator, .{
        .name = "checkmultisigverify rejects non-minimal signature count",
        .unlocking_hex = "0002000000",
        .locking_hex = checkmultisigverify_1,
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });
}

test "go direct script-pair rows: control flow cannot span scripts" {
    const allocator = std.testing.allocator;
    const flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    try harness.runCase(allocator, .{
        .name = "if endif cannot span unlocking and locking scripts",
        .unlocking_hex = "5163",
        .locking_hex = "5168",
        .flags = flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });

    try harness.runCase(allocator, .{
        .name = "opening conditional in unlocking script remains unbalanced",
        .unlocking_hex = "51630068",
        .locking_hex = "5168",
        .flags = flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });

    try harness.runCase(allocator, .{
        .name = "else branch cannot begin in unlocking script and end in locking script",
        .unlocking_hex = "51670068",
        .locking_hex = "51",
        .flags = flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });

    try harness.runCase(allocator, .{
        .name = "notif branch cannot remain open across script boundary",
        .unlocking_hex = "0064",
        .locking_hex = "017b",
        .flags = flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });
}

test "go direct script-pair rows: op_return seam behavior" {
    const allocator = std.testing.allocator;
    const legacy_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    const post_genesis_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();

    try harness.runCase(allocator, .{
        .name = "post-genesis if return bad opcode endif is still ok when return is taken",
        .unlocking_hex = "51",
        .locking_hex = "63556aba68",
        .flags = post_genesis_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "legacy if return endif bad opcode tail is still bad opcode when branch is not taken",
        .unlocking_hex = "00",
        .locking_hex = "636a68ba",
        .flags = legacy_flags,
        .expected = .{ .err = error.UnknownOpcode },
    });

    try harness.runCase(allocator, .{
        .name = "post-genesis if return endif bad opcode tail is still bad opcode when branch is not taken",
        .unlocking_hex = "00",
        .locking_hex = "636a68ba",
        .flags = post_genesis_flags,
        .expected = .{ .err = error.UnknownOpcode },
    });

    try harness.runCase(allocator, .{
        .name = "pre-genesis taken if return endif followed by taken return still errors",
        .unlocking_hex = "51",
        .locking_hex = "63556a68556aba",
        .flags = legacy_flags,
        .expected = .{ .err = error.ReturnEncountered },
    });

    try harness.runCase(allocator, .{
        .name = "post-genesis taken if return endif followed by taken return is still ok",
        .unlocking_hex = "51",
        .locking_hex = "63556a68556aba",
        .flags = post_genesis_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "legacy if return bad opcode endif tail is ok when branch is not taken",
        .unlocking_hex = "00",
        .locking_hex = "636a68ba55",
        .flags = legacy_flags,
        .expected = .{ .err = error.UnknownOpcode },
    });

    try harness.runCase(allocator, .{
        .name = "legacy taken if return bad opcode endif tail still errors",
        .unlocking_hex = "51",
        .locking_hex = "63556aba6855",
        .flags = legacy_flags,
        .expected = .{ .err = error.ReturnEncountered },
    });

    try harness.runCase(allocator, .{
        .name = "pre-genesis unlocking op_return is still an op_return error",
        .unlocking_hex = "6a",
        .locking_hex = "51",
        .flags = legacy_flags,
        .expected = .{ .err = error.ReturnEncountered },
    });

    try harness.runCase(allocator, .{
        .name = "post-genesis unlocking op_return can still satisfy a simple lock",
        .unlocking_hex = "6a",
        .locking_hex = "51",
        .flags = post_genesis_flags,
        .expected = .{ .success = true },
    });

    var push_only_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();
    push_only_flags.sig_push_only = true;

    try harness.runCase(allocator, .{
        .name = "sigpushonly rejects op_return in unlocking script after genesis",
        .unlocking_hex = "6a",
        .locking_hex = "51",
        .flags = push_only_flags,
        .expected = .{ .err = error.SigPushOnly },
    });

    try harness.runCase(allocator, .{
        .name = "pre-genesis locking op_return still errors with true unlocking stack top",
        .unlocking_hex = "51",
        .locking_hex = "6a",
        .flags = legacy_flags,
        .expected = .{ .err = error.ReturnEncountered },
    });

    try harness.runCase(allocator, .{
        .name = "pre-genesis locking op_return still errors with false unlocking stack top",
        .unlocking_hex = "00",
        .locking_hex = "6a",
        .flags = legacy_flags,
        .expected = .{ .err = error.ReturnEncountered },
    });

    try harness.runCase(allocator, .{
        .name = "post-genesis locking op_return preserves a true unlocking stack top",
        .unlocking_hex = "51",
        .locking_hex = "6a",
        .flags = post_genesis_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "post-genesis locking op_return preserves a false unlocking stack top",
        .unlocking_hex = "00",
        .locking_hex = "6a",
        .flags = post_genesis_flags,
        .expected = .{ .success = false },
    });

    try harness.runCase(allocator, .{
        .name = "pre-genesis return only works if not executed across the script seam",
        .unlocking_hex = "00",
        .locking_hex = "636a6851",
        .flags = legacy_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "post-genesis return only works if not executed across the script seam",
        .unlocking_hex = "00",
        .locking_hex = "636a6851",
        .flags = post_genesis_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "pre-genesis taken branch return still errors across the script seam",
        .unlocking_hex = "51",
        .locking_hex = "76636a68",
        .flags = legacy_flags,
        .expected = .{ .err = error.ReturnEncountered },
    });

    try harness.runCase(allocator, .{
        .name = "post-genesis taken branch return keeps the true stack top across the script seam",
        .unlocking_hex = "51",
        .locking_hex = "76636a68",
        .flags = post_genesis_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "pre-genesis locking return if still errors",
        .unlocking_hex = "51",
        .locking_hex = "6a63",
        .flags = legacy_flags,
        .expected = .{ .err = error.ReturnEncountered },
    });

    try harness.runCase(allocator, .{
        .name = "post-genesis locking return if short-circuits to success",
        .unlocking_hex = "51",
        .locking_hex = "6a63",
        .flags = post_genesis_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "pre-genesis locking return bad opcode tail still errors",
        .unlocking_hex = "51",
        .locking_hex = "6aba",
        .flags = legacy_flags,
        .expected = .{ .err = error.ReturnEncountered },
    });

    try harness.runCase(allocator, .{
        .name = "post-genesis locking return bad opcode tail still succeeds",
        .unlocking_hex = "51",
        .locking_hex = "6aba",
        .flags = post_genesis_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "if return without endif stays unbalanced when branch is not taken",
        .unlocking_hex = "00",
        .locking_hex = "636a",
        .flags = legacy_flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });

    try harness.runCase(allocator, .{
        .name = "if return without endif stays unbalanced after genesis when branch is not taken",
        .unlocking_hex = "00",
        .locking_hex = "636a",
        .flags = post_genesis_flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });

    try harness.runCase(allocator, .{
        .name = "pre-genesis taken if return still errors before endif",
        .unlocking_hex = "51",
        .locking_hex = "63556a",
        .flags = legacy_flags,
        .expected = .{ .err = error.ReturnEncountered },
    });

    try harness.runCase(allocator, .{
        .name = "post-genesis taken if return remains unbalanced without endif",
        .unlocking_hex = "51",
        .locking_hex = "63556a",
        .flags = post_genesis_flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });

    try harness.runCase(allocator, .{
        .name = "if return endif tail succeeds when branch is not taken",
        .unlocking_hex = "00",
        .locking_hex = "636a6855",
        .flags = legacy_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "if return endif tail succeeds after genesis when branch is not taken",
        .unlocking_hex = "00",
        .locking_hex = "636a6855",
        .flags = post_genesis_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "if return bad opcode tail without endif stays unbalanced when branch is not taken",
        .unlocking_hex = "00",
        .locking_hex = "636aba",
        .flags = legacy_flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });

    try harness.runCase(allocator, .{
        .name = "if return bad opcode tail without endif stays unbalanced after genesis when branch is not taken",
        .unlocking_hex = "00",
        .locking_hex = "636aba",
        .flags = post_genesis_flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });

    try harness.runCase(allocator, .{
        .name = "pre-genesis taken if return bad opcode tail still errors",
        .unlocking_hex = "51",
        .locking_hex = "63556aba",
        .flags = legacy_flags,
        .expected = .{ .err = error.ReturnEncountered },
    });

    try harness.runCase(allocator, .{
        .name = "post-genesis taken if return bad opcode tail remains unbalanced",
        .unlocking_hex = "51",
        .locking_hex = "63556aba",
        .flags = post_genesis_flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });

    try harness.runCase(allocator, .{
        .name = "if return bad opcode endif tail succeeds when branch is not taken",
        .unlocking_hex = "00",
        .locking_hex = "636aba6855",
        .flags = legacy_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "if return bad opcode endif tail succeeds after genesis when branch is not taken",
        .unlocking_hex = "00",
        .locking_hex = "636aba6855",
        .flags = post_genesis_flags,
        .expected = .{ .success = true },
    });
}

test "go direct script rows: legacy versus post-genesis multiple else" {
    const allocator = std.testing.allocator;
    const legacy_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    const post_genesis_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();

    try harness.runCase(allocator, .{
        .name = "legacy multiple else inverts execution when if branch is false",
        .unlocking_hex = "00",
        .locking_hex = "63006751670068",
        .flags = legacy_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "post-genesis multiple else is unbalanced when if branch is false",
        .unlocking_hex = "00",
        .locking_hex = "63006751670068",
        .flags = post_genesis_flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });

    try harness.runCase(allocator, .{
        .name = "legacy multiple else inverts execution when if branch is true",
        .unlocking_hex = "51",
        .locking_hex = "635167006768",
        .flags = legacy_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "post-genesis multiple else is unbalanced when if branch is true",
        .unlocking_hex = "51",
        .locking_hex = "635167006768",
        .flags = post_genesis_flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });

    try harness.runCase(allocator, .{
        .name = "legacy multiple else with empty first branch still reaches final true branch",
        .unlocking_hex = "51",
        .locking_hex = "636700675168",
        .flags = legacy_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "post-genesis multiple else with empty first branch is unbalanced",
        .unlocking_hex = "51",
        .locking_hex = "636700675168",
        .flags = post_genesis_flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });
}

test "go direct script rows: nested else else legacy versus post-genesis" {
    const allocator = std.testing.allocator;
    const legacy_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    const post_genesis_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();

    try harness.runCase(allocator, .{
        .name = "legacy nested else else succeeds for outer false path",
        .unlocking_hex = "00",
        .locking_hex = "6351636a676a676a6867516351676a675168676a68935287",
        .flags = legacy_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "post-genesis nested else else is unbalanced for outer false path",
        .unlocking_hex = "00",
        .locking_hex = "6351636a676a676a6867516351676a675168676a68935287",
        .flags = post_genesis_flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });

    try harness.runCase(allocator, .{
        .name = "legacy nested else else succeeds for outer true notif path",
        .unlocking_hex = "51",
        .locking_hex = "6400646a676a676a6867006451676a675168676a68935287",
        .flags = legacy_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "post-genesis nested else else is unbalanced for outer true notif path",
        .unlocking_hex = "51",
        .locking_hex = "6400646a676a676a6867006451676a675168676a68935287",
        .flags = post_genesis_flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });
}

test "go direct script rows: op_return in different branches" {
    const allocator = std.testing.allocator;
    const legacy_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    const post_genesis_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();

    try harness.runCase(allocator, .{
        .name = "legacy branch-selected op_return still errors",
        .unlocking_hex = "00",
        .locking_hex = "636a05646174613167516a05646174613268",
        .flags = legacy_flags,
        .expected = .{ .err = error.ReturnEncountered },
    });

    try harness.runCase(allocator, .{
        .name = "post-genesis branch-selected op_return keeps success when else branch pushes one first",
        .unlocking_hex = "00",
        .locking_hex = "636a05646174613167516a05646174613268",
        .flags = post_genesis_flags,
        .expected = .{ .success = true },
    });
}

test "go direct script-pair rows: stack and conditional state do not cross the seam" {
    const allocator = std.testing.allocator;
    const legacy_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    const post_genesis_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();

    try harness.runCase(allocator, .{
        .name = "altstack is not shared between unlocking and locking scripts",
        .unlocking_hex = "516b",
        .locking_hex = "6c51",
        .flags = legacy_flags,
        .expected = .{ .err = error.AltStackUnderflow },
    });

    try harness.runCase(allocator, .{
        .name = "if endif cannot span script pair even with return in locking script pre-genesis",
        .unlocking_hex = "0063",
        .locking_hex = "6a6851",
        .flags = legacy_flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });

    try harness.runCase(allocator, .{
        .name = "if endif cannot span script pair even with return in locking script post-genesis",
        .unlocking_hex = "0063",
        .locking_hex = "6a6851",
        .flags = post_genesis_flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });

    try harness.runCase(allocator, .{
        .name = "skipped if return endif tail still succeeds after genesis",
        .unlocking_hex = "00",
        .locking_hex = "63006a6851",
        .flags = post_genesis_flags,
        .expected = .{ .success = true },
    });
}

test "go direct script rows: executed and skipped disabled opcode precedence" {
    const allocator = std.testing.allocator;
    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.strict_encoding = true;

    try harness.runCase(allocator, .{
        .name = "executed vernotif remains a bad opcode",
        .unlocking_hex = "51",
        .locking_hex = "6366675168",
        .flags = flags,
        .expected = .{ .err = error.UnknownOpcode },
    });

    var post_genesis_flags = flags;
    post_genesis_flags.utxo_after_genesis = true;

    try harness.runCase(allocator, .{
        .name = "multiple else beats later vernotif after genesis",
        .unlocking_hex = "51",
        .locking_hex = "636751676668",
        .flags = post_genesis_flags,
        .expected = .{ .err = error.UnbalancedConditionals },
    });

    try harness.runCase(allocator, .{
        .name = "skipped disabled opcode in untaken branch is still ok",
        .unlocking_hex = "00",
        .locking_hex = "63ec675168",
        .flags = flags,
        .expected = .{ .success = true },
    });
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

test "go direct script rows: minimaldata not parity" {
    const allocator = std.testing.allocator;
    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.minimal_data = true;

    try harness.runCase(allocator, .{
        .name = "not rejects non-minimally encoded operand",
        .unlocking_hex = "03ff7f00",
        .locking_hex = "917551",
        .flags = flags,
        .expected = .{ .err = error.MinimalData },
    });
}

test "go direct script rows: pick parity" {
    const allocator = std.testing.allocator;

    try runRows(allocator, bsvz.script.engine.ExecutionFlags.legacyReference(), &[_]GoRow{
        .{ .row = 611, .name = "pick with minimally encoded index succeeds", .unlocking_hex = "51020000", .locking_hex = "7975", .expected = .{ .success = true } },
    });

    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.minimal_data = true;

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 1262, .name = "pick rejects non-minimally encoded index under minimaldata", .unlocking_hex = "51020000", .locking_hex = "7975", .expected = .{ .err = error.MinimalData } },
    });
}

test "go direct script rows: roll parity" {
    const allocator = std.testing.allocator;

    try runRows(allocator, bsvz.script.engine.ExecutionFlags.legacyReference(), &[_]GoRow{
        .{ .row = 612, .name = "roll with minimally encoded index succeeds", .unlocking_hex = "51020000", .locking_hex = "7a7551", .expected = .{ .success = true } },
    });

    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.minimal_data = true;

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 1263, .name = "roll rejects non-minimally encoded index under minimaldata", .unlocking_hex = "51020000", .locking_hex = "7a7551", .expected = .{ .err = error.MinimalData } },
    });
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

test "go direct script rows: size parity" {
    const allocator = std.testing.allocator;
    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.strict_encoding = true;

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

test "go direct script rows: skipped disabled opcode exact row" {
    const allocator = std.testing.allocator;
    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.strict_encoding = true;

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 353, .name = "if disabled opcode in untaken branch remains ok", .unlocking_hex = "00", .locking_hex = "63ec675168", .expected = .{ .success = true } },
    });

    try harness.runCase(allocator, .{
        .name = "if disabled 2div in untaken branch remains ok after genesis",
        .unlocking_hex = "5200",
        .locking_hex = "639668",
        .flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv(),
        .expected = .{ .success = true },
    });
}

test "go direct script rows: small integer opcode push sanity" {
    const allocator = std.testing.allocator;

    try runRows(allocator, bsvz.script.engine.ExecutionFlags.legacyReference(), &[_]GoRow{
        .{ .row = 552, .name = "op_10 pushes byte 0x0a", .unlocking_hex = "010a", .locking_hex = "5a87", .expected = .{ .success = true } },
    });
}

test "go direct script rows: minimaldata ignored in untaken branches" {
    const allocator = std.testing.allocator;
    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.minimal_data = true;

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 570, .name = "non-minimal pusdata1 is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "634c006851", .expected = .{ .success = true } },
        .{ .row = 571, .name = "non-minimal pusdata2 is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "634d00006851", .expected = .{ .success = true } },
        .{ .row = 572, .name = "non-minimal pusdata4 is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "634e000000006851", .expected = .{ .success = true } },
        .{ .row = 573, .name = "1negate-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "6301816851", .expected = .{ .success = true } },
        .{ .row = 574, .name = "op_1-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "6301016851", .expected = .{ .success = true } },
        .{ .row = 575, .name = "op_2-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "6301026851", .expected = .{ .success = true } },
        .{ .row = 576, .name = "op_3-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "6301036851", .expected = .{ .success = true } },
        .{ .row = 577, .name = "op_4-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "6301046851", .expected = .{ .success = true } },
        .{ .row = 578, .name = "op_5-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "6301056851", .expected = .{ .success = true } },
        .{ .row = 579, .name = "op_6-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "6301066851", .expected = .{ .success = true } },
        .{ .row = 580, .name = "op_7-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "6301076851", .expected = .{ .success = true } },
        .{ .row = 581, .name = "op_8-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "6301086851", .expected = .{ .success = true } },
        .{ .row = 582, .name = "op_9-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "6301096851", .expected = .{ .success = true } },
        .{ .row = 583, .name = "op_10-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "63010a6851", .expected = .{ .success = true } },
        .{ .row = 584, .name = "op_11-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "63010b6851", .expected = .{ .success = true } },
        .{ .row = 585, .name = "op_12-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "63010c6851", .expected = .{ .success = true } },
        .{ .row = 586, .name = "op_13-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "63010d6851", .expected = .{ .success = true } },
        .{ .row = 587, .name = "op_14-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "63010e6851", .expected = .{ .success = true } },
        .{ .row = 588, .name = "op_15-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "63010f6851", .expected = .{ .success = true } },
        .{ .row = 589, .name = "op_16-equivalent push is ignored in untaken branch", .unlocking_hex = "00", .locking_hex = "6301106851", .expected = .{ .success = true } },
    });
}

test "go direct script rows: minimaldata non-minimal unlocking pushes can still satisfy a simple lock" {
    const allocator = std.testing.allocator;
    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.minimal_data = true;

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 591, .name = "non-minimal zero push still satisfies simple lock", .unlocking_hex = "0100", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 592, .name = "negative zero push still satisfies simple lock", .unlocking_hex = "0180", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 593, .name = "non-minimal minus one push still satisfies simple lock", .unlocking_hex = "020180", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 594, .name = "non-minimal one push still satisfies simple lock", .unlocking_hex = "020100", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 595, .name = "non-minimal two push still satisfies simple lock", .unlocking_hex = "020200", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 596, .name = "non-minimal three push still satisfies simple lock", .unlocking_hex = "020300", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 597, .name = "non-minimal four push still satisfies simple lock", .unlocking_hex = "020400", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 598, .name = "non-minimal five push still satisfies simple lock", .unlocking_hex = "020500", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 599, .name = "non-minimal six push still satisfies simple lock", .unlocking_hex = "020600", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 600, .name = "non-minimal seven push still satisfies simple lock", .unlocking_hex = "020700", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 601, .name = "non-minimal eight push still satisfies simple lock", .unlocking_hex = "020800", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 602, .name = "non-minimal nine push still satisfies simple lock", .unlocking_hex = "020900", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 603, .name = "non-minimal ten push still satisfies simple lock", .unlocking_hex = "020a00", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 604, .name = "non-minimal eleven push still satisfies simple lock", .unlocking_hex = "020b00", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 605, .name = "non-minimal twelve push still satisfies simple lock", .unlocking_hex = "020c00", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 606, .name = "non-minimal thirteen push still satisfies simple lock", .unlocking_hex = "020d00", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 607, .name = "non-minimal fourteen push still satisfies simple lock", .unlocking_hex = "020e00", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 608, .name = "non-minimal fifteen push still satisfies simple lock", .unlocking_hex = "020f00", .locking_hex = "51", .expected = .{ .success = true } },
        .{ .row = 609, .name = "non-minimal sixteen push still satisfies simple lock", .unlocking_hex = "021000", .locking_hex = "51", .expected = .{ .success = true } },
    });
}

test "go direct script rows: minimaldata push form boundaries" {
    const allocator = std.testing.allocator;
    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.minimal_data = true;

    const push72 = try repeatedHexByte(allocator, 72, 0x11);
    defer allocator.free(push72);
    const push255 = try repeatedHexByte(allocator, 255, 0x11);
    defer allocator.free(push255);
    const push256 = try repeatedHexByte(allocator, 256, 0x11);
    defer allocator.free(push256);

    var row1245_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer row1245_bytes.deinit(allocator);
    try row1245_bytes.append(allocator, @intFromEnum(bsvz.script.opcode.Opcode.OP_PUSHDATA1));
    try row1245_bytes.append(allocator, 0x48);
    try row1245_bytes.appendSlice(allocator, push72);
    try row1245_bytes.appendSlice(allocator, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_DROP),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_1),
    });
    const row1245_hex = try scriptHexFromBytes(allocator, row1245_bytes.items);
    defer allocator.free(row1245_hex);

    var row1246_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer row1246_bytes.deinit(allocator);
    try row1246_bytes.append(allocator, @intFromEnum(bsvz.script.opcode.Opcode.OP_PUSHDATA2));
    try row1246_bytes.appendSlice(allocator, &[_]u8{ 0xff, 0x00 });
    try row1246_bytes.appendSlice(allocator, push255);
    try row1246_bytes.appendSlice(allocator, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_DROP),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_1),
    });
    const row1246_hex = try scriptHexFromBytes(allocator, row1246_bytes.items);
    defer allocator.free(row1246_hex);

    var row1247_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer row1247_bytes.deinit(allocator);
    try row1247_bytes.append(allocator, @intFromEnum(bsvz.script.opcode.Opcode.OP_PUSHDATA4));
    try row1247_bytes.appendSlice(allocator, &[_]u8{ 0x00, 0x01, 0x00, 0x00 });
    try row1247_bytes.appendSlice(allocator, push256);
    try row1247_bytes.appendSlice(allocator, &[_]u8{
        @intFromEnum(bsvz.script.opcode.Opcode.OP_DROP),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_1),
    });
    const row1247_hex = try scriptHexFromBytes(allocator, row1247_bytes.items);
    defer allocator.free(row1247_hex);

    try runRows(allocator, flags, &[_]GoRow{
        .{ .row = 1227, .name = "minimaldata rejects pusdata1 empty vector", .unlocking_hex = "", .locking_hex = "4c007551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1228, .name = "minimaldata rejects explicit -1 push", .unlocking_hex = "", .locking_hex = "01817551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1229, .name = "minimaldata rejects explicit 1 push", .unlocking_hex = "", .locking_hex = "01017551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1238, .name = "minimaldata rejects explicit 10 push", .unlocking_hex = "", .locking_hex = "010a7551", .expected = .{ .err = error.MinimalData } },
        .{ .row = 1245, .name = "minimaldata rejects pusdata1 of 72 bytes", .unlocking_hex = "", .locking_hex = row1245_hex, .expected = .{ .err = error.MinimalData } },
        .{ .row = 1246, .name = "minimaldata rejects pusdata2 of 255 bytes", .unlocking_hex = "", .locking_hex = row1246_hex, .expected = .{ .err = error.MinimalData } },
        .{ .row = 1247, .name = "minimaldata rejects pusdata4 of 256 bytes", .unlocking_hex = "", .locking_hex = row1247_hex, .expected = .{ .err = error.MinimalData } },
    });
}

test "go direct script rows: boolean and minmaxwithin parity" {
    const allocator = std.testing.allocator;

    try runRows(allocator, bsvz.script.engine.ExecutionFlags.legacyReference(), &[_]GoRow{
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
