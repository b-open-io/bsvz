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
