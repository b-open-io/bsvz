const std = @import("std");
const bsvz = @import("bsvz");
const harness = @import("support/go_script_harness.zig");

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

test "go strict sigcheck rows: stack and count preconditions" {
    const allocator = std.testing.allocator;
    const flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    try runRows(allocator, flags, &[_]GoRow{
        .{
            .row = 1206,
            .name = "row 1206 checksig not errors when there are no stack items",
            .unlocking_hex = "",
            .locking_hex = "ac91",
            .expected = .{ .err = error.StackUnderflow },
        },
        .{
            .row = 1207,
            .name = "row 1207 checksig not errors when there is only one stack item",
            .unlocking_hex = "00",
            .locking_hex = "ac91",
            .expected = .{ .err = error.StackUnderflow },
        },
        .{
            .name = "row 1208 checkmultisig not errors when there are no stack items",
            .unlocking_hex = "",
            .locking_hex = "ae91",
            .expected = .{ .err = error.StackUnderflow },
        },
        .{
            .row = 1209,
            .name = "row 1209 checkmultisig not errors on a negative pubkey count",
            .unlocking_hex = "",
            .locking_hex = "4fae91",
            .expected = .{ .err = error.InvalidStackIndex },
        },
        .{
            .name = "row 1210 checkmultisig not errors when pubkeys are missing",
            .unlocking_hex = "",
            .locking_hex = "51ae91",
            .expected = .{ .err = error.StackUnderflow },
        },
        .{
            .row = 1211,
            .name = "row 1211 checkmultisig not errors on a negative signature count",
            .unlocking_hex = "",
            .locking_hex = "4f00ae91",
            .expected = .{ .err = error.InvalidStackIndex },
        },
        .{
            .name = "row 1212 checkmultisig not errors when signatures are missing",
            .unlocking_hex = "",
            .locking_hex = "5103706b3151ae91",
            .expected = .{ .err = error.StackUnderflow },
        },
        .{
            .row = 1218,
            .name = "row 1218 checkmultisig rejects pubkey counts above twenty",
            .unlocking_hex = "00005152535455565758595a5b5c5d5e5f6001110112011301140115",
            .locking_hex = "0115ae51",
            .expected = .{ .err = error.InvalidMultisigKeyCount },
        },
        .{
            .row = 1220,
            .name = "row 1220 checkmultisig rejects more signatures than pubkeys",
            .unlocking_hex = "00037369675100",
            .locking_hex = "ae51",
            .expected = .{ .err = error.InvalidMultisigSignatureCount },
        },
    });
}

test "go strict sigcheck rows: signature policy gates" {
    const allocator = std.testing.allocator;

    var low_s_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    low_s_flags.low_s = true;

    try harness.runCase(allocator, .{
        .name = "row 2020 p2pk with high s under low_s",
        .unlocking_hex = "48304502203e4516da7253cf068effec6b95c41221c0cf3a8e6ccb8cbf1725b562e9afde2c022100ab1e3da73d67e32045a20e0b999e049978ea8d6ee5480d485fcf2ce0d03b2ef001",
        .locking_hex = "2103363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640ac",
        .flags = low_s_flags,
        .expected = .{ .err = error.HighS },
    });

    try harness.runCase(allocator, .{
        .name = "row 1375 p2pk with high s",
        .unlocking_hex = "48304502203e4516da7253cf068effec6b95c41221c0cf3a8e6ccb8cbf1725b562e9afde2c022100ab1e3da73d67e32045a20e0b999e049978ea8d6ee5480d485fcf2ce0d03b2ef001",
        .locking_hex = "2103363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640ac",
        .flags = low_s_flags,
        .expected = .{ .err = error.HighS },
    });

    var dersig_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    dersig_flags.der_signatures = true;

    try harness.runCase(allocator, .{
        .name = "row 1373 p2pk with multi byte hashtype under dersig",
        .unlocking_hex = "48304402203e4516da7253cf068effec6b95c41221c0cf3a8e6ccb8cbf1725b562e9afde2c022054e1c258c2981cdfba5df1f46661fb6541c44f77ca0092f3600331abfffb12510101",
        .locking_hex = "2103363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640ac",
        .flags = dersig_flags,
        .expected = .{ .err = error.InvalidSignatureEncoding },
    });
}

test "go direct checksig rows: bip66 example 4 nullfail matrix" {
    const allocator = std.testing.allocator;
    const locking_hex =
        "21" ++ "038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508" ++ "ac91";

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
        "21" ++ "038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508" ++ "ac";

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
        .locking_hex = "21" ++ "03363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640" ++ "ac91",
        .flags = relaxed_flags,
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "p2pk checksig not bad sig with too much r padding with dersig",
        .unlocking_hex = "4730440220005ece1335e7f757a1a1f476a7fb5bd90964e8a022489f890614a04acfb734c002206c12b8294a6513c7710e8c82d3c23d75cdbfe83200eb7efb495701958501a5d601",
        .locking_hex = "21" ++ "03363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640" ++ "ac91",
        .flags = dersig_flags,
        .expected = .{ .err = error.InvalidSignatureEncoding },
    });

    try harness.runCase(allocator, .{
        .name = "p2pk checksig too little r padding with dersig",
        .unlocking_hex = "4730440220d7a0417c3f6d1a15094d1cf2a3378ca0503eb8a57630953a9e2987e21ddd0a6502207a6266d686c99090920249991d3d42065b6d43eb70187b219c0db82e4f94d1a201",
        .locking_hex = "21" ++ "038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508" ++ "ac",
        .flags = dersig_flags,
        .expected = .{ .err = error.InvalidSignatureEncoding },
    });

    try harness.runCase(allocator, .{
        .name = "p2pk checksig too much r padding with dersig",
        .unlocking_hex = "47304402200060558477337b9022e70534f1fea71a318caf836812465a2509931c5e7c4987022078ec32bd50ac9e03a349ba953dfd9fe1c8d2dd8bdb1d38ddca844d3d5c78c11801",
        .locking_hex = "21" ++ "038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508" ++ "ac",
        .flags = dersig_flags,
        .expected = .{ .err = error.InvalidSignatureEncoding },
    });

    try harness.runCase(allocator, .{
        .name = "p2pk checksig too much s padding with dersig",
        .unlocking_hex = "48304502202de8c03fc525285c9c535631019a5f2af7c6454fa9eb392a3756a4917c420edd02210046130bf2baf7cfc065067c8b9e33a066d9c15edcea9feb0ca2d233e3597925b401",
        .locking_hex = "21" ++ "038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508" ++ "ac",
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

test "go direct checksig rows: exact malformed dersig checksig-not rows" {
    const allocator = std.testing.allocator;
    const locking_hex = "00ac91";

    var dersig_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    dersig_flags.der_signatures = true;

    try runRows(allocator, dersig_flags, &[_]GoRow{
        .{ .row = 1311, .name = "row 1311 overly long signature is invalid under dersig", .unlocking_hex = "4a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", .locking_hex = locking_hex, .expected = .{ .err = error.InvalidSignatureEncoding } },
        .{ .row = 1312, .name = "row 1312 missing s is invalid under dersig", .unlocking_hex = "24302202200000000000000000000000000000000000000000000000000000000000000000", .locking_hex = locking_hex, .expected = .{ .err = error.InvalidSignatureEncoding } },
        .{ .row = 1313, .name = "row 1313 invalid s length is invalid under dersig", .unlocking_hex = "273024021077777777777777777777777777777777020a7777777777777777777777777777777701", .locking_hex = locking_hex, .expected = .{ .err = error.InvalidSignatureEncoding } },
        .{ .row = 1314, .name = "row 1314 non-integer r is invalid under dersig", .unlocking_hex = "27302403107777777777777777777777777777777702107777777777777777777777777777777701", .locking_hex = locking_hex, .expected = .{ .err = error.InvalidSignatureEncoding } },
        .{ .row = 1315, .name = "row 1315 non-integer s is invalid under dersig", .unlocking_hex = "27302402107777777777777777777777777777777703107777777777777777777777777777777701", .locking_hex = locking_hex, .expected = .{ .err = error.InvalidSignatureEncoding } },
        .{ .row = 1316, .name = "row 1316 zero-length r is invalid under dersig", .unlocking_hex = "173014020002107777777777777777777777777777777701", .locking_hex = locking_hex, .expected = .{ .err = error.InvalidSignatureEncoding } },
        .{ .row = 1317, .name = "row 1317 zero-length s is invalid under dersig", .unlocking_hex = "173014021077777777777777777777777777777777020001", .locking_hex = locking_hex, .expected = .{ .err = error.InvalidSignatureEncoding } },
        .{ .row = 1318, .name = "row 1318 negative s is invalid under dersig", .unlocking_hex = "27302402107777777777777777777777777777777702108777777777777777777777777777777701", .locking_hex = locking_hex, .expected = .{ .err = error.InvalidSignatureEncoding } },
    });
}

test "go direct checksig rows: sighash policy gates" {
    const allocator = std.testing.allocator;

    const checksig_not_locking_hex =
        "21" ++ "02865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac0" ++ "ac91";

    var legacy_strict = bsvz.script.engine.ExecutionFlags.legacyReference();
    legacy_strict.strict_encoding = true;

    try harness.runCase(allocator, .{
        .name = "row 2424 checksig not rejects illegal forkid under strictenc",
        .unlocking_hex = "09300602010102010141",
        .locking_hex = checksig_not_locking_hex,
        .flags = legacy_strict,
        .expected = .{ .err = error.IllegalForkId },
    });

    var forkid_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();
    forkid_flags.der_signatures = true;

    try harness.runCase(allocator, .{
        .name = "row 2425 checksig not accepts forkid under sighash_forkid",
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
        .name = "row 2097 p2pk rejects undefined sighash type under strictenc",
        .unlocking_hex = "47304402206177d513ec2cda444c021a1f4f656fc4c72ba108ae063e157eb86dc3575784940220666fc66702815d0e5413bb9b1df22aed44f5f1efb8b99d41dd5dc9a5be6d205205",
        .locking_hex = "41048282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f5150811f8a8098557dfe45e8256e830b60ace62d613ac2f7b17bed31b6eaff6e26cafac",
        .flags = legacy_strict,
        .expected = .{ .err = error.InvalidSigHashType },
    });

    try harness.runCase(allocator, .{
        .name = "p2pk rejects invalid forkid under legacy strict policy",
        .unlocking_hex = "4730440220368d68340dfbebf99d5ec87d77fba899763e466c0a7ab2fa0221fb868ab0f3ef0220266c1a52a8e5b7b597613b80cf53814d3925dfb6715dce712c8e7a25e63a044041",
        .locking_hex = "41" ++ "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8" ++ "ac",
        .flags = legacy_strict,
        .expected = .{ .err = error.IllegalForkId },
    });

    try harness.runCase(allocator, .{
        .name = "row 2111 p2pkh rejects invalid sighash type under strictenc",
        .unlocking_hex = "4730440220647a83507454f15f85f7e24de6e70c9d7b1d4020c71d0e53f4412425487e1dde022015737290670b4ab17b6783697a88ddd581c2d9c9efe26a59ac213076fc67f53021" ++ "41" ++ "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        .locking_hex = "76" ++ "a9" ++ "14" ++ "91b24bf9f5288532960ac687abb035127b1d28a5" ++ "88" ++ "ac",
        .flags = legacy_strict,
        .expected = .{ .err = error.InvalidSigHashType },
    });

    try harness.runCase(allocator, .{
        .name = "row 2132 checksig not accepts undefined sighash type without strictenc",
        .unlocking_hex = "47304402207409b5b320296e5e2136a7b281a7f803028ca4ca44e2b83eebd46932677725de02202d4eea1c8d3c98e6f42614f54764e6e5e6542e213eb4d079737e9a8b6e9812ec05",
        .locking_hex = "41048282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f5150811f8a8098557dfe45e8256e830b60ace62d613ac2f7b17bed31b6eaff6e26cafac91",
        .flags = bsvz.script.engine.ExecutionFlags.legacyReference(),
        .expected = .{ .success = true },
    });

    try harness.runCase(allocator, .{
        .name = "row 2139 checksig not rejects undefined sighash type under strictenc",
        .unlocking_hex = "47304402207409b5b320296e5e2136a7b281a7f803028ca4ca44e2b83eebd46932677725de02202d4eea1c8d3c98e6f42614f54764e6e5e6542e213eb4d079737e9a8b6e9812ec05",
        .locking_hex = "41048282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f5150811f8a8098557dfe45e8256e830b60ace62d613ac2f7b17bed31b6eaff6e26cafac91",
        .flags = legacy_strict,
        .expected = .{ .err = error.InvalidSigHashType },
    });

    const checkmultisig_not_locking_hex =
        "51" ++ "21" ++ "02865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac0" ++ "51" ++ "ae91";

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

test "go direct checksig rows: exact checksig-not padding and strict sighash rows" {
    const allocator = std.testing.allocator;

    var dersig_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    dersig_flags.der_signatures = true;

    try runRows(allocator, dersig_flags, &[_]GoRow{
        .{
            .row = 1342,
            .name = "row 1342 checksig not with bad sig and too much r padding under dersig",
            .unlocking_hex = "4730440220005ece1335e7f757a1a1f476a7fb5bd90964e8a022489f890614a04acfb734c002206c12b8294a6513c7710e8c82d3c23d75cdbfe83200eb7efb495701958501a5d601",
            .locking_hex = "21" ++ "03363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640" ++ "ac91",
            .expected = .{ .err = error.InvalidSignatureEncoding },
        },
        .{
            .row = 1344,
            .name = "row 1344 checksig not with too much r padding under dersig",
            .unlocking_hex = "4730440220005ece1335e7f657a1a1f476a7fb5bd90964e8a022489f890614a04acfb734c002206c12b8294a6513c7710e8c82d3c23d75cdbfe83200eb7efb495701958501a5d601",
            .locking_hex = "21" ++ "03363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640" ++ "ac91",
            .expected = .{ .err = error.InvalidSignatureEncoding },
        },
    });

    var strict_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    strict_flags.strict_encoding = true;

    try runRows(allocator, strict_flags, &[_]GoRow{
        .{
            .row = 1386,
            .name = "row 1386 p2pk rejects undefined sighash type under strictenc",
            .unlocking_hex = "47304402206177d513ec2cda444c021a1f4f656fc4c72ba108ae063e157eb86dc3575784940220666fc66702815d0e5413bb9b1df22aed44f5f1efb8b99d41dd5dc9a5be6d205205",
            .locking_hex = "41" ++ "048282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f5150811f8a8098557dfe45e8256e830b60ace62d613ac2f7b17bed31b6eaff6e26caf" ++ "ac",
            .expected = .{ .err = error.InvalidSigHashType },
        },
        .{
            .row = 1388,
            .name = "row 1388 p2pkh rejects invalid sighash type under strictenc",
            .unlocking_hex = "4730440220647a83507454f15f85f7e24de6e70c9d7b1d4020c71d0e53f4412425487e1dde022015737290670b4ab17b6783697a88ddd581c2d9c9efe26a59ac213076fc67f53021" ++ "41" ++ "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
            .locking_hex = "76" ++ "a9" ++ "14" ++ "91b24bf9f5288532960ac687abb035127b1d28a5" ++ "88" ++ "ac",
            .expected = .{ .err = error.InvalidSigHashType },
        },
        .{
            .row = 1392,
            .name = "row 1392 checksig not rejects invalid sighash type under strictenc",
            .unlocking_hex = "47304402207409b5b320296e5e2136a7b281a7f803028ca4ca44e2b83eebd46932677725de02202d4eea1c8d3c98e6f42614f54764e6e5e6542e213eb4d079737e9a8b6e9812ec05",
            .locking_hex = "41" ++ "048282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f5150811f8a8098557dfe45e8256e830b60ace62d613ac2f7b17bed31b6eaff6e26caf" ++ "ac91",
            .expected = .{ .err = error.InvalidSigHashType },
        },
    });
}

test "go strict sigcheck rows: strict pubkey encoding" {
    const allocator = std.testing.allocator;
    const relaxed_flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    var strict_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    strict_flags.strict_encoding = true;

    try runRows(allocator, relaxed_flags, &[_]GoRow{
        .{
            .name = "row 2027 p2pk with hybrid pubkey without strictenc",
            .unlocking_hex = "473044022057292e2d4dfe775becdd0a9e6547997c728cdf35390f6a017da56d654d374e4902206b643be2fc53763b4e284845bfea2c597d2dc7759941dce937636c9d341b71ed01",
            .locking_hex = "410679be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8ac",
            .expected = .{ .success = false },
        },
        .{
            .name = "row 2041 p2pk not with hybrid pubkey without strictenc",
            .unlocking_hex = "4730440220035d554e3153c14950c9993f41c496607a8e24093db0595be7bf875cf64fcf1f02204731c8c4e5daf15e706cec19cdd8f2c5b1d05490e11dab8465ed426569b6e92101",
            .locking_hex = "410679be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8ac91",
            .expected = .{ .success = true },
        },
        .{
            .name = "row 2055 p2pk not with invalid hybrid pubkey without strictenc",
            .unlocking_hex = "4730440220035d554e3153c04950c9993f41c496607a8e24093db0595be7bf875cf64fcf1f02204731c8c4e5daf15e706cec19cdd8f2c5b1d05490e11dab8465ed426569b6e92101",
            .locking_hex = "410679be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8ac91",
            .expected = .{ .success = true },
        },
    });

    try runRows(allocator, strict_flags, &[_]GoRow{
        .{
            .name = "row 2034 p2pk with hybrid pubkey under strictenc",
            .unlocking_hex = "473044022057292e2d4dfe775becdd0a9e6547997c728cdf35390f6a017da56d654d374e4902206b643be2fc53763b4e284845bfea2c597d2dc7759941dce937636c9d341b71ed01",
            .locking_hex = "410679be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8ac",
            .expected = .{ .err = error.InvalidPublicKeyEncoding },
        },
        .{
            .name = "row 2050 p2pk not with hybrid pubkey under strictenc",
            .unlocking_hex = "4730440220035d554e3153c14950c9993f41c496607a8e24093db0595be7bf875cf64fcf1f02204731c8c4e5daf15e706cec19cdd8f2c5b1d05490e11dab8465ed426569b6e92101",
            .locking_hex = "410679be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8ac91",
            .expected = .{ .err = error.InvalidPublicKeyEncoding },
        },
        .{
            .name = "row 2064 p2pk not with invalid hybrid pubkey under strictenc",
            .unlocking_hex = "4730440220035d554e3153c04950c9993f41c496607a8e24093db0595be7bf875cf64fcf1f02204731c8c4e5daf15e706cec19cdd8f2c5b1d05490e11dab8465ed426569b6e92101",
            .locking_hex = "410679be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8ac91",
            .expected = .{ .err = error.InvalidPublicKeyEncoding },
        },
    });

    try runRows(allocator, strict_flags, &[_]GoRow{
        .{
            .row = 1377,
            .name = "row 1377 p2pk rejects a hybrid pubkey",
            .unlocking_hex = "473044022057292e2d4dfe775becdd0a9e6547997c728cdf35390f6a017da56d654d374e4902206b643be2fc53763b4e284845bfea2c597d2dc7759941dce937636c9d341b71ed01",
            .locking_hex = "410679be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8ac",
            .expected = .{ .err = error.InvalidPublicKeyEncoding },
        },
        .{
            .row = 1379,
            .name = "row 1379 p2pk not rejects a hybrid pubkey",
            .unlocking_hex = "4730440220035d554e3153c14950c9993f41c496607a8e24093db0595be7bf875cf64fcf1f02204731c8c4e5daf15e706cec19cdd8f2c5b1d05490e11dab8465ed426569b6e92101",
            .locking_hex = "410679be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8ac91",
            .expected = .{ .err = error.InvalidPublicKeyEncoding },
        },
        .{
            .row = 1381,
            .name = "row 1381 p2pk not rejects an invalid hybrid pubkey",
            .unlocking_hex = "4730440220035d554e3153c04950c9993f41c496607a8e24093db0595be7bf875cf64fcf1f02204731c8c4e5daf15e706cec19cdd8f2c5b1d05490e11dab8465ed426569b6e92101",
            .locking_hex = "410679be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8ac91",
            .expected = .{ .err = error.InvalidPublicKeyEncoding },
        },
        .{
            .row = 1384,
            .name = "row 1384 checkmultisig rejects a hybrid pubkey in the first checked slot",
            .unlocking_hex = "00473044022079c7824d6c868e0e1a273484e28c2654a27d043c8a27f49f52cb72efed0759090220452bbbf7089574fa082095a4fc1b3a16bafcf97a3a34d745fafc922cce66b27201",
            .locking_hex = "5121038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508410679be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b852ae",
            .expected = .{ .err = error.InvalidPublicKeyEncoding },
        },
    });
}

test "go strict sigcheck rows: nulldummy result shapes" {
    const allocator = std.testing.allocator;

    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.null_dummy = true;

    try runRows(allocator, flags, &[_]GoRow{
        .{
            .name = "row 1394 checkmultisig rejects a nonzero dummy",
            .unlocking_hex = "51473044022051254b9fb476a52d85530792b578f86fea70ec1ffb4393e661bcccb23d8d63d3022076505f94a403c86097841944e044c70c2045ce90e36de51f7e9d3828db98a0750147304402200a358f750934b3feb822f1966bfcd8bbec9eeaa3a8ca941e11ee5960e181fa01022050bf6b5a8e7750f70354ae041cb68a7bade67ec6c3ab19eb359638974410626e0147304402200955d031fff71d8653221e85e36c3c85533d2312fc3045314b19650b7ae2f81002202a6bb8505e36201909d0921f01abff390ae6b7ff97bbf959f98aedeb0a56730901",
            .locking_hex = "53210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179821038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f515082103363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff464053ae",
            .expected = .{ .err = error.NullDummy },
        },
        .{
            .name = "row 1396 checkmultisig not rejects a nonzero dummy before bad signatures matter",
            .unlocking_hex = "5147304402201bb2edab700a5d020236df174fefed78087697143731f659bea59642c759c16d022061f42cdbae5bcd3e8790f20bf76687443436e94a634321c16a72aa54cbc7c2ea0147304402204bb4a64f2a6e5c7fb2f07fef85ee56fde5e6da234c6a984262307a20e99842d702206f8303aaba5e625d223897e2ffd3f88ef1bcffef55f38dc3768e5f2e94c923f901473044022040c2809b71fffb155ec8b82fe7a27f666bd97f941207be4e14ade85a1249dd4d02204d56c85ec525dd18e29a0533d5ddf61b6b1bb32980c2f63edf951aebf7a27bfe01",
            .locking_hex = "53210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179821038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f515082103363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff464053ae91",
            .expected = .{ .err = error.NullDummy },
        },
    });
}

test "go direct sigcheck rows: exact illegal forkid checksig-not cases" {
    const allocator = std.testing.allocator;

    var strict_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    strict_flags.strict_encoding = true;

    try runRows(allocator, strict_flags, &[_]GoRow{
        .{
            .row = 1494,
            .name = "row 1494 checksig not rejects an illegal forkid under strictenc",
            .unlocking_hex = "09300602010102010141",
            .locking_hex = "21" ++ "02865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac0" ++ "ac91",
            .expected = .{ .err = error.IllegalForkId },
        },
        .{
            .name = "row 1496 checkmultisig not rejects an illegal forkid under strictenc",
            .unlocking_hex = "0009300602010102010141",
            .locking_hex = "51" ++ "21" ++ "02865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac0" ++ "51" ++ "ae91",
            .expected = .{ .err = error.IllegalForkId },
        },
    });
}
