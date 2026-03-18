const std = @import("std");
const bsvz = @import("bsvz");
const harness = @import("support/go_script_harness.zig");

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
            .row = 1208,
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
            .row = 1210,
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
            .row = 1212,
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

test "go strict sigcheck rows: strict pubkey encoding" {
    const allocator = std.testing.allocator;

    var strict_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    strict_flags.strict_encoding = true;

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
            .row = 1394,
            .name = "row 1394 checkmultisig rejects a nonzero dummy",
            .unlocking_hex = "51473044022051254b9fb476a52d85530792b578f86fea70ec1ffb4393e661bcccb23d8d63d3022076505f94a403c86097841944e044c70c2045ce90e36de51f7e9d3828db98a0750147304402200a358f750934b3feb822f1966bfcd8bbec9eeaa3a8ca941e11ee5960e181fa01022050bf6b5a8e7750f70354ae041cb68a7bade67ec6c3ab19eb359638974410626e0147304402200955d031fff71d8653221e85e36c3c85533d2312fc3045314b19650b7ae2f81002202a6bb8505e36201909d0921f01abff390ae6b7ff97bbf959f98aedeb0a56730901",
            .locking_hex = "53210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179821038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f515082103363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff464053ae",
            .expected = .{ .err = error.NullDummy },
        },
        .{
            .row = 1396,
            .name = "row 1396 checkmultisig not rejects a nonzero dummy before bad signatures matter",
            .unlocking_hex = "5147304402201bb2edab700a5d020236df174fefed78087697143731f659bea59642c759c16d022061f42cdbae5bcd3e8790f20bf76687443436e94a634321c16a72aa54cbc7c2ea0147304402204bb4a64f2a6e5c7fb2f07fef85ee56fde5e6da234c6a984262307a20e99842d702206f8303aaba5e625d223897e2ffd3f88ef1bcffef55f38dc3768e5f2e94c923f901473044022040c2809b71fffb155ec8b82fe7a27f666bd97f941207be4e14ade85a1249dd4d02204d56c85ec525dd18e29a0533d5ddf61b6b1bb32980c2f63edf951aebf7a27bfe01",
            .locking_hex = "53210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179821038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f515082103363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff464053ae91",
            .expected = .{ .err = error.NullDummy },
        },
    });
}
