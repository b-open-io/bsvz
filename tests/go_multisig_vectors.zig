const std = @import("std");
const bsvz = @import("bsvz");
const harness = @import("support/go_script_harness.zig");

const GoRow = struct {
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

test "go multisig rows: nullfail and nulldummy matrix" {
    const allocator = std.testing.allocator;
    const locking_hex = "011451515151515151515151515151515151515151510114ae91";

    var dersig_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    dersig_flags.der_signatures = true;

    var nullfail_flags = dersig_flags;
    nullfail_flags.null_fail = true;

    var nulldummy_flags = nullfail_flags;
    nulldummy_flags.null_dummy = true;

    try runRows(allocator, dersig_flags, &[_]GoRow{
        .{
            .name = "row 2414 exact checkmultisig not all-empty signatures with dersig",
            .unlocking_hex = "000000000000000000000000000000000000000000",
            .locking_hex = locking_hex,
            .expected = .{ .success = true },
        },
        .{
            .name = "row 2418 exact checkmultisig not trailing non-null der-compliant invalid signature with dersig",
            .unlocking_hex = "000000000000000000000000000000000000000009300602010102010101",
            .locking_hex = locking_hex,
            .expected = .{ .success = true },
        },
        .{
            .name = "row 2420 exact checkmultisig not leading non-null der-compliant invalid signature with dersig",
            .unlocking_hex = "000930060201010201010100000000000000000000000000000000000000",
            .locking_hex = locking_hex,
            .expected = .{ .success = true },
        },
    });

    try runRows(allocator, nullfail_flags, &[_]GoRow{
        .{
            .name = "row 2415 exact checkmultisig not all-empty signatures with dersig and nullfail",
            .unlocking_hex = "000000000000000000000000000000000000000000",
            .locking_hex = locking_hex,
            .expected = .{ .success = true },
        },
        .{
            .name = "row 2416 exact checkmultisig not nonzero dummy with nullfail but no nulldummy",
            .unlocking_hex = "510000000000000000000000000000000000000000",
            .locking_hex = locking_hex,
            .expected = .{ .success = true },
        },
        .{
            .name = "row 2419 exact checkmultisig not trailing non-null der-compliant invalid signature with nullfail",
            .unlocking_hex = "000000000000000000000000000000000000000009300602010102010101",
            .locking_hex = locking_hex,
            .expected = .{ .err = error.NullFail },
        },
        .{
            .name = "row 2421 exact checkmultisig not leading non-null der-compliant invalid signature with nullfail",
            .unlocking_hex = "000930060201010201010100000000000000000000000000000000000000",
            .locking_hex = locking_hex,
            .expected = .{ .err = error.NullFail },
        },
    });

    try runRows(allocator, nulldummy_flags, &[_]GoRow{
        .{
            .name = "row 2417 exact checkmultisig not nonzero dummy with nulldummy precedence",
            .unlocking_hex = "510000000000000000000000000000000000000000",
            .locking_hex = locking_hex,
            .expected = .{ .err = error.NullDummy },
        },
    });
}

test "go multisig rows: strict evaluation order" {
    const allocator = std.testing.allocator;

    var strict_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    strict_flags.strict_encoding = true;

    try runRows(allocator, strict_flags, &[_]GoRow{
        .{
            .name = "2-of-2 checkmultisig not errors on first checked invalid pubkey",
            .unlocking_hex = "00" ++ "09" ++ "300602010102010101" ++ "09" ++ "300602010102010101",
            .locking_hex = "52" ++ "21" ++ "02865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac0" ++ "00" ++ "52" ++ "ae91",
            .expected = .{ .err = error.InvalidPublicKeyEncoding },
        },
        .{
            .name = "2-of-2 checkmultisig not errors on first checked malformed signature",
            .unlocking_hex = "00" ++ "09" ++ "300602010102010101" ++ "51",
            .locking_hex = "52" ++ "21" ++ "02865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac0" ++ "21" ++ "02865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac0" ++ "52" ++ "ae91",
            .expected = .{ .err = error.InvalidSignatureEncoding },
        },
    });
}

test "go multisig rows: exact strict oracle rows" {
    const allocator = std.testing.allocator;

    var strict_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    strict_flags.strict_encoding = true;

    try runRows(allocator, strict_flags, &[_]GoRow{
        .{
            .name = "row 1602 2-of-2 checksig not first pubkey invalid with both signatures well-formed",
            .unlocking_hex = "00" ++ "47" ++ "3044022044dc17b0887c161bb67ba9635bf758735bdde503e4b0a0987f587f14a4e1143d022009a215772d49a85dae40d8ca03955af26ad3978a0ff965faa12915e9586249a501" ++ "47" ++ "3044022044dc17b0887c161bb67ba9635bf758735bdde503e4b0a0987f587f14a4e1143d022009a215772d49a85dae40d8ca03955af26ad3978a0ff965faa12915e9586249a501",
            .locking_hex = "52" ++ "21" ++ "02865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac0" ++ "00" ++ "52" ++ "ae91",
            .expected = .{ .err = error.InvalidPublicKeyEncoding },
        },
        .{
            .name = "row 1610 2-of-2 checksig not first malformed signature with valid pubkeys",
            .unlocking_hex = "00" ++ "47" ++ "3044022044dc17b0887c161bb67ba9635bf758735bdde503e4b0a0987f587f14a4e1143d022009a215772d49a85dae40d8ca03955af26ad3978a0ff965faa12915e9586249a501" ++ "51",
            .locking_hex = "52" ++ "21" ++ "02865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac0" ++ "21" ++ "02865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac0" ++ "52" ++ "ae91",
            .expected = .{ .err = error.InvalidSignatureEncoding },
        },
        .{
            .name = "row 1616 2-of-3 checkmultisig one valid and one malformed signature",
            .unlocking_hex = "00" ++ "47" ++ "304402205451ce65ad844dbb978b8bdedf5082e33b43cae8279c30f2c74d9e9ee49a94f802203fe95a7ccf74da7a232ee523ef4a53cb4d14bdd16289680cdb97a63819b8f42f01" ++ "46" ++ "304402205451ce65ad844dbb978b8bdedf5082e33b43cae8279c30f2c74d9e9ee49a94f802203fe95a7ccf74da7a232ee523ef4a53cb4d14bdd16289680cdb97a63819b8f42f",
            .locking_hex = "52" ++ "21" ++ "02a673638cb9587cb68ea08dbef685c6f2d2a751a8b3c6f2a7e9a4999e6e4bfaf5" ++ "21" ++ "02a673638cb9587cb68ea08dbef685c6f2d2a751a8b3c6f2a7e9a4999e6e4bfaf5" ++ "21" ++ "02a673638cb9587cb68ea08dbef685c6f2d2a751a8b3c6f2a7e9a4999e6e4bfaf5" ++ "53" ++ "ae",
            .expected = .{ .err = error.InvalidSignatureEncoding },
        },
    });
}

test "go multisig rows: exact strict hybrid pubkey row" {
    const allocator = std.testing.allocator;

    var strict_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    strict_flags.strict_encoding = true;

    try runRows(allocator, strict_flags, &[_]GoRow{
        .{
            .name = "row 2085 1-of-2 checkmultisig with first hybrid pubkey",
            .unlocking_hex = "00" ++ "47" ++ "3044022079c7824d6c868e0e1a273484e28c2654a27d043c8a27f49f52cb72efed0759090220452bbbf7089574fa082095a4fc1b3a16bafcf97a3a34d745fafc922cce66b27201",
            .locking_hex = "51" ++ "21" ++ "038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508" ++ "41" ++ "0679be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8" ++ "52" ++ "ae",
            .expected = .{ .err = error.InvalidPublicKeyEncoding },
        },
    });
}

test "go multisig rows: exact bip66 result-shape rows" {
    const allocator = std.testing.allocator;

    const relaxed_flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    var dersig_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    dersig_flags.der_signatures = true;

    try runRows(allocator, relaxed_flags, &[_]GoRow{
        .{
            .name = "row 1972 bip66 example 11 checkmultisig without dersig",
            .unlocking_hex = "00" ++ "47" ++ "30440220cae00b1444babfbf6071b0ba8707f6bd373da3df494d6e74119b0430c5db810502205d5231b8c5939c8ff0c82242656d6e06edb073d42af336c99fe8837c36ea39d501" ++ "00",
            .locking_hex = "52" ++ "21" ++ "038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508" ++ "21" ++ "03363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640" ++ "52" ++ "ae",
            .expected = .{ .success = false },
        },
        .{
            .name = "row 1986 bip66 example 12 checkmultisig not without dersig",
            .unlocking_hex = "00" ++ "47" ++ "30440220b119d67d389315308d1745f734a51ff3ec72e06081e84e236fdf9dc2f5d2a64802204b04e3bc38674c4422ea317231d642b56dc09d214a1ecbbf16ecca01ed996e2201" ++ "00",
            .locking_hex = "52" ++ "21" ++ "038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508" ++ "21" ++ "03363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640" ++ "52" ++ "ae91",
            .expected = .{ .success = true },
        },
    });

    try runRows(allocator, dersig_flags, &[_]GoRow{
        .{
            .name = "row 1979 bip66 example 11 checkmultisig with dersig",
            .unlocking_hex = "00" ++ "47" ++ "30440220cae00b1444babfbf6071b0ba8707f6bd373da3df494d6e74119b0430c5db810502205d5231b8c5939c8ff0c82242656d6e06edb073d42af336c99fe8837c36ea39d501" ++ "00",
            .locking_hex = "52" ++ "21" ++ "038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508" ++ "21" ++ "03363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640" ++ "52" ++ "ae",
            .expected = .{ .success = false },
        },
        .{
            .name = "row 1993 bip66 example 12 checkmultisig not with dersig",
            .unlocking_hex = "00" ++ "47" ++ "30440220b119d67d389315308d1745f734a51ff3ec72e06081e84e236fdf9dc2f5d2a64802204b04e3bc38674c4422ea317231d642b56dc09d214a1ecbbf16ecca01ed996e2201" ++ "00",
            .locking_hex = "52" ++ "21" ++ "038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508" ++ "21" ++ "03363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640" ++ "52" ++ "ae91",
            .expected = .{ .success = true },
        },
    });
}

test "go multisig rows: exact nulldummy rows with real signatures" {
    const allocator = std.testing.allocator;
    const checksig_locking_hex =
        "53" ++
        "21" ++ "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" ++
        "21" ++ "038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508" ++
        "21" ++ "03363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640" ++
        "53" ++ "ae";
    const checksig_not_locking_hex = checksig_locking_hex ++ "91";

    const nonzero_dummy_sigs =
        "51" ++
        "47" ++ "3044022051254b9fb476a52d85530792b578f86fea70ec1ffb4393e661bcccb23d8d63d3022076505f94a403c86097841944e044c70c2045ce90e36de51f7e9d3828db98a07501" ++
        "47" ++ "304402200a358f750934b3feb822f1966bfcd8bbec9eeaa3a8ca941e11ee5960e181fa01022050bf6b5a8e7750f70354ae041cb68a7bade67ec6c3ab19eb359638974410626e01" ++
        "47" ++ "304402200955d031fff71d8653221e85e36c3c85533d2312fc3045314b19650b7ae2f81002202a6bb8505e36201909d0921f01abff390ae6b7ff97bbf959f98aedeb0a56730901";
    const nonzero_dummy_invalid_not_sigs =
        "51" ++
        "47" ++ "304402201bb2edab700a5d020236df174fefed78087697143731f659bea59642c759c16d022061f42cdbae5bcd3e8790f20bf76687443436e94a634321c16a72aa54cbc7c2ea01" ++
        "47" ++ "304402204bb4a64f2a6e5c7fb2f07fef85ee56fde5e6da234c6a984262307a20e99842d702206f8303aaba5e625d223897e2ffd3f88ef1bcffef55f38dc3768e5f2e94c923f901" ++
        "47" ++ "3044022040c2809b71fffb155ec8b82fe7a27f666bd97f941207be4e14ade85a1249dd4d02204d56c85ec525dd18e29a0533d5ddf61b6b1bb32980c2f63edf951aebf7a27bfe01";

    var nulldummy_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    nulldummy_flags.null_dummy = true;

    try runRows(allocator, nulldummy_flags, &[_]GoRow{
        .{
            .name = "row 2153 3-of-3 checkmultisig with nonzero dummy",
            .unlocking_hex = nonzero_dummy_sigs,
            .locking_hex = checksig_locking_hex,
            .expected = .{ .err = error.NullDummy },
        },
        .{
            .name = "row 2167 3-of-3 checkmultisig not with invalid sig and nonzero dummy",
            .unlocking_hex = nonzero_dummy_invalid_not_sigs,
            .locking_hex = checksig_not_locking_hex,
            .expected = .{ .err = error.NullDummy },
        },
    });
}

test "go multisig rows: exact forkid policy rows" {
    const allocator = std.testing.allocator;
    const unlocking_hex = "00" ++ "09" ++ "300602010102010141";
    const locking_hex = "51" ++ "21" ++ "02865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac0" ++ "51" ++ "ae91";

    var legacy_strict = bsvz.script.engine.ExecutionFlags.legacyReference();
    legacy_strict.strict_encoding = true;

    try runRows(allocator, legacy_strict, &[_]GoRow{
        .{
            .name = "row 2426 checkmultisig not rejects illegal forkid under strictenc",
            .unlocking_hex = unlocking_hex,
            .locking_hex = locking_hex,
            .expected = .{ .err = error.IllegalForkId },
        },
    });

    var forkid_flags = bsvz.script.engine.ExecutionFlags.postGenesisBsv();
    forkid_flags.der_signatures = true;

    try runRows(allocator, forkid_flags, &[_]GoRow{
        .{
            .name = "row 2427 checkmultisig not accepts forkid under sighash_forkid policy",
            .unlocking_hex = unlocking_hex,
            .locking_hex = locking_hex,
            .expected = .{ .success = true },
        },
    });
}

test "go multisig rows: exact checkmultisigverify zero-count rows" {
    const allocator = std.testing.allocator;
    const strict_flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    const relaxed_flags = bsvz.script.engine.ExecutionFlags.legacyReference();

    try runRows(allocator, strict_flags, &[_]GoRow{
        .{
            .name = "row 566 checkmultisigverify allows zero keys and zero sigs",
            .unlocking_hex = "",
            .locking_hex = "000000af740087",
            .expected = .{ .success = true },
        },
        .{
            .name = "row 568 checkmultisigverify ignores keys when zero sigs are required",
            .unlocking_hex = "",
            .locking_hex = "00000051af740087",
            .expected = .{ .success = true },
        },
    });

    try runRows(allocator, relaxed_flags, &[_]GoRow{
        .{
            .name = "row 775 checkmultisigverify succeeds with pushed zero count shape",
            .unlocking_hex = "0000020000",
            .locking_hex = "af51",
            .expected = .{ .success = true },
        },
        .{
            .name = "row 776 checkmultisigverify succeeds with alternate pushed zero count shape",
            .unlocking_hex = "0002000000",
            .locking_hex = "af51",
            .expected = .{ .success = true },
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
