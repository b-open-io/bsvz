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
