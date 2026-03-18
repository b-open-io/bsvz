const std = @import("std");
const bsvz = @import("bsvz");
const harness = @import("support/go_script_harness.zig");

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
