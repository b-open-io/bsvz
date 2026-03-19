const std = @import("std");

const corpus_path = "../go-sdk/script/interpreter/data/script_tests.json";

const MetaRow = struct {
    row: usize,
    text: []const u8,
};

fn accessOrSkip(rel_path: []const u8) !void {
    std.fs.cwd().access(rel_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
}

fn expectMetaRows(rows: []const MetaRow) !void {
    const allocator = std.testing.allocator;
    try accessOrSkip(corpus_path);

    const file = try std.fs.cwd().readFileAlloc(allocator, corpus_path, 8 * 1024 * 1024);
    defer allocator.free(file);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, file, .{});
    defer parsed.deinit();

    if (parsed.value != .array) return error.InvalidEncoding;

    for (rows) |row| {
        try std.testing.expect(row.row < parsed.value.array.items.len);
        const value = parsed.value.array.items[row.row];
        try std.testing.expect(value == .array);
        try std.testing.expectEqual(@as(usize, 1), value.array.items.len);
        try std.testing.expect(value.array.items[0] == .string);
        try std.testing.expectEqualStrings(row.text, value.array.items[0].string);
    }
}

test "go corpus meta rows are explicitly audited" {
    try expectMetaRows(&[_]MetaRow{
        .{ .row = 0, .text = "Copyright (c) 2018-2019 Bitcoin Association" },
        .{ .row = 1, .text = "Distributed under the Open BSV software license, see the accompanying file LICENSE." },
        .{ .row = 2, .text = "Presumably there is an earlier copyright from the Bitcoin Core developers and/or the Bitcoin ABC developers but it was not listed" },
        .{ .row = 3, .text = "Format is: [[wit..., amount]?, scriptSig, scriptPubKey, flags, expected_scripterror, ... comments]" },
        .{ .row = 4, .text = "It is evaluated as if there was a crediting coinbase transaction with two 0" },
        .{ .row = 5, .text = "pushes as scriptSig, and one output of 0 satoshi and given scriptPubKey," },
        .{ .row = 6, .text = "followed by a spending transaction which spends this output as only input (and" },
        .{ .row = 7, .text = "correct prevout hash), using the given scriptSig. All nLockTimes are 0, all" },
        .{ .row = 8, .text = "nSequences are max." },
        .{ .row = 537, .text = "all PUSHDATA forms are equivalent" },
        .{ .row = 541, .text = "Numeric pushes" },
        .{ .row = 559, .text = "Equivalency of different numeric encodings" },
        .{ .row = 569, .text = "Unevaluated non-minimal pushes are ignored" },
        .{ .row = 590, .text = "Numeric minimaldata rules are only applied when a stack item is numerically evaluated; the push itself is allowed" },
        .{ .row = 610, .text = "Valid version of the 'Test every numeric-accepting opcode for correct handling of the numeric minimal encoding rule' script_invalid test" },
        .{ .row = 653, .text = "While not really correctly DER encoded, the empty signature is allowed by" },
        .{ .row = 654, .text = "STRICTENC to provide a compact way to provide a delibrately invalid signature." },
        .{ .row = 657, .text = "CHECKMULTISIG evaluation order tests. CHECKMULTISIG evaluates signatures and" },
        .{ .row = 658, .text = "pubkeys in a specific order, and will exit early if the number of signatures" },
        .{ .row = 659, .text = "left to check is greater than the number of keys left. As STRICTENC fails the" },
        .{ .row = 660, .text = "script when it reaches an invalidly encoded signature or pubkey, we can use it" },
        .{ .row = 661, .text = "to test the exact order in which signatures and pubkeys are evaluated by" },
        .{ .row = 662, .text = "distinguishing CHECKMULTISIG returning false on the stack and the script as a" },
        .{ .row = 663, .text = "whole failing." },
        .{ .row = 664, .text = "See also the corresponding inverted versions of these tests in script_invalid.json" },
        .{ .row = 667, .text = "Increase test coverage for DERSIG" },
        .{ .row = 784, .text = "CAT" },
        .{ .row = 795, .text = "SPLIT" },
        .{ .row = 807, .text = "NUM2BIN" },
        .{ .row = 823, .text = "BIN2NUM" },
        .{ .row = 849, .text = "Disabled opcodes" },
        .{ .row = 854, .text = "Bitwise opcodes" },
        .{ .row = 855, .text = "AND" },
        .{ .row = 865, .text = "OR" },
        .{ .row = 875, .text = "XOR" },
        .{ .row = 885, .text = "INVERT" },
        .{ .row = 896, .text = "LSHIFT" },
        .{ .row = 916, .text = "RSHIFT" },
        .{ .row = 936, .text = "Arithmetic Opcodes" },
        .{ .row = 937, .text = "MUL" },
        .{ .row = 967, .text = "DIV" },
        .{ .row = 997, .text = "MOD" },
        .{ .row = 1027, .text = "EQUAL" },
        .{ .row = 1039, .text = "Ensure 100% coverage of discouraged NOPS" },
        .{ .row = 1205, .text = "Increase CHECKSIG and CHECKMULTISIG negative test coverage" },
        .{ .row = 1226, .text = "MINIMALDATA enforcement for PUSHDATAs" },
        .{ .row = 1248, .text = "MINIMALDATA enforcement for numeric arguments" },
        .{ .row = 1261, .text = "Test every numeric-accepting opcode for correct handling of the numeric minimal encoding rule" },
        .{ .row = 1304, .text = "Order of CHECKMULTISIG evaluation tests, inverted by swapping the order of" },
        .{ .row = 1305, .text = "pubkeys/signatures so they fail due to the STRICTENC rules on validly encoded" },
        .{ .row = 1306, .text = "signatures and pubkeys." },
        .{ .row = 1310, .text = "Increase DERSIG test coverage" },
        .{ .row = 1319, .text = "Automatically generated test cases" },
        .{ .row = 1420, .text = "CHECKSEQUENCEVERIFY tests" },
        .{ .row = 1426, .text = "MINIMALIF tests" },
        .{ .row = 1427, .text = "MINIMALIF is not applied if the flag is passed" },
        .{ .row = 1444, .text = "Normal P2SH IF 1 ENDIF" },
        .{ .row = 1465, .text = "Normal P2SH NOTIF 1 ENDIF, trying firs before than after genesis, if the hash is wrong should fail allways, if the redeem script is bad should fail only before genesis" },
        .{ .row = 1484, .text = "NULLFAIL should cover all signatures and signatures only" },
        .{ .row = 1493, .text = "SIGHASH_FORKID" },
        .{ .row = 1498, .text = "The End" },
    });
}
