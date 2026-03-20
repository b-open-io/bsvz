const std = @import("std");
const interpreter = @import("../script/interpreter.zig");
const txmod = @import("../transaction/lib.zig");

pub const Error = interpreter.Error || error{
    FeeTooLow,
    InvalidBeef,
    MissingSourceOutput,
    MissingTransaction,
    InvalidMerklePath,
    ScriptVerificationFailed,
};

pub const GullibleChainTracker = struct {
    pub fn isValidRootForHeight(_: GullibleChainTracker, _: @import("../crypto/lib.zig").Hash256, _: u32) !bool {
        return true;
    }
};

pub fn verify(
    allocator: std.mem.Allocator,
    tx: *const txmod.Transaction,
    chain_tracker: anytype,
    fee_model: ?txmod.fee_model.SatoshisPerKilobyte,
) !bool {
    var verified = std.AutoHashMap(@import("../primitives/lib.zig").chainhash.Hash, void).init(allocator);
    defer verified.deinit();
    var queue: std.ArrayList(*const txmod.Transaction) = .empty;
    defer queue.deinit(allocator);
    try queue.append(allocator, tx);

    if (fee_model) |model| {
        const paid_fee = try txmod.fees.getFee(tx);
        const required_fee = try model.computeFee(tx);
        if (paid_fee < required_fee) return error.FeeTooLow;
    }

    while (queue.items.len > 0) {
        const current = queue.pop().?;
        const current_txid = try current.txid(allocator);
        const hash = @import("../primitives/lib.zig").chainhash.Hash{ .bytes = current_txid.bytes };
        if (verified.contains(hash)) continue;

        if (current.merkle_path) |merkle_path| {
            if (!try merkle_path.verify(allocator, current_txid, chain_tracker)) {
                return error.InvalidMerklePath;
            }
            try verified.put(hash, {});
            continue;
        }

        for (current.inputs, 0..) |input, index| {
            const prevout = txmod.sourceOutputForInput(&input) orelse return error.MissingSourceOutput;
            if (!try interpreter.verifyPrevout(.{
                .allocator = allocator,
                .tx = current,
                .input_index = index,
                .previous_output = prevout,
                .unlocking_script = input.unlocking_script,
            })) {
                return error.ScriptVerificationFailed;
            }

            if (txmod.sourceTransactionForInput(&input)) |source_tx| {
                const source_txid = @import("../primitives/lib.zig").chainhash.Hash{
                    .bytes = input.previous_outpoint.txid.bytes,
                };
                if (!verified.contains(source_txid)) {
                    try queue.append(allocator, source_tx);
                }
            }
        }

        try verified.put(hash, {});
    }
    return true;
}

pub fn verifyBeef(
    allocator: std.mem.Allocator,
    beef: *const txmod.Beef,
    root_txid: @import("../primitives/lib.zig").chainhash.Hash,
    chain_tracker: anytype,
    fee_model: ?txmod.fee_model.SatoshisPerKilobyte,
) !bool {
    if (!try beef.isValid(allocator, false)) return error.InvalidBeef;

    const root_tx = beef.findTransaction(root_txid) orelse return error.MissingTransaction;
    if (fee_model) |model| {
        const paid_fee = try txmod.fees.getFee(root_tx);
        const required_fee = try model.computeFee(root_tx);
        if (paid_fee < required_fee) return error.FeeTooLow;
    }

    var verified = std.AutoHashMap(@import("../primitives/lib.zig").chainhash.Hash, void).init(allocator);
    defer verified.deinit();
    var queue: std.ArrayList(@import("../primitives/lib.zig").chainhash.Hash) = .empty;
    defer queue.deinit(allocator);
    try queue.append(allocator, root_txid);

    while (queue.items.len > 0) {
        const current_txid = queue.pop().?;
        if (verified.contains(current_txid)) continue;

        const tx = beef.findTransaction(current_txid) orelse return error.MissingTransaction;
        if (tx.merkle_path) |merkle_path| {
            if (!try merkle_path.verify(allocator, .{ .bytes = current_txid.bytes }, chain_tracker)) {
                return error.InvalidMerklePath;
            }
            try verified.put(current_txid, {});
            continue;
        }

        for (tx.inputs, 0..) |input, index| {
            const prevout = txmod.sourceOutputForInput(&input) orelse return error.MissingSourceOutput;
            if (!try interpreter.verifyPrevout(.{
                .allocator = allocator,
                .tx = tx,
                .input_index = index,
                .previous_output = prevout,
                .unlocking_script = input.unlocking_script,
            })) {
                return error.ScriptVerificationFailed;
            }

            const source_txid = @import("../primitives/lib.zig").chainhash.Hash{
                .bytes = input.previous_outpoint.txid.bytes,
            };
            if (beef.findTransaction(source_txid) != null and !verified.contains(source_txid)) {
                try queue.append(allocator, source_txid);
            }
        }

        try verified.put(current_txid, {});
    }

    return true;
}

pub fn verifyScripts(allocator: std.mem.Allocator, tx: *const txmod.Transaction) !bool {
    return verify(allocator, tx, GullibleChainTracker{}, null);
}

const go_brc62_hex =
    "0100beef01fe636d0c0007021400fe507c0c7aa754cef1f7889d5fd395cf1f785dd7de98eed895dbedfe4e5bc70d1502ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e010b00bc4ff395efd11719b277694cface5aa50d085a0bb81f613f70313acd28cf4557010400574b2d9142b8d28b61d88e3b2c3f44d858411356b49a28a4643b6d1a6a092a5201030051a05fc84d531b5d250c23f4f886f6812f9fe3f402d61607f977b4ecd2701c19010000fd781529d58fc2523cf396a7f25440b409857e7e221766c57214b1d38c7b481f01010062f542f45ea3660f86c013ced80534cb5fd4c19d66c56e7e8c5d4bf2d40acc5e010100b121e91836fd7cd5102b654e9f72f3cf6fdbfd0b161c53a9c54b12c841126331020100000001cd4e4cac3c7b56920d1e7655e7e260d31f29d9a388d04910f1bbd72304a79029010000006b483045022100e75279a205a547c445719420aa3138bf14743e3f42618e5f86a19bde14bb95f7022064777d34776b05d816daf1699493fcdf2ef5a5ab1ad710d9c97bfb5b8f7cef3641210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013e660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000001000100000001ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e000000006a47304402203a61a2e931612b4bda08d541cfb980885173b8dcf64a3471238ae7abcd368d6402204cbf24f04b9aa2256d8901f0ed97866603d2be8324c2bfb7a37bf8fc90edd5b441210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013c660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000000";

test "verify accepts merkle path with gullible tracker" {
    const allocator = std.testing.allocator;

    var tx = txmod.Transaction{
        .version = 1,
        .inputs = &.{},
        .outputs = &.{},
        .lock_time = 0,
    };
    const txid = try tx.txid(allocator);

    var path = MerklePath{
        .block_height = 100,
        .path = try allocator.alloc([]PathElement, 1),
    };
    defer path.deinit(allocator);
    path.path[0] = try allocator.alloc(PathElement, 1);
    path.path[0][0] = .{
        .offset = 0,
        .hash = txid,
        .txid = true,
    };
    tx.merkle_path = path;

    try std.testing.expect(try verify(allocator, &tx, GullibleChainTracker{}, null));
}

test "verify walks non-owning source transaction ancestry" {
    const allocator = std.testing.allocator;

    var parent = txmod.Transaction{
        .version = 1,
        .inputs = try allocator.alloc(txmod.Input, 0),
        .outputs = try allocator.alloc(txmod.Output, 1),
        .lock_time = 0,
    };
    defer parent.deinit(allocator);
    @constCast(parent.outputs)[0] = .{
        .satoshis = 10,
        .locking_script = .{ .bytes = &[_]u8{0x51} },
    };
    const parent_txid = try parent.txid(allocator);
    parent.merkle_path = .{
        .block_height = 7,
        .path = try allocator.alloc([]PathElement, 1),
    };
    parent.owns_merkle_path = true;
    parent.merkle_path.?.path[0] = try allocator.alloc(PathElement, 1);
    parent.merkle_path.?.path[0][0] = .{
        .offset = 0,
        .hash = parent_txid,
        .txid = true,
    };

    var child = txmod.Transaction{
        .version = 1,
        .inputs = try allocator.alloc(txmod.Input, 1),
        .outputs = try allocator.alloc(txmod.Output, 1),
        .lock_time = 0,
    };
    defer child.deinit(allocator);
    @constCast(child.inputs)[0] = .{
        .previous_outpoint = .{
            .txid = .{ .bytes = parent_txid.bytes },
            .index = 0,
        },
        .unlocking_script = .{ .bytes = &[_]u8{0x51} },
        .sequence = 0xffff_ffff,
        .source_transaction = @ptrCast(&parent),
    };
    @constCast(child.outputs)[0] = .{
        .satoshis = 9,
        .locking_script = .{ .bytes = &[_]u8{0x51} },
    };

    try std.testing.expect(try verify(allocator, &child, GullibleChainTracker{}, null));
}

test "verifyBeef walks ancestor transactions from root txid" {
    const allocator = std.testing.allocator;

    var parent = txmod.Transaction{
        .version = 1,
        .inputs = try allocator.alloc(txmod.Input, 0),
        .outputs = try allocator.alloc(txmod.Output, 1),
        .lock_time = 0,
    };
    defer parent.deinit(allocator);
    @constCast(parent.outputs)[0] = .{
        .satoshis = 50,
        .locking_script = .{ .bytes = &[_]u8{0x51} },
    };
    const parent_txid = try parent.txid(allocator);

    var child = txmod.Transaction{
        .version = 1,
        .inputs = try allocator.alloc(txmod.Input, 1),
        .outputs = try allocator.alloc(txmod.Output, 1),
        .lock_time = 0,
    };
    defer child.deinit(allocator);
    @constCast(child.inputs)[0] = .{
        .previous_outpoint = .{
            .txid = .{ .bytes = parent_txid.bytes },
            .index = 0,
        },
        .unlocking_script = .{ .bytes = &[_]u8{0x51} },
        .sequence = 0xffff_ffff,
        .source_output = try parent.outputs[0].clone(allocator),
    };
    @constCast(child.outputs)[0] = .{
        .satoshis = 25,
        .locking_script = .{ .bytes = &[_]u8{0x51} },
    };
    const child_txid = try child.txid(allocator);

    var proof = MerklePath{
        .block_height = 22,
        .path = try allocator.alloc([]PathElement, 1),
    };
    defer proof.deinit(allocator);
    proof.path[0] = try allocator.alloc(PathElement, 1);
    proof.path[0][0] = .{
        .offset = 0,
        .hash = parent_txid,
        .txid = true,
    };

    var beef = txmod.newBeefV2(allocator);
    defer beef.deinit();
    beef.bumps = try allocator.alloc(MerklePath, 1);
    beef.bumps[0] = try proof.clone(allocator);

    var parent_entry = try parent.clone(allocator);
    parent_entry.merkle_path = beef.bumps[0];
    parent_entry.owns_merkle_path = false;
    try beef.transactions.put(.{ .bytes = parent_txid.bytes }, .{
        .data_format = .RawTxAndBumpIndex,
        .transaction = parent_entry,
        .bump_index = 0,
    });
    try beef.transactions.put(.{ .bytes = child_txid.bytes }, .{
        .data_format = .RawTx,
        .transaction = try child.clone(allocator),
    });

    try std.testing.expect(try verifyBeef(
        allocator,
        &beef,
        .{ .bytes = child_txid.bytes },
        GullibleChainTracker{},
        null,
    ));
}

test "verify fee model paid vs required" {
    const allocator = std.testing.allocator;
    const FeeModel = txmod.fee_model.SatoshisPerKilobyte;
    const locking = [_]u8{0x51};

    const inputs = try allocator.alloc(txmod.Input, 1);
    errdefer allocator.free(inputs);
    inputs[0] = .{
        .previous_outpoint = .{
            .txid = .{ .bytes = [_]u8{0xab} ** 32 },
            .index = 0,
        },
        .unlocking_script = .{ .bytes = &[_]u8{0x51} },
        .sequence = 0xffff_ffff,
        .source_output = .{
            .satoshis = 50_000,
            .locking_script = .{ .bytes = &locking },
        },
    };
    const outputs = try allocator.alloc(txmod.Output, 1);
    errdefer allocator.free(outputs);
    outputs[0] = .{
        .satoshis = 49_900,
        .locking_script = .{ .bytes = &locking },
    };

    var tx = txmod.Transaction{
        .version = 2,
        .inputs = inputs,
        .outputs = outputs,
        .lock_time = 0,
    };
    defer tx.deinit(allocator);

    const txid = try tx.txid(allocator);
    var path = MerklePath{
        .block_height = 1,
        .path = try allocator.alloc([]PathElement, 1),
    };
    path.path[0] = try allocator.alloc(PathElement, 1);
    path.path[0][0] = .{
        .offset = 0,
        .hash = txid,
        .txid = true,
    };
    tx.merkle_path = path;
    tx.owns_merkle_path = true;

    const paid = try txmod.fees.getFee(&tx);
    try std.testing.expectEqual(@as(u64, 100), paid);

    try std.testing.expect(try verify(allocator, &tx, GullibleChainTracker{}, FeeModel{ .satoshis = 1 }));
    try std.testing.expectError(error.FeeTooLow, verify(
        allocator,
        &tx,
        GullibleChainTracker{},
        FeeModel{ .satoshis = 2_000_000 },
    ));
}

const MerklePath = @import("merkle_path.zig").MerklePath;
const PathElement = @import("merkle_path.zig").PathElement;
