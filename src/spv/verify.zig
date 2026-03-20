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
    fee_model: anytype,
) !bool {
    var verified = std.AutoHashMap(@import("../primitives/lib.zig").chainhash.Hash, void).init(allocator);
    defer verified.deinit();
    var queue: std.ArrayList(*const txmod.Transaction) = .empty;
    defer queue.deinit(allocator);
    try queue.append(allocator, tx);

    if (fee_model != null) {
        const paid_fee = try txmod.fees.getFee(tx);
        const required_fee = try fee_model.?.computeFee(tx);
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
    fee_model: anytype,
) !bool {
    if (!try beef.isValid(allocator, false)) return error.InvalidBeef;

    const root_tx = beef.findTransaction(root_txid) orelse return error.MissingTransaction;
    if (fee_model != null) {
        const paid_fee = try txmod.fees.getFee(root_tx);
        const required_fee = try fee_model.?.computeFee(root_tx);
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

const MerklePath = @import("merkle_path.zig").MerklePath;
const PathElement = @import("merkle_path.zig").PathElement;
