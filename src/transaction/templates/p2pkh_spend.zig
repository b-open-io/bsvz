const std = @import("std");
const crypto = @import("../../crypto/lib.zig");
const Script = @import("../../script/script.zig").Script;
const p2pkh = @import("../../script/templates/p2pkh.zig");
const sighash = @import("../sighash.zig");
const Transaction = @import("../transaction.zig").Transaction;

pub const default_scope: u32 = sighash.SigHashType.forkid | sighash.SigHashType.all;
pub const Error = error{
    InvalidSigHashType,
    PushDataTooLarge,
};

pub fn signInput(
    allocator: std.mem.Allocator,
    tx: *const Transaction,
    input_index: usize,
    previous_locking_script: Script,
    previous_satoshis: i64,
    private_key: crypto.PrivateKey,
    scope: u32,
) !crypto.TxSignature {
    if (scope > std.math.maxInt(u8)) return error.InvalidSigHashType;
    const preimage = try sighash.formatPreimage(allocator, tx, input_index, previous_locking_script, previous_satoshis, scope);
    defer allocator.free(preimage);

    return .{
        .der = try private_key.signHash256(preimage),
        .sighash_type = @truncate(scope),
    };
}

pub fn buildUnlockingScript(
    allocator: std.mem.Allocator,
    tx_signature: crypto.TxSignature,
    public_key: crypto.PublicKey,
) !Script {
    const checksig_sig = try tx_signature.toChecksigFormat(allocator);
    defer allocator.free(checksig_sig);

    const pubkey_sec1 = public_key.toCompressedSec1();
    if (checksig_sig.len > 0x4b or pubkey_sec1.len > 0x4b) return error.PushDataTooLarge;
    const total_len = 1 + checksig_sig.len + 1 + pubkey_sec1.len;
    var bytes = try allocator.alloc(u8, total_len);

    bytes[0] = @intCast(checksig_sig.len);
    @memcpy(bytes[1 .. 1 + checksig_sig.len], checksig_sig);
    bytes[1 + checksig_sig.len] = pubkey_sec1.len;
    @memcpy(bytes[2 + checksig_sig.len ..], &pubkey_sec1);

    return .{ .bytes = bytes };
}

pub fn signAndBuildUnlockingScript(
    allocator: std.mem.Allocator,
    tx: *const Transaction,
    input_index: usize,
    previous_locking_script: Script,
    previous_satoshis: i64,
    private_key: crypto.PrivateKey,
    scope: u32,
) !Script {
    const tx_signature = try signInput(allocator, tx, input_index, previous_locking_script, previous_satoshis, private_key, scope);
    const public_key = try private_key.publicKey();
    return buildUnlockingScript(allocator, tx_signature, public_key);
}

pub fn verifyInput(
    allocator: std.mem.Allocator,
    tx: *const Transaction,
    input_index: usize,
    previous_locking_script: Script,
    previous_satoshis: i64,
    public_key: crypto.PublicKey,
    tx_signature: crypto.TxSignature,
) !bool {
    const preimage = try sighash.formatPreimage(
        allocator,
        tx,
        input_index,
        previous_locking_script,
        previous_satoshis,
        tx_signature.sighash_type,
    );
    defer allocator.free(preimage);

    return public_key.verifyHash256(preimage, tx_signature.der);
}

test "p2pkh spend signs and verifies a forkid input" {
    const allocator = std.testing.allocator;
    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;

    const private_key = try crypto.PrivateKey.fromBytes(key_bytes);
    const public_key = try private_key.publicKey();
    const pubkey_hash = crypto.hash.hash160(&public_key.bytes);
    const previous_locking_script_bytes = p2pkh.encode(pubkey_hash);
    const previous_locking_script = Script.init(&previous_locking_script_bytes);
    const output_locking_script_bytes = p2pkh.encode(pubkey_hash);

    const tx = Transaction{
        .version = 2,
        .inputs = &[_]@import("../input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x33} ** 32 },
                    .index = 0,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 0xffff_fffe,
            },
        },
        .outputs = &[_]@import("../output.zig").Output{
            .{
                .satoshis = 900,
                .locking_script = .{ .bytes = &output_locking_script_bytes },
            },
        },
        .lock_time = 0,
    };

    const tx_signature = try signInput(allocator, &tx, 0, previous_locking_script, 1_000, private_key, default_scope);
    try std.testing.expect(try verifyInput(allocator, &tx, 0, previous_locking_script, 1_000, public_key, tx_signature));

    const unlocking_script = try buildUnlockingScript(allocator, tx_signature, public_key);
    defer allocator.free(unlocking_script.bytes);

    try std.testing.expectEqual(@as(usize, tx_signature.der.len + public_key.bytes.len + 3), unlocking_script.len());
    try std.testing.expectEqual(@as(u8, @intCast(tx_signature.der.len + 1)), unlocking_script.bytes[0]);
    try std.testing.expectEqual(@as(u8, public_key.bytes.len), unlocking_script.bytes[1 + tx_signature.der.len + 1]);
}

test "p2pkh spend rejects sighash values that do not fit the checksig byte" {
    const allocator = std.testing.allocator;
    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;

    const private_key = try crypto.PrivateKey.fromBytes(key_bytes);
    const public_key = try private_key.publicKey();
    const pubkey_hash = crypto.hash.hash160(&public_key.bytes);
    const previous_locking_script_bytes = p2pkh.encode(pubkey_hash);
    const previous_locking_script = Script.init(&previous_locking_script_bytes);
    const output_locking_script_bytes = p2pkh.encode(pubkey_hash);

    const tx = Transaction{
        .version = 2,
        .inputs = &[_]@import("../input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x33} ** 32 },
                    .index = 0,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 0xffff_fffe,
            },
        },
        .outputs = &[_]@import("../output.zig").Output{
            .{
                .satoshis = 900,
                .locking_script = .{ .bytes = &output_locking_script_bytes },
            },
        },
        .lock_time = 0,
    };

    try std.testing.expectError(
        error.InvalidSigHashType,
        signInput(allocator, &tx, 0, previous_locking_script, 1_000, private_key, 0x1_0000),
    );
}

test "p2pkh interpreter verifies the signed unlocking script end to end" {
    const interpreter = @import("../../script/interpreter.zig");
    const allocator = std.testing.allocator;
    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;

    const private_key = try crypto.PrivateKey.fromBytes(key_bytes);
    const public_key = try private_key.publicKey();
    const pubkey_hash = crypto.hash.hash160(&public_key.bytes);
    const previous_locking_script_bytes = p2pkh.encode(pubkey_hash);
    const previous_locking_script = Script.init(&previous_locking_script_bytes);
    const output_locking_script_bytes = p2pkh.encode(pubkey_hash);

    var tx = Transaction{
        .version = 2,
        .inputs = &[_]@import("../input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x33} ** 32 },
                    .index = 0,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 0xffff_fffe,
            },
        },
        .outputs = &[_]@import("../output.zig").Output{
            .{
                .satoshis = 900,
                .locking_script = .{ .bytes = &output_locking_script_bytes },
            },
        },
        .lock_time = 0,
    };

    const unlocking_script = try signAndBuildUnlockingScript(
        allocator,
        &tx,
        0,
        previous_locking_script,
        1_000,
        private_key,
        default_scope,
    );
    defer allocator.free(unlocking_script.bytes);

    try std.testing.expect(try interpreter.verify(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_satoshis = 1_000,
        .unlocking_script = unlocking_script,
        .locking_script = previous_locking_script,
    }));

    try std.testing.expect(!(try interpreter.verify(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_satoshis = 999,
        .unlocking_script = unlocking_script,
        .locking_script = previous_locking_script,
    })));

    var wrong_locking_script_bytes = previous_locking_script_bytes;
    wrong_locking_script_bytes[3] ^= 0xff;
    const wrong_locking_script = Script.init(&wrong_locking_script_bytes);

    try std.testing.expect(!(try interpreter.verify(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_satoshis = 1_000,
        .unlocking_script = unlocking_script,
        .locking_script = wrong_locking_script,
    })));
}
