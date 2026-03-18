const std = @import("std");
const crypto = @import("../crypto/lib.zig");
const errors = @import("errors.zig");
const Script = @import("script.zig").Script;
const p2pkh = @import("templates/p2pkh.zig");
const secp256k1 = @import("../crypto/secp256k1.zig");
const sighash = @import("../transaction/sighash.zig");
const Transaction = @import("../transaction/transaction.zig").Transaction;
const p2pkh_spend = @import("../transaction/templates/p2pkh_spend.zig");

pub const Error = errors.ScriptError || sighash.Error || secp256k1.Error || error{OutOfMemory};

pub const P2pkhSpendContext = struct {
    allocator: std.mem.Allocator,
    tx: *const Transaction,
    input_index: usize,
    previous_satoshis: i64,
    unlocking_script: Script,
    locking_script: Script,
};

pub fn verify(ctx: P2pkhSpendContext) Error!bool {
    if (p2pkh.matches(ctx.locking_script.bytes)) {
        return verifyP2pkh(ctx);
    }
    return error.UnsupportedLockingScript;
}

const ParsedUnlockingScript = struct {
    tx_signature: crypto.TxSignature,
    public_key: crypto.PublicKey,
};

fn verifyP2pkh(ctx: P2pkhSpendContext) Error!bool {
    const pubkey_hash = p2pkh.extractPubKeyHash(ctx.locking_script.bytes) catch return error.UnsupportedLockingScript;
    const parsed_unlocking_script = try parseP2pkhUnlockingScript(ctx.unlocking_script.bytes);

    if (!crypto.hash.hash160(&parsed_unlocking_script.public_key.bytes).eql(pubkey_hash)) {
        return false;
    }

    return p2pkh_spend.verifyInput(
        ctx.allocator,
        ctx.tx,
        ctx.input_index,
        ctx.locking_script,
        ctx.previous_satoshis,
        parsed_unlocking_script.public_key,
        parsed_unlocking_script.tx_signature,
    );
}

fn parseP2pkhUnlockingScript(unlocking_script: []const u8) Error!ParsedUnlockingScript {
    var cursor: usize = 0;
    const signature_bytes = try readDirectPush(unlocking_script, &cursor);
    const public_key_bytes = try readDirectPush(unlocking_script, &cursor);

    if (cursor != unlocking_script.len) return error.InvalidUnlockingScript;

    return .{
        .tx_signature = crypto.TxSignature.fromChecksigFormat(signature_bytes) catch return error.InvalidSignatureEncoding,
        .public_key = crypto.PublicKey.fromSec1(public_key_bytes) catch return error.InvalidPublicKeyEncoding,
    };
}

fn readDirectPush(script_bytes: []const u8, cursor: *usize) Error![]const u8 {
    if (cursor.* >= script_bytes.len) return error.InvalidPushData;

    const push_len = script_bytes[cursor.*];
    if (push_len == 0 or push_len > 75) return error.InvalidPushData;
    cursor.* += 1;

    if (script_bytes.len < cursor.* + push_len) return error.InvalidPushData;

    const data = script_bytes[cursor.* .. cursor.* + push_len];
    cursor.* += push_len;
    return data;
}

test "interpreter rejects malformed unlocking scripts" {
    const pubkey_hash = crypto.Hash160{ .bytes = [_]u8{0x11} ** 20 };
    const locking_script = Script.init(&p2pkh.encode(pubkey_hash));

    const tx = Transaction{
        .version = 1,
        .inputs = &.{},
        .outputs = &.{},
        .lock_time = 0,
    };

    try std.testing.expectError(error.InvalidPushData, verify(.{
        .allocator = std.testing.allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_satoshis = 0,
        .unlocking_script = Script.init(&[_]u8{0x00}),
        .locking_script = locking_script,
    }));
}
