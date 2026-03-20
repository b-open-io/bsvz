const std = @import("std");
const primitives = @import("../../primitives/lib.zig");
const Transaction = @import("../transaction.zig").Transaction;
const errors = @import("errors.zig");

pub const Error = errors.Error || error{
    Overflow,
};

pub const SatoshisPerKilobyte = struct {
    satoshis: u64,

    pub fn computeFee(self: *const SatoshisPerKilobyte, tx: *const Transaction) Error!u64 {
        var size: u64 = 4;
        size = try addU64(size, try lenU64(primitives.varint.VarInt.encodedLen(try lenU64(tx.inputs.len))));
        for (tx.inputs) |input| {
            size = try addU64(size, 40);
            const script_len = input.unlocking_script.bytes.len;
            if (script_len == 0) return error.NoUnlockingScript;
            size = try addU64(size, try lenU64(primitives.varint.VarInt.encodedLen(try lenU64(script_len))));
            size = try addU64(size, try lenU64(script_len));
        }
        size = try addU64(size, try lenU64(primitives.varint.VarInt.encodedLen(try lenU64(tx.outputs.len))));
        for (tx.outputs) |out| {
            size = try addU64(size, 8);
            const script_len = out.locking_script.bytes.len;
            size = try addU64(size, try lenU64(primitives.varint.VarInt.encodedLen(try lenU64(script_len))));
            size = try addU64(size, try lenU64(script_len));
        }
        size = try addU64(size, 4);
        return calculateFee(size, self.satoshis);
    }
};

pub fn calculateFee(tx_size_bytes: u64, satoshis_per_kb: u64) Error!u64 {
    const product = @as(u128, tx_size_bytes) * @as(u128, satoshis_per_kb);
    const fee = (product + 999) / 1000;
    return std.math.cast(u64, fee) orelse return error.Overflow;
}

fn lenU64(value: usize) Error!u64 {
    return std.math.cast(u64, value) orelse return error.Overflow;
}

fn addU64(a: u64, b: u64) Error!u64 {
    const sum = @addWithOverflow(a, b);
    if (sum[1] != 0) return error.Overflow;
    return sum[0];
}

test "calculate fee matches sats per kb table" {
    const cases = [_]struct {
        size: u64,
        sats_per_kb: u64,
        expected: u64,
    }{
        .{ .size = 240, .sats_per_kb = 100, .expected = 24 },
        .{ .size = 240, .sats_per_kb = 1, .expected = 1 },
        .{ .size = 240, .sats_per_kb = 10, .expected = 3 },
        .{ .size = 250, .sats_per_kb = 500, .expected = 125 },
        .{ .size = 1000, .sats_per_kb = 100, .expected = 100 },
        .{ .size = 1500, .sats_per_kb = 100, .expected = 150 },
        .{ .size = 1500, .sats_per_kb = 500, .expected = 750 },
    };

    for (cases) |case| {
        const fee = try calculateFee(case.size, case.sats_per_kb);
        try std.testing.expectEqual(case.expected, fee);
    }
}
