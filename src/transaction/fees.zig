const std = @import("std");
const primitives = @import("../primitives/lib.zig");
const Transaction = @import("transaction.zig").Transaction;
const Output = @import("output.zig").Output;

pub const ChangeDistribution = enum(u8) {
    equal = 1,
    random = 2,
};

pub const Error = error{
    EmptyPreviousOutput,
    InsufficientInputs,
    RandomDistributionNotImplemented,
    NegativeSatoshis,
    Overflow,
};

pub fn fee(tx: *Transaction, allocator: std.mem.Allocator, model: anytype, dist: ChangeDistribution) !void {
    const sats_in = try totalInputSatoshis(tx);

    while (true) {
        const fee_sats = try model.computeFee(tx);

        var sats_out: u64 = 0;
        var change_outs: usize = 0;
        for (tx.outputs) |out| {
            const sat = try toU64(out.satoshis);
            if (out.change) {
                change_outs += 1;
            } else {
                sats_out = try addU64(sats_out, sat);
            }
        }

        const required = try addU64(sats_out, fee_sats);
        if (sats_in < required) return error.InsufficientInputs;

        const change = sats_in - required;
        if (change_outs == 0) return;

        const change_count = std.math.cast(u64, change_outs) orelse return error.Overflow;
        if (change_count > change) {
            try removeChangeOutputs(tx, allocator);
            continue;
        }

        switch (dist) {
            .random => return error.RandomDistributionNotImplemented,
            .equal => {
                const per = change / change_count;
                const remainder = change % change_count;
                const per_i64 = std.math.cast(primitives.money.Satoshis, per) orelse return error.Overflow;
                const remainder_i64 = std.math.cast(primitives.money.Satoshis, remainder) orelse return error.Overflow;
                var change_index: usize = 0;
                for (@constCast(tx.outputs)) |*out| {
                    if (out.change) {
                        out.satoshis = per_i64 + if (change_index == 0) remainder_i64 else 0;
                        change_index += 1;
                    }
                }
            },
        }
        return;
    }
}

pub fn getFee(tx: *const Transaction) !u64 {
    const total_in = try totalInputSatoshis(tx);
    const total_out = try totalOutputSatoshis(tx);
    if (total_in < total_out) return error.InsufficientInputs;
    return total_in - total_out;
}

pub fn totalInputSatoshis(tx: *const Transaction) !u64 {
    var total: u64 = 0;
    for (tx.inputs) |input| {
        const src = @import("transaction.zig").sourceOutputForInput(&input) orelse return error.EmptyPreviousOutput;
        const sat = try toU64(src.satoshis);
        total = try addU64(total, sat);
    }
    return total;
}

pub fn totalOutputSatoshis(tx: *const Transaction) !u64 {
    var total: u64 = 0;
    for (tx.outputs) |out| {
        const sat = try toU64(out.satoshis);
        total = try addU64(total, sat);
    }
    return total;
}

fn toU64(value: primitives.money.Satoshis) !u64 {
    if (value < 0) return error.NegativeSatoshis;
    return std.math.cast(u64, value) orelse return error.Overflow;
}

fn addU64(a: u64, b: u64) !u64 {
    const sum = @addWithOverflow(a, b);
    if (sum[1] != 0) return error.Overflow;
    return sum[0];
}

fn removeChangeOutputs(tx: *Transaction, allocator: std.mem.Allocator) !void {
    const old_outputs = tx.outputs;
    const new_len = old_outputs.len - countChangeOutputs(old_outputs);
    const new_outputs = try allocator.alloc(Output, new_len);
    var idx: usize = 0;
    for (old_outputs) |out| {
        if (!out.change) {
            new_outputs[idx] = try out.clone(allocator);
            idx += 1;
        }
    }
    for (@constCast(old_outputs)) |*out| out.deinit(allocator);
    allocator.free(old_outputs);
    tx.outputs = new_outputs;
}

fn countChangeOutputs(outputs: []const Output) usize {
    var total: usize = 0;
    for (outputs) |out| {
        if (out.change) total += 1;
    }
    return total;
}

test "total satoshis and fee compute" {
    const allocator = std.testing.allocator;
    const inputs = try allocator.alloc(@import("input.zig").Input, 1);
    inputs[0] = .{
        .previous_outpoint = .{
            .txid = .{ .bytes = [_]u8{0x11} ** 32 },
            .index = 0,
        },
        .unlocking_script = .{ .bytes = &[_]u8{0x51} },
        .sequence = 0xffffffff,
        .source_output = .{
            .satoshis = 1500,
            .locking_script = .{ .bytes = &[_]u8{0x51} },
        },
    };

    const outputs = try allocator.alloc(Output, 2);
    outputs[0] = .{
        .satoshis = 500,
        .locking_script = .{ .bytes = &[_]u8{0x51} },
    };
    outputs[1] = .{
        .satoshis = 0,
        .locking_script = .{ .bytes = &[_]u8{0x51} },
        .change = true,
    };

    var tx = Transaction{
        .version = 1,
        .inputs = inputs,
        .outputs = outputs,
        .lock_time = 0,
    };
    defer tx.deinit(allocator);

    var fee_model = @import("fee_model/sats_per_kb.zig").SatoshisPerKilobyte{
        .satoshis = 1000,
    };

    try fee(&tx, allocator, &fee_model, .equal);

    const total_in = try totalInputSatoshis(&tx);
    const total_out = try totalOutputSatoshis(&tx);
    try std.testing.expectEqual(total_in, total_out + try getFee(&tx));
}

test "fee distributes remainder to first change output" {
    const allocator = std.testing.allocator;
    const inputs = try allocator.alloc(@import("input.zig").Input, 1);
    const outputs = try allocator.alloc(Output, 3);

    var tx = Transaction{
        .version = 1,
        .inputs = inputs,
        .outputs = outputs,
        .lock_time = 0,
    };
    defer tx.deinit(allocator);

    inputs[0] = .{
        .previous_outpoint = .{
            .txid = .{ .bytes = [_]u8{0x11} ** 32 },
            .index = 0,
        },
        .unlocking_script = .{ .bytes = &[_]u8{0x51} },
        .sequence = 0xffff_ffff,
        .source_output = .{
            .satoshis = 1003,
            .locking_script = .{ .bytes = &[_]u8{0x51} },
        },
    };
    outputs[0] = .{ .satoshis = 1000, .locking_script = .{ .bytes = &[_]u8{0x51} } };
    outputs[1] = .{ .satoshis = 0, .locking_script = .{ .bytes = &[_]u8{0x51} }, .change = true };
    outputs[2] = .{ .satoshis = 0, .locking_script = .{ .bytes = &[_]u8{0x51} }, .change = true };

    const ZeroFeeModel = struct {
        pub fn computeFee(_: @This(), _: *Transaction) !u64 {
            return 0;
        }
    };
    try fee(&tx, allocator, ZeroFeeModel{}, .equal);

    try std.testing.expectEqual(@as(i64, 2), tx.outputs[1].satoshis);
    try std.testing.expectEqual(@as(i64, 1), tx.outputs[2].satoshis);
}
