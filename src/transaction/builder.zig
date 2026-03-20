const std = @import("std");
const crypto = @import("../crypto/lib.zig");
const compat_address = @import("../compat/address.zig");
const script = @import("../script/lib.zig");
const txmod = @import("transaction.zig");
const fees = @import("fees.zig");
const Input = @import("input.zig").Input;
const Output = @import("output.zig").Output;
const p2pkh_spend = @import("templates/p2pkh_spend.zig");

pub const Error = crypto.Secp256k1Error || p2pkh_spend.Error || error{
    MissingSourceOutput,
    MissingSigningKey,
    InputIndexOutOfRange,
    OutputIndexOutOfRange,
    UnsupportedLockingScript,
    KeyMismatch,
};

pub const Builder = struct {
    allocator: std.mem.Allocator,
    version: i32 = 1,
    lock_time: u32 = 0,
    inputs: std.ArrayList(Input) = .empty,
    outputs: std.ArrayList(Output) = .empty,

    pub fn init(allocator: std.mem.Allocator) Builder {
        return .{
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Builder) void {
        for (self.inputs.items) |*input| input.deinit(self.allocator);
        self.inputs.deinit(self.allocator);
        for (self.outputs.items) |*output| output.deinit(self.allocator);
        self.outputs.deinit(self.allocator);
        self.* = init(self.allocator);
    }

    pub fn addInput(self: *Builder, input: Input) !void {
        try self.inputs.append(self.allocator, try cloneInputPreserveAncestry(self.allocator, input));
    }

    pub fn addInputWithOutput(self: *Builder, input: Input, output: Output) !void {
        var cloned = try cloneInputPreserveAncestry(self.allocator, input);
        if (cloned.source_output) |*source_output| source_output.deinit(self.allocator);
        cloned.source_output = try output.clone(self.allocator);
        try self.inputs.append(self.allocator, cloned);
    }

    pub fn addInputFromTx(self: *Builder, source_tx: *const txmod.Transaction, vout: u32) !void {
        const index = std.math.cast(usize, vout) orelse return error.OutputIndexOutOfRange;
        if (index >= source_tx.outputs.len) return error.OutputIndexOutOfRange;
        const source_txid = try source_tx.txid(self.allocator);
        try self.inputs.append(self.allocator, .{
            .previous_outpoint = .{
                .txid = .{ .bytes = source_txid.bytes },
                .index = vout,
            },
            .unlocking_script = .empty(),
            .sequence = 0xffff_ffff,
            .source_output = try source_tx.outputs[index].clone(self.allocator),
            .source_transaction = @ptrCast(source_tx),
        });
    }

    pub fn addOutput(self: *Builder, output: Output) !void {
        try self.outputs.append(self.allocator, try output.clone(self.allocator));
    }

    pub fn payToAddress(self: *Builder, address_text: []const u8, satoshis: i64) !void {
        const decoded = try compat_address.decodeP2pkh(self.allocator, address_text);
        const locking_script = decoded.lockingScript();
        try self.outputs.append(self.allocator, .{
            .satoshis = satoshis,
            .locking_script = try script.Script.init(&locking_script).clone(self.allocator),
        });
    }

    pub fn addChangeOutputToAddress(self: *Builder, address_text: []const u8) !void {
        const decoded = try compat_address.decodeP2pkh(self.allocator, address_text);
        const locking_script = decoded.lockingScript();
        try self.outputs.append(self.allocator, .{
            .satoshis = 0,
            .locking_script = try script.Script.init(&locking_script).clone(self.allocator),
            .change = true,
        });
    }

    pub fn applyFee(self: *Builder, model: anytype, dist: fees.ChangeDistribution) !void {
        var tx = try self.build();
        defer tx.deinit(self.allocator);

        for (@constCast(tx.inputs)) |*input| {
            if (input.unlocking_script.bytes.len != 0) continue;
            const prevout = txmod.sourceOutputForInput(input) orelse return error.MissingSourceOutput;
            if (!script.templates.p2pkh.matches(prevout.locking_script.bytes)) {
                return error.UnsupportedLockingScript;
            }
            input.unlocking_script = try placeholderP2pkhUnlockingScript(self.allocator);
        }

        try fees.fee(&tx, self.allocator, model, dist);
        try self.replaceOutputs(tx.outputs);
    }

    pub fn sign(self: *Builder, private_key: crypto.PrivateKey) !void {
        try self.signImpl(private_key, false);
    }

    pub fn signUnsigned(self: *Builder, private_key: crypto.PrivateKey) !void {
        try self.signImpl(private_key, true);
    }

    pub fn signAllP2pkh(self: *Builder, private_keys: []const crypto.PrivateKey) !void {
        try self.signManyImpl(private_keys, false);
    }

    pub fn signAllUnsignedP2pkh(self: *Builder, private_keys: []const crypto.PrivateKey) !void {
        try self.signManyImpl(private_keys, true);
    }

    pub fn signInputP2pkh(self: *Builder, input_index: usize, private_key: crypto.PrivateKey) !void {
        if (input_index >= self.inputs.items.len) return error.InputIndexOutOfRange;
        try self.signOneInput(input_index, private_key);
    }

    pub fn finalizeSigned(
        self: *Builder,
        private_key: crypto.PrivateKey,
        model: anytype,
        dist: fees.ChangeDistribution,
    ) !txmod.Transaction {
        try self.applyFee(model, dist);
        try self.sign(private_key);
        return self.build();
    }

    pub fn finalizeSignedAllP2pkh(
        self: *Builder,
        private_keys: []const crypto.PrivateKey,
        model: anytype,
        dist: fees.ChangeDistribution,
    ) !txmod.Transaction {
        try self.applyFee(model, dist);
        try self.signAllP2pkh(private_keys);
        return self.build();
    }

    fn signImpl(self: *Builder, private_key: crypto.PrivateKey, unsigned_only: bool) !void {
        const public_key = try private_key.publicKey();
        const pubkey_hash = crypto.hash.hash160(&public_key.bytes);

        for (self.inputs.items) |*input| {
            if (unsigned_only and input.unlocking_script.bytes.len != 0) continue;
            const prevout = txmod.sourceOutputForInput(input) orelse return error.MissingSourceOutput;
            if (!script.templates.p2pkh.matches(prevout.locking_script.bytes)) {
                return error.UnsupportedLockingScript;
            }
            const expected = try script.templates.p2pkh.extractPubKeyHash(prevout.locking_script.bytes);
            if (!expected.eql(pubkey_hash)) return error.KeyMismatch;
        }

        for (self.inputs.items, 0..) |input, index| {
            if (unsigned_only and input.unlocking_script.bytes.len != 0) continue;
            try self.signOneInput(index, private_key);
        }
    }

    fn signOneInput(self: *Builder, input_index: usize, private_key: crypto.PrivateKey) !void {
        const input = &self.inputs.items[input_index];
        const public_key = try private_key.publicKey();
        const pubkey_hash = crypto.hash.hash160(&public_key.bytes);
        const prevout = txmod.sourceOutputForInput(input) orelse return error.MissingSourceOutput;
        if (!script.templates.p2pkh.matches(prevout.locking_script.bytes)) {
            return error.UnsupportedLockingScript;
        }
        const expected = try script.templates.p2pkh.extractPubKeyHash(prevout.locking_script.bytes);
        if (!expected.eql(pubkey_hash)) return error.KeyMismatch;

        var tx = self.transactionView();
        const unlocking_script = try p2pkh_spend.signAndBuildUnlockingScript(
            self.allocator,
            &tx,
            input_index,
            prevout.locking_script,
            prevout.satoshis,
            private_key,
            p2pkh_spend.default_scope,
        );
        input.unlocking_script.deinit(self.allocator);
        input.unlocking_script = unlocking_script;
    }

    fn signManyImpl(self: *Builder, private_keys: []const crypto.PrivateKey, unsigned_only: bool) !void {
        for (self.inputs.items, 0..) |input, index| {
            if (unsigned_only and input.unlocking_script.bytes.len != 0) continue;
            const prevout = txmod.sourceOutputForInput(&input) orelse return error.MissingSourceOutput;
            if (!script.templates.p2pkh.matches(prevout.locking_script.bytes)) {
                return error.UnsupportedLockingScript;
            }
            const expected = try script.templates.p2pkh.extractPubKeyHash(prevout.locking_script.bytes);
            const key = try findSigningKey(private_keys, expected);
            try self.signOneInput(index, key);
        }
    }

    pub fn build(self: *const Builder) !txmod.Transaction {
        const built_inputs = try self.allocator.alloc(Input, self.inputs.items.len);
        errdefer self.allocator.free(built_inputs);
        for (built_inputs) |*input| input.* = Input.empty();
        errdefer for (built_inputs) |*input| input.deinit(self.allocator);
        for (self.inputs.items, 0..) |input, index| {
            built_inputs[index] = try cloneInputPreserveAncestry(self.allocator, input);
        }

        const built_outputs = try self.allocator.alloc(Output, self.outputs.items.len);
        errdefer self.allocator.free(built_outputs);
        for (built_outputs) |*output| output.* = Output.empty();
        errdefer for (built_outputs) |*output| output.deinit(self.allocator);
        for (self.outputs.items, 0..) |output, index| {
            built_outputs[index] = try output.clone(self.allocator);
        }

        return .{
            .version = self.version,
            .inputs = built_inputs,
            .outputs = built_outputs,
            .lock_time = self.lock_time,
        };
    }

    fn transactionView(self: *const Builder) txmod.Transaction {
        return .{
            .version = self.version,
            .inputs = self.inputs.items,
            .outputs = self.outputs.items,
            .lock_time = self.lock_time,
        };
    }

    fn replaceOutputs(self: *Builder, outputs: []const Output) !void {
        for (self.outputs.items) |*output| output.deinit(self.allocator);
        self.outputs.clearRetainingCapacity();
        try self.outputs.ensureTotalCapacity(self.allocator, outputs.len);
        for (outputs) |output| {
            try self.outputs.append(self.allocator, try output.clone(self.allocator));
        }
    }
};

fn cloneInputPreserveAncestry(allocator: std.mem.Allocator, input: Input) !Input {
    var cloned = try input.clone(allocator);
    cloned.source_transaction = input.source_transaction;
    return cloned;
}

fn placeholderP2pkhUnlockingScript(allocator: std.mem.Allocator) !script.Script {
    const bytes = try allocator.alloc(u8, 108);
    @memset(bytes, 0);
    return .{
        .bytes = bytes,
        .owned = true,
    };
}

fn findSigningKey(private_keys: []const crypto.PrivateKey, expected: crypto.Hash160) !crypto.PrivateKey {
    for (private_keys) |private_key| {
        const public_key = try private_key.publicKey();
        if (crypto.hash.hash160(&public_key.bytes).eql(expected)) return private_key;
    }
    return error.MissingSigningKey;
}

test "builder addInput addOutput builds canonical unsigned transaction" {
    const allocator = std.testing.allocator;
    const expected_hex =
        "010000000111111111111111111111111111111111111111111111111111111111111111110200000000feffffff018403000000000000015100000000";
    var builder = Builder.init(allocator);
    defer builder.deinit();

    try builder.addInput(.{
        .previous_outpoint = .{
            .txid = .{ .bytes = [_]u8{0x11} ** 32 },
            .index = 2,
        },
        .unlocking_script = .empty(),
        .sequence = 0xffff_fffe,
        .source_output = .{
            .satoshis = 1000,
            .locking_script = .{ .bytes = &[_]u8{0x51} },
        },
    });
    try builder.addOutput(.{
        .satoshis = 900,
        .locking_script = .{ .bytes = &[_]u8{0x51} },
    });

    var tx = try builder.build();
    defer tx.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), tx.inputs.len);
    try std.testing.expectEqual(@as(usize, 1), tx.outputs.len);
    try std.testing.expectEqual(@as(u32, 2), tx.inputs[0].previous_outpoint.index);
    try std.testing.expectEqual(@as(i64, 900), tx.outputs[0].satoshis);

    const serialized = try tx.serialize(allocator);
    defer allocator.free(serialized);
    const encoded = try allocator.alloc(u8, serialized.len * 2);
    defer allocator.free(encoded);
    _ = try @import("../primitives/lib.zig").hex.encodeLower(serialized, encoded);
    try std.testing.expectEqualStrings(expected_hex, encoded);
}

test "builder payToAddress creates standard p2pkh output" {
    const allocator = std.testing.allocator;
    var builder = Builder.init(allocator);
    defer builder.deinit();

    try builder.payToAddress("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", 42);

    const expected_locking_script = try @import("../primitives/lib.zig").hex.decode(
        allocator,
        "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac",
    );
    defer allocator.free(expected_locking_script);

    try std.testing.expectEqual(@as(usize, 1), builder.outputs.items.len);
    try std.testing.expect(script.templates.p2pkh.matches(builder.outputs.items[0].locking_script.bytes));
    try std.testing.expectEqualSlices(u8, expected_locking_script, builder.outputs.items[0].locking_script.bytes);
    try std.testing.expectEqual(@as(i64, 42), builder.outputs.items[0].satoshis);
}

test "builder sign signs simple p2pkh transaction and built tx survives builder deinit" {
    const allocator = std.testing.allocator;
    var builder = Builder.init(allocator);

    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;
    const private_key = try crypto.PrivateKey.fromBytes(key_bytes);
    const public_key = try private_key.publicKey();
    const pubkey_hash = crypto.hash.hash160(&public_key.bytes);
    const prev_script = script.templates.p2pkh.encode(pubkey_hash);

    try builder.addInput(.{
        .previous_outpoint = .{
            .txid = .{ .bytes = [_]u8{0x22} ** 32 },
            .index = 0,
        },
        .unlocking_script = .empty(),
        .sequence = 0xffff_ffff,
        .source_output = .{
            .satoshis = 1000,
            .locking_script = .{ .bytes = &prev_script },
        },
    });
    try builder.payToAddress("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", 900);
    try builder.sign(private_key);

    try std.testing.expect(builder.inputs.items[0].unlocking_script.bytes.len > 0);

    var tx = try builder.build();
    builder.deinit();
    defer tx.deinit(allocator);

    try std.testing.expect(try @import("../script/interpreter.zig").verifyPrevout(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_output = txmod.sourceOutputForInput(&tx.inputs[0]).?,
        .unlocking_script = tx.inputs[0].unlocking_script,
    }));
}

test "builder sign fails when input source output is missing" {
    const allocator = std.testing.allocator;
    var builder = Builder.init(allocator);
    defer builder.deinit();

    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;
    const private_key = try crypto.PrivateKey.fromBytes(key_bytes);

    try builder.addInput(.{
        .previous_outpoint = .{
            .txid = .{ .bytes = [_]u8{0x33} ** 32 },
            .index = 0,
        },
        .unlocking_script = .empty(),
        .sequence = 0xffff_ffff,
    });

    try std.testing.expectError(error.MissingSourceOutput, builder.sign(private_key));
}

test "builder applyFee fills change output and can signUnsigned afterwards" {
    const allocator = std.testing.allocator;
    var builder = Builder.init(allocator);
    defer builder.deinit();

    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;
    const private_key = try crypto.PrivateKey.fromBytes(key_bytes);
    const public_key = try private_key.publicKey();
    const pubkey_hash = crypto.hash.hash160(&public_key.bytes);
    const prev_script = script.templates.p2pkh.encode(pubkey_hash);

    try builder.addInput(.{
        .previous_outpoint = .{
            .txid = .{ .bytes = [_]u8{0x44} ** 32 },
            .index = 0,
        },
        .unlocking_script = .empty(),
        .sequence = 0xffff_ffff,
        .source_output = .{
            .satoshis = 1000,
            .locking_script = .{ .bytes = &prev_script },
        },
    });
    try builder.payToAddress("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", 900);
    try builder.addChangeOutputToAddress("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");

    const FixedFeeModel = struct {
        pub fn computeFee(_: @This(), _: *const txmod.Transaction) !u64 {
            return 50;
        }
    };
    try builder.applyFee(FixedFeeModel{}, .equal);

    try std.testing.expectEqual(@as(usize, 2), builder.outputs.items.len);
    try std.testing.expect(!builder.outputs.items[0].change);
    try std.testing.expect(builder.outputs.items[1].change);
    try std.testing.expectEqual(@as(i64, 50), builder.outputs.items[1].satoshis);

    try builder.signUnsigned(private_key);
    var tx = try builder.build();
    defer tx.deinit(allocator);
    try std.testing.expect(try @import("../script/interpreter.zig").verifyPrevout(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_output = txmod.sourceOutputForInput(&tx.inputs[0]).?,
        .unlocking_script = tx.inputs[0].unlocking_script,
    }));
}

test "builder applyFee drops zero change output on exact spend" {
    const allocator = std.testing.allocator;
    var builder = Builder.init(allocator);
    defer builder.deinit();

    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;
    const private_key = try crypto.PrivateKey.fromBytes(key_bytes);
    const public_key = try private_key.publicKey();
    const pubkey_hash = crypto.hash.hash160(&public_key.bytes);
    const prev_script = script.templates.p2pkh.encode(pubkey_hash);

    try builder.addInput(.{
        .previous_outpoint = .{
            .txid = .{ .bytes = [_]u8{0x55} ** 32 },
            .index = 0,
        },
        .unlocking_script = .empty(),
        .sequence = 0xffff_ffff,
        .source_output = .{
            .satoshis = 1000,
            .locking_script = .{ .bytes = &prev_script },
        },
    });
    try builder.payToAddress("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", 950);
    try builder.addChangeOutputToAddress("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");

    const FixedFeeModel = struct {
        pub fn computeFee(_: @This(), _: *const txmod.Transaction) !u64 {
            return 50;
        }
    };
    try builder.applyFee(FixedFeeModel{}, .equal);

    try std.testing.expectEqual(@as(usize, 1), builder.outputs.items.len);
    try std.testing.expect(!builder.outputs.items[0].change);
    try builder.sign(private_key);
    var tx = try builder.build();
    defer tx.deinit(allocator);
    try std.testing.expect(try @import("../script/interpreter.zig").verifyPrevout(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_output = txmod.sourceOutputForInput(&tx.inputs[0]).?,
        .unlocking_script = tx.inputs[0].unlocking_script,
    }));
}

test "builder signInputP2pkh signs only the requested input" {
    const allocator = std.testing.allocator;
    var builder = Builder.init(allocator);
    defer builder.deinit();

    var key_a_bytes = [_]u8{0} ** 32;
    key_a_bytes[31] = 1;
    const key_a = try crypto.PrivateKey.fromBytes(key_a_bytes);
    const pub_a = try key_a.publicKey();
    const hash_a = crypto.hash.hash160(&pub_a.bytes);
    const script_a = script.templates.p2pkh.encode(hash_a);

    var key_b_bytes = [_]u8{0} ** 32;
    key_b_bytes[31] = 2;
    const key_b = try crypto.PrivateKey.fromBytes(key_b_bytes);
    const pub_b = try key_b.publicKey();
    const hash_b = crypto.hash.hash160(&pub_b.bytes);
    const script_b = script.templates.p2pkh.encode(hash_b);

    try builder.addInput(.{
        .previous_outpoint = .{
            .txid = .{ .bytes = [_]u8{0x66} ** 32 },
            .index = 0,
        },
        .unlocking_script = .empty(),
        .sequence = 0xffff_ffff,
        .source_output = .{
            .satoshis = 1000,
            .locking_script = .{ .bytes = &script_a },
        },
    });
    try builder.addInput(.{
        .previous_outpoint = .{
            .txid = .{ .bytes = [_]u8{0x77} ** 32 },
            .index = 1,
        },
        .unlocking_script = .empty(),
        .sequence = 0xffff_ffff,
        .source_output = .{
            .satoshis = 900,
            .locking_script = .{ .bytes = &script_b },
        },
    });

    try builder.signInputP2pkh(1, key_b);
    try std.testing.expectEqual(@as(usize, 0), builder.inputs.items[0].unlocking_script.bytes.len);
    var tx = try builder.build();
    defer tx.deinit(allocator);
    try std.testing.expect(try @import("../script/interpreter.zig").verifyPrevout(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 1,
        .previous_output = txmod.sourceOutputForInput(&tx.inputs[1]).?,
        .unlocking_script = tx.inputs[1].unlocking_script,
    }));
}

test "builder finalizeSigned applies fee then signs" {
    const allocator = std.testing.allocator;
    var builder = Builder.init(allocator);
    defer builder.deinit();

    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;
    const private_key = try crypto.PrivateKey.fromBytes(key_bytes);
    const public_key = try private_key.publicKey();
    const pubkey_hash = crypto.hash.hash160(&public_key.bytes);
    const prev_script = script.templates.p2pkh.encode(pubkey_hash);

    try builder.addInput(.{
        .previous_outpoint = .{
            .txid = .{ .bytes = [_]u8{0x88} ** 32 },
            .index = 0,
        },
        .unlocking_script = .empty(),
        .sequence = 0xffff_ffff,
        .source_output = .{
            .satoshis = 1000,
            .locking_script = .{ .bytes = &prev_script },
        },
    });
    try builder.payToAddress("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", 900);
    try builder.addChangeOutputToAddress("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");

    const FixedFeeModel = struct {
        pub fn computeFee(_: @This(), _: *const txmod.Transaction) !u64 {
            return 50;
        }
    };

    var tx = try builder.finalizeSigned(private_key, FixedFeeModel{}, .equal);
    defer tx.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), tx.outputs.len);
    try std.testing.expectEqual(@as(u64, 50), try tx.getFee());
    try std.testing.expect(try @import("../script/interpreter.zig").verifyPrevout(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_output = txmod.sourceOutputForInput(&tx.inputs[0]).?,
        .unlocking_script = tx.inputs[0].unlocking_script,
    }));
}

test "builder signAllP2pkh signs mixed-key inputs" {
    const allocator = std.testing.allocator;
    var builder = Builder.init(allocator);
    defer builder.deinit();

    var key_a_bytes = [_]u8{0} ** 32;
    key_a_bytes[31] = 1;
    const key_a = try crypto.PrivateKey.fromBytes(key_a_bytes);
    const pub_a = try key_a.publicKey();
    const hash_a = crypto.hash.hash160(&pub_a.bytes);
    const script_a = script.templates.p2pkh.encode(hash_a);

    var key_b_bytes = [_]u8{0} ** 32;
    key_b_bytes[31] = 2;
    const key_b = try crypto.PrivateKey.fromBytes(key_b_bytes);
    const pub_b = try key_b.publicKey();
    const hash_b = crypto.hash.hash160(&pub_b.bytes);
    const script_b = script.templates.p2pkh.encode(hash_b);

    try builder.addInput(.{
        .previous_outpoint = .{
            .txid = .{ .bytes = [_]u8{0x90} ** 32 },
            .index = 0,
        },
        .unlocking_script = .empty(),
        .sequence = 0xffff_ffff,
        .source_output = .{
            .satoshis = 1000,
            .locking_script = .{ .bytes = &script_a },
        },
    });
    try builder.addInput(.{
        .previous_outpoint = .{
            .txid = .{ .bytes = [_]u8{0x91} ** 32 },
            .index = 1,
        },
        .unlocking_script = .empty(),
        .sequence = 0xffff_ffff,
        .source_output = .{
            .satoshis = 900,
            .locking_script = .{ .bytes = &script_b },
        },
    });

    try builder.signAllP2pkh(&[_]crypto.PrivateKey{ key_b, key_a });

    var tx = try builder.build();
    defer tx.deinit(allocator);
    try std.testing.expect(try @import("../script/interpreter.zig").verifyPrevout(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_output = txmod.sourceOutputForInput(&tx.inputs[0]).?,
        .unlocking_script = tx.inputs[0].unlocking_script,
    }));
    try std.testing.expect(try @import("../script/interpreter.zig").verifyPrevout(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 1,
        .previous_output = txmod.sourceOutputForInput(&tx.inputs[1]).?,
        .unlocking_script = tx.inputs[1].unlocking_script,
    }));
}
