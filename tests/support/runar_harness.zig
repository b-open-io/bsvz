const std = @import("std");
const bsvz = @import("bsvz");

const Script = bsvz.script.Script;

pub const PushValue = union(enum) {
    int: i64,
    boolean: bool,
    hex: []const u8,
    script_num_hex: []const u8,
    signature: void,
};

pub const SpendSpec = struct {
    previous_satoshis: i64 = 100_000,
    signing_key: [32]u8,
};

pub const VerificationOutcome = bsvz.script.thread.VerificationOutcome;
pub const VerificationResult = bsvz.script.thread.VerificationResult;
pub const TracedVerificationResult = bsvz.script.thread.TracedVerificationResult;

pub const Case = struct {
    name: []const u8,
    locking_script_hex: []const u8,
    args: []const PushValue,
    method_selector: ?i64 = null,
    expect_success: bool,
    spend: ?SpendSpec = null,
};

const default_output_script = [_]u8{0x6a};

pub fn verificationOutcome(result: bsvz.script.thread.Error!bool) VerificationOutcome {
    return bsvz.script.thread.verificationOutcome(result);
}

pub fn runCaseDetailed(allocator: std.mem.Allocator, case: Case) !VerificationResult {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    errdefer arena_state.deinit();
    const arena = arena_state.allocator();

    const locking_script_bytes = try bsvz.primitives.hex.decode(arena, case.locking_script_hex);
    const locking_script = Script.init(locking_script_bytes);

    var signature_bytes: ?[]const u8 = null;

    var inputs = [_]bsvz.transaction.Input{
        .{
            .previous_outpoint = .{
                .txid = .{ .bytes = [_]u8{0xaa} ** 32 },
                .index = 0,
            },
            .unlocking_script = Script.init(""),
            .sequence = 0xffff_ffff,
        },
    };
    var outputs = [_]bsvz.transaction.Output{
        .{
            .satoshis = 99_000,
            .locking_script = Script.init(&default_output_script),
        },
    };
    var tx = bsvz.transaction.Transaction{
        .version = 2,
        .inputs = &inputs,
        .outputs = &outputs,
        .lock_time = 0,
    };

    if (case.spend) |spend| {
        outputs[0].satoshis = spend.previous_satoshis - 1_000;
        const private_key = try bsvz.crypto.PrivateKey.fromBytes(spend.signing_key);
        const tx_signature = try bsvz.transaction.templates.p2pkh_spend.signInput(
            arena,
            &tx,
            0,
            locking_script,
            spend.previous_satoshis,
            private_key,
            bsvz.transaction.templates.p2pkh_spend.default_scope,
        );
        signature_bytes = try tx_signature.toChecksigFormat(arena);
    }

    const unlocking_script = try buildUnlockingScript(arena, case.args, case.method_selector, signature_bytes);
    defer arena_state.deinit();

    if (case.spend) |spend| {
        const previous_output = bsvz.transaction.Output{
            .satoshis = spend.previous_satoshis,
            .locking_script = locking_script,
        };
        return bsvz.script.interpreter.verifyPrevoutDetailed(.{
            .allocator = allocator,
            .tx = &tx,
            .input_index = 0,
            .previous_output = previous_output,
            .unlocking_script = unlocking_script,
        });
    }

    return bsvz.script.thread.verifyScriptsDetailed(.{
        .allocator = allocator,
    }, unlocking_script, locking_script);
}

pub fn runCaseTraced(allocator: std.mem.Allocator, case: Case) !TracedVerificationResult {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    errdefer arena_state.deinit();
    const arena = arena_state.allocator();

    const locking_script_bytes = try bsvz.primitives.hex.decode(arena, case.locking_script_hex);
    const locking_script = Script.init(locking_script_bytes);

    var signature_bytes: ?[]const u8 = null;

    var inputs = [_]bsvz.transaction.Input{
        .{
            .previous_outpoint = .{
                .txid = .{ .bytes = [_]u8{0xaa} ** 32 },
                .index = 0,
            },
            .unlocking_script = Script.init(""),
            .sequence = 0xffff_ffff,
        },
    };
    var outputs = [_]bsvz.transaction.Output{
        .{
            .satoshis = 99_000,
            .locking_script = Script.init(&default_output_script),
        },
    };
    var tx = bsvz.transaction.Transaction{
        .version = 2,
        .inputs = &inputs,
        .outputs = &outputs,
        .lock_time = 0,
    };

    if (case.spend) |spend| {
        outputs[0].satoshis = spend.previous_satoshis - 1_000;
        const private_key = try bsvz.crypto.PrivateKey.fromBytes(spend.signing_key);
        const tx_signature = try bsvz.transaction.templates.p2pkh_spend.signInput(
            arena,
            &tx,
            0,
            locking_script,
            spend.previous_satoshis,
            private_key,
            bsvz.transaction.templates.p2pkh_spend.default_scope,
        );
        signature_bytes = try tx_signature.toChecksigFormat(arena);
    }

    const unlocking_script = try buildUnlockingScript(arena, case.args, case.method_selector, signature_bytes);
    defer arena_state.deinit();

    if (case.spend) |spend| {
        const previous_output = bsvz.transaction.Output{
            .satoshis = spend.previous_satoshis,
            .locking_script = locking_script,
        };
        return bsvz.script.interpreter.verifyPrevoutTraced(.{
            .allocator = allocator,
            .tx = &tx,
            .input_index = 0,
            .previous_output = previous_output,
            .unlocking_script = unlocking_script,
        });
    }

    return bsvz.script.thread.verifyScriptsTraced(.{
        .allocator = allocator,
    }, unlocking_script, locking_script);
}

pub fn runCaseOutcome(allocator: std.mem.Allocator, case: Case) !VerificationOutcome {
    var result = try runCaseDetailed(allocator, case);
    return result.deinitToOutcome(allocator);
}

pub fn runCase(allocator: std.mem.Allocator, case: Case) !bool {
    return switch (try runCaseOutcome(allocator, case)) {
        .success => true,
        .false_result => false,
        .script_error => |err| return err,
    };
}

fn buildUnlockingScript(
    allocator: std.mem.Allocator,
    args: []const PushValue,
    method_selector: ?i64,
    signature_bytes: ?[]const u8,
) !Script {
    var bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer bytes.deinit(allocator);

    for (args) |arg| {
        try appendPushValue(&bytes, allocator, arg, signature_bytes);
    }
    if (method_selector) |selector| {
        try appendScriptNumberPush(&bytes, allocator, selector);
    }

    return .{ .bytes = try bytes.toOwnedSlice(allocator) };
}

fn appendPushValue(
    bytes: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    value: PushValue,
    signature_bytes: ?[]const u8,
) !void {
    switch (value) {
        .int => |int_value| try appendScriptNumberPush(bytes, allocator, int_value),
        .boolean => |boolean_value| try bytes.append(allocator, if (boolean_value) 0x51 else 0x00),
        .hex => |hex_value| {
            const decoded = try bsvz.primitives.hex.decode(allocator, hex_value);
            try appendPushData(bytes, allocator, decoded);
        },
        .script_num_hex => |hex_value| {
            var managed = try std.math.big.int.Managed.init(allocator);
            try managed.setString(16, hex_value);

            var script_num = bsvz.script.ScriptNum{ .big = managed };
            defer script_num.deinit();

            const encoded = try script_num.encodeOwned(allocator);
            try appendPushData(bytes, allocator, encoded);
        },
        .signature => {
            const checksig_bytes = signature_bytes orelse return error.MissingSignatureMaterial;
            try appendPushData(bytes, allocator, checksig_bytes);
        },
    }
}

fn appendScriptNumberPush(
    bytes: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    value: i64,
) !void {
    const encoded = try bsvz.script.ScriptNum.encode(allocator, value);
    try appendPushData(bytes, allocator, encoded);
}

fn appendPushData(
    bytes: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    data: []const u8,
) !void {
    if (data.len == 0) {
        try bytes.append(allocator, 0x00);
        return;
    }

    if (data.len <= 75) {
        try bytes.append(allocator, @intCast(data.len));
    } else if (data.len <= std.math.maxInt(u8)) {
        try bytes.append(allocator, 0x4c);
        try bytes.append(allocator, @intCast(data.len));
    } else if (data.len <= std.math.maxInt(u16)) {
        try bytes.append(allocator, 0x4d);
        var len_buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &len_buf, @intCast(data.len), .little);
        try bytes.appendSlice(allocator, &len_buf);
    } else {
        try bytes.append(allocator, 0x4e);
        var len_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &len_buf, @intCast(data.len), .little);
        try bytes.appendSlice(allocator, &len_buf);
    }

    try bytes.appendSlice(allocator, data);
}

test "runar harness can return traced verification results" {
    const allocator = std.testing.allocator;

    var traced = try runCaseTraced(allocator, .{
        .name = "trace-demo",
        .locking_script_hex = "5176",
        .args = &.{},
        .expect_success = true,
    });
    defer traced.deinit(allocator);

    try std.testing.expect(traced.result.success);
    try std.testing.expect(traced.trace.steps.items.len >= 2);
}
