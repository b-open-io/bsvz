const std = @import("std");
const context = @import("context.zig");
const crypto = @import("../crypto/lib.zig");
const errors = @import("errors.zig");
const hash = @import("../crypto/hash.zig");
const num = @import("num.zig");
const opcode = @import("opcode.zig");
const parser = @import("parser.zig");
const chunk = @import("chunk.zig");
const Script = @import("script.zig").Script;
const script_helpers = @import("bytes.zig");
const sighash = @import("../transaction/sighash.zig");

pub const Error = errors.ScriptError || sighash.Error || num.Error || error{
    OutOfMemory,
};

const ActiveScript = enum {
    unlocking,
    locking,
};

const secp256k1_half_order_be = [_]u8{
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
    0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
};

pub const ExecutionContext = context.ExecutionContext;
pub const ExecutionFlags = context.ExecutionFlags;
pub const ExecutionState = context.ExecutionState;
pub const ExecutionResult = context.ExecutionResult;

pub fn isTruthy(item: []const u8) bool {
    if (item.len == 0) return false;

    for (item, 0..) |byte, index| {
        if (byte != 0) {
            return !(index == item.len - 1 and byte == 0x80);
        }
    }

    return false;
}

pub fn parseScript(allocator: std.mem.Allocator, bytes: []const u8) Error![]chunk.ScriptChunk {
    return parser.parseAlloc(allocator, Script.init(bytes));
}

pub fn serializeScript(allocator: std.mem.Allocator, chunks: []const chunk.ScriptChunk) Error![]u8 {
    return parser.serializeAlloc(allocator, chunks);
}

pub fn isPushOnly(script: Script) Error!bool {
    return parser.isPushOnly(script);
}

pub fn executeScript(ctx: ExecutionContext, script: Script) Error!ExecutionResult {
    var state: ExecutionState = .{};
    errdefer state.deinit(ctx.allocator);

    try executeIntoState(ctx, &state, .locking, script);
    if (state.condition_stack.items.len != 0) return error.UnbalancedConditionals;

    return .{
        .success = state.stack.items.len > 0 and isTruthy(state.stack.items[state.stack.items.len - 1]),
        .state = state,
    };
}

pub fn executeUnlockingScript(ctx: ExecutionContext, state: *ExecutionState, script: Script) Error!void {
    try executeIntoState(ctx, state, .unlocking, script);
}

pub fn executeLockingScript(ctx: ExecutionContext, state: *ExecutionState, script: Script) Error!void {
    try executeIntoState(ctx, state, .locking, script);
}

pub fn verifyScripts(ctx: ExecutionContext, unlocking_script: Script, locking_script: Script) Error!bool {
    var state: ExecutionState = .{};
    defer state.deinit(ctx.allocator);

    if (ctx.flags.sig_push_only and !(try isPushOnly(unlocking_script))) return error.SigPushOnly;

    executeIntoState(ctx, &state, .unlocking, unlocking_script) catch |err| switch (err) {
        error.VerifyFailed, error.ReturnEncountered => return false,
        else => return err,
    };
    state.clearAltStack(ctx.allocator);
    executeIntoState(ctx, &state, .locking, locking_script) catch |err| switch (err) {
        error.VerifyFailed, error.ReturnEncountered => return false,
        else => return err,
    };

    if (state.condition_stack.items.len != 0) return error.UnbalancedConditionals;
    if (state.stack.items.len == 0) return false;
    if (ctx.flags.clean_stack and state.stack.items.len != 1) return error.CleanStack;
    return isTruthy(state.stack.items[state.stack.items.len - 1]);
}

fn executeIntoState(
    ctx: ExecutionContext,
    state: *ExecutionState,
    active_script: ActiveScript,
    script: Script,
) Error!void {
    var cursor: usize = 0;
    var early_return_after_genesis = false;
    state.last_code_separator = 0;

    while (cursor < script.bytes.len) {
        const byte = script.bytes[cursor];
        cursor += 1;

        if (byte >= 0x01 and byte <= 0x4b) {
            if (byte > ctx.flags.max_script_element_size) return error.ElementTooBig;
            if (!early_return_after_genesis and shouldExecute(state)) {
                if (script.bytes.len < cursor + byte) return error.InvalidPushData;
                if (ctx.flags.minimal_data and !isMinimalPush(byte, script.bytes[cursor .. cursor + byte])) return error.MinimalData;
                try pushCopy(ctx, state, script.bytes[cursor .. cursor + byte]);
            } else if (script.bytes.len < cursor + byte) {
                return error.InvalidPushData;
            }
            cursor += byte;
            continue;
        }

        if (byte == @intFromEnum(opcode.Opcode.OP_0)) {
            if (!early_return_after_genesis and shouldExecute(state)) try pushBool(ctx, state, false);
            continue;
        }

        if (byte == @intFromEnum(opcode.Opcode.OP_PUSHDATA1)) {
            const len = try readPushLength(u8, script.bytes, &cursor);
            if (len > ctx.flags.max_script_element_size) return error.ElementTooBig;
            if (script.bytes.len < cursor + len) return error.InvalidPushData;
            if (!early_return_after_genesis and shouldExecute(state)) {
                if (ctx.flags.minimal_data and !isMinimalPush(byte, script.bytes[cursor .. cursor + len])) return error.MinimalData;
                try pushCopy(ctx, state, script.bytes[cursor .. cursor + len]);
            }
            cursor += len;
            continue;
        }

        if (byte == @intFromEnum(opcode.Opcode.OP_PUSHDATA2)) {
            const len = try readPushLength(u16, script.bytes, &cursor);
            if (len > ctx.flags.max_script_element_size) return error.ElementTooBig;
            if (script.bytes.len < cursor + len) return error.InvalidPushData;
            if (!early_return_after_genesis and shouldExecute(state)) {
                if (ctx.flags.minimal_data and !isMinimalPush(byte, script.bytes[cursor .. cursor + len])) return error.MinimalData;
                try pushCopy(ctx, state, script.bytes[cursor .. cursor + len]);
            }
            cursor += len;
            continue;
        }

        if (byte == @intFromEnum(opcode.Opcode.OP_PUSHDATA4)) {
            const len = try readPushLength(u32, script.bytes, &cursor);
            if (len > ctx.flags.max_script_element_size) return error.ElementTooBig;
            if (script.bytes.len < cursor + len) return error.InvalidPushData;
            if (!early_return_after_genesis and shouldExecute(state)) {
                if (ctx.flags.minimal_data and !isMinimalPush(byte, script.bytes[cursor .. cursor + len])) return error.MinimalData;
                try pushCopy(ctx, state, script.bytes[cursor .. cursor + len]);
            }
            cursor += len;
            continue;
        }

        const op = opcode.Opcode.fromByte(byte);
        if (op.smallIntegerValue()) |small_int| {
            if (!early_return_after_genesis and shouldExecute(state)) try pushNum(ctx, state, small_int);
            continue;
        }

        switch (op) {
            .OP_IF, .OP_NOTIF => {
                try countOp(ctx, state);
                if (!early_return_after_genesis and shouldExecute(state)) {
                    const cond_bytes = try popOwned(state);
                    defer ctx.allocator.free(cond_bytes);
                    if (ctx.flags.minimal_if) {
                        if (cond_bytes.len > 1) return error.MinimalIf;
                        if (cond_bytes.len == 1 and cond_bytes[0] != 0x01) return error.MinimalIf;
                    }
                    const cond = isTruthy(cond_bytes);
                    try state.condition_stack.append(ctx.allocator, if (op == .OP_IF) cond else !cond);
                } else {
                    try state.condition_stack.append(ctx.allocator, false);
                }
                try state.else_seen_stack.append(ctx.allocator, false);
                continue;
            },
            .OP_ELSE => {
                if (state.condition_stack.items.len == 0) return error.UnexpectedElse;
                const last_index = state.condition_stack.items.len - 1;
                if (state.else_seen_stack.items[last_index]) return error.UnexpectedElse;
                const parent_exec = if (last_index == 0) true else allTrue(state.condition_stack.items[0..last_index]);
                state.condition_stack.items[last_index] = parent_exec and !state.condition_stack.items[last_index];
                state.else_seen_stack.items[last_index] = true;
                continue;
            },
            .OP_ENDIF => {
                if (state.condition_stack.items.len == 0) return error.UnexpectedEndIf;
                _ = state.condition_stack.pop();
                _ = state.else_seen_stack.pop();
                continue;
            },
            else => {},
        }

        if (early_return_after_genesis or !shouldExecute(state)) continue;

        if (!ctx.flags.enable_reenabled_opcodes) {
            switch (op) {
                .OP_CAT,
                .OP_SPLIT,
                .OP_NUM2BIN,
                .OP_BIN2NUM,
                .OP_SIZE,
                .OP_INVERT,
                .OP_AND,
                .OP_OR,
                .OP_XOR,
                .OP_MUL,
                .OP_DIV,
                .OP_MOD,
                .OP_LSHIFT,
                .OP_RSHIFT,
                => return error.UnknownOpcode,
                else => {},
            }
        }

        switch (op) {
            .OP_0, .OP_PUSHDATA1, .OP_PUSHDATA2, .OP_PUSHDATA4, .OP_1NEGATE, .OP_1, .OP_2, .OP_3, .OP_4, .OP_5, .OP_6, .OP_7, .OP_8, .OP_9, .OP_10, .OP_11, .OP_12, .OP_13, .OP_14, .OP_15, .OP_16, .OP_IF, .OP_NOTIF, .OP_ELSE, .OP_ENDIF => unreachable,
            .OP_NOP => try countOp(ctx, state),
            .OP_VERIFY => {
                try countOp(ctx, state);
                const value = try popOwned(state);
                defer ctx.allocator.free(value);
                if (!isTruthy(value)) return error.VerifyFailed;
            },
            .OP_RETURN => {
                if (!ctx.flags.utxo_after_genesis) return error.ReturnEncountered;
                if (state.condition_stack.items.len == 0) return;
                early_return_after_genesis = true;
            },
            .OP_CODESEPARATOR => {
                try countOp(ctx, state);
                if (active_script == .locking) state.last_code_separator = cursor;
            },
            .OP_TOALTSTACK => {
                try countOp(ctx, state);
                const item = try popOwned(state);
                try state.alt_stack.append(ctx.allocator, item);
                try checkStackSize(ctx, state);
            },
            .OP_FROMALTSTACK => {
                try countOp(ctx, state);
                if (state.alt_stack.items.len == 0) return error.AltStackUnderflow;
                const item = state.alt_stack.pop() orelse unreachable;
                try state.stack.append(ctx.allocator, item);
                try checkStackSize(ctx, state);
            },
            .OP_2DROP => {
                try countOp(ctx, state);
                const a = try popOwned(state);
                defer ctx.allocator.free(a);
                const b = try popOwned(state);
                defer ctx.allocator.free(b);
            },
            .OP_2DUP => {
                try countOp(ctx, state);
                const a = try peek(state, 1);
                const b = try peek(state, 0);
                try pushCopy(ctx, state, a);
                try pushCopy(ctx, state, b);
            },
            .OP_3DUP => {
                try countOp(ctx, state);
                try pushCopy(ctx, state, try peek(state, 2));
                try pushCopy(ctx, state, try peek(state, 1));
                try pushCopy(ctx, state, try peek(state, 0));
            },
            .OP_2OVER => {
                try countOp(ctx, state);
                try pushCopy(ctx, state, try peek(state, 3));
                try pushCopy(ctx, state, try peek(state, 2));
            },
            .OP_2ROT => {
                try countOp(ctx, state);
                if (state.stack.items.len < 6) return error.StackUnderflow;
                const index = state.stack.items.len - 6;
                const a = state.stack.orderedRemove(index);
                const b = state.stack.orderedRemove(index);
                try state.stack.append(ctx.allocator, a);
                try state.stack.append(ctx.allocator, b);
                try checkStackSize(ctx, state);
            },
            .OP_2SWAP => {
                try countOp(ctx, state);
                if (state.stack.items.len < 4) return error.StackUnderflow;
                const len = state.stack.items.len;
                const a = state.stack.items[len - 4];
                const b = state.stack.items[len - 3];
                const c = state.stack.items[len - 2];
                const d = state.stack.items[len - 1];
                state.stack.items[len - 4] = c;
                state.stack.items[len - 3] = d;
                state.stack.items[len - 2] = a;
                state.stack.items[len - 1] = b;
            },
            .OP_IFDUP => {
                try countOp(ctx, state);
                const top = try peek(state, 0);
                if (isTruthy(top)) try pushCopy(ctx, state, top);
            },
            .OP_DEPTH => {
                try countOp(ctx, state);
                try pushNum(ctx, state, @intCast(state.stack.items.len));
            },
            .OP_DROP => {
                try countOp(ctx, state);
                const value = try popOwned(state);
                defer ctx.allocator.free(value);
            },
            .OP_DUP => {
                try countOp(ctx, state);
                try pushCopy(ctx, state, try peek(state, 0));
            },
            .OP_NIP => {
                try countOp(ctx, state);
                if (state.stack.items.len < 2) return error.StackUnderflow;
                const value = state.stack.orderedRemove(state.stack.items.len - 2);
                ctx.allocator.free(value);
            },
            .OP_OVER => {
                try countOp(ctx, state);
                try pushCopy(ctx, state, try peek(state, 1));
            },
            .OP_PICK => {
                try countOp(ctx, state);
                const n = try popIndex(ctx, state);
                try pushCopy(ctx, state, try peek(state, n));
            },
            .OP_ROLL => {
                try countOp(ctx, state);
                const n = try popIndex(ctx, state);
                const index = state.stack.items.len - 1 - n;
                const item = state.stack.orderedRemove(index);
                try state.stack.append(ctx.allocator, item);
            },
            .OP_ROT => {
                try countOp(ctx, state);
                if (state.stack.items.len < 3) return error.StackUnderflow;
                const index = state.stack.items.len - 3;
                const item = state.stack.orderedRemove(index);
                try state.stack.append(ctx.allocator, item);
            },
            .OP_SWAP => {
                try countOp(ctx, state);
                if (state.stack.items.len < 2) return error.StackUnderflow;
                const len = state.stack.items.len;
                std.mem.swap([]u8, &state.stack.items[len - 1], &state.stack.items[len - 2]);
            },
            .OP_TUCK => {
                try countOp(ctx, state);
                if (state.stack.items.len < 2) return error.StackUnderflow;
                try ensureCanGrow(ctx, state, 1);
                const copy = try ctx.allocator.dupe(u8, state.stack.items[state.stack.items.len - 1]);
                errdefer ctx.allocator.free(copy);
                try state.stack.insert(ctx.allocator, state.stack.items.len - 1, copy);
                if (state.stack.items.len + state.alt_stack.items.len > state.max_stack_depth) {
                    state.max_stack_depth = state.stack.items.len + state.alt_stack.items.len;
                }
            },
            .OP_CAT => {
                try countOp(ctx, state);
                const right = try popOwned(state);
                defer ctx.allocator.free(right);
                const left = try popOwned(state);
                defer ctx.allocator.free(left);
                var out = try ctx.allocator.alloc(u8, left.len + right.len);
                @memcpy(out[0..left.len], left);
                @memcpy(out[left.len..], right);
                try pushOwned(ctx, state, out);
            },
            .OP_SPLIT => {
                try countOp(ctx, state);
                const position = try popIndex(ctx, state);
                const data = try popOwned(state);
                defer ctx.allocator.free(data);
                if (position > data.len) return error.InvalidSplitPosition;
                try pushCopy(ctx, state, data[0..position]);
                try pushCopy(ctx, state, data[position..]);
            },
            .OP_NUM2BIN => {
                try countOp(ctx, state);
                const size = try popIndex(ctx, state);
                if (size > ctx.flags.max_script_element_size) return error.NumberTooBig;
                const value_bytes = try popOwned(state);
                defer ctx.allocator.free(value_bytes);
                var value = try decodeScriptNum(ctx, value_bytes);
                defer value.deinit();
                const encoded = try value.num2binOwned(ctx.allocator, size);
                try pushOwned(ctx, state, encoded);
            },
            .OP_BIN2NUM => {
                try countOp(ctx, state);
                const value_bytes = try popOwned(state);
                defer ctx.allocator.free(value_bytes);
                var value = try num.ScriptNum.bin2num(ctx.allocator, value_bytes);
                defer value.deinit();
                const minimal = try value.encodeOwned(ctx.allocator);
                defer ctx.allocator.free(minimal);
                if (minimal.len > ctx.flags.max_script_number_length) return error.NumberTooBig;
                try pushCopy(ctx, state, minimal);
            },
            .OP_SIZE => {
                try countOp(ctx, state);
                try pushNum(ctx, state, @intCast((try peek(state, 0)).len));
            },
            .OP_INVERT => {
                try countOp(ctx, state);
                const data = try popOwned(state);
                defer ctx.allocator.free(data);
                var out = try ctx.allocator.alloc(u8, data.len);
                for (data, 0..) |byte_value, index| out[index] = ~byte_value;
                try pushOwned(ctx, state, out);
            },
            .OP_AND, .OP_OR, .OP_XOR => {
                try countOp(ctx, state);
                const right = try popOwned(state);
                defer ctx.allocator.free(right);
                const left = try popOwned(state);
                defer ctx.allocator.free(left);
                if (left.len != right.len) return error.InvalidOperandSize;
                var out = try ctx.allocator.alloc(u8, left.len);
                for (left, right, 0..) |left_byte, right_byte, index| {
                    out[index] = switch (op) {
                        .OP_AND => left_byte & right_byte,
                        .OP_OR => left_byte | right_byte,
                        .OP_XOR => left_byte ^ right_byte,
                        else => unreachable,
                    };
                }
                try pushOwned(ctx, state, out);
            },
            .OP_EQUAL => {
                try countOp(ctx, state);
                const right = try popOwned(state);
                defer ctx.allocator.free(right);
                const left = try popOwned(state);
                defer ctx.allocator.free(left);
                try pushBool(ctx, state, std.mem.eql(u8, left, right));
            },
            .OP_EQUALVERIFY => {
                try countOp(ctx, state);
                const right = try popOwned(state);
                defer ctx.allocator.free(right);
                const left = try popOwned(state);
                defer ctx.allocator.free(left);
                if (!std.mem.eql(u8, left, right)) return error.VerifyFailed;
            },
            .OP_1ADD, .OP_1SUB, .OP_NEGATE, .OP_ABS, .OP_NOT, .OP_0NOTEQUAL => {
                try countOp(ctx, state);
                var value = try popNum(ctx, state);
                defer value.deinit();
                if (op == .OP_NOT or op == .OP_0NOTEQUAL) {
                    try pushBool(ctx, state, if (op == .OP_NOT) value.isZero() else !value.isZero());
                } else {
                    var out = switch (op) {
                        .OP_1ADD => try value.add(&num.ScriptNum.fromInt(1), ctx.allocator),
                        .OP_1SUB => try value.sub(&num.ScriptNum.fromInt(1), ctx.allocator),
                        .OP_NEGATE => try value.negate(ctx.allocator),
                        .OP_ABS => try value.abs(ctx.allocator),
                        else => unreachable,
                    };
                    defer out.deinit();
                    try pushScriptNum(ctx, state, &out);
                }
            },
            .OP_ADD, .OP_SUB, .OP_MUL, .OP_DIV, .OP_MOD => {
                try countOp(ctx, state);
                var right = try popNum(ctx, state);
                defer right.deinit();
                var left = try popNum(ctx, state);
                defer left.deinit();
                if (right.isZero() and (op == .OP_DIV or op == .OP_MOD)) return error.DivisionByZero;
                var out = switch (op) {
                    .OP_ADD => try left.add(&right, ctx.allocator),
                    .OP_SUB => try left.sub(&right, ctx.allocator),
                    .OP_MUL => try left.mul(&right, ctx.allocator),
                    .OP_DIV => try left.divTrunc(&right, ctx.allocator),
                    .OP_MOD => try left.mod(&right, ctx.allocator),
                    else => unreachable,
                };
                defer out.deinit();
                try pushScriptNum(ctx, state, &out);
            },
            .OP_LSHIFT, .OP_RSHIFT => {
                try countOp(ctx, state);
                const shift = try popIndex(ctx, state);
                const data = try popOwned(state);
                defer ctx.allocator.free(data);
                const out = try shiftBytes(ctx.allocator, data, shift, op == .OP_LSHIFT);
                try pushOwned(ctx, state, out);
            },
            .OP_BOOLAND, .OP_BOOLOR => {
                try countOp(ctx, state);
                var right = try popNum(ctx, state);
                defer right.deinit();
                var left = try popNum(ctx, state);
                defer left.deinit();
                try pushBool(ctx, state, switch (op) {
                    .OP_BOOLAND => !left.isZero() and !right.isZero(),
                    .OP_BOOLOR => !left.isZero() or !right.isZero(),
                    else => unreachable,
                });
            },
            .OP_NUMEQUAL, .OP_NUMNOTEQUAL, .OP_LESSTHAN, .OP_GREATERTHAN, .OP_LESSTHANOREQUAL, .OP_GREATERTHANOREQUAL => {
                try countOp(ctx, state);
                var right = try popNum(ctx, state);
                defer right.deinit();
                var left = try popNum(ctx, state);
                defer left.deinit();
                const ordering = left.order(&right);
                try pushBool(ctx, state, switch (op) {
                    .OP_NUMEQUAL => ordering == .eq,
                    .OP_NUMNOTEQUAL => ordering != .eq,
                    .OP_LESSTHAN => ordering == .lt,
                    .OP_GREATERTHAN => ordering == .gt,
                    .OP_LESSTHANOREQUAL => ordering != .gt,
                    .OP_GREATERTHANOREQUAL => ordering != .lt,
                    else => unreachable,
                });
            },
            .OP_NUMEQUALVERIFY => {
                try countOp(ctx, state);
                var right = try popNum(ctx, state);
                defer right.deinit();
                var left = try popNum(ctx, state);
                defer left.deinit();
                if (!left.eql(&right)) return error.VerifyFailed;
            },
            .OP_MIN, .OP_MAX => {
                try countOp(ctx, state);
                var right = try popNum(ctx, state);
                defer right.deinit();
                var left = try popNum(ctx, state);
                defer left.deinit();
                const chosen = if (op == .OP_MIN)
                    (if (left.order(&right) == .gt) &right else &left)
                else
                    (if (left.order(&right) == .lt) &right else &left);
                try pushScriptNum(ctx, state, chosen);
            },
            .OP_WITHIN => {
                try countOp(ctx, state);
                var max = try popNum(ctx, state);
                defer max.deinit();
                var min = try popNum(ctx, state);
                defer min.deinit();
                var value = try popNum(ctx, state);
                defer value.deinit();
                try pushBool(ctx, state, value.order(&min) != .lt and value.order(&max) == .lt);
            },
            .OP_RIPEMD160, .OP_SHA1, .OP_SHA256, .OP_HASH160, .OP_HASH256 => {
                try countOp(ctx, state);
                const data = try popOwned(state);
                defer ctx.allocator.free(data);
                try pushOwned(ctx, state, try hashOp(ctx.allocator, op, data));
            },
            .OP_CHECKSIG, .OP_CHECKSIGVERIFY => {
                try countOp(ctx, state);
                const pubkey_bytes = try popOwned(state);
                defer ctx.allocator.free(pubkey_bytes);
                const sig_bytes = try popOwned(state);
                defer ctx.allocator.free(sig_bytes);
                const valid = try verifyChecksig(ctx, script, state.last_code_separator, sig_bytes, pubkey_bytes);
                if (!valid and ctx.flags.null_fail and sig_bytes.len != 0) return error.NullFail;
                if (op == .OP_CHECKSIGVERIFY) {
                    if (!valid) return error.VerifyFailed;
                } else {
                    try pushBool(ctx, state, valid);
                }
            },
            .OP_CHECKMULTISIG, .OP_CHECKMULTISIGVERIFY => {
                try countOp(ctx, state);
                const valid = try verifyCheckmultisig(ctx, state, script);
                if (op == .OP_CHECKMULTISIGVERIFY) {
                    if (!valid) return error.VerifyFailed;
                } else {
                    try pushBool(ctx, state, valid);
                }
            },
            _ => return error.UnknownOpcode,
        }
    }
}

fn readPushLength(comptime Int: type, bytes: []const u8, cursor: *usize) Error!usize {
    if (bytes.len < cursor.* + @sizeOf(Int)) return error.InvalidPushData;
    const value = std.mem.readInt(Int, bytes[cursor.*..][0..@sizeOf(Int)], .little);
    cursor.* += @sizeOf(Int);
    return std.math.cast(usize, value) orelse error.Overflow;
}

fn allTrue(values: []const bool) bool {
    for (values) |value| {
        if (!value) return false;
    }
    return true;
}

fn shouldExecute(state: *const ExecutionState) bool {
    return allTrue(state.condition_stack.items);
}

fn countOp(ctx: ExecutionContext, state: *ExecutionState) Error!void {
    state.ops_executed += 1;
    if (state.ops_executed > ctx.flags.max_ops) return error.OpCountLimitExceeded;
}

fn checkStackSize(ctx: ExecutionContext, state: *ExecutionState) Error!void {
    const depth = state.stack.items.len + state.alt_stack.items.len;
    if (depth > ctx.flags.max_stack_items) return error.StackSizeLimitExceeded;
    if (depth > state.max_stack_depth) state.max_stack_depth = depth;
}

fn ensureCanGrow(ctx: ExecutionContext, state: *const ExecutionState, extra_items: usize) Error!void {
    const depth = state.stack.items.len + state.alt_stack.items.len;
    const next_depth = depth + extra_items;
    if (next_depth > ctx.flags.max_stack_items) return error.StackSizeLimitExceeded;
}

fn pushOwned(ctx: ExecutionContext, state: *ExecutionState, item: []u8) Error!void {
    errdefer ctx.allocator.free(item);
    if (item.len > ctx.flags.max_script_element_size) return error.ElementTooBig;
    try ensureCanGrow(ctx, state, 1);
    try state.stack.append(ctx.allocator, item);
    const depth = state.stack.items.len + state.alt_stack.items.len;
    if (depth > state.max_stack_depth) state.max_stack_depth = depth;
}

fn pushCopy(ctx: ExecutionContext, state: *ExecutionState, item: []const u8) Error!void {
    const duped = try ctx.allocator.dupe(u8, item);
    try pushOwned(ctx, state, duped);
}

fn pushBool(ctx: ExecutionContext, state: *ExecutionState, value: bool) Error!void {
    const bytes = if (value) try ctx.allocator.dupe(u8, &[_]u8{0x01}) else try ctx.allocator.alloc(u8, 0);
    try pushOwned(ctx, state, bytes);
}

fn pushNum(ctx: ExecutionContext, state: *ExecutionState, value: i64) Error!void {
    const encoded = try num.ScriptNum.encode(ctx.allocator, value);
    try pushOwned(ctx, state, encoded);
}

fn pushScriptNum(ctx: ExecutionContext, state: *ExecutionState, value: *const num.ScriptNum) Error!void {
    const encoded = try value.encodeOwned(ctx.allocator);
    try pushOwned(ctx, state, encoded);
}

fn popOwned(state: *ExecutionState) Error![]u8 {
    if (state.stack.items.len == 0) return error.StackUnderflow;
    return state.stack.pop() orelse unreachable;
}

fn peek(state: *const ExecutionState, offset: usize) Error![]const u8 {
    if (state.stack.items.len <= offset) return error.StackUnderflow;
    return state.stack.items[state.stack.items.len - 1 - offset];
}

fn popNum(ctx: ExecutionContext, state: *ExecutionState) Error!num.ScriptNum {
    const value_bytes = try popOwned(state);
    defer ctx.allocator.free(value_bytes);
    return decodeScriptNum(ctx, value_bytes);
}

fn decodeScriptNum(ctx: ExecutionContext, value_bytes: []const u8) Error!num.ScriptNum {
    if (value_bytes.len > ctx.flags.max_script_number_length) return error.NumberTooBig;
    if (ctx.flags.minimal_data) {
        return num.ScriptNum.decodeMinimalOwned(ctx.allocator, value_bytes) catch |err| switch (err) {
            error.NonMinimalEncoding => error.MinimalData,
            error.InvalidEncoding => error.InvalidEncoding,
            error.Overflow => error.Overflow,
            error.OutOfMemory => error.OutOfMemory,
        };
    }
    return num.ScriptNum.decodeOwned(ctx.allocator, value_bytes);
}

fn popIndex(ctx: ExecutionContext, state: *ExecutionState) Error!usize {
    var value = try popNum(ctx, state);
    defer value.deinit();
    return value.toIndex() catch error.InvalidStackIndex;
}

fn shiftBytes(allocator: std.mem.Allocator, data: []const u8, shift: usize, left: bool) Error![]u8 {
    var out = try allocator.alloc(u8, data.len);
    @memset(out, 0);
    if (data.len == 0 or shift == 0) {
        @memcpy(out, data);
        return out;
    }

    const byte_shift = shift / 8;
    const bit_shift = shift % 8;

    if (byte_shift >= data.len) return out;

    if (left) {
        const masks = [_]u8{ 0xFF, 0x7F, 0x3F, 0x1F, 0x0F, 0x07, 0x03, 0x01 };
        const mask = masks[bit_shift];
        const overflow_mask: u8 = ~mask;

        var idx = data.len;
        while (idx > 0) {
            idx -= 1;
            if (byte_shift <= idx) {
                const dest_index = idx - byte_shift;
                var value: u8 = data[idx] & mask;
                value <<= @intCast(bit_shift);
                out[dest_index] |= value;

                if (dest_index >= 1 and bit_shift != 0) {
                    var carry: u8 = data[idx] & overflow_mask;
                    carry >>= @intCast(8 - bit_shift);
                    out[dest_index - 1] |= carry;
                }
            }
        }
    } else {
        const masks = [_]u8{ 0xFF, 0xFE, 0xFC, 0xF8, 0xF0, 0xE0, 0xC0, 0x80 };
        const mask = masks[bit_shift];
        const overflow_mask: u8 = ~mask;

        for (data, 0..) |byte, index| {
            const dest_index = index + byte_shift;
            if (dest_index < data.len) {
                var value: u8 = byte & mask;
                value >>= @intCast(bit_shift);
                out[dest_index] |= value;
            }

            if (dest_index + 1 < data.len and bit_shift != 0) {
                var carry: u8 = byte & overflow_mask;
                carry <<= @intCast(8 - bit_shift);
                out[dest_index + 1] |= carry;
            }
        }
    }

    return out;
}

fn isMinimalPush(op_byte: u8, data: []const u8) bool {
    if (data.len == 0) return op_byte == @intFromEnum(opcode.Opcode.OP_0);

    if (data.len == 1) {
        const value = data[0];
        if (value >= 1 and value <= 16) {
            return op_byte == @intFromEnum(opcode.Opcode.OP_1) - 1 + value;
        }
        if (value == 0x81) return op_byte == @intFromEnum(opcode.Opcode.OP_1NEGATE);
    }

    if (data.len <= 75) return op_byte == data.len;
    if (data.len <= std.math.maxInt(u8)) return op_byte == @intFromEnum(opcode.Opcode.OP_PUSHDATA1);
    if (data.len <= std.math.maxInt(u16)) return op_byte == @intFromEnum(opcode.Opcode.OP_PUSHDATA2);
    return op_byte == @intFromEnum(opcode.Opcode.OP_PUSHDATA4);
}

fn hashOp(allocator: std.mem.Allocator, op: opcode.Opcode, data: []const u8) Error![]u8 {
    return switch (op) {
        .OP_RIPEMD160 => try allocator.dupe(u8, &hash.ripemd160(data).bytes),
        .OP_SHA1 => blk: {
            var out: [20]u8 = undefined;
            std.crypto.hash.Sha1.hash(data, &out, .{});
            break :blk try allocator.dupe(u8, &out);
        },
        .OP_SHA256 => try allocator.dupe(u8, &hash.sha256(data).bytes),
        .OP_HASH160 => try allocator.dupe(u8, &hash.hash160(data).bytes),
        .OP_HASH256 => try allocator.dupe(u8, &hash.hash256(data).bytes),
        else => unreachable,
    };
}

fn verifyChecksig(
    ctx: ExecutionContext,
    current_script: Script,
    last_code_separator: usize,
    sig_bytes: []const u8,
    pubkey_bytes: []const u8,
) Error!bool {
    const signing_script = ctx.previous_locking_script orelse current_script;
    if (sig_bytes.len < 1) return false;
    try checkHashTypeEncoding(ctx, sig_bytes[sig_bytes.len - 1]);
    const legacy_normalization = !sighash.SigHashType.hasForkId(sig_bytes[sig_bytes.len - 1]);

    const script_code = try buildScriptCode(
        ctx.allocator,
        signing_script,
        last_code_separator,
        if (legacy_normalization) &[_][]const u8{sig_bytes} else &.{},
        legacy_normalization,
    );
    defer ctx.allocator.free(script_code.bytes);

    return verifyChecksigWithScriptCode(ctx, script_code, sig_bytes, pubkey_bytes);
}

fn verifyCheckmultisig(
    ctx: ExecutionContext,
    state: *ExecutionState,
    current_script: Script,
) Error!bool {
    const signing_script = ctx.previous_locking_script orelse current_script;

    const key_count = try popIndex(ctx, state);
    if (!ctx.flags.utxo_after_genesis and key_count > 20) return error.InvalidMultisigKeyCount;

    const pubkeys = try ctx.allocator.alloc([]u8, key_count);
    defer ctx.allocator.free(pubkeys);
    for (pubkeys) |*slot| {
        slot.* = try popOwned(state);
    }
    defer {
        for (pubkeys) |item| ctx.allocator.free(item);
    }

    const signature_count = try popIndex(ctx, state);
    if (signature_count > key_count) return error.InvalidMultisigSignatureCount;

    const signatures = try ctx.allocator.alloc([]u8, signature_count);
    defer ctx.allocator.free(signatures);
    for (signatures) |*slot| {
        slot.* = try popOwned(state);
    }
    defer {
        for (signatures) |item| ctx.allocator.free(item);
    }

    const dummy = try popOwned(state);
    defer ctx.allocator.free(dummy);
    if (ctx.flags.null_dummy and dummy.len != 0) return error.NullDummy;

    const script_code = try buildScriptCode(ctx.allocator, signing_script, state.last_code_separator, signatures, true);
    defer ctx.allocator.free(script_code.bytes);

    var key_index: usize = 0;
    var sig_index: usize = 0;
    while (sig_index < signatures.len and key_index < pubkeys.len) {
        if (try verifyChecksigWithScriptCode(ctx, script_code, signatures[sig_index], pubkeys[key_index])) {
            sig_index += 1;
        }
        key_index += 1;

        if (signatures.len - sig_index > pubkeys.len - key_index) {
            if (ctx.flags.null_fail) {
                for (signatures) |candidate| {
                    if (candidate.len != 0) return error.NullFail;
                }
            }
            return false;
        }
    }

    if (sig_index != signatures.len) {
        if (ctx.flags.null_fail) {
            for (signatures) |candidate| {
                if (candidate.len != 0) return error.NullFail;
            }
        }
        return false;
    }

    return true;
}

fn verifyChecksigWithScriptCode(
    ctx: ExecutionContext,
    script_code: Script,
    sig_bytes: []const u8,
    pubkey_bytes: []const u8,
) Error!bool {
    const tx = ctx.tx orelse return error.MissingChecksigContext;
    if (sig_bytes.len < 1) return false;
    const hash_type = sig_bytes[sig_bytes.len - 1];
    const der_bytes = sig_bytes[0 .. sig_bytes.len - 1];

    try checkHashTypeEncoding(ctx, hash_type);
    if (shouldCheckSignatureEncoding(ctx)) {
        try checkSignatureEncoding(ctx, der_bytes);
    }
    if (shouldCheckPubKeyEncoding(ctx)) {
        try checkPubKeyEncoding(pubkey_bytes);
    }

    const tx_signature = crypto.TxSignature.fromChecksigFormat(sig_bytes) catch |err| switch (err) {
        error.InvalidEncoding => {
            if (shouldCheckSignatureEncoding(ctx)) return error.InvalidSignatureEncoding;
            return false;
        },
        else => return err,
    };
    const public_key = crypto.PublicKey.fromSec1(pubkey_bytes) catch {
        if (shouldCheckPubKeyEncoding(ctx)) return error.InvalidPublicKeyEncoding;
        return false;
    };

    const digest = try sighash.digest(
        ctx.allocator,
        tx,
        ctx.input_index,
        script_code,
        ctx.previous_satoshis,
        tx_signature.sighash_type,
    );
    return public_key.verifyDigest256(digest.bytes, tx_signature.der) catch {
        if (shouldCheckSignatureEncoding(ctx)) return error.InvalidSignatureEncoding;
        return false;
    };
}

fn shouldCheckSignatureEncoding(ctx: ExecutionContext) bool {
    return ctx.flags.strict_encoding or ctx.flags.der_signatures or ctx.flags.low_s;
}

fn shouldCheckPubKeyEncoding(ctx: ExecutionContext) bool {
    return ctx.flags.strict_encoding or ctx.flags.strict_pubkey_encoding;
}

fn checkHashTypeEncoding(ctx: ExecutionContext, hash_type: u8) Error!void {
    if (!ctx.flags.strict_encoding and !ctx.flags.enable_sighash_forkid and !ctx.flags.verify_bip143_sighash) return;

    const anyone_can_pay: u8 = @intCast(sighash.SigHashType.anyone_can_pay);
    const forkid: u8 = @intCast(sighash.SigHashType.forkid);
    const base_with_forkid = hash_type & ~anyone_can_pay;
    const has_forkid = (hash_type & forkid) != 0;
    const base_type = if (has_forkid) (base_with_forkid ^ forkid) else base_with_forkid;

    if (base_type < sighash.SigHashType.all or base_type > sighash.SigHashType.single) {
        return error.InvalidSigHashType;
    }
    if (ctx.flags.verify_bip143_sighash and !has_forkid) return error.IllegalForkId;
    if (!ctx.flags.enable_sighash_forkid and has_forkid) return error.IllegalForkId;
    if (ctx.flags.enable_sighash_forkid and !has_forkid) return error.IllegalForkId;
}

fn checkPubKeyEncoding(pubkey: []const u8) Error!void {
    if (pubkey.len == 33 and (pubkey[0] == 0x02 or pubkey[0] == 0x03)) return;
    if (pubkey.len == 65 and pubkey[0] == 0x04) return;
    return error.InvalidPublicKeyEncoding;
}

fn checkSignatureEncoding(ctx: ExecutionContext, sig: []const u8) Error!void {
    if (sig.len < 8) return error.InvalidSignatureEncoding;
    if (sig.len > crypto.signature.max_der_signature_len) return error.InvalidSignatureEncoding;
    if (sig[0] != 0x30) return error.InvalidSignatureEncoding;
    if (sig[1] != sig.len - 2) return error.InvalidSignatureEncoding;
    if (sig[2] != 0x02) return error.InvalidSignatureEncoding;

    const r_len = sig[3];
    const s_type_offset = 4 + r_len;
    const s_len_offset = s_type_offset + 1;
    if (s_type_offset >= sig.len) return error.InvalidSignatureEncoding;
    if (s_len_offset >= sig.len) return error.InvalidSignatureEncoding;
    if (sig[s_type_offset] != 0x02) return error.InvalidSignatureEncoding;

    const s_len = sig[s_len_offset];
    const s_offset = s_len_offset + 1;
    if (s_offset + s_len != sig.len) return error.InvalidSignatureEncoding;
    if (r_len == 0 or s_len == 0) return error.InvalidSignatureEncoding;

    const r_offset = 4;
    if ((sig[r_offset] & 0x80) != 0) return error.InvalidSignatureEncoding;
    if (r_len > 1 and sig[r_offset] == 0x00 and (sig[r_offset + 1] & 0x80) == 0) return error.InvalidSignatureEncoding;
    if ((sig[s_offset] & 0x80) != 0) return error.InvalidSignatureEncoding;
    if (s_len > 1 and sig[s_offset] == 0x00 and (sig[s_offset + 1] & 0x80) == 0) return error.InvalidSignatureEncoding;

    if (ctx.flags.low_s) {
        const s_bytes = sig[s_offset .. s_offset + s_len];
        if (std.mem.order(u8, trimLeadingZeroes(s_bytes), trimLeadingZeroes(&secp256k1_half_order_be)) == .gt) {
            return error.HighS;
        }
    }
}

fn trimLeadingZeroes(bytes: []const u8) []const u8 {
    var index: usize = 0;
    while (index < bytes.len and bytes[index] == 0) : (index += 1) {}
    return bytes[index..];
}

fn buildScriptCode(
    allocator: std.mem.Allocator,
    current_script: Script,
    last_code_separator: usize,
    signatures_to_remove: []const []const u8,
    strip_remaining_code_separators: bool,
) Error!Script {
    if (last_code_separator > current_script.bytes.len) return error.InvalidPushData;

    const sliced = current_script.bytes[last_code_separator..];
    const state_separator_offset = try script_helpers.findStateSeparatorOpReturnOffset(sliced);
    const executable_end = state_separator_offset orelse sliced.len;
    const executable_prefix = sliced[0..executable_end];
    const raw_state_suffix = if (state_separator_offset) |offset| sliced[offset..] else "";

    var normalized_prefix = try allocator.dupe(u8, executable_prefix);
    errdefer allocator.free(normalized_prefix);

    for (signatures_to_remove) |signature_bytes| {
        const target_push = try encodePushDataElement(allocator, signature_bytes);
        defer allocator.free(target_push);

        const next_prefix = try findAndDeletePushData(allocator, normalized_prefix, target_push);
        allocator.free(normalized_prefix);
        normalized_prefix = next_prefix;
    }

    if (strip_remaining_code_separators) {
        const stripped_prefix = try stripCodeSeparatorsAlloc(allocator, normalized_prefix);
        allocator.free(normalized_prefix);
        normalized_prefix = stripped_prefix;
    }

    if (raw_state_suffix.len == 0) {
        return Script.init(normalized_prefix);
    }

    const out = try allocator.alloc(u8, normalized_prefix.len + raw_state_suffix.len);
    @memcpy(out[0..normalized_prefix.len], normalized_prefix);
    @memcpy(out[normalized_prefix.len..], raw_state_suffix);
    allocator.free(normalized_prefix);
    return Script.init(out);
}

fn stripCodeSeparatorsAlloc(allocator: std.mem.Allocator, script_bytes: []const u8) Error![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(allocator);

    var cursor: usize = 0;
    while (cursor < script_bytes.len) {
        const byte = script_bytes[cursor];
        cursor += 1;

        if (byte >= 0x01 and byte <= 0x4b) {
            if (script_bytes.len < cursor + byte) return error.InvalidPushData;
            try out.append(allocator, byte);
            try out.appendSlice(allocator, script_bytes[cursor .. cursor + byte]);
            cursor += byte;
            continue;
        }

        if (byte == @intFromEnum(opcode.Opcode.OP_PUSHDATA1)) {
            if (script_bytes.len < cursor + 1) return error.InvalidPushData;
            const len = script_bytes[cursor];
            if (script_bytes.len < cursor + 1 + len) return error.InvalidPushData;
            try out.append(allocator, byte);
            try out.append(allocator, script_bytes[cursor]);
            try out.appendSlice(allocator, script_bytes[cursor + 1 .. cursor + 1 + len]);
            cursor += 1 + len;
            continue;
        }

        if (byte == @intFromEnum(opcode.Opcode.OP_PUSHDATA2)) {
            if (script_bytes.len < cursor + 2) return error.InvalidPushData;
            const len = std.mem.readInt(u16, script_bytes[cursor..][0..2], .little);
            if (script_bytes.len < cursor + 2 + len) return error.InvalidPushData;
            try out.append(allocator, byte);
            try out.appendSlice(allocator, script_bytes[cursor..][0..2]);
            try out.appendSlice(allocator, script_bytes[cursor + 2 .. cursor + 2 + len]);
            cursor += 2 + len;
            continue;
        }

        if (byte == @intFromEnum(opcode.Opcode.OP_PUSHDATA4)) {
            if (script_bytes.len < cursor + 4) return error.InvalidPushData;
            const len = std.mem.readInt(u32, script_bytes[cursor..][0..4], .little);
            if (script_bytes.len < cursor + 4 + len) return error.InvalidPushData;
            try out.append(allocator, byte);
            try out.appendSlice(allocator, script_bytes[cursor..][0..4]);
            try out.appendSlice(allocator, script_bytes[cursor + 4 .. cursor + 4 + len]);
            cursor += 4 + len;
            continue;
        }

        if (byte != @intFromEnum(opcode.Opcode.OP_CODESEPARATOR)) {
            try out.append(allocator, byte);
        }
    }

    return out.toOwnedSlice(allocator);
}

fn encodePushDataElement(allocator: std.mem.Allocator, data: []const u8) Error![]u8 {
    var bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer bytes.deinit(allocator);

    if (data.len == 0) {
        try bytes.append(allocator, @intFromEnum(opcode.Opcode.OP_0));
        return bytes.toOwnedSlice(allocator);
    }

    if (data.len <= 75) {
        try bytes.append(allocator, @intCast(data.len));
    } else if (data.len <= std.math.maxInt(u8)) {
        try bytes.append(allocator, @intFromEnum(opcode.Opcode.OP_PUSHDATA1));
        try bytes.append(allocator, @intCast(data.len));
    } else if (data.len <= std.math.maxInt(u16)) {
        try bytes.append(allocator, @intFromEnum(opcode.Opcode.OP_PUSHDATA2));
        var len_buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &len_buf, @intCast(data.len), .little);
        try bytes.appendSlice(allocator, &len_buf);
    } else {
        try bytes.append(allocator, @intFromEnum(opcode.Opcode.OP_PUSHDATA4));
        var len_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &len_buf, @intCast(data.len), .little);
        try bytes.appendSlice(allocator, &len_buf);
    }

    try bytes.appendSlice(allocator, data);
    return bytes.toOwnedSlice(allocator);
}

fn findAndDeletePushData(
    allocator: std.mem.Allocator,
    script_bytes: []const u8,
    target_push: []const u8,
) Error![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(allocator);

    var cursor: usize = 0;
    while (cursor < script_bytes.len) {
        const start = cursor;
        const byte = script_bytes[cursor];
        cursor += 1;

        if (byte >= 0x01 and byte <= 0x4b) {
            if (script_bytes.len < cursor + byte) return error.InvalidPushData;
            cursor += byte;
        } else if (byte == @intFromEnum(opcode.Opcode.OP_PUSHDATA1)) {
            const len = try readPushLength(u8, script_bytes, &cursor);
            if (script_bytes.len < cursor + len) return error.InvalidPushData;
            cursor += len;
        } else if (byte == @intFromEnum(opcode.Opcode.OP_PUSHDATA2)) {
            const len = try readPushLength(u16, script_bytes, &cursor);
            if (script_bytes.len < cursor + len) return error.InvalidPushData;
            cursor += len;
        } else if (byte == @intFromEnum(opcode.Opcode.OP_PUSHDATA4)) {
            const len = try readPushLength(u32, script_bytes, &cursor);
            if (script_bytes.len < cursor + len) return error.InvalidPushData;
            cursor += len;
        }

        const segment = script_bytes[start..cursor];
        if (!std.mem.eql(u8, segment, target_push)) {
            try out.appendSlice(allocator, segment);
        }
    }

    return out.toOwnedSlice(allocator);
}

fn buildTwoOfTwoLockingScript(pubkey_a: crypto.PublicKey, pubkey_b: crypto.PublicKey) [71]u8 {
    var out: [71]u8 = undefined;
    out[0] = @intFromEnum(opcode.Opcode.OP_2);
    out[1] = 33;
    @memcpy(out[2..35], &pubkey_a.bytes);
    out[35] = 33;
    @memcpy(out[36..69], &pubkey_b.bytes);
    out[69] = @intFromEnum(opcode.Opcode.OP_2);
    out[70] = @intFromEnum(opcode.Opcode.OP_CHECKMULTISIG);
    return out;
}

fn buildMultisigUnlockingScript(
    allocator: std.mem.Allocator,
    signatures: []const crypto.TxSignature,
) !Script {
    var total_len: usize = 1;
    var encoded_sigs: std.ArrayListUnmanaged([]u8) = .empty;
    defer {
        for (encoded_sigs.items) |encoded| allocator.free(encoded);
        encoded_sigs.deinit(allocator);
    }

    for (signatures) |signature| {
        const encoded = try signature.toChecksigFormat(allocator);
        errdefer allocator.free(encoded);
        try encoded_sigs.append(allocator, encoded);
        total_len += 1 + encoded.len;
    }

    var bytes = try allocator.alloc(u8, total_len);
    bytes[0] = @intFromEnum(opcode.Opcode.OP_0);

    var cursor: usize = 1;
    for (encoded_sigs.items) |encoded| {
        if (encoded.len > 75) return error.InvalidPushData;
        bytes[cursor] = @intCast(encoded.len);
        cursor += 1;
        @memcpy(bytes[cursor .. cursor + encoded.len], encoded);
        cursor += encoded.len;
    }

    return Script.init(bytes);
}

fn buildChecksigUnlockingScript(
    allocator: std.mem.Allocator,
    signatures: []const crypto.TxSignature,
) !Script {
    var total_len: usize = 0;
    var encoded_sigs: std.ArrayListUnmanaged([]u8) = .empty;
    defer {
        for (encoded_sigs.items) |encoded| allocator.free(encoded);
        encoded_sigs.deinit(allocator);
    }

    for (signatures) |signature| {
        const encoded = try signature.toChecksigFormat(allocator);
        errdefer allocator.free(encoded);
        try encoded_sigs.append(allocator, encoded);
        total_len += 1 + encoded.len;
    }

    var bytes = try allocator.alloc(u8, total_len);
    var cursor: usize = 0;
    for (encoded_sigs.items) |encoded| {
        if (encoded.len > 75) return error.InvalidPushData;
        bytes[cursor] = @intCast(encoded.len);
        cursor += 1;
        @memcpy(bytes[cursor .. cursor + encoded.len], encoded);
        cursor += encoded.len;
    }

    return Script.init(bytes);
}

fn runUnlockAndLock(
    ctx: ExecutionContext,
    unlocking_script: Script,
    locking_script: Script,
) Error!ExecutionState {
    var state: ExecutionState = .{};
    errdefer state.deinit(ctx.allocator);

    try executeUnlockingScript(ctx, &state, unlocking_script);
    state.clearAltStack(ctx.allocator);
    try executeLockingScript(ctx, &state, locking_script);
    if (state.condition_stack.items.len != 0) return error.UnbalancedConditionals;
    return state;
}

test "engine executes arithmetic and boolean flow" {
    const allocator = std.testing.allocator;
    const script = Script.init(&[_]u8{
        @intFromEnum(opcode.Opcode.OP_2),
        @intFromEnum(opcode.Opcode.OP_3),
        @intFromEnum(opcode.Opcode.OP_ADD),
        @intFromEnum(opcode.Opcode.OP_5),
        @intFromEnum(opcode.Opcode.OP_NUMEQUAL),
    });

    var result = try executeScript(.{ .allocator = allocator }, script);
    defer result.deinit(allocator);

    try std.testing.expect(result.success);
    try std.testing.expectEqual(@as(usize, 1), result.state.stack.items.len);
    try std.testing.expect(isTruthy(result.state.stack.items[0]));
}

test "engine executes arithmetic over script numbers larger than i64" {
    const allocator = std.testing.allocator;
    const left_value: i128 = (@as(i128, 1) << 70) + 5;
    const right_value: i128 = (@as(i128, 1) << 69) + 7;
    const sum_value: i128 = left_value + right_value;

    const left = try num.ScriptNum.encode(allocator, left_value);
    defer allocator.free(left);
    const right = try num.ScriptNum.encode(allocator, right_value);
    defer allocator.free(right);
    const expected = try num.ScriptNum.encode(allocator, sum_value);
    defer allocator.free(expected);

    const left_push = try encodePushDataElement(allocator, left);
    defer allocator.free(left_push);
    const right_push = try encodePushDataElement(allocator, right);
    defer allocator.free(right_push);
    const expected_push = try encodePushDataElement(allocator, expected);
    defer allocator.free(expected_push);

    var script_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer script_bytes.deinit(allocator);
    try script_bytes.appendSlice(allocator, left_push);
    try script_bytes.appendSlice(allocator, right_push);
    try script_bytes.append(allocator, @intFromEnum(opcode.Opcode.OP_ADD));
    try script_bytes.appendSlice(allocator, expected_push);
    try script_bytes.append(allocator, @intFromEnum(opcode.Opcode.OP_NUMEQUAL));

    const script = Script.init(try script_bytes.toOwnedSlice(allocator));
    defer allocator.free(script.bytes);

    var result = try executeScript(.{ .allocator = allocator }, script);
    defer result.deinit(allocator);

    try std.testing.expect(result.success);
}

test "engine supports runar critical byte ops" {
    const allocator = std.testing.allocator;
    const script = Script.init(&[_]u8{
        0x01,                                    0x2a,
        @intFromEnum(opcode.Opcode.OP_1),        @intFromEnum(opcode.Opcode.OP_NUM2BIN),
        @intFromEnum(opcode.Opcode.OP_SIZE),     @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_NUMEQUAL),
    });

    var result = try executeScript(.{ .allocator = allocator }, script);
    defer result.deinit(allocator);

    try std.testing.expect(result.success);
}

test "engine matches exact empty-input hash opcode vectors" {
    const allocator = std.testing.allocator;

    const Case = struct {
        op: opcode.Opcode,
        expected: []const u8,
    };

    const cases = [_]Case{
        .{ .op = .OP_RIPEMD160, .expected = &.{ 0x9c, 0x11, 0x85, 0xa5, 0xc5, 0xe9, 0xfc, 0x54, 0x61, 0x28, 0x08, 0x97, 0x7e, 0xe8, 0xf5, 0x48, 0xb2, 0x25, 0x8d, 0x31 } },
        .{ .op = .OP_SHA1, .expected = &.{ 0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09 } },
        .{ .op = .OP_SHA256, .expected = &.{ 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55 } },
        .{ .op = .OP_HASH160, .expected = &.{ 0xb4, 0x72, 0xa2, 0x66, 0xd0, 0xbd, 0x89, 0xc1, 0x37, 0x06, 0xa4, 0x13, 0x2c, 0xcf, 0xb1, 0x6f, 0x7c, 0x3b, 0x9f, 0xcb } },
        .{ .op = .OP_HASH256, .expected = &.{ 0x5d, 0xf6, 0xe0, 0xe2, 0x76, 0x13, 0x59, 0xd3, 0x0a, 0x82, 0x75, 0x05, 0x8e, 0x29, 0x9f, 0xcc, 0x03, 0x81, 0x53, 0x45, 0x45, 0xf5, 0x5c, 0xf4, 0x3e, 0x41, 0x98, 0x3f, 0x5d, 0x4c, 0x94, 0x56 } },
    };

    inline for (cases) |case| {
        const expected_push = try encodePushDataElement(allocator, case.expected);
        defer allocator.free(expected_push);

        var script_bytes: std.ArrayListUnmanaged(u8) = .empty;
        defer script_bytes.deinit(allocator);
        try script_bytes.append(allocator, @intFromEnum(opcode.Opcode.OP_0));
        try script_bytes.append(allocator, @intFromEnum(case.op));
        try script_bytes.appendSlice(allocator, expected_push);
        try script_bytes.append(allocator, @intFromEnum(opcode.Opcode.OP_EQUAL));

        const script = Script.init(try script_bytes.toOwnedSlice(allocator));
        defer allocator.free(script.bytes);

        var result = try executeScript(.{ .allocator = allocator }, script);
        defer result.deinit(allocator);
        try std.testing.expect(result.success);
    }
}

test "engine hash opcodes require a stack item" {
    const allocator = std.testing.allocator;

    const ops = [_]opcode.Opcode{
        .OP_RIPEMD160,
        .OP_SHA1,
        .OP_SHA256,
        .OP_HASH160,
        .OP_HASH256,
    };

    inline for (ops) |op| {
        try std.testing.expectError(error.StackUnderflow, executeScript(.{
            .allocator = allocator,
        }, Script.init(&[_]u8{@intFromEnum(op)})));
    }
}

test "engine matches go-sdk OP_LSHIFT vectors" {
    const allocator = std.testing.allocator;

    const Case = struct {
        initial: []const u8,
        shift: i64,
        expected: []const u8,
    };

    const cases = [_]Case{
        .{ .initial = &.{}, .shift = 0x00, .expected = &.{} },
        .{ .initial = &.{}, .shift = 0x11, .expected = &.{} },
        .{ .initial = &.{ 0xFF }, .shift = 0x00, .expected = &.{ 0xFF } },
        .{ .initial = &.{ 0xFF }, .shift = 0x01, .expected = &.{ 0xFE } },
        .{ .initial = &.{ 0xFF }, .shift = 0x07, .expected = &.{ 0x80 } },
        .{ .initial = &.{ 0xFF }, .shift = 0x08, .expected = &.{ 0x00 } },
        .{ .initial = &.{ 0x00, 0x80 }, .shift = 0x01, .expected = &.{ 0x01, 0x00 } },
        .{ .initial = &.{ 0x00, 0x80, 0x00 }, .shift = 0x01, .expected = &.{ 0x01, 0x00, 0x00 } },
        .{ .initial = &.{ 0x00, 0x00, 0x80 }, .shift = 0x01, .expected = &.{ 0x00, 0x01, 0x00 } },
        .{ .initial = &.{ 0x80, 0x00, 0x00 }, .shift = 0x01, .expected = &.{ 0x00, 0x00, 0x00 } },
        .{ .initial = &.{ 0x9F, 0x11, 0xF5, 0x55 }, .shift = 0x00, .expected = &.{ 0b10011111, 0b00010001, 0b11110101, 0b01010101 } },
        .{ .initial = &.{ 0x9F, 0x11, 0xF5, 0x55 }, .shift = 0x01, .expected = &.{ 0b00111110, 0b00100011, 0b11101010, 0b10101010 } },
        .{ .initial = &.{ 0x9F, 0x11, 0xF5, 0x55 }, .shift = 0x02, .expected = &.{ 0b01111100, 0b01000111, 0b11010101, 0b01010100 } },
        .{ .initial = &.{ 0x9F, 0x11, 0xF5, 0x55 }, .shift = 0x03, .expected = &.{ 0b11111000, 0b10001111, 0b10101010, 0b10101000 } },
        .{ .initial = &.{ 0x9F, 0x11, 0xF5, 0x55 }, .shift = 0x04, .expected = &.{ 0b11110001, 0b00011111, 0b01010101, 0b01010000 } },
        .{ .initial = &.{ 0x9F, 0x11, 0xF5, 0x55 }, .shift = 0x05, .expected = &.{ 0b11100010, 0b00111110, 0b10101010, 0b10100000 } },
        .{ .initial = &.{ 0x9F, 0x11, 0xF5, 0x55 }, .shift = 0x06, .expected = &.{ 0b11000100, 0b01111101, 0b01010101, 0b01000000 } },
        .{ .initial = &.{ 0x9F, 0x11, 0xF5, 0x55 }, .shift = 0x07, .expected = &.{ 0b10001000, 0b11111010, 0b10101010, 0b10000000 } },
        .{ .initial = &.{ 0x9F, 0x11, 0xF5, 0x55 }, .shift = 0x08, .expected = &.{ 0b00010001, 0b11110101, 0b01010101, 0b00000000 } },
        .{ .initial = &.{ 0x9F, 0x11, 0xF5, 0x55 }, .shift = 0x09, .expected = &.{ 0b00100011, 0b11101010, 0b10101010, 0b00000000 } },
        .{ .initial = &.{ 0x9F, 0x11, 0xF5, 0x55 }, .shift = 0x0A, .expected = &.{ 0b01000111, 0b11010101, 0b01010100, 0b00000000 } },
        .{ .initial = &.{ 0x9F, 0x11, 0xF5, 0x55 }, .shift = 0x0B, .expected = &.{ 0b10001111, 0b10101010, 0b10101000, 0b00000000 } },
        .{ .initial = &.{ 0x9F, 0x11, 0xF5, 0x55 }, .shift = 0x0C, .expected = &.{ 0b00011111, 0b01010101, 0b01010000, 0b00000000 } },
        .{ .initial = &.{ 0x9F, 0x11, 0xF5, 0x55 }, .shift = 0x0D, .expected = &.{ 0b00111110, 0b10101010, 0b10100000, 0b00000000 } },
        .{ .initial = &.{ 0x9F, 0x11, 0xF5, 0x55 }, .shift = 0x0E, .expected = &.{ 0b01111101, 0b01010101, 0b01000000, 0b00000000 } },
        .{ .initial = &.{ 0x9F, 0x11, 0xF5, 0x55 }, .shift = 0x0F, .expected = &.{ 0b11111010, 0b10101010, 0b10000000, 0b00000000 } },
    };

    inline for (cases) |case| {
        const initial_push = try encodePushDataElement(allocator, case.initial);
        defer allocator.free(initial_push);
        const shift_encoded = try num.ScriptNum.encode(allocator, case.shift);
        defer allocator.free(shift_encoded);
        const shift_push = try encodePushDataElement(allocator, shift_encoded);
        defer allocator.free(shift_push);

        var script_bytes: std.ArrayListUnmanaged(u8) = .empty;
        defer script_bytes.deinit(allocator);
        try script_bytes.appendSlice(allocator, initial_push);
        try script_bytes.appendSlice(allocator, shift_push);
        try script_bytes.append(allocator, @intFromEnum(opcode.Opcode.OP_LSHIFT));

        const script = Script.init(try script_bytes.toOwnedSlice(allocator));
        defer allocator.free(script.bytes);

        var result = try executeScript(.{ .allocator = allocator }, script);
        defer result.deinit(allocator);

        try std.testing.expectEqual(@as(usize, 1), result.state.stack.items.len);
        try std.testing.expectEqualSlices(u8, case.expected, result.state.stack.items[0]);
    }
}

test "engine matches go-sdk OP_RSHIFT vectors" {
    const allocator = std.testing.allocator;

    const Case = struct {
        initial: []const u8,
        shift: i64,
        expected: []const u8,
    };

    const cases = [_]Case{
        .{ .initial = &.{}, .shift = 0x00, .expected = &.{} },
        .{ .initial = &.{}, .shift = 0x11, .expected = &.{} },
        .{ .initial = &.{ 0xFF }, .shift = 0x00, .expected = &.{ 0xFF } },
        .{ .initial = &.{ 0xFF }, .shift = 0x01, .expected = &.{ 0x7F } },
        .{ .initial = &.{ 0xFF }, .shift = 0x07, .expected = &.{ 0x01 } },
        .{ .initial = &.{ 0xFF }, .shift = 0x08, .expected = &.{ 0x00 } },
        .{ .initial = &.{ 0x01, 0x00 }, .shift = 0x01, .expected = &.{ 0x00, 0x80 } },
        .{ .initial = &.{ 0x01, 0x00, 0x00 }, .shift = 0x01, .expected = &.{ 0x00, 0x80, 0x00 } },
        .{ .initial = &.{ 0x00, 0x01, 0x00 }, .shift = 0x01, .expected = &.{ 0x00, 0x00, 0x80 } },
        .{ .initial = &.{ 0x00, 0x00, 0x01 }, .shift = 0x01, .expected = &.{ 0x00, 0x00, 0x00 } },
        .{ .initial = &.{ 0x9F, 0x11, 0xF5, 0x55 }, .shift = 0x00, .expected = &.{ 0b10011111, 0b00010001, 0b11110101, 0b01010101 } },
        .{ .initial = &.{ 0x9F, 0x11, 0xF5, 0x55 }, .shift = 0x01, .expected = &.{ 0b01001111, 0b10001000, 0b11111010, 0b10101010 } },
        .{ .initial = &.{ 0x9F, 0x11, 0xF5, 0x55 }, .shift = 0x02, .expected = &.{ 0b00100111, 0b11000100, 0b01111101, 0b01010101 } },
        .{ .initial = &.{ 0x9F, 0x11, 0xF5, 0x55 }, .shift = 0x03, .expected = &.{ 0b00010011, 0b11100010, 0b00111110, 0b10101010 } },
        .{ .initial = &.{ 0x9F, 0x11, 0xF5, 0x55 }, .shift = 0x04, .expected = &.{ 0b00001001, 0b11110001, 0b00011111, 0b01010101 } },
        .{ .initial = &.{ 0x9F, 0x11, 0xF5, 0x55 }, .shift = 0x05, .expected = &.{ 0b00000100, 0b11111000, 0b10001111, 0b10101010 } },
        .{ .initial = &.{ 0x9F, 0x11, 0xF5, 0x55 }, .shift = 0x06, .expected = &.{ 0b00000010, 0b01111100, 0b01000111, 0b11010101 } },
        .{ .initial = &.{ 0x9F, 0x11, 0xF5, 0x55 }, .shift = 0x07, .expected = &.{ 0b00000001, 0b00111110, 0b00100011, 0b11101010 } },
        .{ .initial = &.{ 0x9F, 0x11, 0xF5, 0x55 }, .shift = 0x08, .expected = &.{ 0b00000000, 0b10011111, 0b00010001, 0b11110101 } },
        .{ .initial = &.{ 0x9F, 0x11, 0xF5, 0x55 }, .shift = 0x09, .expected = &.{ 0b00000000, 0b01001111, 0b10001000, 0b11111010 } },
        .{ .initial = &.{ 0x9F, 0x11, 0xF5, 0x55 }, .shift = 0x0A, .expected = &.{ 0b00000000, 0b00100111, 0b11000100, 0b01111101 } },
        .{ .initial = &.{ 0x9F, 0x11, 0xF5, 0x55 }, .shift = 0x0B, .expected = &.{ 0b00000000, 0b00010011, 0b11100010, 0b00111110 } },
        .{ .initial = &.{ 0x9F, 0x11, 0xF5, 0x55 }, .shift = 0x0C, .expected = &.{ 0b00000000, 0b00001001, 0b11110001, 0b00011111 } },
        .{ .initial = &.{ 0x9F, 0x11, 0xF5, 0x55 }, .shift = 0x0D, .expected = &.{ 0b00000000, 0b00000100, 0b11111000, 0b10001111 } },
        .{ .initial = &.{ 0x9F, 0x11, 0xF5, 0x55 }, .shift = 0x0E, .expected = &.{ 0b00000000, 0b00000010, 0b01111100, 0b01000111 } },
        .{ .initial = &.{ 0x9F, 0x11, 0xF5, 0x55 }, .shift = 0x0F, .expected = &.{ 0b00000000, 0b00000001, 0b00111110, 0b00100011 } },
    };

    inline for (cases) |case| {
        const initial_push = try encodePushDataElement(allocator, case.initial);
        defer allocator.free(initial_push);
        const shift_encoded = try num.ScriptNum.encode(allocator, case.shift);
        defer allocator.free(shift_encoded);
        const shift_push = try encodePushDataElement(allocator, shift_encoded);
        defer allocator.free(shift_push);

        var script_bytes: std.ArrayListUnmanaged(u8) = .empty;
        defer script_bytes.deinit(allocator);
        try script_bytes.appendSlice(allocator, initial_push);
        try script_bytes.appendSlice(allocator, shift_push);
        try script_bytes.append(allocator, @intFromEnum(opcode.Opcode.OP_RSHIFT));

        const script = Script.init(try script_bytes.toOwnedSlice(allocator));
        defer allocator.free(script.bytes);

        var result = try executeScript(.{ .allocator = allocator }, script);
        defer result.deinit(allocator);

        try std.testing.expectEqual(@as(usize, 1), result.state.stack.items.len);
        try std.testing.expectEqualSlices(u8, case.expected, result.state.stack.items[0]);
    }
}

test "engine executes runar-style dispatch branches" {
    const allocator = std.testing.allocator;
    const select_first = Script.init(&[_]u8{
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_DUP),
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_NUMEQUAL),
        @intFromEnum(opcode.Opcode.OP_IF),
        @intFromEnum(opcode.Opcode.OP_DROP),
        @intFromEnum(opcode.Opcode.OP_2),
        @intFromEnum(opcode.Opcode.OP_ELSE),
        @intFromEnum(opcode.Opcode.OP_DROP),
        @intFromEnum(opcode.Opcode.OP_3),
        @intFromEnum(opcode.Opcode.OP_ENDIF),
        @intFromEnum(opcode.Opcode.OP_2),
        @intFromEnum(opcode.Opcode.OP_NUMEQUAL),
    });

    var first_result = try executeScript(.{ .allocator = allocator }, select_first);
    defer first_result.deinit(allocator);
    try std.testing.expect(first_result.success);

    const select_second = Script.init(&[_]u8{
        @intFromEnum(opcode.Opcode.OP_2),
        @intFromEnum(opcode.Opcode.OP_DUP),
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_NUMEQUAL),
        @intFromEnum(opcode.Opcode.OP_IF),
        @intFromEnum(opcode.Opcode.OP_DROP),
        @intFromEnum(opcode.Opcode.OP_2),
        @intFromEnum(opcode.Opcode.OP_ELSE),
        @intFromEnum(opcode.Opcode.OP_DROP),
        @intFromEnum(opcode.Opcode.OP_3),
        @intFromEnum(opcode.Opcode.OP_ENDIF),
        @intFromEnum(opcode.Opcode.OP_3),
        @intFromEnum(opcode.Opcode.OP_NUMEQUAL),
    });

    var second_result = try executeScript(.{ .allocator = allocator }, select_second);
    defer second_result.deinit(allocator);
    try std.testing.expect(second_result.success);
}

test "engine rejects duplicate else in the same conditional block" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.UnexpectedElse, executeScript(.{
        .allocator = allocator,
    }, Script.init(&[_]u8{
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_IF),
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_ELSE),
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_ELSE),
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_ENDIF),
    })));
}

test "engine supports skipped nested branches without executing side effects" {
    const allocator = std.testing.allocator;
    const script = Script.init(&[_]u8{
        @intFromEnum(opcode.Opcode.OP_0),
        @intFromEnum(opcode.Opcode.OP_IF),
            @intFromEnum(opcode.Opcode.OP_1),
            @intFromEnum(opcode.Opcode.OP_IF),
                @intFromEnum(opcode.Opcode.OP_RETURN),
            @intFromEnum(opcode.Opcode.OP_ENDIF),
        @intFromEnum(opcode.Opcode.OP_ELSE),
            @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_ENDIF),
    });

    var result = try executeScript(.{ .allocator = allocator }, script);
    defer result.deinit(allocator);
    try std.testing.expect(result.success);
    try std.testing.expectEqual(@as(usize, 1), result.state.stack.items.len);
    try std.testing.expectEqualSlices(u8, &.{0x01}, result.state.stack.items[0]);
}

test "engine can enforce minimal-if semantics" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.MinimalIf, executeScript(.{
        .allocator = allocator,
        .flags = .{ .minimal_if = true },
    }, Script.init(&[_]u8{
        0x01,
        0x02,
        @intFromEnum(opcode.Opcode.OP_IF),
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_ENDIF),
    })));

    var true_result = try executeScript(.{
        .allocator = allocator,
        .flags = .{ .minimal_if = true },
    }, Script.init(&[_]u8{
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_IF),
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_ENDIF),
    }));
    defer true_result.deinit(allocator);
    try std.testing.expect(true_result.success);
}

test "engine supports altstack and deep stack access opcodes" {
    const allocator = std.testing.allocator;

    const altstack_script = Script.init(&[_]u8{
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_TOALTSTACK),
        @intFromEnum(opcode.Opcode.OP_2),
        @intFromEnum(opcode.Opcode.OP_FROMALTSTACK),
        @intFromEnum(opcode.Opcode.OP_ADD),
        @intFromEnum(opcode.Opcode.OP_3),
        @intFromEnum(opcode.Opcode.OP_NUMEQUAL),
    });

    var altstack_result = try executeScript(.{ .allocator = allocator }, altstack_script);
    defer altstack_result.deinit(allocator);
    try std.testing.expect(altstack_result.success);

    const deep_stack_script = Script.init(&[_]u8{
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_2),
        @intFromEnum(opcode.Opcode.OP_3),
        @intFromEnum(opcode.Opcode.OP_0),
        @intFromEnum(opcode.Opcode.OP_PICK),
        @intFromEnum(opcode.Opcode.OP_3),
        @intFromEnum(opcode.Opcode.OP_NUMEQUALVERIFY),
        @intFromEnum(opcode.Opcode.OP_2),
        @intFromEnum(opcode.Opcode.OP_ROLL),
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_NUMEQUAL),
    });

    var deep_stack_result = try executeScript(.{ .allocator = allocator }, deep_stack_script);
    defer deep_stack_result.deinit(allocator);
    try std.testing.expect(deep_stack_result.success);
}

test "engine verifies 2-of-2 checksig ordering with checkmultisig" {
    const allocator = std.testing.allocator;

    var key_bytes_a = [_]u8{0} ** 32;
    key_bytes_a[31] = 1;
    var key_bytes_b = [_]u8{0} ** 32;
    key_bytes_b[31] = 2;

    const private_key_a = try crypto.PrivateKey.fromBytes(key_bytes_a);
    const private_key_b = try crypto.PrivateKey.fromBytes(key_bytes_b);
    const public_key_a = try private_key_a.publicKey();
    const public_key_b = try private_key_b.publicKey();

    const locking_script_bytes = buildTwoOfTwoLockingScript(public_key_a, public_key_b);
    const locking_script = Script.init(&locking_script_bytes);

    const tx = @import("../transaction/transaction.zig").Transaction{
        .version = 2,
        .inputs = &[_]@import("../transaction/input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x55} ** 32 },
                    .index = 0,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 0xffff_fffe,
            },
        },
        .outputs = &[_]@import("../transaction/output.zig").Output{
            .{
                .satoshis = 1_200,
                .locking_script = locking_script,
            },
        },
        .lock_time = 0,
    };

    const p2pkh_spend = @import("../transaction/templates/p2pkh_spend.zig");
    const sig_a = try p2pkh_spend.signInput(
        allocator,
        &tx,
        0,
        locking_script,
        1_500,
        private_key_a,
        p2pkh_spend.default_scope,
    );
    const sig_b = try p2pkh_spend.signInput(
        allocator,
        &tx,
        0,
        locking_script,
        1_500,
        private_key_b,
        p2pkh_spend.default_scope,
    );

    const unlocking_script = try buildMultisigUnlockingScript(allocator, &[_]crypto.TxSignature{ sig_a, sig_b });
    defer allocator.free(unlocking_script.bytes);

    try std.testing.expect(try verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = locking_script,
        .previous_satoshis = 1_500,
    }, unlocking_script, locking_script));

    const wrong_unlocking_script = try buildMultisigUnlockingScript(allocator, &[_]crypto.TxSignature{ sig_b, sig_a });
    defer allocator.free(wrong_unlocking_script.bytes);

    try std.testing.expect(!(try verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = locking_script,
        .previous_satoshis = 1_500,
    }, wrong_unlocking_script, locking_script)));
}

test "engine checkmultisig exits early before touching later invalid pubkeys" {
    const allocator = std.testing.allocator;

    var key_bytes_a = [_]u8{0} ** 32;
    key_bytes_a[31] = 1;
    var key_bytes_b = [_]u8{0} ** 32;
    key_bytes_b[31] = 2;

    const private_key_a = try crypto.PrivateKey.fromBytes(key_bytes_a);
    const private_key_b = try crypto.PrivateKey.fromBytes(key_bytes_b);
    const public_key_a = try private_key_a.publicKey();
    _ = try private_key_b.publicKey();

    var invalid_pubkey = [_]u8{0} ** 33;
    invalid_pubkey[0] = 0x05;

    const locking_script_bytes = [_]u8{
        @intFromEnum(opcode.Opcode.OP_2),
        33,
    } ++ invalid_pubkey ++ [_]u8{
        33,
    } ++ public_key_a.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_2),
        @intFromEnum(opcode.Opcode.OP_CHECKMULTISIG),
    };
    const locking_script = Script.init(&locking_script_bytes);

    const tx = @import("../transaction/transaction.zig").Transaction{
        .version = 2,
        .inputs = &[_]@import("../transaction/input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x56} ** 32 },
                    .index = 0,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 0xffff_fffe,
            },
        },
        .outputs = &[_]@import("../transaction/output.zig").Output{
            .{
                .satoshis = 1_200,
                .locking_script = locking_script,
            },
        },
        .lock_time = 0,
    };

    const p2pkh_spend = @import("../transaction/templates/p2pkh_spend.zig");
    const sig_a = try p2pkh_spend.signInput(
        allocator,
        &tx,
        0,
        locking_script,
        1_500,
        private_key_a,
        p2pkh_spend.default_scope,
    );
    const sig_b = try p2pkh_spend.signInput(
        allocator,
        &tx,
        0,
        locking_script,
        1_500,
        private_key_b,
        p2pkh_spend.default_scope,
    );

    const unlocking_script = try buildMultisigUnlockingScript(allocator, &[_]crypto.TxSignature{ sig_a, sig_b });
    defer allocator.free(unlocking_script.bytes);

    try std.testing.expect(!(try verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = locking_script,
        .previous_satoshis = 1_500,
        .flags = .{ .strict_pubkey_encoding = true },
    }, unlocking_script, locking_script)));
}

test "engine checkmultisig errors on the first checked invalid pubkey under strict policy" {
    const allocator = std.testing.allocator;

    var key_bytes_a = [_]u8{0} ** 32;
    var key_bytes_b = [_]u8{0} ** 32;
    key_bytes_a[31] = 1;
    key_bytes_b[31] = 2;

    const private_key_a = try crypto.PrivateKey.fromBytes(key_bytes_a);
    const private_key_b = try crypto.PrivateKey.fromBytes(key_bytes_b);
    const public_key_a = try private_key_a.publicKey();
    _ = try private_key_b.publicKey();

    var invalid_pubkey = [_]u8{0} ** 33;
    invalid_pubkey[0] = 0x05;

    const locking_script_bytes = [_]u8{
        @intFromEnum(opcode.Opcode.OP_2),
        33,
    } ++ public_key_a.bytes ++ [_]u8{
        33,
    } ++ invalid_pubkey ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_2),
        @intFromEnum(opcode.Opcode.OP_CHECKMULTISIG),
    };
    const locking_script = Script.init(&locking_script_bytes);

    const tx = @import("../transaction/transaction.zig").Transaction{
        .version = 2,
        .inputs = &[_]@import("../transaction/input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x57} ** 32 },
                    .index = 0,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 0xffff_fffe,
            },
        },
        .outputs = &[_]@import("../transaction/output.zig").Output{
            .{
                .satoshis = 1_200,
                .locking_script = locking_script,
            },
        },
        .lock_time = 0,
    };

    const p2pkh_spend = @import("../transaction/templates/p2pkh_spend.zig");
    const sig_a = try p2pkh_spend.signInput(
        allocator,
        &tx,
        0,
        locking_script,
        1_500,
        private_key_a,
        p2pkh_spend.default_scope,
    );
    const sig_b = try p2pkh_spend.signInput(
        allocator,
        &tx,
        0,
        locking_script,
        1_500,
        private_key_b,
        p2pkh_spend.default_scope,
    );

    const unlocking_script = try buildMultisigUnlockingScript(allocator, &[_]crypto.TxSignature{ sig_a, sig_b });
    defer allocator.free(unlocking_script.bytes);

    try std.testing.expectError(error.InvalidPublicKeyEncoding, verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = locking_script,
        .previous_satoshis = 1_500,
        .flags = .{
            .strict_encoding = false,
            .strict_pubkey_encoding = true,
        },
    }, unlocking_script, locking_script));
}

test "engine checkmultisig errors on the first checked malformed signature under strict policy" {
    const allocator = std.testing.allocator;

    var key_bytes_a = [_]u8{0} ** 32;
    var key_bytes_b = [_]u8{0} ** 32;
    key_bytes_a[31] = 1;
    key_bytes_b[31] = 2;

    const private_key_a = try crypto.PrivateKey.fromBytes(key_bytes_a);
    const private_key_b = try crypto.PrivateKey.fromBytes(key_bytes_b);
    const public_key_a = try private_key_a.publicKey();
    const public_key_b = try private_key_b.publicKey();

    const locking_script_bytes = buildTwoOfTwoLockingScript(public_key_a, public_key_b);
    const locking_script = Script.init(&locking_script_bytes);

    const tx = @import("../transaction/transaction.zig").Transaction{
        .version = 2,
        .inputs = &[_]@import("../transaction/input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x58} ** 32 },
                    .index = 0,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 0xffff_fffe,
            },
        },
        .outputs = &[_]@import("../transaction/output.zig").Output{
            .{
                .satoshis = 1_200,
                .locking_script = locking_script,
            },
        },
        .lock_time = 0,
    };

    const p2pkh_spend = @import("../transaction/templates/p2pkh_spend.zig");
    const sig_a = try p2pkh_spend.signInput(
        allocator,
        &tx,
        0,
        locking_script,
        1_500,
        private_key_a,
        p2pkh_spend.default_scope,
    );

    const invalid_sig_bytes = [_]u8{@intCast(p2pkh_spend.default_scope)};
    const valid_sig_bytes = try sig_a.toChecksigFormat(allocator);
    defer allocator.free(valid_sig_bytes);

    var unlocking_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer unlocking_bytes.deinit(allocator);
    try unlocking_bytes.append(allocator, @intFromEnum(opcode.Opcode.OP_0));
    const valid_push = try encodePushDataElement(allocator, valid_sig_bytes);
    defer allocator.free(valid_push);
    try unlocking_bytes.appendSlice(allocator, valid_push);
    const invalid_push = try encodePushDataElement(allocator, &invalid_sig_bytes);
    defer allocator.free(invalid_push);
    try unlocking_bytes.appendSlice(allocator, invalid_push);
    const unlocking_script = Script.init(try unlocking_bytes.toOwnedSlice(allocator));
    defer allocator.free(unlocking_script.bytes);

    try std.testing.expectError(error.InvalidSignatureEncoding, verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = locking_script,
        .previous_satoshis = 1_500,
        .flags = .{
            .strict_encoding = false,
            .der_signatures = true,
        },
    }, unlocking_script, locking_script));
}

test "engine checkmultisig ignores later hybrid pubkeys when an earlier key already satisfies the signature" {
    const allocator = std.testing.allocator;

    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;

    const private_key = try crypto.PrivateKey.fromBytes(key_bytes);
    const public_key = try private_key.publicKey();
    const std_public_key = try std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256.PublicKey.fromSec1(&public_key.bytes);
    const uncompressed = std_public_key.toUncompressedSec1();

    var hybrid_pubkey = uncompressed;
    hybrid_pubkey[0] = 0x06;

    const locking_script_bytes = [_]u8{
        @intFromEnum(opcode.Opcode.OP_1),
        65,
    } ++ hybrid_pubkey ++ [_]u8{
        33,
    } ++ public_key.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_2),
        @intFromEnum(opcode.Opcode.OP_CHECKMULTISIG),
    };
    const locking_script = Script.init(&locking_script_bytes);

    const tx = @import("../transaction/transaction.zig").Transaction{
        .version = 2,
        .inputs = &[_]@import("../transaction/input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x59} ** 32 },
                    .index = 0,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 0xffff_fffe,
            },
        },
        .outputs = &[_]@import("../transaction/output.zig").Output{
            .{
                .satoshis = 1_200,
                .locking_script = locking_script,
            },
        },
        .lock_time = 0,
    };

    const p2pkh_spend = @import("../transaction/templates/p2pkh_spend.zig");
    const sig = try p2pkh_spend.signInput(
        allocator,
        &tx,
        0,
        locking_script,
        1_500,
        private_key,
        p2pkh_spend.default_scope,
    );
    const unlocking_script = try buildMultisigUnlockingScript(allocator, &[_]crypto.TxSignature{sig});
    defer allocator.free(unlocking_script.bytes);

    try std.testing.expect(try verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = locking_script,
        .previous_satoshis = 1_500,
        .flags = .{
            .strict_encoding = true,
            .strict_pubkey_encoding = true,
        },
    }, unlocking_script, locking_script));
}

test "engine checkmultisig errors on the first checked hybrid pubkey under strict policy" {
    const allocator = std.testing.allocator;

    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;

    const private_key = try crypto.PrivateKey.fromBytes(key_bytes);
    const public_key = try private_key.publicKey();
    const std_public_key = try std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256.PublicKey.fromSec1(&public_key.bytes);
    const uncompressed = std_public_key.toUncompressedSec1();

    var hybrid_pubkey = uncompressed;
    hybrid_pubkey[0] = 0x06;

    const locking_script_bytes = [_]u8{
        @intFromEnum(opcode.Opcode.OP_1),
        33,
    } ++ public_key.bytes ++ [_]u8{
        65,
    } ++ hybrid_pubkey ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_2),
        @intFromEnum(opcode.Opcode.OP_CHECKMULTISIG),
    };
    const locking_script = Script.init(&locking_script_bytes);

    const tx = @import("../transaction/transaction.zig").Transaction{
        .version = 2,
        .inputs = &[_]@import("../transaction/input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x5a} ** 32 },
                    .index = 0,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 0xffff_fffe,
            },
        },
        .outputs = &[_]@import("../transaction/output.zig").Output{
            .{
                .satoshis = 1_200,
                .locking_script = locking_script,
            },
        },
        .lock_time = 0,
    };

    const p2pkh_spend = @import("../transaction/templates/p2pkh_spend.zig");
    const sig = try p2pkh_spend.signInput(
        allocator,
        &tx,
        0,
        locking_script,
        1_500,
        private_key,
        p2pkh_spend.default_scope,
    );
    const unlocking_script = try buildMultisigUnlockingScript(allocator, &[_]crypto.TxSignature{sig});
    defer allocator.free(unlocking_script.bytes);

    try std.testing.expectError(error.InvalidPublicKeyEncoding, verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = locking_script,
        .previous_satoshis = 1_500,
        .flags = .{
            .strict_encoding = true,
            .strict_pubkey_encoding = true,
        },
    }, unlocking_script, locking_script));
}

test "engine checkmultisig rejects illegal forkid under legacy strict policy" {
    const allocator = std.testing.allocator;

    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;

    const private_key = try crypto.PrivateKey.fromBytes(key_bytes);
    const public_key = try private_key.publicKey();

    const locking_script_bytes = [_]u8{
        @intFromEnum(opcode.Opcode.OP_1),
        33,
    } ++ public_key.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_CHECKMULTISIG),
    };
    const locking_script = Script.init(&locking_script_bytes);

    const tx = @import("../transaction/transaction.zig").Transaction{
        .version = 2,
        .inputs = &[_]@import("../transaction/input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x5b} ** 32 },
                    .index = 0,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 0xffff_fffe,
            },
        },
        .outputs = &[_]@import("../transaction/output.zig").Output{
            .{
                .satoshis = 1_200,
                .locking_script = locking_script,
            },
        },
        .lock_time = 0,
    };

    const tx_signature = try @import("../transaction/templates/p2pkh_spend.zig").signInput(
        allocator,
        &tx,
        0,
        locking_script,
        1_500,
        private_key,
        @intCast(sighash.SigHashType.forkid | sighash.SigHashType.all),
    );
    const checksig_bytes = try tx_signature.toChecksigFormat(allocator);
    defer allocator.free(checksig_bytes);

    var unlocking_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer unlocking_bytes.deinit(allocator);
    try unlocking_bytes.append(allocator, @intFromEnum(opcode.Opcode.OP_0));
    const sig_push = try encodePushDataElement(allocator, checksig_bytes);
    defer allocator.free(sig_push);
    try unlocking_bytes.appendSlice(allocator, sig_push);
    const unlocking_script = Script.init(try unlocking_bytes.toOwnedSlice(allocator));
    defer allocator.free(unlocking_script.bytes);

    try std.testing.expectError(error.IllegalForkId, verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = locking_script,
        .previous_satoshis = 1_500,
        .flags = .{
            .strict_encoding = true,
            .enable_sighash_forkid = false,
            .verify_bip143_sighash = false,
        },
    }, unlocking_script, locking_script));
}

test "engine checkmultisig not accepts a forkid signature when forkid mode is enabled" {
    const allocator = std.testing.allocator;

    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;

    const private_key = try crypto.PrivateKey.fromBytes(key_bytes);
    const public_key = try private_key.publicKey();

    const locking_script_bytes = [_]u8{
        @intFromEnum(opcode.Opcode.OP_1),
        33,
    } ++ public_key.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_CHECKMULTISIG),
        @intFromEnum(opcode.Opcode.OP_NOT),
    };
    const locking_script = Script.init(&locking_script_bytes);

    const tx = @import("../transaction/transaction.zig").Transaction{
        .version = 2,
        .inputs = &[_]@import("../transaction/input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x5c} ** 32 },
                    .index = 0,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 0xffff_fffe,
            },
        },
        .outputs = &[_]@import("../transaction/output.zig").Output{
            .{
                .satoshis = 1_200,
                .locking_script = locking_script,
            },
        },
        .lock_time = 0,
    };

    const forkid_invalid_signature = [_]u8{ 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x41 };

    var unlocking_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer unlocking_bytes.deinit(allocator);
    try unlocking_bytes.append(allocator, @intFromEnum(opcode.Opcode.OP_0));
    const sig_push = try encodePushDataElement(allocator, &forkid_invalid_signature);
    defer allocator.free(sig_push);
    try unlocking_bytes.appendSlice(allocator, sig_push);
    const unlocking_script = Script.init(try unlocking_bytes.toOwnedSlice(allocator));
    defer allocator.free(unlocking_script.bytes);

    try std.testing.expectError(error.IllegalForkId, verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = locking_script,
        .previous_satoshis = 1_500,
        .flags = .{
            .strict_encoding = true,
            .enable_sighash_forkid = false,
            .verify_bip143_sighash = false,
        },
    }, unlocking_script, locking_script));

    try std.testing.expect(try verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = locking_script,
        .previous_satoshis = 1_500,
        .flags = .{
            .enable_sighash_forkid = true,
            .verify_bip143_sighash = true,
        },
    }, unlocking_script, locking_script));
}

test "engine checkmultisig surfaces malformed signature before ordinary 2-of-3 failure" {
    const allocator = std.testing.allocator;

    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;

    const private_key = try crypto.PrivateKey.fromBytes(key_bytes);
    const public_key = try private_key.publicKey();

    const locking_script_bytes = [_]u8{
        @intFromEnum(opcode.Opcode.OP_2),
        33,
    } ++ public_key.bytes ++ [_]u8{
        33,
    } ++ public_key.bytes ++ [_]u8{
        33,
    } ++ public_key.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_3),
        @intFromEnum(opcode.Opcode.OP_CHECKMULTISIG),
    };
    const locking_script = Script.init(&locking_script_bytes);

    const tx = @import("../transaction/transaction.zig").Transaction{
        .version = 2,
        .inputs = &[_]@import("../transaction/input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x5c} ** 32 },
                    .index = 0,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 0xffff_fffe,
            },
        },
        .outputs = &[_]@import("../transaction/output.zig").Output{
            .{
                .satoshis = 1_200,
                .locking_script = locking_script,
            },
        },
        .lock_time = 0,
    };

    const p2pkh_spend = @import("../transaction/templates/p2pkh_spend.zig");
    const valid_sig = try p2pkh_spend.signInput(
        allocator,
        &tx,
        0,
        locking_script,
        1_500,
        private_key,
        p2pkh_spend.default_scope,
    );
    const valid_sig_bytes = try valid_sig.toChecksigFormat(allocator);
    defer allocator.free(valid_sig_bytes);

    var invalid_sig_bytes = try allocator.dupe(u8, valid_sig_bytes);
    defer allocator.free(invalid_sig_bytes);
    invalid_sig_bytes[0] = 0x31;

    var unlocking_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer unlocking_bytes.deinit(allocator);
    try unlocking_bytes.append(allocator, @intFromEnum(opcode.Opcode.OP_0));
    const valid_push = try encodePushDataElement(allocator, valid_sig_bytes);
    defer allocator.free(valid_push);
    try unlocking_bytes.appendSlice(allocator, valid_push);
    const invalid_push = try encodePushDataElement(allocator, invalid_sig_bytes);
    defer allocator.free(invalid_push);
    try unlocking_bytes.appendSlice(allocator, invalid_push);
    const unlocking_script = Script.init(try unlocking_bytes.toOwnedSlice(allocator));
    defer allocator.free(unlocking_script.bytes);

    try std.testing.expectError(error.InvalidSignatureEncoding, verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = locking_script,
        .previous_satoshis = 1_500,
        .flags = .{
            .strict_encoding = true,
        },
    }, unlocking_script, locking_script));
}

test "engine legacy checksig removes pushed signature copies from script code when legacy mode is enabled" {
    const allocator = std.testing.allocator;

    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;

    const private_key = try crypto.PrivateKey.fromBytes(key_bytes);
    const public_key = try private_key.publicKey();

    const script_code_bytes = [_]u8{
        @intFromEnum(opcode.Opcode.OP_DROP),
        33,
    } ++ public_key.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIG),
    };
    const script_code = Script.init(&script_code_bytes);

    const tx = @import("../transaction/transaction.zig").Transaction{
        .version = 2,
        .inputs = &[_]@import("../transaction/input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x77} ** 32 },
                    .index = 0,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 0xffff_fffe,
            },
        },
        .outputs = &[_]@import("../transaction/output.zig").Output{
            .{
                .satoshis = 900,
                .locking_script = .{ .bytes = &[_]u8{0x6a} },
            },
        },
        .lock_time = 0,
    };

    const scope = sighash.SigHashType.all;
    const digest = try sighash.digest(allocator, &tx, 0, script_code, 1_000, scope);

    const tx_signature = crypto.TxSignature{
        .der = try private_key.signDigest256(digest.bytes),
        .sighash_type = @truncate(scope),
    };
    const checksig_bytes = try tx_signature.toChecksigFormat(allocator);
    defer allocator.free(checksig_bytes);

    const checksig_push = try encodePushDataElement(allocator, checksig_bytes);
    defer allocator.free(checksig_push);

    var locking_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer locking_bytes.deinit(allocator);
    try locking_bytes.appendSlice(allocator, checksig_push);
    try locking_bytes.append(allocator, @intFromEnum(opcode.Opcode.OP_DROP));
    try locking_bytes.append(allocator, 33);
    try locking_bytes.appendSlice(allocator, &public_key.bytes);
    try locking_bytes.append(allocator, @intFromEnum(opcode.Opcode.OP_CHECKSIG));
    const locking_script = Script.init(try locking_bytes.toOwnedSlice(allocator));
    defer allocator.free(locking_script.bytes);

    const unlocking_script = Script.init(checksig_push);

    try std.testing.expect(try verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = locking_script,
        .previous_satoshis = 1_000,
        .flags = .{
            .enable_sighash_forkid = false,
            .verify_bip143_sighash = false,
        },
    }, unlocking_script, locking_script));
}

test "engine enforces NULLDUMMY for checkmultisig when enabled" {
    const allocator = std.testing.allocator;

    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;

    const private_key = try crypto.PrivateKey.fromBytes(key_bytes);
    const public_key = try private_key.publicKey();

    const locking_script_bytes = [_]u8{
        @intFromEnum(opcode.Opcode.OP_1),
        33,
    } ++ public_key.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_CHECKMULTISIG),
    };
    const locking_script = Script.init(&locking_script_bytes);

    const tx = @import("../transaction/transaction.zig").Transaction{
        .version = 2,
        .inputs = &[_]@import("../transaction/input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x88} ** 32 },
                    .index = 0,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 0xffff_fffe,
            },
        },
        .outputs = &[_]@import("../transaction/output.zig").Output{
            .{
                .satoshis = 900,
                .locking_script = .{ .bytes = &[_]u8{0x6a} },
            },
        },
        .lock_time = 0,
    };

    const p2pkh_spend = @import("../transaction/templates/p2pkh_spend.zig");
    const tx_signature = try p2pkh_spend.signInput(
        allocator,
        &tx,
        0,
        locking_script,
        1_000,
        private_key,
        p2pkh_spend.default_scope,
    );
    const checksig_bytes = try tx_signature.toChecksigFormat(allocator);
    defer allocator.free(checksig_bytes);

    var unlocking_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer unlocking_bytes.deinit(allocator);
    try unlocking_bytes.append(allocator, @intFromEnum(opcode.Opcode.OP_1));
    const sig_push = try encodePushDataElement(allocator, checksig_bytes);
    defer allocator.free(sig_push);
    try unlocking_bytes.appendSlice(allocator, sig_push);
    const unlocking_script = Script.init(try unlocking_bytes.toOwnedSlice(allocator));
    defer allocator.free(unlocking_script.bytes);

    try std.testing.expectError(error.NullDummy, verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = locking_script,
        .previous_satoshis = 1_000,
        .flags = .{ .null_dummy = true },
    }, unlocking_script, locking_script));

    try std.testing.expect(try verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = locking_script,
        .previous_satoshis = 1_000,
        .flags = .{ .null_dummy = false },
    }, unlocking_script, locking_script));
}

test "engine multisig nullfail only trips on non-empty failing signatures" {
    const allocator = std.testing.allocator;

    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;

    const private_key = try crypto.PrivateKey.fromBytes(key_bytes);
    const public_key = try private_key.publicKey();

    const locking_script_bytes = [_]u8{
        @intFromEnum(opcode.Opcode.OP_1),
        33,
    } ++ public_key.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_CHECKMULTISIG),
    };
    const locking_script = Script.init(&locking_script_bytes);

    const tx = @import("../transaction/transaction.zig").Transaction{
        .version = 2,
        .inputs = &[_]@import("../transaction/input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x91} ** 32 },
                    .index = 0,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 0xffff_fffe,
            },
        },
        .outputs = &[_]@import("../transaction/output.zig").Output{
            .{
                .satoshis = 900,
                .locking_script = .{ .bytes = &[_]u8{0x6a} },
            },
        },
        .lock_time = 0,
    };

    const p2pkh_spend = @import("../transaction/templates/p2pkh_spend.zig");
    const tx_signature = try p2pkh_spend.signInput(
        allocator,
        &tx,
        0,
        locking_script,
        1_000,
        private_key,
        p2pkh_spend.default_scope,
    );
    const checksig_bytes = try tx_signature.toChecksigFormat(allocator);
    defer allocator.free(checksig_bytes);

    var failing_unlocking_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer failing_unlocking_bytes.deinit(allocator);
    try failing_unlocking_bytes.append(allocator, @intFromEnum(opcode.Opcode.OP_0));
    const sig_push = try encodePushDataElement(allocator, checksig_bytes);
    defer allocator.free(sig_push);
    try failing_unlocking_bytes.appendSlice(allocator, sig_push);
    const failing_unlocking_script = Script.init(try failing_unlocking_bytes.toOwnedSlice(allocator));
    defer allocator.free(failing_unlocking_script.bytes);

    try std.testing.expect(!(try verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = locking_script,
        .previous_satoshis = 999,
        .flags = .{ .null_fail = false },
    }, failing_unlocking_script, locking_script)));

    try std.testing.expectError(error.NullFail, verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = locking_script,
        .previous_satoshis = 999,
        .flags = .{ .null_fail = true },
    }, failing_unlocking_script, locking_script));

    const empty_unlocking_script = Script.init(&[_]u8{
        @intFromEnum(opcode.Opcode.OP_0),
        @intFromEnum(opcode.Opcode.OP_0),
    });

    try std.testing.expect(!(try verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = locking_script,
        .previous_satoshis = 999,
        .flags = .{ .null_fail = true },
    }, empty_unlocking_script, locking_script)));
}

test "engine multisig nullfail scans later signatures after checkmultisig-not failure" {
    const allocator = std.testing.allocator;

    var key_bytes_a = [_]u8{0} ** 32;
    var key_bytes_b = [_]u8{0} ** 32;
    key_bytes_a[31] = 1;
    key_bytes_b[31] = 2;

    const private_key_a = try crypto.PrivateKey.fromBytes(key_bytes_a);
    const private_key_b = try crypto.PrivateKey.fromBytes(key_bytes_b);
    const public_key_a = try private_key_a.publicKey();
    const public_key_b = try private_key_b.publicKey();

    const locking_script_bytes = [_]u8{
        @intFromEnum(opcode.Opcode.OP_2),
        33,
    } ++ public_key_a.bytes ++ [_]u8{
        33,
    } ++ public_key_b.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_2),
        @intFromEnum(opcode.Opcode.OP_CHECKMULTISIG),
        @intFromEnum(opcode.Opcode.OP_NOT),
    };
    const locking_script = Script.init(&locking_script_bytes);

    const tx = @import("../transaction/transaction.zig").Transaction{
        .version = 2,
        .inputs = &[_]@import("../transaction/input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x92} ** 32 },
                    .index = 0,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 0xffff_fffe,
            },
        },
        .outputs = &[_]@import("../transaction/output.zig").Output{
            .{
                .satoshis = 900,
                .locking_script = .{ .bytes = &[_]u8{0x6a} },
            },
        },
        .lock_time = 0,
    };

    const der_like_invalid_signature = [_]u8{ 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01 };

    var unlocking_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer unlocking_bytes.deinit(allocator);
    try unlocking_bytes.append(allocator, @intFromEnum(opcode.Opcode.OP_0));
    try unlocking_bytes.append(allocator, @intFromEnum(opcode.Opcode.OP_0));
    const sig_push = try encodePushDataElement(allocator, &der_like_invalid_signature);
    defer allocator.free(sig_push);
    try unlocking_bytes.appendSlice(allocator, sig_push);
    const unlocking_script = Script.init(try unlocking_bytes.toOwnedSlice(allocator));
    defer allocator.free(unlocking_script.bytes);

    try std.testing.expect(try verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = locking_script,
        .previous_satoshis = 1_000,
        .flags = .{
            .der_signatures = true,
            .null_fail = false,
            .enable_sighash_forkid = false,
            .verify_bip143_sighash = false,
        },
    }, unlocking_script, locking_script));

    try std.testing.expectError(error.NullFail, verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = locking_script,
        .previous_satoshis = 1_000,
        .flags = .{
            .der_signatures = true,
            .null_fail = true,
            .enable_sighash_forkid = false,
            .verify_bip143_sighash = false,
        },
    }, unlocking_script, locking_script));
}

test "engine multisig nullfail ignores a nonzero dummy when nulldummy is disabled" {
    const allocator = std.testing.allocator;

    var key_bytes_a = [_]u8{0} ** 32;
    var key_bytes_b = [_]u8{0} ** 32;
    key_bytes_a[31] = 1;
    key_bytes_b[31] = 2;

    const private_key_a = try crypto.PrivateKey.fromBytes(key_bytes_a);
    const private_key_b = try crypto.PrivateKey.fromBytes(key_bytes_b);
    const public_key_a = try private_key_a.publicKey();
    const public_key_b = try private_key_b.publicKey();

    const locking_script_bytes = [_]u8{
        @intFromEnum(opcode.Opcode.OP_2),
        33,
    } ++ public_key_a.bytes ++ [_]u8{
        33,
    } ++ public_key_b.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_2),
        @intFromEnum(opcode.Opcode.OP_CHECKMULTISIG),
        @intFromEnum(opcode.Opcode.OP_NOT),
    };
    const locking_script = Script.init(&locking_script_bytes);

    const tx = @import("../transaction/transaction.zig").Transaction{
        .version = 2,
        .inputs = &[_]@import("../transaction/input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x93} ** 32 },
                    .index = 0,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 0xffff_fffe,
            },
        },
        .outputs = &[_]@import("../transaction/output.zig").Output{
            .{
                .satoshis = 900,
                .locking_script = .{ .bytes = &[_]u8{0x6a} },
            },
        },
        .lock_time = 0,
    };

    const unlocking_script = Script.init(&[_]u8{
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_0),
        @intFromEnum(opcode.Opcode.OP_0),
    });

    try std.testing.expect(try verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = locking_script,
        .previous_satoshis = 1_000,
        .flags = .{
            .null_fail = true,
            .null_dummy = false,
            .enable_sighash_forkid = false,
            .verify_bip143_sighash = false,
        },
    }, unlocking_script, locking_script));
}

test "engine multisig nulldummy takes precedence over nullfail" {
    const allocator = std.testing.allocator;

    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;

    const private_key = try crypto.PrivateKey.fromBytes(key_bytes);
    const public_key = try private_key.publicKey();

    const locking_script_bytes = [_]u8{
        @intFromEnum(opcode.Opcode.OP_1),
        33,
    } ++ public_key.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_CHECKMULTISIG),
    };
    const locking_script = Script.init(&locking_script_bytes);

    const tx = @import("../transaction/transaction.zig").Transaction{
        .version = 2,
        .inputs = &[_]@import("../transaction/input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x92} ** 32 },
                    .index = 0,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 0xffff_fffe,
            },
        },
        .outputs = &[_]@import("../transaction/output.zig").Output{
            .{
                .satoshis = 900,
                .locking_script = .{ .bytes = &[_]u8{0x6a} },
            },
        },
        .lock_time = 0,
    };

    const p2pkh_spend = @import("../transaction/templates/p2pkh_spend.zig");
    const tx_signature = try p2pkh_spend.signInput(
        allocator,
        &tx,
        0,
        locking_script,
        1_000,
        private_key,
        p2pkh_spend.default_scope,
    );
    const checksig_bytes = try tx_signature.toChecksigFormat(allocator);
    defer allocator.free(checksig_bytes);

    var unlocking_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer unlocking_bytes.deinit(allocator);
    try unlocking_bytes.append(allocator, @intFromEnum(opcode.Opcode.OP_1));
    const sig_push = try encodePushDataElement(allocator, checksig_bytes);
    defer allocator.free(sig_push);
    try unlocking_bytes.appendSlice(allocator, sig_push);
    const unlocking_script = Script.init(try unlocking_bytes.toOwnedSlice(allocator));
    defer allocator.free(unlocking_script.bytes);

    try std.testing.expectError(error.NullDummy, verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = locking_script,
        .previous_satoshis = 999,
        .flags = .{
            .null_dummy = true,
            .null_fail = true,
        },
    }, unlocking_script, locking_script));
}

test "engine allows more than 20 multisig pubkeys after genesis" {
    const allocator = std.testing.allocator;

    var script_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer script_bytes.deinit(allocator);

    try script_bytes.append(allocator, @intFromEnum(opcode.Opcode.OP_0));
    try script_bytes.append(allocator, @intFromEnum(opcode.Opcode.OP_0));
    for (0..21) |index| {
        try script_bytes.append(allocator, 0x01);
        try script_bytes.append(allocator, @intCast(index + 1));
    }
    try script_bytes.append(allocator, 0x01);
    try script_bytes.append(allocator, 21);
    try script_bytes.append(allocator, @intFromEnum(opcode.Opcode.OP_CHECKMULTISIG));

    const script = Script.init(try script_bytes.toOwnedSlice(allocator));
    defer allocator.free(script.bytes);

    var result = try executeScript(.{
        .allocator = allocator,
    }, script);
    defer result.deinit(allocator);

    try std.testing.expect(result.success);

    try std.testing.expectError(error.InvalidMultisigKeyCount, executeScript(.{
        .allocator = allocator,
        .flags = .{ .utxo_after_genesis = false },
    }, script));
}

test "engine can require push-only unlocking scripts" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.SigPushOnly, verifyScripts(.{
        .allocator = allocator,
        .flags = .{ .sig_push_only = true },
    }, Script.init(&[_]u8{
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_DUP),
    }), Script.init(&[_]u8{
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_EQUAL),
    })));
}

test "engine can enforce minimal push encodings only on executed branches" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.MinimalData, executeScript(.{
        .allocator = allocator,
        .flags = .{ .minimal_data = true },
    }, Script.init(&[_]u8{
        0x01, 0x01,
    })));

    var result = try executeScript(.{
        .allocator = allocator,
        .flags = .{ .minimal_data = true },
    }, Script.init(&[_]u8{
        @intFromEnum(opcode.Opcode.OP_0),
        @intFromEnum(opcode.Opcode.OP_IF),
        @intFromEnum(opcode.Opcode.OP_PUSHDATA1),
        0x01,
        0x01,
        @intFromEnum(opcode.Opcode.OP_ENDIF),
        @intFromEnum(opcode.Opcode.OP_1),
    }));
    defer result.deinit(allocator);

    try std.testing.expect(result.success);
}

test "engine enforces minimal numeric encoding at arithmetic opcode boundaries" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.MinimalData, executeScript(.{
        .allocator = allocator,
        .flags = .{ .minimal_data = true },
    }, Script.init(&[_]u8{
        0x03, 0xFF, 0x00, 0x00,
        @intFromEnum(opcode.Opcode.OP_2),
        @intFromEnum(opcode.Opcode.OP_MUL),
    })));

    try std.testing.expectError(error.MinimalData, executeScript(.{
        .allocator = allocator,
        .flags = .{ .minimal_data = true },
    }, Script.init(&[_]u8{
        0x02, 0x00, 0x00,
        @intFromEnum(opcode.Opcode.OP_NOT),
        @intFromEnum(opcode.Opcode.OP_DROP),
        @intFromEnum(opcode.Opcode.OP_1),
    })));
}

test "engine enforces minimal numeric encoding for stack index opcodes" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.MinimalData, executeScript(.{
        .allocator = allocator,
        .flags = .{ .minimal_data = true },
    }, Script.init(&[_]u8{
        @intFromEnum(opcode.Opcode.OP_1),
        0x02, 0x00, 0x00,
        @intFromEnum(opcode.Opcode.OP_PICK),
        @intFromEnum(opcode.Opcode.OP_DROP),
        @intFromEnum(opcode.Opcode.OP_1),
    })));

    try std.testing.expectError(error.MinimalData, executeScript(.{
        .allocator = allocator,
        .flags = .{ .minimal_data = true },
    }, Script.init(&[_]u8{
        0x02, 0x00, 0x00,
        @intFromEnum(opcode.Opcode.OP_1ADD),
        @intFromEnum(opcode.Opcode.OP_DROP),
        @intFromEnum(opcode.Opcode.OP_1),
    })));
}

test "engine can require a clean final stack" {
    const allocator = std.testing.allocator;

    try std.testing.expect(try verifyScripts(.{
        .allocator = allocator,
    }, Script.init(&[_]u8{}), Script.init(&[_]u8{
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_1),
    })));

    try std.testing.expectError(error.CleanStack, verifyScripts(.{
        .allocator = allocator,
        .flags = .{ .clean_stack = true },
    }, Script.init(&[_]u8{}), Script.init(&[_]u8{
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_1),
    })));
}

test "engine matches the go-sdk nop/codeseparator sanity row" {
    const allocator = std.testing.allocator;

    try std.testing.expect(try verifyScripts(.{
        .allocator = allocator,
        .flags = .{ .strict_encoding = true },
    }, Script.init(&[_]u8{
        @intFromEnum(opcode.Opcode.OP_NOP),
    }), Script.init(&[_]u8{
        @intFromEnum(opcode.Opcode.OP_CODESEPARATOR),
        @intFromEnum(opcode.Opcode.OP_1),
    })));
}

test "engine surfaces malformed control flow and bounds errors" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.UnexpectedEndIf, executeScript(.{
        .allocator = allocator,
    }, Script.init(&[_]u8{@intFromEnum(opcode.Opcode.OP_ENDIF)})));

    try std.testing.expectError(error.UnbalancedConditionals, executeScript(.{
        .allocator = allocator,
    }, Script.init(&[_]u8{
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_IF),
        @intFromEnum(opcode.Opcode.OP_1),
    })));

    try std.testing.expectError(error.InvalidSplitPosition, executeScript(.{
        .allocator = allocator,
    }, Script.init(&[_]u8{
        0x02,                             0xaa,                                 0xbb,
        @intFromEnum(opcode.Opcode.OP_3), @intFromEnum(opcode.Opcode.OP_SPLIT),
    })));
}

test "engine treats OP_RETURN as post-genesis early success at top level" {
    const allocator = std.testing.allocator;

    var result = try executeScript(.{
        .allocator = allocator,
    }, Script.init(&[_]u8{
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_RETURN),
        0xba,
    }));
    defer result.deinit(allocator);

    try std.testing.expect(result.success);

    var false_result = try executeScript(.{
        .allocator = allocator,
    }, Script.init(&[_]u8{
        @intFromEnum(opcode.Opcode.OP_0),
        @intFromEnum(opcode.Opcode.OP_RETURN),
        0xba,
    }));
    defer false_result.deinit(allocator);

    try std.testing.expect(!false_result.success);

    try std.testing.expectError(error.ReturnEncountered, executeScript(.{
        .allocator = allocator,
        .flags = .{ .utxo_after_genesis = false },
    }, Script.init(&[_]u8{
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_RETURN),
    })));
}

test "engine enforces op and stack limits" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.OpCountLimitExceeded, executeScript(.{
        .allocator = allocator,
        .flags = .{ .max_ops = 1 },
    }, Script.init(&[_]u8{
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_DUP),
        @intFromEnum(opcode.Opcode.OP_DUP),
    })));

    try std.testing.expectError(error.StackSizeLimitExceeded, executeScript(.{
        .allocator = allocator,
        .flags = .{ .max_stack_items = 2 },
    }, Script.init(&[_]u8{
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_1),
    })));
}

test "engine enforces script element and script number length limits" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.ElementTooBig, executeScript(.{
        .allocator = allocator,
        .flags = .{ .max_script_element_size = 1 },
    }, Script.init(&[_]u8{
        0x02, 0xaa, 0xbb,
    })));

    try std.testing.expectError(error.ElementTooBig, executeScript(.{
        .allocator = allocator,
        .flags = .{ .max_script_element_size = 1 },
    }, Script.init(&[_]u8{
        @intFromEnum(opcode.Opcode.OP_0),
        @intFromEnum(opcode.Opcode.OP_IF),
        0x02,
        0xaa,
        0xbb,
        @intFromEnum(opcode.Opcode.OP_ENDIF),
        @intFromEnum(opcode.Opcode.OP_1),
    })));

    try std.testing.expectError(error.NumberTooBig, executeScript(.{
        .allocator = allocator,
        .flags = .{ .max_script_number_length = 4 },
    }, Script.init(&[_]u8{
        0x05, 0x00, 0x00, 0x00, 0x80, 0x00,
        @intFromEnum(opcode.Opcode.OP_1ADD),
    })));

    var bin2num_result = try executeScript(.{
        .allocator = allocator,
        .flags = .{ .max_script_number_length = 1 },
    }, Script.init(&[_]u8{
        0x02, 0x01, 0x00,
        @intFromEnum(opcode.Opcode.OP_BIN2NUM),
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_EQUAL),
    }));
    defer bin2num_result.deinit(allocator);
    try std.testing.expect(bin2num_result.success);
}

test "engine can disable re-enabled BSV opcodes through flags" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.UnknownOpcode, executeScript(.{
        .allocator = allocator,
        .flags = .{ .enable_reenabled_opcodes = false },
    }, Script.init(&[_]u8{
        0x01,                               0xaa,
        0x01,                               0xbb,
        @intFromEnum(opcode.Opcode.OP_CAT),
    })));
}

test "engine verifies p2pkh end to end through checksig" {
    const allocator = std.testing.allocator;
    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;

    const private_key = try crypto.PrivateKey.fromBytes(key_bytes);
    const public_key = try private_key.publicKey();
    const pubkey_hash = crypto.hash.hash160(&public_key.bytes);
    const previous_locking_script_bytes = @import("templates/p2pkh.zig").encode(pubkey_hash);
    const previous_locking_script = Script.init(&previous_locking_script_bytes);

    var tx = @import("../transaction/transaction.zig").Transaction{
        .version = 2,
        .inputs = &[_]@import("../transaction/input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x33} ** 32 },
                    .index = 0,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 0xffff_fffe,
            },
        },
        .outputs = &[_]@import("../transaction/output.zig").Output{
            .{
                .satoshis = 900,
                .locking_script = previous_locking_script,
            },
        },
        .lock_time = 0,
    };

    const unlocking_script = try @import("../transaction/templates/p2pkh_spend.zig").signAndBuildUnlockingScript(
        allocator,
        &tx,
        0,
        previous_locking_script,
        1_000,
        private_key,
        @import("../transaction/templates/p2pkh_spend.zig").default_scope,
    );
    defer allocator.free(unlocking_script.bytes);

    try std.testing.expect(try verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = previous_locking_script,
        .previous_satoshis = 1_000,
    }, unlocking_script, previous_locking_script));

    try std.testing.expect(!(try verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = previous_locking_script,
        .previous_satoshis = 999,
    }, unlocking_script, previous_locking_script)));

    try std.testing.expectError(error.NullFail, verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = previous_locking_script,
        .previous_satoshis = 999,
        .flags = .{ .null_fail = true },
    }, unlocking_script, previous_locking_script));
}

test "engine treats malformed pubkeys as false unless strict pubkey policy is enabled" {
    const allocator = std.testing.allocator;
    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;

    const private_key = try crypto.PrivateKey.fromBytes(key_bytes);
    const public_key = try private_key.publicKey();
    const locking_script_bytes = [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIG),
    };
    const previous_locking_script = Script.init(&locking_script_bytes);

    var tx = @import("../transaction/transaction.zig").Transaction{
        .version = 2,
        .inputs = &[_]@import("../transaction/input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x22} ** 32 },
                    .index = 0,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 0xffff_fffe,
            },
        },
        .outputs = &[_]@import("../transaction/output.zig").Output{
            .{
                .satoshis = 900,
                .locking_script = previous_locking_script,
            },
        },
        .lock_time = 0,
    };

    const tx_signature = try @import("../transaction/templates/p2pkh_spend.zig").signInput(
        allocator,
        &tx,
        0,
        previous_locking_script,
        1_000,
        private_key,
        @import("../transaction/templates/p2pkh_spend.zig").default_scope,
    );
    const checksig_bytes = try tx_signature.toChecksigFormat(allocator);
    defer allocator.free(checksig_bytes);
    const sig_push = try encodePushDataElement(allocator, checksig_bytes);
    defer allocator.free(sig_push);
    const pubkey_push = try encodePushDataElement(allocator, &public_key.bytes);
    defer allocator.free(pubkey_push);

    var malformed_unlocking = try allocator.alloc(u8, sig_push.len + pubkey_push.len);
    defer allocator.free(malformed_unlocking);
    @memcpy(malformed_unlocking[0..sig_push.len], sig_push);
    @memcpy(malformed_unlocking[sig_push.len..], pubkey_push);
    malformed_unlocking[sig_push.len + 1] = 0x05;

    try std.testing.expect(!(try verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = previous_locking_script,
        .previous_satoshis = 1_000,
        .flags = .{ .strict_encoding = false, .strict_pubkey_encoding = false },
    }, Script.init(malformed_unlocking), previous_locking_script)));

    try std.testing.expectError(error.InvalidPublicKeyEncoding, verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = previous_locking_script,
        .previous_satoshis = 1_000,
        .flags = .{ .strict_encoding = false, .strict_pubkey_encoding = true },
    }, Script.init(malformed_unlocking), previous_locking_script));
}

test "engine treats malformed DER signatures as false unless DER policy is enabled" {
    const allocator = std.testing.allocator;
    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;

    const private_key = try crypto.PrivateKey.fromBytes(key_bytes);
    const public_key = try private_key.publicKey();
    const locking_script_bytes = [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIG),
    };
    const previous_locking_script = Script.init(&locking_script_bytes);

    var tx = @import("../transaction/transaction.zig").Transaction{
        .version = 2,
        .inputs = &[_]@import("../transaction/input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x23} ** 32 },
                    .index = 0,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 0xffff_fffe,
            },
        },
        .outputs = &[_]@import("../transaction/output.zig").Output{
            .{
                .satoshis = 900,
                .locking_script = previous_locking_script,
            },
        },
        .lock_time = 0,
    };

    const tx_signature = try @import("../transaction/templates/p2pkh_spend.zig").signInput(
        allocator,
        &tx,
        0,
        previous_locking_script,
        1_000,
        private_key,
        @import("../transaction/templates/p2pkh_spend.zig").default_scope,
    );
    const checksig_bytes = try tx_signature.toChecksigFormat(allocator);
    defer allocator.free(checksig_bytes);
    const sig_push = try encodePushDataElement(allocator, checksig_bytes);
    defer allocator.free(sig_push);
    const pubkey_push = try encodePushDataElement(allocator, &public_key.bytes);
    defer allocator.free(pubkey_push);

    var malformed_unlocking = try allocator.alloc(u8, sig_push.len + pubkey_push.len);
    defer allocator.free(malformed_unlocking);
    @memcpy(malformed_unlocking[0..sig_push.len], sig_push);
    @memcpy(malformed_unlocking[sig_push.len..], pubkey_push);
    malformed_unlocking[1] = 0x31;

    try std.testing.expect(!(try verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = previous_locking_script,
        .previous_satoshis = 1_000,
        .flags = .{ .strict_encoding = false, .der_signatures = false },
    }, Script.init(malformed_unlocking), previous_locking_script)));

    try std.testing.expectError(error.InvalidSignatureEncoding, verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = previous_locking_script,
        .previous_satoshis = 1_000,
        .flags = .{ .strict_encoding = false, .der_signatures = true },
    }, Script.init(malformed_unlocking), previous_locking_script));
}

test "engine rejects missing forkid when forkid mode is enabled" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.IllegalForkId, checkHashTypeEncoding(.{
        .allocator = allocator,
    }, @intCast(sighash.SigHashType.all)));

    try checkHashTypeEncoding(.{
        .allocator = allocator,
    }, @intCast(sighash.SigHashType.all | sighash.SigHashType.forkid));
}

test "engine rejects reserved sighash bits under strict encoding" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.InvalidSigHashType, checkHashTypeEncoding(.{
        .allocator = allocator,
        .flags = .{
            .enable_sighash_forkid = false,
            .verify_bip143_sighash = false,
            .strict_encoding = true,
        },
    }, 0x21));
}

test "engine can disable forkid mode explicitly for legacy sighash policy" {
    const allocator = std.testing.allocator;

    try checkHashTypeEncoding(.{
        .allocator = allocator,
        .flags = .{
            .enable_sighash_forkid = false,
            .verify_bip143_sighash = false,
            .strict_encoding = true,
        },
    }, @intCast(sighash.SigHashType.all));

    try std.testing.expectError(error.IllegalForkId, checkHashTypeEncoding(.{
        .allocator = allocator,
        .flags = .{
            .enable_sighash_forkid = false,
            .verify_bip143_sighash = false,
            .strict_encoding = true,
        },
    }, @intCast(sighash.SigHashType.all | sighash.SigHashType.forkid)));
}

test "engine can enforce low-S policy on DER signatures" {
    const allocator = std.testing.allocator;
    const high_s_der = [_]u8{
        0x30, 0x25,
        0x02, 0x01, 0x01,
        0x02, 0x20,
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
        0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa1,
    };

    try checkSignatureEncoding(.{
        .allocator = allocator,
        .flags = .{ .strict_encoding = false, .low_s = false },
    }, &high_s_der);
    try std.testing.expectError(error.HighS, checkSignatureEncoding(.{
        .allocator = allocator,
        .flags = .{ .strict_encoding = false, .low_s = true },
    }, &high_s_der));
}

test "engine checkmultisig not enforces low-S policy" {
    const allocator = std.testing.allocator;

    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;

    const private_key = try crypto.PrivateKey.fromBytes(key_bytes);
    const public_key = try private_key.publicKey();

    const locking_script_bytes = [_]u8{
        @intFromEnum(opcode.Opcode.OP_1),
        33,
    } ++ public_key.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_CHECKMULTISIG),
        @intFromEnum(opcode.Opcode.OP_NOT),
    };
    const locking_script = Script.init(&locking_script_bytes);

    const tx = @import("../transaction/transaction.zig").Transaction{
        .version = 2,
        .inputs = &[_]@import("../transaction/input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x71} ** 32 },
                    .index = 0,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 0xffff_fffe,
            },
        },
        .outputs = &[_]@import("../transaction/output.zig").Output{
            .{
                .satoshis = 1_200,
                .locking_script = locking_script,
            },
        },
        .lock_time = 0,
    };

    const high_s_der = [_]u8{
        0x30, 0x25,
        0x02, 0x01, 0x01,
        0x02, 0x20,
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
        0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa1,
    };
    const high_s_signature = crypto.TxSignature{
        .der = try crypto.signature.DerSignature.fromDer(&high_s_der),
        .sighash_type = @intCast(sighash.SigHashType.all),
    };
    const checksig_bytes = try high_s_signature.toChecksigFormat(allocator);
    defer allocator.free(checksig_bytes);

    var unlocking_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer unlocking_bytes.deinit(allocator);
    try unlocking_bytes.append(allocator, @intFromEnum(opcode.Opcode.OP_0));
    const sig_push = try encodePushDataElement(allocator, checksig_bytes);
    defer allocator.free(sig_push);
    try unlocking_bytes.appendSlice(allocator, sig_push);
    const unlocking_script = Script.init(try unlocking_bytes.toOwnedSlice(allocator));
    defer allocator.free(unlocking_script.bytes);

    try std.testing.expect(try verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = locking_script,
        .previous_satoshis = 1_500,
        .flags = .{
            .strict_encoding = false,
            .low_s = false,
            .enable_sighash_forkid = false,
            .verify_bip143_sighash = false,
        },
    }, unlocking_script, locking_script));

    try std.testing.expectError(error.HighS, verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = locking_script,
        .previous_satoshis = 1_500,
        .flags = .{
            .strict_encoding = false,
            .low_s = true,
            .enable_sighash_forkid = false,
            .verify_bip143_sighash = false,
        },
    }, unlocking_script, locking_script));
}

test "engine honors op_codeseparator in checksig subscript" {
    const allocator = std.testing.allocator;
    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;

    const private_key = try crypto.PrivateKey.fromBytes(key_bytes);
    const public_key = try private_key.publicKey();
    const pubkey_hash = crypto.hash.hash160(&public_key.bytes);
    const p2pkh_script = @import("templates/p2pkh.zig").encode(pubkey_hash);

    var locking_script_bytes: [1 + p2pkh_script.len]u8 = undefined;
    locking_script_bytes[0] = @intFromEnum(opcode.Opcode.OP_CODESEPARATOR);
    @memcpy(locking_script_bytes[1..], &p2pkh_script);
    const locking_script = Script.init(&locking_script_bytes);
    const signing_subscript = Script.init(locking_script_bytes[1..]);

    var tx = @import("../transaction/transaction.zig").Transaction{
        .version = 2,
        .inputs = &[_]@import("../transaction/input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x44} ** 32 },
                    .index = 1,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 0xffff_fffe,
            },
        },
        .outputs = &[_]@import("../transaction/output.zig").Output{
            .{
                .satoshis = 500,
                .locking_script = locking_script,
            },
        },
        .lock_time = 0,
    };

    const unlocking_script = try @import("../transaction/templates/p2pkh_spend.zig").signAndBuildUnlockingScript(
        allocator,
        &tx,
        0,
        signing_subscript,
        700,
        private_key,
        @import("../transaction/templates/p2pkh_spend.zig").default_scope,
    );
    defer allocator.free(unlocking_script.bytes);

    try std.testing.expect(try verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = locking_script,
        .previous_satoshis = 700,
    }, unlocking_script, locking_script));
}

test "engine ignores codeseparator in an unexecuted legacy branch" {
    const allocator = std.testing.allocator;
    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;

    const private_key = try crypto.PrivateKey.fromBytes(key_bytes);
    const public_key = try private_key.publicKey();

    const locking_script_bytes = [_]u8{
        @intFromEnum(opcode.Opcode.OP_0),
        @intFromEnum(opcode.Opcode.OP_IF),
        @intFromEnum(opcode.Opcode.OP_CODESEPARATOR),
        @intFromEnum(opcode.Opcode.OP_ENDIF),
        33,
    } ++ public_key.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIG),
    };
    const locking_script = Script.init(&locking_script_bytes);

    const signing_subscript_bytes = [_]u8{
        @intFromEnum(opcode.Opcode.OP_0),
        @intFromEnum(opcode.Opcode.OP_IF),
        @intFromEnum(opcode.Opcode.OP_ENDIF),
        33,
    } ++ public_key.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIG),
    };
    const signing_subscript = Script.init(&signing_subscript_bytes);

    var tx = @import("../transaction/transaction.zig").Transaction{
        .version = 2,
        .inputs = &[_]@import("../transaction/input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x54} ** 32 },
                    .index = 0,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 0xffff_fffe,
            },
        },
        .outputs = &[_]@import("../transaction/output.zig").Output{
            .{
                .satoshis = 500,
                .locking_script = locking_script,
            },
        },
        .lock_time = 0,
    };

    const legacy_scope: u32 = sighash.SigHashType.all;
    const tx_signature = try @import("../transaction/templates/p2pkh_spend.zig").signInput(
        allocator,
        &tx,
        0,
        signing_subscript,
        700,
        private_key,
        legacy_scope,
    );
    const unlocking_script = try buildChecksigUnlockingScript(allocator, &[_]crypto.TxSignature{tx_signature});
    defer allocator.free(unlocking_script.bytes);

    try std.testing.expect(try verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = locking_script,
        .previous_satoshis = 700,
        .flags = .{
            .enable_sighash_forkid = false,
            .verify_bip143_sighash = false,
        },
    }, unlocking_script, locking_script));
}

test "engine honors chained legacy codeseparator signing boundaries" {
    const allocator = std.testing.allocator;
    var key_bytes_a = [_]u8{0} ** 32;
    var key_bytes_b = [_]u8{0} ** 32;
    var key_bytes_c = [_]u8{0} ** 32;
    key_bytes_a[31] = 1;
    key_bytes_b[31] = 2;
    key_bytes_c[31] = 3;

    const private_key_a = try crypto.PrivateKey.fromBytes(key_bytes_a);
    const private_key_b = try crypto.PrivateKey.fromBytes(key_bytes_b);
    const private_key_c = try crypto.PrivateKey.fromBytes(key_bytes_c);
    const public_key_a = try private_key_a.publicKey();
    const public_key_b = try private_key_b.publicKey();
    const public_key_c = try private_key_c.publicKey();

    const locking_script_bytes = [_]u8{
        33,
    } ++ public_key_a.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIGVERIFY),
        @intFromEnum(opcode.Opcode.OP_CODESEPARATOR),
        33,
    } ++ public_key_b.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIGVERIFY),
        @intFromEnum(opcode.Opcode.OP_CODESEPARATOR),
        33,
    } ++ public_key_c.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIG),
    };
    const locking_script = Script.init(&locking_script_bytes);

    const subscript_a_bytes = [_]u8{
        33,
    } ++ public_key_a.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIGVERIFY),
        33,
    } ++ public_key_b.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIGVERIFY),
        33,
    } ++ public_key_c.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIG),
    };
    const subscript_b_bytes = [_]u8{
        33,
    } ++ public_key_b.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIGVERIFY),
        33,
    } ++ public_key_c.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIG),
    };
    const subscript_c_bytes = [_]u8{
        33,
    } ++ public_key_c.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIG),
    };
    const subscript_a = Script.init(&subscript_a_bytes);
    const subscript_b = Script.init(&subscript_b_bytes);
    const subscript_c = Script.init(&subscript_c_bytes);

    var tx = @import("../transaction/transaction.zig").Transaction{
        .version = 2,
        .inputs = &[_]@import("../transaction/input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x63} ** 32 },
                    .index = 1,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 0xffff_fffe,
            },
        },
        .outputs = &[_]@import("../transaction/output.zig").Output{
            .{
                .satoshis = 500,
                .locking_script = locking_script,
            },
        },
        .lock_time = 0,
    };

    const legacy_scope: u32 = sighash.SigHashType.all;
    const sig_a = try @import("../transaction/templates/p2pkh_spend.zig").signInput(
        allocator,
        &tx,
        0,
        subscript_a,
        700,
        private_key_a,
        legacy_scope,
    );
    const sig_b = try @import("../transaction/templates/p2pkh_spend.zig").signInput(
        allocator,
        &tx,
        0,
        subscript_b,
        700,
        private_key_b,
        legacy_scope,
    );
    const sig_c = try @import("../transaction/templates/p2pkh_spend.zig").signInput(
        allocator,
        &tx,
        0,
        subscript_c,
        700,
        private_key_c,
        legacy_scope,
    );

    const unlocking_script = try buildChecksigUnlockingScript(allocator, &[_]crypto.TxSignature{
        sig_c,
        sig_b,
        sig_a,
    });
    defer allocator.free(unlocking_script.bytes);

    try std.testing.expect(try verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = locking_script,
        .previous_satoshis = 700,
        .flags = .{
            .enable_sighash_forkid = false,
            .verify_bip143_sighash = false,
        },
    }, unlocking_script, locking_script));

    const wrong_sig_b = try @import("../transaction/templates/p2pkh_spend.zig").signInput(
        allocator,
        &tx,
        0,
        subscript_a,
        700,
        private_key_b,
        legacy_scope,
    );
    const wrong_unlocking_script = try buildChecksigUnlockingScript(allocator, &[_]crypto.TxSignature{
        sig_c,
        wrong_sig_b,
        sig_a,
    });
    defer allocator.free(wrong_unlocking_script.bytes);

    try std.testing.expect(!(try verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = locking_script,
        .previous_satoshis = 700,
        .flags = .{
            .enable_sighash_forkid = false,
            .verify_bip143_sighash = false,
        },
    }, wrong_unlocking_script, locking_script)));
}

test "engine codeseparator wrong final signature yields a clean false result" {
    const allocator = std.testing.allocator;
    var key_bytes_a = [_]u8{0} ** 32;
    var key_bytes_b = [_]u8{0} ** 32;
    var key_bytes_c = [_]u8{0} ** 32;
    key_bytes_a[31] = 1;
    key_bytes_b[31] = 2;
    key_bytes_c[31] = 3;

    const private_key_a = try crypto.PrivateKey.fromBytes(key_bytes_a);
    const private_key_b = try crypto.PrivateKey.fromBytes(key_bytes_b);
    const private_key_c = try crypto.PrivateKey.fromBytes(key_bytes_c);
    const public_key_a = try private_key_a.publicKey();
    const public_key_b = try private_key_b.publicKey();
    const public_key_c = try private_key_c.publicKey();

    const locking_script_bytes = [_]u8{
        33,
    } ++ public_key_a.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIGVERIFY),
        @intFromEnum(opcode.Opcode.OP_CODESEPARATOR),
        33,
    } ++ public_key_b.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIGVERIFY),
        @intFromEnum(opcode.Opcode.OP_CODESEPARATOR),
        33,
    } ++ public_key_c.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIG),
    };
    const locking_script = Script.init(&locking_script_bytes);

    const subscript_a_bytes = [_]u8{
        33,
    } ++ public_key_a.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIGVERIFY),
        33,
    } ++ public_key_b.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIGVERIFY),
        33,
    } ++ public_key_c.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIG),
    };
    const subscript_b_bytes = [_]u8{
        33,
    } ++ public_key_b.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIGVERIFY),
        33,
    } ++ public_key_c.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIG),
    };
    const subscript_a = Script.init(&subscript_a_bytes);
    const subscript_b = Script.init(&subscript_b_bytes);

    var tx = @import("../transaction/transaction.zig").Transaction{
        .version = 2,
        .inputs = &[_]@import("../transaction/input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x64} ** 32 },
                    .index = 1,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 0xffff_fffe,
            },
        },
        .outputs = &[_]@import("../transaction/output.zig").Output{
            .{
                .satoshis = 500,
                .locking_script = locking_script,
            },
        },
        .lock_time = 0,
    };

    const legacy_scope: u32 = sighash.SigHashType.all;
    const sig_a = try @import("../transaction/templates/p2pkh_spend.zig").signInput(
        allocator,
        &tx,
        0,
        subscript_a,
        700,
        private_key_a,
        legacy_scope,
    );
    const sig_b = try @import("../transaction/templates/p2pkh_spend.zig").signInput(
        allocator,
        &tx,
        0,
        subscript_b,
        700,
        private_key_b,
        legacy_scope,
    );
    const wrong_sig_c = try @import("../transaction/templates/p2pkh_spend.zig").signInput(
        allocator,
        &tx,
        0,
        subscript_a,
        700,
        private_key_c,
        legacy_scope,
    );

    const unlocking_script = try buildChecksigUnlockingScript(allocator, &[_]crypto.TxSignature{
        wrong_sig_c,
        sig_b,
        sig_a,
    });
    defer allocator.free(unlocking_script.bytes);

    var state = try runUnlockAndLock(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = locking_script,
        .previous_satoshis = 700,
        .flags = .{
            .enable_sighash_forkid = false,
            .verify_bip143_sighash = false,
        },
    }, unlocking_script, locking_script);
    defer state.deinit(allocator);

    try std.testing.expect(state.stack.items.len > 0);
    try std.testing.expect(!isTruthy(state.stack.items[state.stack.items.len - 1]));
}

test "engine codeseparator wrong middle signature fails at checksigverify" {
    const allocator = std.testing.allocator;
    var key_bytes_a = [_]u8{0} ** 32;
    var key_bytes_b = [_]u8{0} ** 32;
    var key_bytes_c = [_]u8{0} ** 32;
    key_bytes_a[31] = 1;
    key_bytes_b[31] = 2;
    key_bytes_c[31] = 3;

    const private_key_a = try crypto.PrivateKey.fromBytes(key_bytes_a);
    const private_key_b = try crypto.PrivateKey.fromBytes(key_bytes_b);
    const private_key_c = try crypto.PrivateKey.fromBytes(key_bytes_c);
    const public_key_a = try private_key_a.publicKey();
    const public_key_b = try private_key_b.publicKey();
    const public_key_c = try private_key_c.publicKey();

    const locking_script_bytes = [_]u8{
        33,
    } ++ public_key_a.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIGVERIFY),
        @intFromEnum(opcode.Opcode.OP_CODESEPARATOR),
        33,
    } ++ public_key_b.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIGVERIFY),
        @intFromEnum(opcode.Opcode.OP_CODESEPARATOR),
        33,
    } ++ public_key_c.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIG),
    };
    const locking_script = Script.init(&locking_script_bytes);

    const subscript_a_bytes = [_]u8{
        33,
    } ++ public_key_a.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIGVERIFY),
        33,
    } ++ public_key_b.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIGVERIFY),
        33,
    } ++ public_key_c.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIG),
    };
    const subscript_c_bytes = [_]u8{
        33,
    } ++ public_key_c.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIG),
    };
    const subscript_a = Script.init(&subscript_a_bytes);
    const subscript_c = Script.init(&subscript_c_bytes);

    var tx = @import("../transaction/transaction.zig").Transaction{
        .version = 2,
        .inputs = &[_]@import("../transaction/input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x65} ** 32 },
                    .index = 1,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 0xffff_fffe,
            },
        },
        .outputs = &[_]@import("../transaction/output.zig").Output{
            .{
                .satoshis = 500,
                .locking_script = locking_script,
            },
        },
        .lock_time = 0,
    };

    const legacy_scope: u32 = sighash.SigHashType.all;
    const sig_a = try @import("../transaction/templates/p2pkh_spend.zig").signInput(
        allocator,
        &tx,
        0,
        subscript_a,
        700,
        private_key_a,
        legacy_scope,
    );
    const wrong_sig_b = try @import("../transaction/templates/p2pkh_spend.zig").signInput(
        allocator,
        &tx,
        0,
        subscript_a,
        700,
        private_key_b,
        legacy_scope,
    );
    const sig_c = try @import("../transaction/templates/p2pkh_spend.zig").signInput(
        allocator,
        &tx,
        0,
        subscript_c,
        700,
        private_key_c,
        legacy_scope,
    );

    const unlocking_script = try buildChecksigUnlockingScript(allocator, &[_]crypto.TxSignature{
        sig_c,
        wrong_sig_b,
        sig_a,
    });
    defer allocator.free(unlocking_script.bytes);

    try std.testing.expectError(error.VerifyFailed, runUnlockAndLock(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = locking_script,
        .previous_satoshis = 700,
        .flags = .{
            .enable_sighash_forkid = false,
            .verify_bip143_sighash = false,
        },
    }, unlocking_script, locking_script));
}

test "engine codeseparator can ignore a leading verified prelude in legacy mode" {
    const allocator = std.testing.allocator;
    var key_bytes_a = [_]u8{0} ** 32;
    var key_bytes_b = [_]u8{0} ** 32;
    var key_bytes_c = [_]u8{0} ** 32;
    key_bytes_a[31] = 1;
    key_bytes_b[31] = 2;
    key_bytes_c[31] = 3;

    const private_key_a = try crypto.PrivateKey.fromBytes(key_bytes_a);
    const private_key_b = try crypto.PrivateKey.fromBytes(key_bytes_b);
    const private_key_c = try crypto.PrivateKey.fromBytes(key_bytes_c);
    const public_key_a = try private_key_a.publicKey();
    const public_key_b = try private_key_b.publicKey();
    const public_key_c = try private_key_c.publicKey();

    const locking_script_bytes = [_]u8{
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_VERIFY),
        @intFromEnum(opcode.Opcode.OP_CODESEPARATOR),
        33,
    } ++ public_key_a.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIGVERIFY),
        @intFromEnum(opcode.Opcode.OP_CODESEPARATOR),
        33,
    } ++ public_key_b.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIGVERIFY),
        @intFromEnum(opcode.Opcode.OP_CODESEPARATOR),
        33,
    } ++ public_key_c.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIG),
    };
    const locking_script = Script.init(&locking_script_bytes);

    const subscript_a_bytes = [_]u8{
        33,
    } ++ public_key_a.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIGVERIFY),
        33,
    } ++ public_key_b.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIGVERIFY),
        33,
    } ++ public_key_c.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIG),
    };
    const subscript_b_bytes = [_]u8{
        33,
    } ++ public_key_b.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIGVERIFY),
        33,
    } ++ public_key_c.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIG),
    };
    const subscript_c_bytes = [_]u8{
        33,
    } ++ public_key_c.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIG),
    };
    const subscript_a = Script.init(&subscript_a_bytes);
    const subscript_b = Script.init(&subscript_b_bytes);
    const subscript_c = Script.init(&subscript_c_bytes);

    var tx = @import("../transaction/transaction.zig").Transaction{
        .version = 2,
        .inputs = &[_]@import("../transaction/input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x66} ** 32 },
                    .index = 1,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 0xffff_fffe,
            },
        },
        .outputs = &[_]@import("../transaction/output.zig").Output{
            .{
                .satoshis = 500,
                .locking_script = locking_script,
            },
        },
        .lock_time = 0,
    };

    const legacy_scope: u32 = sighash.SigHashType.all;
    const sig_a = try @import("../transaction/templates/p2pkh_spend.zig").signInput(
        allocator,
        &tx,
        0,
        subscript_a,
        700,
        private_key_a,
        legacy_scope,
    );
    const sig_b = try @import("../transaction/templates/p2pkh_spend.zig").signInput(
        allocator,
        &tx,
        0,
        subscript_b,
        700,
        private_key_b,
        legacy_scope,
    );
    const sig_c = try @import("../transaction/templates/p2pkh_spend.zig").signInput(
        allocator,
        &tx,
        0,
        subscript_c,
        700,
        private_key_c,
        legacy_scope,
    );

    const unlocking_script = try buildChecksigUnlockingScript(allocator, &[_]crypto.TxSignature{
        sig_c,
        sig_b,
        sig_a,
    });
    defer allocator.free(unlocking_script.bytes);

    try std.testing.expect(try verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = locking_script,
        .previous_satoshis = 700,
        .flags = .{
            .enable_sighash_forkid = false,
            .verify_bip143_sighash = false,
        },
    }, unlocking_script, locking_script));
}

test "engine codeseparator can isolate middle prelude to the final signature in legacy mode" {
    const allocator = std.testing.allocator;
    var key_bytes_a = [_]u8{0} ** 32;
    var key_bytes_b = [_]u8{0} ** 32;
    var key_bytes_c = [_]u8{0} ** 32;
    key_bytes_a[31] = 1;
    key_bytes_b[31] = 2;
    key_bytes_c[31] = 3;

    const private_key_a = try crypto.PrivateKey.fromBytes(key_bytes_a);
    const private_key_b = try crypto.PrivateKey.fromBytes(key_bytes_b);
    const private_key_c = try crypto.PrivateKey.fromBytes(key_bytes_c);
    const public_key_a = try private_key_a.publicKey();
    const public_key_b = try private_key_b.publicKey();
    const public_key_c = try private_key_c.publicKey();

    const locking_script_bytes = [_]u8{
        33,
    } ++ public_key_a.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIGVERIFY),
        @intFromEnum(opcode.Opcode.OP_CODESEPARATOR),
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_VERIFY),
        @intFromEnum(opcode.Opcode.OP_CODESEPARATOR),
        33,
    } ++ public_key_b.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIGVERIFY),
        @intFromEnum(opcode.Opcode.OP_CODESEPARATOR),
        33,
    } ++ public_key_c.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIG),
    };
    const locking_script = Script.init(&locking_script_bytes);

    const subscript_a_bytes = [_]u8{
        33,
    } ++ public_key_a.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIGVERIFY),
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_VERIFY),
        33,
    } ++ public_key_b.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIGVERIFY),
        33,
    } ++ public_key_c.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIG),
    };
    const subscript_b_bytes = [_]u8{
        33,
    } ++ public_key_b.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIGVERIFY),
        33,
    } ++ public_key_c.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIG),
    };
    const subscript_c_bytes = [_]u8{
        33,
    } ++ public_key_c.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIG),
    };
    const subscript_a = Script.init(&subscript_a_bytes);
    const subscript_b = Script.init(&subscript_b_bytes);
    const subscript_c = Script.init(&subscript_c_bytes);

    var tx = @import("../transaction/transaction.zig").Transaction{
        .version = 2,
        .inputs = &[_]@import("../transaction/input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x67} ** 32 },
                    .index = 1,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 0xffff_fffe,
            },
        },
        .outputs = &[_]@import("../transaction/output.zig").Output{
            .{
                .satoshis = 500,
                .locking_script = locking_script,
            },
        },
        .lock_time = 0,
    };

    const legacy_scope: u32 = sighash.SigHashType.all;
    const sig_a = try @import("../transaction/templates/p2pkh_spend.zig").signInput(
        allocator,
        &tx,
        0,
        subscript_a,
        700,
        private_key_a,
        legacy_scope,
    );
    const sig_b = try @import("../transaction/templates/p2pkh_spend.zig").signInput(
        allocator,
        &tx,
        0,
        subscript_b,
        700,
        private_key_b,
        legacy_scope,
    );
    const sig_c = try @import("../transaction/templates/p2pkh_spend.zig").signInput(
        allocator,
        &tx,
        0,
        subscript_c,
        700,
        private_key_c,
        legacy_scope,
    );

    const unlocking_script = try buildChecksigUnlockingScript(allocator, &[_]crypto.TxSignature{
        sig_c,
        sig_b,
        sig_a,
    });
    defer allocator.free(unlocking_script.bytes);

    try std.testing.expect(try verifyScripts(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = locking_script,
        .previous_satoshis = 700,
        .flags = .{
            .enable_sighash_forkid = false,
            .verify_bip143_sighash = false,
        },
    }, unlocking_script, locking_script));
}

test "engine codeseparator wrong first signature fails at the first checksigverify" {
    const allocator = std.testing.allocator;
    var key_bytes_a = [_]u8{0} ** 32;
    var key_bytes_b = [_]u8{0} ** 32;
    var key_bytes_c = [_]u8{0} ** 32;
    key_bytes_a[31] = 1;
    key_bytes_b[31] = 2;
    key_bytes_c[31] = 3;

    const private_key_a = try crypto.PrivateKey.fromBytes(key_bytes_a);
    const private_key_b = try crypto.PrivateKey.fromBytes(key_bytes_b);
    const private_key_c = try crypto.PrivateKey.fromBytes(key_bytes_c);
    const public_key_a = try private_key_a.publicKey();
    const public_key_b = try private_key_b.publicKey();
    const public_key_c = try private_key_c.publicKey();

    const locking_script_bytes = [_]u8{
        33,
    } ++ public_key_a.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIGVERIFY),
        @intFromEnum(opcode.Opcode.OP_CODESEPARATOR),
        33,
    } ++ public_key_b.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIGVERIFY),
        @intFromEnum(opcode.Opcode.OP_CODESEPARATOR),
        33,
    } ++ public_key_c.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIG),
    };
    const locking_script = Script.init(&locking_script_bytes);

    const subscript_b_bytes = [_]u8{
        33,
    } ++ public_key_b.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIGVERIFY),
        33,
    } ++ public_key_c.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIG),
    };
    const subscript_c_bytes = [_]u8{
        33,
    } ++ public_key_c.bytes ++ [_]u8{
        @intFromEnum(opcode.Opcode.OP_CHECKSIG),
    };
    const subscript_b = Script.init(&subscript_b_bytes);
    const subscript_c = Script.init(&subscript_c_bytes);

    var tx = @import("../transaction/transaction.zig").Transaction{
        .version = 2,
        .inputs = &[_]@import("../transaction/input.zig").Input{
            .{
                .previous_outpoint = .{
                    .txid = .{ .bytes = [_]u8{0x68} ** 32 },
                    .index = 1,
                },
                .unlocking_script = .{ .bytes = "" },
                .sequence = 0xffff_fffe,
            },
        },
        .outputs = &[_]@import("../transaction/output.zig").Output{
            .{
                .satoshis = 500,
                .locking_script = locking_script,
            },
        },
        .lock_time = 0,
    };

    const legacy_scope: u32 = sighash.SigHashType.all;
    const wrong_sig_a = try @import("../transaction/templates/p2pkh_spend.zig").signInput(
        allocator,
        &tx,
        0,
        subscript_b,
        700,
        private_key_a,
        legacy_scope,
    );
    const sig_b = try @import("../transaction/templates/p2pkh_spend.zig").signInput(
        allocator,
        &tx,
        0,
        subscript_b,
        700,
        private_key_b,
        legacy_scope,
    );
    const sig_c = try @import("../transaction/templates/p2pkh_spend.zig").signInput(
        allocator,
        &tx,
        0,
        subscript_c,
        700,
        private_key_c,
        legacy_scope,
    );

    const unlocking_script = try buildChecksigUnlockingScript(allocator, &[_]crypto.TxSignature{
        sig_c,
        sig_b,
        wrong_sig_a,
    });
    defer allocator.free(unlocking_script.bytes);

    try std.testing.expectError(error.VerifyFailed, runUnlockAndLock(.{
        .allocator = allocator,
        .tx = &tx,
        .input_index = 0,
        .previous_locking_script = locking_script,
        .previous_satoshis = 700,
        .flags = .{
            .enable_sighash_forkid = false,
            .verify_bip143_sighash = false,
        },
    }, unlocking_script, locking_script));
}

test "legacy scriptCode strips remaining op_codeseparators after the active boundary" {
    const allocator = std.testing.allocator;
    const script = Script.init(&[_]u8{
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_CODESEPARATOR),
        @intFromEnum(opcode.Opcode.OP_2),
        @intFromEnum(opcode.Opcode.OP_CODESEPARATOR),
        @intFromEnum(opcode.Opcode.OP_3),
        @intFromEnum(opcode.Opcode.OP_CHECKSIG),
    });

    const script_code = try buildScriptCode(allocator, script, 2, &.{}, true);
    defer allocator.free(script_code.bytes);

    try std.testing.expectEqualSlices(u8, &[_]u8{
        @intFromEnum(opcode.Opcode.OP_2),
        @intFromEnum(opcode.Opcode.OP_3),
        @intFromEnum(opcode.Opcode.OP_CHECKSIG),
    }, script_code.bytes);
}

test "forkid scriptCode preserves later op_codeseparators after the active boundary" {
    const allocator = std.testing.allocator;
    const script = Script.init(&[_]u8{
        @intFromEnum(opcode.Opcode.OP_1),
        @intFromEnum(opcode.Opcode.OP_CODESEPARATOR),
        @intFromEnum(opcode.Opcode.OP_2),
        @intFromEnum(opcode.Opcode.OP_CODESEPARATOR),
        @intFromEnum(opcode.Opcode.OP_3),
        @intFromEnum(opcode.Opcode.OP_CHECKSIG),
    });

    const script_code = try buildScriptCode(allocator, script, 2, &.{}, false);
    defer allocator.free(script_code.bytes);

    try std.testing.expectEqualSlices(u8, &[_]u8{
        @intFromEnum(opcode.Opcode.OP_2),
        @intFromEnum(opcode.Opcode.OP_CODESEPARATOR),
        @intFromEnum(opcode.Opcode.OP_3),
        @intFromEnum(opcode.Opcode.OP_CHECKSIG),
    }, script_code.bytes);
}

test "engine treats equivalent pushdata forms equally at 75-byte and 255-byte boundaries" {
    const allocator = std.testing.allocator;

    var data_75 = [_]u8{0x11} ** 75;
    var script_75 = try allocator.alloc(u8, 1 + 1 + data_75.len + 1 + data_75.len + 1);
    defer allocator.free(script_75);
    var cursor_75: usize = 0;
    script_75[cursor_75] = @intFromEnum(opcode.Opcode.OP_PUSHDATA1);
    cursor_75 += 1;
    script_75[cursor_75] = data_75.len;
    cursor_75 += 1;
    @memcpy(script_75[cursor_75 .. cursor_75 + data_75.len], &data_75);
    cursor_75 += data_75.len;
    script_75[cursor_75] = @intCast(data_75.len);
    cursor_75 += 1;
    @memcpy(script_75[cursor_75 .. cursor_75 + data_75.len], &data_75);
    cursor_75 += data_75.len;
    script_75[cursor_75] = @intFromEnum(opcode.Opcode.OP_EQUAL);

    var result_75 = try executeScript(.{
        .allocator = allocator,
    }, Script.init(script_75));
    defer result_75.deinit(allocator);
    try std.testing.expect(result_75.success);

    var data_255 = [_]u8{0x22} ** 255;
    var script_255 = try allocator.alloc(u8, 3 + data_255.len + 2 + data_255.len + 1);
    defer allocator.free(script_255);
    var cursor_255: usize = 0;
    script_255[cursor_255] = @intFromEnum(opcode.Opcode.OP_PUSHDATA2);
    cursor_255 += 1;
    std.mem.writeInt(u16, script_255[cursor_255..][0..2], @intCast(data_255.len), .little);
    cursor_255 += 2;
    @memcpy(script_255[cursor_255 .. cursor_255 + data_255.len], &data_255);
    cursor_255 += data_255.len;
    script_255[cursor_255] = @intFromEnum(opcode.Opcode.OP_PUSHDATA1);
    cursor_255 += 1;
    script_255[cursor_255] = @intCast(data_255.len);
    cursor_255 += 1;
    @memcpy(script_255[cursor_255 .. cursor_255 + data_255.len], &data_255);
    cursor_255 += data_255.len;
    script_255[cursor_255] = @intFromEnum(opcode.Opcode.OP_EQUAL);

    var result_255 = try executeScript(.{
        .allocator = allocator,
    }, Script.init(script_255));
    defer result_255.deinit(allocator);
    try std.testing.expect(result_255.success);
}
