const std = @import("std");
const bsvz = @import("bsvz");

pub const nonempty_invalid_der_signature = [_]u8{
    0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01,
};

pub fn encodeLowerAlloc(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, bytes.len * 2);
    return try bsvz.primitives.hex.encodeLower(bytes, out);
}

pub fn scriptHexFromBytes(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    return encodeLowerAlloc(allocator, bytes);
}

pub fn appendPushData(
    bytes: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    data: []const u8,
) !void {
    if (data.len <= 75) {
        try bytes.append(allocator, @intCast(data.len));
    } else unreachable;
    try bytes.appendSlice(allocator, data);
}

pub fn scriptHexForOps(allocator: std.mem.Allocator, ops: []const bsvz.script.opcode.Opcode) ![]u8 {
    var bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer bytes.deinit(allocator);
    for (ops) |op| try bytes.append(allocator, @intFromEnum(op));
    return scriptHexFromBytes(allocator, bytes.items);
}

pub fn scriptNumBytes(allocator: std.mem.Allocator, value: i64) ![]u8 {
    return bsvz.script.ScriptNum.encode(allocator, value);
}

pub fn repeatedHexByte(allocator: std.mem.Allocator, count: usize, byte: u8) ![]u8 {
    const bytes = try allocator.alloc(u8, count);
    @memset(bytes, byte);
    return bytes;
}

pub fn buildSyntheticCheckmultisigNotHexes(
    allocator: std.mem.Allocator,
    dummy_opcode: u8,
    nonempty_sig_index: ?usize,
) !struct { unlocking_hex: []u8, locking_hex: []u8 } {
    var unlocking_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer unlocking_bytes.deinit(allocator);
    var locking_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer locking_bytes.deinit(allocator);

    try unlocking_bytes.append(allocator, dummy_opcode);
    for (0..20) |index| {
        if (nonempty_sig_index != null and nonempty_sig_index.? == index) {
            try unlocking_bytes.append(allocator, nonempty_invalid_der_signature.len);
            try unlocking_bytes.appendSlice(allocator, &nonempty_invalid_der_signature);
        } else {
            try unlocking_bytes.append(allocator, 0x00);
        }
    }

    try locking_bytes.appendSlice(allocator, &[_]u8{ 0x01, 0x14 });
    for (0..20) |_| try locking_bytes.append(allocator, 0x51);
    try locking_bytes.appendSlice(allocator, &[_]u8{
        0x01,
        0x14,
        @intFromEnum(bsvz.script.opcode.Opcode.OP_CHECKMULTISIG),
        @intFromEnum(bsvz.script.opcode.Opcode.OP_NOT),
    });

    return .{
        .unlocking_hex = try encodeLowerAlloc(allocator, unlocking_bytes.items),
        .locking_hex = try encodeLowerAlloc(allocator, locking_bytes.items),
    };
}
