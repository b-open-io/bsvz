const std = @import("std");
const bsvz = @import("bsvz");
const harness = @import("support/go_script_harness.zig");

const GoRow = struct {
    row: usize,
    name: []const u8,
    unlocking_hex: []const u8,
    locking_hex: []const u8,
    expected: harness.Expectation,
};

fn strictReferenceFlags() bsvz.script.engine.ExecutionFlags {
    var flags = bsvz.script.engine.ExecutionFlags.legacyReference();
    flags.strict_encoding = true;
    return flags;
}

fn runRows(
    allocator: std.mem.Allocator,
    flags: bsvz.script.engine.ExecutionFlags,
    rows: []const GoRow,
) !void {
    for (rows) |row| {
        try harness.runCase(allocator, .{
            .name = row.name,
            .unlocking_hex = row.unlocking_hex,
            .locking_hex = row.locking_hex,
            .flags = flags,
            .expected = row.expected,
        });
    }
}

test "go bitwise rows: truthiness and size-adjacent bytes" {
    const allocator = std.testing.allocator;
    const flags = strictReferenceFlags();

    try runRows(allocator, flags, &[_]GoRow{
        .{
            .row = 148,
            .name = "row 148 values larger than four bytes still cast to boolean",
            .unlocking_hex = "51050100000000",
            .locking_hex = "69",
            .expected = .{ .success = true },
        },
        .{
            .row = 149,
            .name = "row 149 negative zero is false in if",
            .unlocking_hex = "510180",
            .locking_hex = "630068",
            .expected = .{ .success = true },
        },
        .{
            .row = 442,
            .name = "row 442 size leaves a truthy length on the stack",
            .unlocking_hex = "51",
            .locking_hex = "82",
            .expected = .{ .success = true },
        },
        .{
            .row = 540,
            .name = "row 540 raw op 0 remains zero bytes under size",
            .unlocking_hex = "00",
            .locking_hex = "820087",
            .expected = .{ .success = true },
        },
    });
}

test "go bitwise rows: or exact rows" {
    const allocator = std.testing.allocator;
    const flags = strictReferenceFlags();

    try runRows(allocator, flags, &[_]GoRow{
        .{
            .row = 866,
            .name = "row 866 or preserves empty operands",
            .unlocking_hex = "0000",
            .locking_hex = "850087",
            .expected = .{ .success = true },
        },
        .{
            .row = 867,
            .name = "row 867 or matches equal one byte operands",
            .unlocking_hex = "01000100",
            .locking_hex = "85010087",
            .expected = .{ .success = true },
        },
        .{
            .row = 868,
            .name = "row 868 or accepts small int on the left",
            .unlocking_hex = "510100",
            .locking_hex = "855187",
            .expected = .{ .success = true },
        },
        .{
            .row = 869,
            .name = "row 869 or accepts small int on the right",
            .unlocking_hex = "010051",
            .locking_hex = "855187",
            .expected = .{ .success = true },
        },
        .{
            .row = 870,
            .name = "row 870 or of two small ints stays one",
            .unlocking_hex = "5151",
            .locking_hex = "855187",
            .expected = .{ .success = true },
        },
        .{
            .row = 871,
            .name = "row 871 or underflows with one operand",
            .unlocking_hex = "00",
            .locking_hex = "850087",
            .expected = .{ .err = error.StackUnderflow },
        },
        .{
            .row = 872,
            .name = "row 872 or underflows on an empty stack",
            .unlocking_hex = "",
            .locking_hex = "850087",
            .expected = .{ .err = error.StackUnderflow },
        },
        .{
            .row = 873,
            .name = "row 873 or rejects mismatched operand lengths",
            .unlocking_hex = "0051",
            .locking_hex = "855187",
            .expected = .{ .err = error.InvalidOperandSize },
        },
        .{
            .row = 874,
            .name = "row 874 or combines bytewise operands",
            .unlocking_hex = "01ab01cd",
            .locking_hex = "8501ef87",
            .expected = .{ .success = true },
        },
    });
}

test "go bitwise rows: xor exact rows" {
    const allocator = std.testing.allocator;
    const flags = strictReferenceFlags();

    try runRows(allocator, flags, &[_]GoRow{
        .{
            .row = 876,
            .name = "row 876 xor preserves empty operands",
            .unlocking_hex = "0000",
            .locking_hex = "860087",
            .expected = .{ .success = true },
        },
        .{
            .row = 877,
            .name = "row 877 xor matches equal one byte operands",
            .unlocking_hex = "01000100",
            .locking_hex = "86010087",
            .expected = .{ .success = true },
        },
        .{
            .row = 878,
            .name = "row 878 xor accepts small int on the left",
            .unlocking_hex = "510100",
            .locking_hex = "865187",
            .expected = .{ .success = true },
        },
        .{
            .row = 879,
            .name = "row 879 xor accepts small int on the right",
            .unlocking_hex = "010051",
            .locking_hex = "865187",
            .expected = .{ .success = true },
        },
        .{
            .row = 880,
            .name = "row 880 xor of two small ints becomes one zero byte",
            .unlocking_hex = "5151",
            .locking_hex = "86010087",
            .expected = .{ .success = true },
        },
        .{
            .row = 881,
            .name = "row 881 xor underflows with one operand",
            .unlocking_hex = "00",
            .locking_hex = "860087",
            .expected = .{ .err = error.StackUnderflow },
        },
        .{
            .row = 882,
            .name = "row 882 xor underflows on an empty stack",
            .unlocking_hex = "",
            .locking_hex = "860087",
            .expected = .{ .err = error.StackUnderflow },
        },
        .{
            .row = 883,
            .name = "row 883 xor rejects mismatched operand lengths",
            .unlocking_hex = "0051",
            .locking_hex = "865187",
            .expected = .{ .err = error.InvalidOperandSize },
        },
        .{
            .row = 884,
            .name = "row 884 xor combines bytewise operands",
            .unlocking_hex = "01ab01cd",
            .locking_hex = "86016687",
            .expected = .{ .success = true },
        },
    });
}

test "go bitwise rows: invert exact rows" {
    const allocator = std.testing.allocator;
    const flags = strictReferenceFlags();

    try runRows(allocator, flags, &[_]GoRow{
        .{
            .row = 886,
            .name = "row 886 invert underflows on an empty stack",
            .unlocking_hex = "",
            .locking_hex = "83",
            .expected = .{ .err = error.StackUnderflow },
        },
        .{
            .row = 887,
            .name = "row 887 invert flips one zero byte to ff",
            .unlocking_hex = "0100",
            .locking_hex = "8301ff87",
            .expected = .{ .success = true },
        },
        .{
            .row = 888,
            .name = "row 888 invert flips one ff byte to zero",
            .unlocking_hex = "01ff",
            .locking_hex = "83010087",
            .expected = .{ .success = true },
        },
        .{
            .row = 889,
            .name = "row 889 invert preserves empty data",
            .unlocking_hex = "00",
            .locking_hex = "830087",
            .expected = .{ .success = true },
        },
        .{
            .row = 890,
            .name = "row 890 invert flips two payload bytes",
            .unlocking_hex = "020f0f",
            .locking_hex = "8302f0f087",
            .expected = .{ .success = true },
        },
        .{
            .row = 891,
            .name = "row 891 invert flips a three byte payload to trailing ff bytes",
            .unlocking_hex = "03ff0000",
            .locking_hex = "830300ffff87",
            .expected = .{ .success = true },
        },
        .{
            .row = 892,
            .name = "row 892 invert flips a three byte payload to leading ff bytes",
            .unlocking_hex = "0300ffff",
            .locking_hex = "8303ff000087",
            .expected = .{ .success = true },
        },
        .{
            .row = 893,
            .name = "row 893 invert clears a three byte ff payload",
            .unlocking_hex = "03ffffff",
            .locking_hex = "830300000087",
            .expected = .{ .success = true },
        },
        .{
            .row = 894,
            .name = "row 894 invert handles mixed three byte payloads",
            .unlocking_hex = "03801234",
            .locking_hex = "83037fedcb87",
            .expected = .{ .success = true },
        },
        .{
            .row = 895,
            .name = "row 895 invert handles eight byte payloads",
            .unlocking_hex = "088012348012341234",
            .locking_hex = "83087fedcb7fedcbedcb87",
            .expected = .{ .success = true },
        },
    });
}
