const std = @import("std");
const harness = @import("support/runar_harness.zig");

const key_one_private = [_]u8{0} ** 31 ++ [_]u8{1};
const key_two_private = [_]u8{0} ** 31 ++ [_]u8{2};

const key_one_pub_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const key_two_pub_hex = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const big_a_hex = "400000000000000005";
const big_b_hex = "200000000000000007";

const pure_cases = [_]harness.Case{
    .{
        .name = "runar arithmetic success",
        .locking_script_hex = "6e9352795279945379537995547a547a96537a537a937b937c93011b9c",
        .args = &[_]harness.PushValue{ .{ .int = 3 }, .{ .int = 7 } },
        .expect_success = true,
    },
    .{
        .name = "runar arithmetic fail",
        .locking_script_hex = "6e9352795279945379537995547a547a96537a537a937b937c9391",
        .args = &[_]harness.PushValue{ .{ .int = 3 }, .{ .int = 7 } },
        .expect_success = false,
    },
    .{
        .name = "runar boolean logic success",
        .locking_script_hex = "7b52a07b52a06e9a7b7b9b7b919a9b",
        .args = &[_]harness.PushValue{ .{ .int = 5 }, .{ .int = 3 }, .{ .boolean = false } },
        .expect_success = true,
    },
    .{
        .name = "runar if-else success",
        .locking_script_hex = "007c637c5a93677c5a946800a0",
        .args = &[_]harness.PushValue{ .{ .int = 15 }, .{ .boolean = true } },
        .expect_success = true,
    },
    .{
        .name = "runar if-else fail",
        .locking_script_hex = "007c637c5a93677c5a946800a0",
        .args = &[_]harness.PushValue{ .{ .int = 5 }, .{ .boolean = false } },
        .expect_success = false,
    },
    .{
        .name = "runar if-without-else both above threshold",
        .locking_script_hex = "007b55a06351787c93677668777c55a06351787c936776687700a0",
        .args = &[_]harness.PushValue{ .{ .int = 10 }, .{ .int = 8 } },
        .expect_success = true,
    },
    .{
        .name = "runar if-without-else one above threshold",
        .locking_script_hex = "007b55a06351787c93677668777c55a06351787c936776687700a0",
        .args = &[_]harness.PushValue{ .{ .int = 10 }, .{ .int = 3 } },
        .expect_success = true,
    },
    .{
        .name = "runar if-without-else fail",
        .locking_script_hex = "007b55a06351787c93677668777c55a06351787c936776687700a0",
        .args = &[_]harness.PushValue{ .{ .int = 3 }, .{ .int = 2 } },
        .expect_success = false,
    },
    .{
        .name = "runar bounded loop success",
        .locking_script_hex = "000052797b7c937c935152797b7c937c935252797b7c937c935352797b7c937c93547b7b7c937c9301199c",
        .args = &[_]harness.PushValue{.{ .int = 3 }},
        .expect_success = true,
    },
    .{
        .name = "runar boolean logic supports big script numbers",
        .locking_script_hex = "7b00a07b00a06e9a7b7b9b7b919a9b",
        .args = &[_]harness.PushValue{
            .{ .script_num_hex = big_a_hex },
            .{ .script_num_hex = big_b_hex },
            .{ .boolean = false },
        },
        .expect_success = true,
    },
    .{
        .name = "runar if-else supports big script numbers",
        .locking_script_hex = "007c637c0093677c00946800a0",
        .args = &[_]harness.PushValue{
            .{ .script_num_hex = big_a_hex },
            .{ .boolean = true },
        },
        .expect_success = true,
    },
    .{
        .name = "runar if-without-else supports big script numbers",
        .locking_script_hex = "007b00a06351787c93677668777c00a06351787c936776687700a0",
        .args = &[_]harness.PushValue{
            .{ .script_num_hex = big_a_hex },
            .{ .script_num_hex = big_b_hex },
        },
        .expect_success = true,
    },
};

const spend_cases = [_]harness.Case{
    .{
        .name = "runar basic p2pkh success",
        .locking_script_hex = "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac",
        .args = &[_]harness.PushValue{
            .{ .signature = {} },
            .{ .hex = key_one_pub_hex },
        },
        .expect_success = true,
        .spend = .{ .signing_key = key_one_private },
    },
    .{
        .name = "runar basic p2pkh wrong key fail",
        .locking_script_hex = "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac",
        .args = &[_]harness.PushValue{
            .{ .signature = {} },
            .{ .hex = key_two_pub_hex },
        },
        .expect_success = false,
        .spend = .{ .signing_key = key_two_private },
    },
    .{
        .name = "runar multi-method owner path success",
        .locking_script_hex = "76009c637552958b5aa069210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac67519d2102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5ac68",
        .args = &[_]harness.PushValue{
            .{ .signature = {} },
            .{ .int = 6 },
        },
        .method_selector = 0,
        .expect_success = true,
        .spend = .{ .signing_key = key_one_private },
    },
    .{
        .name = "runar multi-method backup path success",
        .locking_script_hex = "76009c637552958b5aa069210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac67519d2102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5ac68",
        .args = &[_]harness.PushValue{.{ .signature = {} }},
        .method_selector = 1,
        .expect_success = true,
        .spend = .{ .signing_key = key_two_private },
    },
    .{
        .name = "runar multi-method owner threshold fail",
        .locking_script_hex = "76009c637552958b5aa069210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac67519d2102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5ac68",
        .args = &[_]harness.PushValue{
            .{ .signature = {} },
            .{ .int = 3 },
        },
        .method_selector = 0,
        .expect_success = false,
        .spend = .{ .signing_key = key_one_private },
    },
};

test "runar pure conformance cases execute through bsvz" {
    const allocator = std.testing.allocator;

    for (pure_cases) |case| {
        const actual = try harness.runCase(allocator, case);
        if (actual != case.expect_success) {
            std.debug.print("runar case mismatch: {s}\\n", .{case.name});
        }
        try std.testing.expectEqual(case.expect_success, actual);
    }
}

test "runar signed conformance cases execute through bsvz" {
    const allocator = std.testing.allocator;

    for (spend_cases) |case| {
        const actual = try harness.runCase(allocator, case);
        if (actual != case.expect_success) {
            std.debug.print("runar spend case mismatch: {s}\\n", .{case.name});
        }
        try std.testing.expectEqual(case.expect_success, actual);
    }
}
