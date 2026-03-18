const std = @import("std");
const bsvz = @import("bsvz");
const harness = @import("support/runar_harness.zig");
const Secp256k1 = std.crypto.ecc.Secp256k1;

const ec_gen_x_hex = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const ec_gen_y_hex = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
const ec_neg_y_hex = "b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777";
const runar_root = "../runar";
const compiler_dist_path = "packages/runar-compiler/dist/index.js";

fn accessOrSkip(rel_path: []const u8) !void {
    std.fs.cwd().access(rel_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
}

fn compileRunarContract(
    allocator: std.mem.Allocator,
    source_rel_path: []const u8,
    file_name: []const u8,
    args_json: []const u8,
) ![]u8 {
    const source_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ runar_root, source_rel_path });
    defer allocator.free(source_abs_rel);
    try accessOrSkip(source_abs_rel);

    const compiler_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ runar_root, compiler_dist_path });
    defer allocator.free(compiler_abs_rel);
    try accessOrSkip(compiler_abs_rel);

    const code = try std.fmt.allocPrint(allocator,
        \\(async () => {{
        \\const {{ compile }} = await import('./packages/runar-compiler/dist/index.js');
        \\const fs = require('fs');
        \\const src = fs.readFileSync('{s}', 'utf-8');
        \\const args = JSON.parse('{s}');
        \\const result = compile(src, {{ fileName: '{s}', constructorArgs: args }});
        \\if (!result.success || !result.scriptHex) {{
        \\  console.error(JSON.stringify(result));
        \\  process.exit(1);
        \\}}
        \\process.stdout.write(result.scriptHex);
        \\}})();
    , .{ source_rel_path, args_json, file_name });
    defer allocator.free(code);

    const run_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "node", "-e", code },
        .cwd = runar_root,
        .max_output_bytes = 4 * 1024 * 1024,
    }) catch |err| switch (err) {
        error.FileNotFound, error.CurrentWorkingDirectoryUnlinked => return error.SkipZigTest,
        else => return err,
    };
    defer allocator.free(run_result.stderr);

    switch (run_result.term) {
        .Exited => |code_value| {
            if (code_value != 0) {
                std.log.err("runar local compile failed: {s}", .{run_result.stderr});
                allocator.free(run_result.stdout);
                return error.RunarCompileFailed;
            }
        },
        else => {
            allocator.free(run_result.stdout);
            return error.RunarCompileFailed;
        },
    }

    const trimmed = std.mem.trim(u8, run_result.stdout, &std.ascii.whitespace);
    if (trimmed.ptr == run_result.stdout.ptr and trimmed.len == run_result.stdout.len) {
        return run_result.stdout;
    }

    const copy = try allocator.dupe(u8, trimmed);
    allocator.free(run_result.stdout);
    return copy;
}

fn compileEcPrimitives(allocator: std.mem.Allocator) ![]u8 {
    const args_json = try std.fmt.allocPrint(allocator, "{{\"pt\":\"{s}{s}\"}}", .{
        ec_gen_x_hex,
        ec_gen_y_hex,
    });
    defer allocator.free(args_json);

    return compileRunarContract(
        allocator,
        "conformance/tests/ec-primitives/ec-primitives.runar.ts",
        "ec-primitives.runar.ts",
        args_json,
    );
}

fn encodeHexAlloc(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, bytes.len * 2);
    _ = try bsvz.primitives.hex.encodeLower(bytes, out);
    return out;
}

fn fieldHexAlloc(allocator: std.mem.Allocator, field: anytype) ![]u8 {
    const bytes = field.toBytes(.big);
    return encodeHexAlloc(allocator, &bytes);
}

fn pointHexAlloc(allocator: std.mem.Allocator, point: Secp256k1) ![]u8 {
    const affine = point.affineCoordinates();
    const x_bytes = affine.x.toBytes(.big);
    const y_bytes = affine.y.toBytes(.big);
    var point_bytes: [64]u8 = undefined;
    @memcpy(point_bytes[0..32], &x_bytes);
    @memcpy(point_bytes[32..64], &y_bytes);
    return encodeHexAlloc(allocator, &point_bytes);
}

fn scalarBytes(value: u64) [32]u8 {
    var out = [_]u8{0} ** 32;
    std.mem.writeInt(u64, out[24..32], value, .big);
    return out;
}

test "local runar ec-primitives acceptance cases execute through bsvz when fixtures are present" {
    const allocator = std.testing.allocator;
    const locking_script_hex = try compileEcPrimitives(allocator);
    defer allocator.free(locking_script_hex);

    const two_g = Secp256k1.basePoint.dbl();
    const three_g = Secp256k1.basePoint.add(two_g);
    const seven_g = try Secp256k1.basePoint.mul(scalarBytes(7), .big);
    const forty_two_g = try Secp256k1.basePoint.mul(scalarBytes(42), .big);

    const two_g_hex = try pointHexAlloc(allocator, two_g);
    defer allocator.free(two_g_hex);

    const three_g_x_hex = try fieldHexAlloc(allocator, three_g.affineCoordinates().x);
    defer allocator.free(three_g_x_hex);
    const three_g_y_hex = try fieldHexAlloc(allocator, three_g.affineCoordinates().y);
    defer allocator.free(three_g_y_hex);

    const seven_g_x_hex = try fieldHexAlloc(allocator, seven_g.affineCoordinates().x);
    defer allocator.free(seven_g_x_hex);
    const seven_g_y_hex = try fieldHexAlloc(allocator, seven_g.affineCoordinates().y);
    defer allocator.free(seven_g_y_hex);

    const forty_two_g_x_hex = try fieldHexAlloc(allocator, forty_two_g.affineCoordinates().x);
    defer allocator.free(forty_two_g_x_hex);
    const forty_two_g_y_hex = try fieldHexAlloc(allocator, forty_two_g.affineCoordinates().y);
    defer allocator.free(forty_two_g_y_hex);

    const compressed_g_hex = try encodeHexAlloc(allocator, &Secp256k1.basePoint.toCompressedSec1());
    defer allocator.free(compressed_g_hex);

    const cases = [_]harness.Case{
        .{
            .name = "local runar ec checkX",
            .locking_script_hex = locking_script_hex,
            .args = &[_]harness.PushValue{.{ .script_num_hex = ec_gen_x_hex }},
            .method_selector = 0,
            .expect_success = true,
        },
        .{
            .name = "local runar ec checkY",
            .locking_script_hex = locking_script_hex,
            .args = &[_]harness.PushValue{.{ .script_num_hex = ec_gen_y_hex }},
            .method_selector = 1,
            .expect_success = true,
        },
        .{
            .name = "local runar ec checkOnCurve",
            .locking_script_hex = locking_script_hex,
            .args = &[_]harness.PushValue{},
            .method_selector = 2,
            .expect_success = true,
        },
        .{
            .name = "local runar ec checkNegateY",
            .locking_script_hex = locking_script_hex,
            .args = &[_]harness.PushValue{.{ .script_num_hex = ec_neg_y_hex }},
            .method_selector = 3,
            .expect_success = true,
        },
        .{
            .name = "local runar ec checkModReduce",
            .locking_script_hex = locking_script_hex,
            .args = &[_]harness.PushValue{
                .{ .int = -7 },
                .{ .int = 5 },
                .{ .int = 3 },
            },
            .method_selector = 4,
            .expect_success = true,
        },
        .{
            .name = "local runar ec checkAdd",
            .locking_script_hex = locking_script_hex,
            .args = &[_]harness.PushValue{
                .{ .hex = two_g_hex },
                .{ .script_num_hex = three_g_x_hex },
                .{ .script_num_hex = three_g_y_hex },
            },
            .method_selector = 5,
            .expect_success = true,
        },
        .{
            .name = "local runar ec checkMul",
            .locking_script_hex = locking_script_hex,
            .args = &[_]harness.PushValue{
                .{ .int = 7 },
                .{ .script_num_hex = seven_g_x_hex },
                .{ .script_num_hex = seven_g_y_hex },
            },
            .method_selector = 6,
            .expect_success = true,
        },
        .{
            .name = "local runar ec checkMulGen",
            .locking_script_hex = locking_script_hex,
            .args = &[_]harness.PushValue{
                .{ .int = 42 },
                .{ .script_num_hex = forty_two_g_x_hex },
                .{ .script_num_hex = forty_two_g_y_hex },
            },
            .method_selector = 7,
            .expect_success = true,
        },
        .{
            .name = "local runar ec checkMakePoint",
            .locking_script_hex = locking_script_hex,
            .args = &[_]harness.PushValue{
                .{ .script_num_hex = ec_gen_x_hex },
                .{ .script_num_hex = ec_gen_y_hex },
                .{ .script_num_hex = ec_gen_x_hex },
                .{ .script_num_hex = ec_gen_y_hex },
            },
            .method_selector = 8,
            .expect_success = true,
        },
        .{
            .name = "local runar ec checkEncodeCompressed",
            .locking_script_hex = locking_script_hex,
            .args = &[_]harness.PushValue{.{ .hex = compressed_g_hex }},
            .method_selector = 9,
            .expect_success = true,
        },
        .{
            .name = "local runar ec checkMulIdentity",
            .locking_script_hex = locking_script_hex,
            .args = &[_]harness.PushValue{},
            .method_selector = 10,
            .expect_success = true,
        },
        .{
            .name = "local runar ec checkNegateRoundtrip",
            .locking_script_hex = locking_script_hex,
            .args = &[_]harness.PushValue{},
            .method_selector = 11,
            .expect_success = true,
        },
        .{
            .name = "local runar ec checkAddOnCurve",
            .locking_script_hex = locking_script_hex,
            .args = &[_]harness.PushValue{.{ .hex = two_g_hex }},
            .method_selector = 12,
            .expect_success = true,
        },
        .{
            .name = "local runar ec checkMulGenOnCurve",
            .locking_script_hex = locking_script_hex,
            .args = &[_]harness.PushValue{.{ .int = 42 }},
            .method_selector = 13,
            .expect_success = true,
        },
    };

    for (cases) |case| {
        const actual = harness.runCase(allocator, case) catch |err| {
            std.log.err("local runar acceptance case failed: {s}", .{case.name});
            return err;
        };
        try std.testing.expectEqual(case.expect_success, actual);
    }
}

test "local runar convergence-proof acceptance executes through bsvz when fixtures are present" {
    const allocator = std.testing.allocator;

    const r_a = try Secp256k1.basePoint.mul(scalarBytes(14), .big);
    const r_b = try Secp256k1.basePoint.mul(scalarBytes(9), .big);

    const r_a_hex = try pointHexAlloc(allocator, r_a);
    defer allocator.free(r_a_hex);
    const r_b_hex = try pointHexAlloc(allocator, r_b);
    defer allocator.free(r_b_hex);

    const args_json = try std.fmt.allocPrint(allocator, "{{\"rA\":\"{s}\",\"rB\":\"{s}\"}}", .{
        r_a_hex,
        r_b_hex,
    });
    defer allocator.free(args_json);

    const locking_script_hex = try compileRunarContract(
        allocator,
        "conformance/tests/convergence-proof/convergence-proof.runar.ts",
        "convergence-proof.runar.ts",
        args_json,
    );
    defer allocator.free(locking_script_hex);

    const actual = try harness.runCase(allocator, .{
        .name = "local runar convergence proof",
        .locking_script_hex = locking_script_hex,
        .args = &[_]harness.PushValue{.{ .int = 5 }},
        .expect_success = true,
    });
    try std.testing.expect(actual);
}
