const std = @import("std");

const ExternalInput = struct {
    name: []const u8,
    path: []const u8,
    purpose: []const u8,
    optional_step: ?[]const u8 = null,
};

const external_inputs = [_]ExternalInput{
    .{
        .name = "Go script corpus",
        .path = "../go-sdk/script/interpreter/data/script_tests.json",
        .purpose = "exact/filtered Go interpreter corpus suites",
    },
    .{
        .name = "Runar compiler dist",
        .path = "../runar/packages/runar-compiler/dist/index.js",
        .purpose = "optional downstream Runar acceptance coverage",
        .optional_step = "zig build test-runar-acceptance",
    },
};

fn envRequiresExternalCoverage(allocator: std.mem.Allocator) bool {
    const value = std.process.getEnvVarOwned(allocator, "BSVZ_REQUIRE_EXTERNAL_CORPORA") catch return false;
    defer allocator.free(value);
    return std.mem.eql(u8, value, "1") or
        std.ascii.eqlIgnoreCase(value, "true") or
        std.ascii.eqlIgnoreCase(value, "yes");
}

test "external corpus availability is visible in default test runs" {
    const allocator = std.testing.allocator;
    const require_external = envRequiresExternalCoverage(allocator);
    var missing_count: usize = 0;

    std.debug.print(
        "external coverage note: set BSVZ_REQUIRE_EXTERNAL_CORPORA=1 to fail when optional corpora are missing\n",
        .{},
    );

    for (external_inputs) |input| {
        std.fs.cwd().access(input.path, .{}) catch |err| switch (err) {
            error.FileNotFound => {
                missing_count += 1;
                if (input.optional_step) |step| {
                    std.debug.print(
                        "warning: missing optional external input '{s}' at {s}; {s} will not run in default coverage ({s})\n",
                        .{ input.name, input.path, step, input.purpose },
                    );
                } else {
                    std.debug.print(
                        "warning: missing optional external input '{s}' at {s}; related coverage will be skipped ({s})\n",
                        .{ input.name, input.path, input.purpose },
                    );
                }
                continue;
            },
            else => return err,
        };

        std.debug.print("external coverage input present: {s} ({s})\n", .{ input.name, input.purpose });
    }

    std.debug.print(
        "coverage note: filtered Go corpus lanes intentionally skip unsupported rows; see executed/skipped counts in test stderr\n",
        .{},
    );

    if (require_external and missing_count != 0) return error.MissingExternalCoverageInputs;
}
