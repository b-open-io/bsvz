const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const root_module = b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    _ = b.addModule("bsvz", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addLibrary(.{
        .name = "bsvz",
        .root_module = root_module,
        .linkage = .static,
    });
    b.installArtifact(lib);

    const lib_unit_tests = b.addTest(.{
        .root_module = root_module,
    });
    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const test_module = b.createModule(.{
        .root_source_file = b.path("tests/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_module.addImport("bsvz", root_module);

    const integration_tests = b.addTest(.{
        .root_module = test_module,
    });
    const run_integration_tests = b.addRunArtifact(integration_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_integration_tests.step);

    const bench_module = b.createModule(.{
        .root_source_file = b.path("benchmarks/script_engine.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    bench_module.addImport("bsvz", root_module);

    const bench_exe = b.addExecutable(.{
        .name = "bench-script-engine",
        .root_module = bench_module,
    });
    b.installArtifact(bench_exe);

    const run_bench = b.addRunArtifact(bench_exe);
    const bench_step = b.step("bench", "Run script engine benchmarks");
    bench_step.dependOn(&run_bench.step);
}
