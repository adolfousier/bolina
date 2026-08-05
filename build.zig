const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    // LANGUAGE.md O1: ReleaseSafe is the shipped build, never ReleaseFast.
    // The mode is hardcoded and deliberately not exposed through
    // b.standardOptimizeOption, so there is no ReleaseFast path in this
    // repository. Audited by tools/prumo-verify under CONTRIBUTING.md M7.
    const optimize: std.builtin.OptimizeMode = .ReleaseSafe;

    const exe = b.addExecutable(.{
        .name = "bolina",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    b.installArtifact(exe);

    const run_step = b.step("run", "Run bolina");
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_step.dependOn(&run_cmd.step);
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // The test step exists from day one so the M1 bijection
    // (SPEC.md section 11.1) has a home the moment the first
    // BE-bound test lands. Zig registry convention for M1:
    // test blocks are named test "BE_<CLASS>_<NN> ...".
    // The test step root is the aggregator (src/tests.zig), which imports every
    // dedicated *_test.zig module. Source files are production-only; this keeps
    // test code out of the shipped binary while giving the M1 bijection (SPEC
    // section 11.1) one compilation root for all BE-bound tests.
    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tests.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    // The vectors harness (src/vectors_test.zig) embeds test/vectors.json at
    // compile time. That file lives outside src/ (the test module's package
    // path), so it is exposed through a bridge module rooted in test/.
    const vectors_mod = b.createModule(.{
        .root_source_file = b.path("test/vectors_module.zig"),
    });
    tests.root_module.addImport("vectors", vectors_mod);
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_tests.step);
}
