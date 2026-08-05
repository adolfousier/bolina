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

    // Fuzz harness (LANGUAGE.md O2 / SPEC section 11.6). Built and run on demand
    // via `zig build fuzz` (fixed ~1h budget). main.zig never imports it, so it
    // stays out of the shipped binary; a ReleaseSafe panic there is a real
    // bounds gap.
    const fuzz_mod = b.createModule(.{
        .root_source_file = b.path("src/fuzz.zig"),
        .target = target,
        .optimize = optimize,
    });
    const fuzz_vectors = b.createModule(.{
        .root_source_file = b.path("test/vectors_module.zig"),
    });
    fuzz_mod.addImport("vectors", fuzz_vectors);
    const fuzz_exe = b.addExecutable(.{ .name = "bolina-fuzz", .root_module = fuzz_mod });
    const run_fuzz = b.addRunArtifact(fuzz_exe);
    const fuzz_step = b.step("fuzz", "Build and run the parser chaos fuzzer (fixed ~1h budget)");
    fuzz_step.dependOn(&run_fuzz.step);

    // Negative compile test (BE-GRANT-03b). test/negative_capability.zig tries
    // to forge a VerifiedGrant by value, which MUST fail to compile now that the
    // capability is opaque {}. We run the compiler on it directly and assert
    // exit 1: the step PASSES on a compile failure and FAILS the day the file
    // ever compiles (the forgery hole reopened). Run by tools/prumo-verify
    // under M8. The compiler's error output on stderr is expected.
    const neg_cmd = b.addSystemCommand(&.{
        b.graph.zig_exe,
        "build-obj",
        "-fno-emit-bin",
        "src/negative_capability.zig",
    });
    neg_cmd.expectExitCode(1);
    neg_cmd.setName("negative compile (capability forgery must fail)");
    const negative_step = b.step("negative", "Negative compile test: capability forgery MUST fail to compile");
    negative_step.dependOn(&neg_cmd.step);
}
