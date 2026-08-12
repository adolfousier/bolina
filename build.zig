const std = @import("std");

// src/fuzz.zig mode selection (BE-SURF-04 differential oracle, D-056):
// chaos = the bounds-check chaos fuzzer; corpus = deterministic corpus emit;
// diff = corpus replay with one verdict per record. Each build step below
// pins its own mode, so the shipped chaos behavior never changes.
const FuzzMode = enum { chaos, corpus, diff };

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // LANGUAGE.md O1: ReleaseSafe is the shipped build, never ReleaseFast.
    // The mode is hardcoded and deliberately not exposed through
    // b.standardOptimizeOption, so there is no ReleaseFast path in this
    // repository. Audited by tools/prumo-verify under CONTRIBUTING.md M7.
    const optimize: std.builtin.OptimizeMode = .ReleaseSafe;

    // Build options consumed by coverage.zig (ENABLED) and fuzz.zig (budget).
    // coverage_enabled defaults false: the test and shipped builds see coverage
    // comptime-off, so every hit() call is dead-code eliminated and carries no
    // cost or state. Only `zig build coverage -Dcoverage` flips it on. The
    // fuzz_budget default is the full ~1h run (7.3B inputs); the coverage step
    // shortens it via -Dfuzz-budget.
    const coverage_on = b.option(bool, "coverage", "Enable hand-instrumented branch coverage") orelse false;
    const fuzz_budget = b.option(u64, "fuzz-budget", "Fuzz iteration budget (default 7.3B)") orelse 7_300_000_000;
    const corpus_budget = b.option(u64, "corpus-budget", "Differential corpus record count (default 100000)") orelse 100_000;
    const options = b.addOptions();
    options.addOption(bool, "coverage_enabled", coverage_on);
    options.addOption(u64, "fuzz_budget", fuzz_budget);
    options.addOption(FuzzMode, "fuzz_mode", FuzzMode.chaos);
    options.addOption(u64, "corpus_budget", corpus_budget);
    const opts_mod = options.createModule();

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_mod.addImport("build_options", opts_mod);
    const exe = b.addExecutable(.{ .name = "bolina", .root_module = exe_mod });
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
    // single_threaded pins the test binary to sequential execution. Zig
    // function pointers cannot capture state, so the callback doubles in
    // verify_test.zig (ledger_calls, effect_calls, effect_grant_id) and
    // dag_test.zig (sup_dag, sup_effect) record through package-level
    // variables the tests read back. Under the default parallel test runner
    // those variables are shared across concurrently executing test blocks,
    // which produced nondeterministic counts (a call-ordering test observing
    // 2 where it asserted 1) and torn reads of the package-level Dag. The
    // library itself is zero-heap with no global mutable state and no
    // production concurrency, so parallel test execution buys nothing here
    // and a deterministic gate is worth more than a faster one.
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/tests.zig"),
        .target = target,
        .optimize = optimize,
        .single_threaded = true,
    });
    test_mod.addImport("build_options", opts_mod);
    // The vectors harness (src/vectors_test.zig) embeds test/vectors.json at
    // compile time. That file lives outside src/ (the test module's package
    // path), so it is exposed through a bridge module rooted in test/.
    const vectors_mod = b.createModule(.{
        .root_source_file = b.path("test/vectors_module.zig"),
    });
    test_mod.addImport("vectors", vectors_mod);
    const tests = b.addTest(.{ .root_module = test_mod });
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
    fuzz_mod.addImport("build_options", opts_mod);
    const fuzz_vectors = b.createModule(.{
        .root_source_file = b.path("test/vectors_module.zig"),
    });
    fuzz_mod.addImport("vectors", fuzz_vectors);
    const fuzz_exe = b.addExecutable(.{ .name = "bolina-fuzz", .root_module = fuzz_mod });
    const run_fuzz = b.addRunArtifact(fuzz_exe);
    const fuzz_step = b.step("fuzz", "Build and run the parser chaos fuzzer (fixed ~1h budget)");
    fuzz_step.dependOn(&run_fuzz.step);

    // Build-only step: installs the fuzz binary WITHOUT running it. The `fuzz`
    // step above bundles a run, which fails when the target is non-native
    // (e.g. cross-compiling x86_64-linux on an aarch64-macos host to ship the
    // soak to a server). Use `zig build fuzz-bin -Dtarget=... -Dfuzz-budget=...`
    // to produce a clean installable artifact at zig-out/bin/bolina-fuzz.
    const fuzz_bin_step = b.step("fuzz-bin", "Build+install the fuzz binary without running (cross-target shipping)");
    fuzz_bin_step.dependOn(&b.addInstallArtifact(fuzz_exe, .{}).step);

    // Coverage measurement (LANGUAGE.md O2 / SPEC section 11.6). The same fuzz
    // harness, but built with -Dcoverage so coverage.ENABLED is comptime true
    // and every parser exit-point counter is live. Run as
    //   zig build coverage -Dcoverage -Dfuzz-budget=4000000
    // which prints the N/M exit-point-reach report, the unreached list, and
    // the corpus description. Manual instrumentation IS the measurement here;
    // the toolchain's -ffuzz coverage has no script-readable output.
    const coverage_step = b.step("coverage", "Run fuzz with exit-point coverage on (-Dcoverage -Dfuzz-budget=N)");
    coverage_step.dependOn(&run_fuzz.step);

    // Differential fuzz oracle (BE-SURF-04, D-056). The same harness built in
    // two extra modes pinned by the fuzz_mode build option: corpus emits a
    // deterministic corpus file (tag || u16 BE len || bytes records,
    // per-structure seed lineage + random, same PRNG seed and 4 mutation
    // operators as chaos); diff replays a corpus file through the tagged
    // parse entry points and prints one verdict line per record. The
    // independent Python reference parser (tools/refparse.py) replays the
    // SAME file; agreement on every record is the differential verdict.
    //   zig build fuzz-corpus [-Dcorpus-budget=N] [-- OUT_PATH]
    //   zig build fuzz-diff [-- CORPUS_PATH]
    const corpus_opts = b.addOptions();
    corpus_opts.addOption(bool, "coverage_enabled", coverage_on);
    corpus_opts.addOption(u64, "fuzz_budget", fuzz_budget);
    corpus_opts.addOption(FuzzMode, "fuzz_mode", FuzzMode.corpus);
    corpus_opts.addOption(u64, "corpus_budget", corpus_budget);
    const corpus_opts_mod = corpus_opts.createModule();
    const fuzz_corpus_mod = b.createModule(.{
        .root_source_file = b.path("src/fuzz.zig"),
        .target = target,
        .optimize = optimize,
    });
    fuzz_corpus_mod.addImport("build_options", corpus_opts_mod);
    fuzz_corpus_mod.addImport("vectors", b.createModule(.{ .root_source_file = b.path("test/vectors_module.zig") }));
    const corpus_exe = b.addExecutable(.{ .name = "bolina-fuzz-corpus", .root_module = fuzz_corpus_mod });
    const run_corpus = b.addRunArtifact(corpus_exe);
    if (b.args) |args| run_corpus.addArgs(args);
    const corpus_step = b.step("fuzz-corpus", "Emit the deterministic differential corpus (D-056)");
    corpus_step.dependOn(&run_corpus.step);

    const diff_opts = b.addOptions();
    diff_opts.addOption(bool, "coverage_enabled", coverage_on);
    diff_opts.addOption(u64, "fuzz_budget", fuzz_budget);
    diff_opts.addOption(FuzzMode, "fuzz_mode", FuzzMode.diff);
    diff_opts.addOption(u64, "corpus_budget", corpus_budget);
    const diff_opts_mod = diff_opts.createModule();
    const fuzz_diff_mod = b.createModule(.{
        .root_source_file = b.path("src/fuzz.zig"),
        .target = target,
        .optimize = optimize,
    });
    fuzz_diff_mod.addImport("build_options", diff_opts_mod);
    fuzz_diff_mod.addImport("vectors", b.createModule(.{ .root_source_file = b.path("test/vectors_module.zig") }));
    const diff_exe = b.addExecutable(.{ .name = "bolina-fuzz-diff", .root_module = fuzz_diff_mod });
    const run_diff = b.addRunArtifact(diff_exe);
    if (b.args) |args| run_diff.addArgs(args);
    const diff_step = b.step("fuzz-diff", "Replay a corpus file through the tagged parsers, one verdict per record (D-056)");
    diff_step.dependOn(&run_diff.step);
}
