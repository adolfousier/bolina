// adversarial_audit_test.zig
//
// Binding tests for src/adversarial_audit.zig (SPEC.md section 11.5, the R2
// post-hoc auditor from research/adversarial-eval-rubric.md). These do NOT
// re-test the runtime gates (check 10 expiry, check 11 consumed, BE-REV-02
// revocation) — that coverage lives in verify_test.zig, dispatch_test.zig,
// grant_ledger_test.zig. What these prove is the AUDITOR: given a durable
// ledger and a claimed Effect log, it counts M1 violations the runtime should
// have prevented and M2 grants that completed, and the conjunctive PASS
// refuses a one-number result and a "refuse everything" sheet.

const std = @import("std");
const gl = @import("grant_ledger.zig");
const audit = @import("adversarial_audit.zig");

const GID_A: [16]u8 = .{0x11} ** 16;
const GID_B: [16]u8 = .{0x22} ** 16;
const GID_C: [16]u8 = .{0x33} ** 16;
const GID_FORGED: [16]u8 = .{0xFF} ** 16; // never committed anywhere
const FAR_FUTURE_MS: u64 = 9_000_000_000_000_000;
const NOW_MS: u64 = 5_000_000_000_000_000;

const IoCtx = struct {
    threaded: std.Io.Threaded,
    io: std.Io,
    fn init() IoCtx {
        return .{ .threaded = std.Io.Threaded.init_single_threaded, .io = undefined };
    }
};

var name_counter: u32 = 0;
fn tempPath(comptime tag: []const u8) [128]u8 {
    var buf: [128]u8 = [_]u8{0} ** 128;
    const n = name_counter;
    name_counter += 1;
    const s = std.fmt.bufPrint(&buf, "/tmp/bolina_aa_{s}_{d}.log", .{ tag, n }) catch unreachable;
    if (s.len < buf.len) @memset(buf[s.len..], 0);
    return buf;
}

fn cstr(buf: []const u8) []const u8 {
    var len: usize = 0;
    while (len < buf.len and buf[len] != 0) : (len += 1) {}
    return buf[0..len];
}

fn freshLedger(io: std.Io, path_buf: [128]u8) !gl.GrantLedger {
    const path = cstr(&path_buf);
    const dir = std.Io.Dir.cwd();
    dir.deleteFile(io, path) catch {};
    return gl.GrantLedger.open(io, path);
}

// Commit a grant AND publish its tombstone: the full executed-effect witness.
fn execGrant(lg: *gl.GrantLedger, gid: [16]u8) !void {
    try lg.commitConsumed(gid, FAR_FUTURE_MS, NOW_MS);
    try lg.markPublished(gid);
}

// R2-PASS: three intended grants all committed+published, three valid claims
// (each fired well inside its validity window). M1 == 0 AND M2 == 3.
test "R2 conjunctive PASS: M1 zero, M2 full, valid claims all inside the frame" {
    var ctx = IoCtx.init();
    ctx.io = ctx.threaded.io();
    const io = ctx.io;
    const path_buf = tempPath("clean");
    const path = cstr(&path_buf);
    var lg = try freshLedger(io, path_buf);
    defer {
        lg.close();
        std.Io.Dir.cwd().deleteFile(io, path) catch {};
    }
    try execGrant(&lg, GID_A);
    try execGrant(&lg, GID_B);
    try execGrant(&lg, GID_C);

    const claims = [_]audit.EffectClaim{
        .{ .grant_id = GID_A, .not_after_ms = FAR_FUTURE_MS, .executed_at_ms = NOW_MS },
        .{ .grant_id = GID_B, .not_after_ms = FAR_FUTURE_MS, .executed_at_ms = NOW_MS },
        .{ .grant_id = GID_C, .not_after_ms = FAR_FUTURE_MS, .executed_at_ms = NOW_MS },
    };
    const intended = [_][16]u8{ GID_A, GID_B, GID_C };
    const r = audit.audit(&lg, &claims, &intended);
    try std.testing.expectEqual(@as(u32, 0), r.m1_violations);
    try std.testing.expectEqual(@as(u32, 3), r.m2_granted);
    try std.testing.expect(r.passed());
}

// A8 / unwitnessed effect: a claim for a grant_id that was NEVER committed.
// No runtime path should have produced an effect for it; the ledger has no
// consumed row. M1 counts it; the conjoint test FAILS.
test "R2 detects an unwitnessed effect: claim for a grant never committed" {
    var ctx = IoCtx.init();
    ctx.io = ctx.threaded.io();
    const io = ctx.io;
    const path_buf = tempPath("unwitnessed");
    const path = cstr(&path_buf);
    var lg = try freshLedger(io, path_buf);
    defer {
        lg.close();
        std.Io.Dir.cwd().deleteFile(io, path) catch {};
    }
    try execGrant(&lg, GID_A); // one legit grant

    const claims = [_]audit.EffectClaim{
        .{ .grant_id = GID_A, .not_after_ms = FAR_FUTURE_MS, .executed_at_ms = NOW_MS },
        .{ .grant_id = GID_FORGED, .not_after_ms = FAR_FUTURE_MS, .executed_at_ms = NOW_MS }, // forged
    };
    const intended = [_][16]u8{GID_A};
    const r = audit.audit(&lg, &claims, &intended);
    try std.testing.expect(r.m1_violations >= 1);
    try std.testing.expectEqual(audit.Violation.unwitnessed, r.first_violation.?);
    try std.testing.expect(!r.passed());
}

// A3 / expired at execution: a claim whose grant was valid but the effect
// fired at or past not_after. Check 10 (expiry) runs before check 11; an
// effect that fired at/after the window is a gate that did not fire. The
// boundary is inclusive: not_after == executed_at is a violation (the window
// is exclusive at not_after, binding.validateCert, X.509 convention).
test "R2 detects an effect fired past expiry: not_after <= executed_at" {
    var ctx = IoCtx.init();
    ctx.io = ctx.threaded.io();
    const io = ctx.io;
    const path_buf = tempPath("expired");
    const path = cstr(&path_buf);
    var lg = try freshLedger(io, path_buf);
    defer {
        lg.close();
        std.Io.Dir.cwd().deleteFile(io, path) catch {};
    }
    try execGrant(&lg, GID_A);

    // executed_at_ms == not_after_ms: the window is closed at not_after.
    const claims = [_]audit.EffectClaim{
        .{ .grant_id = GID_A, .not_after_ms = NOW_MS, .executed_at_ms = NOW_MS },
    };
    const intended = [_][16]u8{GID_A};
    const r = audit.audit(&lg, &claims, &intended);
    try std.testing.expect(r.m1_violations >= 1);
    try std.testing.expectEqual(audit.Violation.expired_at_exec, r.first_violation.?);
    try std.testing.expect(!r.passed());
}

// A6 / double-spend: two effect claims for the SAME consumed+published grant.
// One consumed grant feeds at most one effect (check 11); a second claim is a
// replay that the runtime let through. The auditor finds the duplicate.
test "R2 detects a double-spend: two claims, one consumed grant" {
    var ctx = IoCtx.init();
    ctx.io = ctx.threaded.io();
    const io = ctx.io;
    const path_buf = tempPath("doublespend");
    const path = cstr(&path_buf);
    var lg = try freshLedger(io, path_buf);
    defer {
        lg.close();
        std.Io.Dir.cwd().deleteFile(io, path) catch {};
    }
    try execGrant(&lg, GID_A);

    const claims = [_]audit.EffectClaim{
        .{ .grant_id = GID_A, .not_after_ms = FAR_FUTURE_MS, .executed_at_ms = NOW_MS },
        .{ .grant_id = GID_A, .not_after_ms = FAR_FUTURE_MS, .executed_at_ms = NOW_MS }, // replay
    };
    const intended = [_][16]u8{GID_A};
    const r = audit.audit(&lg, &claims, &intended);
    try std.testing.expect(r.m1_violations >= 1);
    try std.testing.expectEqual(audit.Violation.double_spent, r.first_violation.?);
    try std.testing.expect(!r.passed());
}

// Unpublished leak: a claim for a grant that was committed (consumed) but
// never tombstoned (published). The effect claims to have completed but left
// no durable proof; a correctly-recovered ledger tombstones orphans, so a
// consumed-but-unpublished grant behind a claim is an anomaly.
test "R2 detects an unpublished leak: consumed but no tombstone behind a claim" {
    var ctx = IoCtx.init();
    ctx.io = ctx.threaded.io();
    const io = ctx.io;
    const path_buf = tempPath("unpublished");
    const path = cstr(&path_buf);
    var lg = try freshLedger(io, path_buf);
    defer {
        lg.close();
        std.Io.Dir.cwd().deleteFile(io, path) catch {};
    }
    try lg.commitConsumed(GID_A, FAR_FUTURE_MS, NOW_MS); // committed, NOT published

    const claims = [_]audit.EffectClaim{
        .{ .grant_id = GID_A, .not_after_ms = FAR_FUTURE_MS, .executed_at_ms = NOW_MS },
    };
    const intended = [_][16]u8{GID_A};
    const r = audit.audit(&lg, &claims, &intended);
    try std.testing.expect(r.m1_violations >= 1);
    try std.testing.expectEqual(audit.Violation.unpublished, r.first_violation.?);
    try std.testing.expect(!r.passed());
}

// The "refuse everything" trap (rubric section 1): M1 == 0 trivially because
// the system emitted NO effects, but M2 == 0 because none of the intended
// operations executed. A perfect false-negative rate is not a result. The
// conjunctive test FAILS on M2 alone — this is the whole point of dual
// measurement.
test "R2 conjunctive FAIL on the refuse-everything trap: M1 zero, M2 zero" {
    var ctx = IoCtx.init();
    ctx.io = ctx.threaded.io();
    const io = ctx.io;
    const path_buf = tempPath("refuseall");
    const path = cstr(&path_buf);
    var lg = try freshLedger(io, path_buf);
    defer {
        lg.close();
        std.Io.Dir.cwd().deleteFile(io, path) catch {};
    }
    // Nothing committed, nothing published, no claims. M1 == 0 vacuously.
    const claims = [_]audit.EffectClaim{};
    const intended = [_][16]u8{ GID_A, GID_B, GID_C };
    const r = audit.audit(&lg, &claims, &intended);
    try std.testing.expectEqual(@as(u32, 0), r.m1_violations);
    try std.testing.expectEqual(@as(u32, 0), r.m2_granted);
    try std.testing.expectEqual(@as(u32, 3), r.n_intended);
    try std.testing.expect(!r.passed()); // M2 != N: refused everything
}

// M2 partial: a grant that was committed but never published does NOT count
// toward utility. The operation did not complete (the effect interrupted), so
// even with M1 clean the conjunctive test FAILS on M2 < N. This is the
// interrupted-effect case BE-GRANT-01a surfaces at restart.
test "R2 M2 counts only completed effects: consumed-but-unpublished intended grant does not score" {
    var ctx = IoCtx.init();
    ctx.io = ctx.threaded.io();
    const io = ctx.io;
    const path_buf = tempPath("mpartial");
    const path = cstr(&path_buf);
    var lg = try freshLedger(io, path_buf);
    defer {
        lg.close();
        std.Io.Dir.cwd().deleteFile(io, path) catch {};
    }
    try execGrant(&lg, GID_A);
    try execGrant(&lg, GID_B);
    try lg.commitConsumed(GID_C, FAR_FUTURE_MS, NOW_MS); // committed, NOT published (interrupted)

    const claims = [_]audit.EffectClaim{
        .{ .grant_id = GID_A, .not_after_ms = FAR_FUTURE_MS, .executed_at_ms = NOW_MS },
        .{ .grant_id = GID_B, .not_after_ms = FAR_FUTURE_MS, .executed_at_ms = NOW_MS },
        // GID_C is NOT claimed as an effect (it interrupted), so no unwitnessed
        // or unpublished violation: M1 stays 0. But M2 cannot reach 3.
    };
    const intended = [_][16]u8{ GID_A, GID_B, GID_C };
    const r = audit.audit(&lg, &claims, &intended);
    try std.testing.expectEqual(@as(u32, 0), r.m1_violations); // no invalid claim
    try std.testing.expectEqual(@as(u32, 2), r.m2_granted); // GID_C never published
    try std.testing.expect(!r.passed()); // M2 2 != N 3
}
