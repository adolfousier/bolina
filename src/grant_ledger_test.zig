// grant_ledger_test.zig
//
// BE-EXEC-01 / BE-GRANT-01/01a / BE-GRANT-04 / BE-REV-02 binding tests
// (SPEC.md section 2 check 11, section 0.4, D-061). Literal values
// throughout (D-027). Each test opens a fresh log under the OS temp dir so
// file state never leaks between tests; the absolute path passes straight
// through createFile, which accepts absolute paths.

const std = @import("std");
const gl = @import("grant_ledger.zig");

// Literal fixtures (D-027).
const GID_A: [16]u8 = .{ 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };
const GID_B: [16]u8 = .{ 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 };
const GID_C: [16]u8 = .{ 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33 };
const KEY_X: [32]u8 = .{0x0A} ** 32;
const KEY_Y: [32]u8 = .{0x0B} ** 32;
const FAR_FUTURE_MS: u64 = 9_000_000_000_000_000;
const NOW_MS: u64 = 5_000_000_000_000_000;

// One threaded io context per test (Zig 0.16 std.Io). The threaded value must
// outlive the io borrow, so it lives on the stack of each test; the helper
// below pairs them so no test repeats the boilerplate.
const IoCtx = struct {
    threaded: std.Io.Threaded,
    io: std.Io,
    fn init() IoCtx {
        return .{ .threaded = std.Io.Threaded.init_single_threaded, .io = undefined };
    }
};

// Build a unique absolute temp path for this test run. A static counter keeps
// tests from sharing a file.
var name_counter: u32 = 0;
fn tempPath(comptime tag: []const u8) [128]u8 {
    var buf: [128]u8 = [_]u8{0} ** 128;
    const tmp = "/tmp";
    const n = name_counter;
    name_counter += 1;
    const s = std.fmt.bufPrint(&buf, "{s}/bolina_gl_{s}_{d}.log", .{ tmp, tag, n }) catch unreachable;
    const len = s.len;
    if (len < buf.len) @memset(buf[len..], 0);
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

test "BE_GRANT_01 commit is durable before the effect: fsync observable on read-back (T1)" {
    var ctx = IoCtx.init();
    ctx.io = ctx.threaded.io();
    const io = ctx.io;
    const dir = std.Io.Dir.cwd();

    const path_buf = tempPath("t1");
    const path = cstr(&path_buf);
    var lg = try freshLedger(io, path_buf);
    defer {
        lg.close();
        dir.deleteFile(io, path) catch {};
    }
    // After commitConsumed returns, the grant MUST be on disk (fsync landed)
    // and BEFORE markPublished (no tombstone yet).
    try lg.commitConsumed(GID_A, FAR_FUTURE_MS, NOW_MS);
    try std.testing.expect(lg.isConsumed(GID_A));
    // Read the raw log: a commit row (0x01 | grant_id | expiry) is present.
    const f = dir.openFile(io, path, .{}) catch return error.TestUnexpectedResult;
    defer f.close(io);
    var buf: [256]u8 = undefined;
    const n = f.readPositionalAll(io, &buf, 0) catch return error.TestUnexpectedResult;
    try std.testing.expect(n >= 25); // at least one full commit row
    try std.testing.expectEqual(@as(u8, 0x01), buf[0]); // TAG_COMMIT
    try std.testing.expectEqual(GID_A[0], buf[1]); // grant_id first byte
}

test "BE_GRANT_01 consumed grant survives restart: replay reconstructs exact state (T2)" {
    var ctx = IoCtx.init();
    ctx.io = ctx.threaded.io();
    const io = ctx.io;
    const dir = std.Io.Dir.cwd();

    const path_buf = tempPath("t2");
    const path = cstr(&path_buf);
    {
        var lg = try freshLedger(io, path_buf);
        try lg.commitConsumed(GID_A, FAR_FUTURE_MS, NOW_MS);
        try lg.commitConsumed(GID_B, FAR_FUTURE_MS, NOW_MS);
        try lg.markPublished(GID_A);
        try lg.markPublished(GID_B);
        lg.close();
    }
    // Reopen + recover: both grants remain consumed (cannot be un-spent).
    var lg = gl.GrantLedger.open(io, path) catch return error.TestUnexpectedResult;
    defer lg.close();
    const r = try lg.recover();
    try std.testing.expectEqual(@as(usize, 2), r.consumed_count);
    try std.testing.expect(lg.isConsumed(GID_A));
    try std.testing.expect(lg.isConsumed(GID_B));
    try std.testing.expectEqual(@as(usize, 0), r.orphans.len); // both published
    dir.deleteFile(io, path) catch {};
}

test "BE_GRANT_01a crash during execution: orphan publishes interrupted, not retried (T3)" {
    var ctx = IoCtx.init();
    ctx.io = ctx.threaded.io();
    const io = ctx.io;
    const dir = std.Io.Dir.cwd();

    const path_buf = tempPath("t3");
    const path = cstr(&path_buf);
    {
        // Commit lands; the process "crashes" before markPublished (no tombstone).
        var lg = try freshLedger(io, path_buf);
        try lg.commitConsumed(GID_A, FAR_FUTURE_MS, NOW_MS);
        lg.close();
    }
    // Restart: recover finds exactly one orphan.
    var lg = gl.GrantLedger.open(io, path) catch return error.TestUnexpectedResult;
    defer lg.close();
    var r = try lg.recover();
    try std.testing.expectEqual(@as(usize, 1), r.orphans.len);
    try std.testing.expectEqual(GID_A, r.orphans[0].grant_id);
    try std.testing.expect(lg.isConsumed(GID_A)); // consumed, so NOT retried
    // Caller publishes the interrupted Effect, then tombstones the orphan.
    try lg.markPublished(GID_A);
    // A second recovery is a no-op for this orphan (idempotent consumed set).
    r = try lg.recover();
    try std.testing.expectEqual(@as(usize, 0), r.orphans.len);
    dir.deleteFile(io, path) catch {};
}

test "BE_GRANT_01a at-least-once: un-tombstoned orphan re-emits on re-recover (fail-safe)" {
    var ctx = IoCtx.init();
    ctx.io = ctx.threaded.io();
    const io = ctx.io;
    const dir = std.Io.Dir.cwd();

    const path_buf = tempPath("t3b");
    const path = cstr(&path_buf);
    {
        var lg = try freshLedger(io, path_buf);
        try lg.commitConsumed(GID_B, FAR_FUTURE_MS, NOW_MS);
        lg.close();
    }
    var lg = gl.GrantLedger.open(io, path) catch return error.TestUnexpectedResult;
    defer lg.close();
    // Crash between recover and markPublished: re-recover re-emits the orphan.
    const r1 = try lg.recover();
    try std.testing.expectEqual(@as(usize, 1), r1.orphans.len);
    const r2 = try lg.recover();
    try std.testing.expectEqual(@as(usize, 1), r2.orphans.len);
    try std.testing.expectEqual(GID_B, r2.orphans[0].grant_id);
    // After tombstoning, it stops re-emitting.
    try lg.markPublished(GID_B);
    const r3 = try lg.recover();
    try std.testing.expectEqual(@as(usize, 0), r3.orphans.len);
    dir.deleteFile(io, path) catch {};
}

test "BE_REV_02 revocation persists across restart and is never pruned (T5)" {
    var ctx = IoCtx.init();
    ctx.io = ctx.threaded.io();
    const io = ctx.io;
    const dir = std.Io.Dir.cwd();

    const path_buf = tempPath("t5");
    const path = cstr(&path_buf);
    {
        var lg = try freshLedger(io, path_buf);
        try lg.commitRevocation(KEY_X, FAR_FUTURE_MS);
        try lg.commitRevocation(KEY_Y, FAR_FUTURE_MS);
        lg.close();
    }
    var lg = gl.GrantLedger.open(io, path) catch return error.TestUnexpectedResult;
    defer lg.close();
    const r = try lg.recover();
    try std.testing.expectEqual(@as(usize, 2), r.revoked_count);
    try std.testing.expect(lg.isRevoked(KEY_X));
    try std.testing.expect(lg.isRevoked(KEY_Y));
    // Even after pruneExpired, revocations survive (never expire within cert life).
    try lg.pruneExpired(NOW_MS);
    try std.testing.expect(lg.isRevoked(KEY_X));
    try std.testing.expect(lg.isRevoked(KEY_Y));
    dir.deleteFile(io, path) catch {};
}

test "BE_EXEC_01 pruneExpired drops expired consumed grants, keeps live ones (T6)" {
    var ctx = IoCtx.init();
    ctx.io = ctx.threaded.io();
    const io = ctx.io;
    const dir = std.Io.Dir.cwd();

    const path_buf = tempPath("t6");
    const path = cstr(&path_buf);
    {
        var lg = try freshLedger(io, path_buf);
        // Live at commit (window ends NOW_MS + 1000); the prune below runs at
        // NOW_MS + 2000, so A is expired by then. An already-expired grant can
        // never reach commitConsumed in the engine (check 10 precedes check 11),
        // so the realistic shape is: commit while live, expire, then prune.
        try lg.commitConsumed(GID_A, NOW_MS + 1000, NOW_MS);
        try lg.commitConsumed(GID_B, FAR_FUTURE_MS, NOW_MS); // live
        try lg.commitConsumed(GID_C, FAR_FUTURE_MS, NOW_MS); // live
        try lg.markPublished(GID_A);
        try lg.markPublished(GID_B);
        try lg.markPublished(GID_C);
        lg.close();
    }
    var lg = gl.GrantLedger.open(io, path) catch return error.TestUnexpectedResult;
    defer lg.close();
    _ = try lg.recover();
    try std.testing.expect(lg.isConsumed(GID_A)); // still here before prune
    try lg.pruneExpired(NOW_MS + 2000); // A's window has passed; B, C live
    try std.testing.expect(!lg.isConsumed(GID_A)); // expired grant dropped
    try std.testing.expect(lg.isConsumed(GID_B)); // live grant kept
    try std.testing.expect(lg.isConsumed(GID_C)); // live grant kept
    // Pruned log survives restart: reopen, the expired grant stays gone.
    lg.close();
    var lg2 = gl.GrantLedger.open(io, path) catch return error.TestUnexpectedResult;
    defer lg2.close();
    _ = try lg2.recover();
    try std.testing.expect(!lg2.isConsumed(GID_A));
    try std.testing.expect(lg2.isConsumed(GID_B));
    dir.deleteFile(io, path) catch {};
}

test "crash mid-write: a partial trailing record is discarded cleanly" {
    var ctx = IoCtx.init();
    ctx.io = ctx.threaded.io();
    const io = ctx.io;
    const dir = std.Io.Dir.cwd();

    const path_buf = tempPath("trunc");
    const path = cstr(&path_buf);
    {
        var lg = try freshLedger(io, path_buf);
        try lg.commitConsumed(GID_A, FAR_FUTURE_MS, NOW_MS);
        try lg.markPublished(GID_A);
        lg.close();
        // Append a truncated commit row by hand (a crash before the fsync landed
        // only a few bytes of the next record). 0x01 tag + 5 bytes < 25 needed.
        const f = dir.openFile(io, path, .{ .mode = .read_write }) catch return error.TestUnexpectedResult;
        defer f.close(io);
        const end = f.length(io) catch return error.TestUnexpectedResult;
        const partial = [_]u8{ 0x01, 0xDE, 0xAD, 0xBE, 0xEF, 0x40 };
        f.writePositionalAll(io, &partial, end) catch return error.TestUnexpectedResult;
    }
    var lg = gl.GrantLedger.open(io, path) catch return error.TestUnexpectedResult;
    defer lg.close();
    const r = try lg.recover(); // must NOT error and must NOT read the partial as a grant
    try std.testing.expectEqual(@as(usize, 1), r.consumed_count);
    try std.testing.expectEqual(@as(usize, 0), r.orphans.len);
    try std.testing.expect(lg.isConsumed(GID_A));
    dir.deleteFile(io, path) catch {};
}

test "BE_GRANT_01 idempotent commit: re-committing a spent grant is a no-op" {
    var ctx = IoCtx.init();
    ctx.io = ctx.threaded.io();
    const io = ctx.io;
    const dir = std.Io.Dir.cwd();

    const path_buf = tempPath("idem");
    const path = cstr(&path_buf);
    var lg = try freshLedger(io, path_buf);
    defer {
        lg.close();
        dir.deleteFile(io, path) catch {};
    }
    try lg.commitConsumed(GID_A, FAR_FUTURE_MS, NOW_MS);
    const before = lg.consumed_len;
    try lg.commitConsumed(GID_A, FAR_FUTURE_MS, NOW_MS); // duplicate
    try std.testing.expectEqual(before, lg.consumed_len); // not added twice
    try std.testing.expect(lg.isConsumed(GID_A));
}

// BE-GRANT-01 regression: pruneExpired MUST be crash-safe. The old scheme
// truncated the live file in place (setLength(0) -> write -> sync), so a crash
// between the truncate and the survivor write left an empty log and recover()
// rebuilt an empty consumed set, un-spending a still-valid grant. The fix is an
// atomic rewrite (write-temp -> fsync-temp -> rename): the live path always
// points at a complete log, never an empty one. This test exercises the fix's
// two new guarantees against a faithfully constructed crash-residue:
//   (a) a crash during the temp-write phase leaves the OLD live log intact, so
//       a live committed grant survives (the invariant);
//   (b) a stale .tmp left by an aborted prune is cleaned up on the next prune
//       and does not corrupt the live log.
test "BE_GRANT_01 crash during prune: atomic rewrite leaves the live log intact and cleans a stale temp" {
    var ctx = IoCtx.init();
    ctx.io = ctx.threaded.io();
    const io = ctx.io;
    const dir = std.Io.Dir.cwd();

    const path_buf = tempPath("crashprune");
    const path = cstr(&path_buf);
    // Build the temp path the engine uses (path ++ ".tmp").
    var tmp_buf: [128]u8 = undefined;
    @memcpy(tmp_buf[0..path.len], path);
    tmp_buf[path.len] = '.';
    tmp_buf[path.len + 1] = 't';
    tmp_buf[path.len + 2] = 'm';
    tmp_buf[path.len + 3] = 'p';
    const tmp_path = tmp_buf[0 .. path.len + 4];
    {
        // GID_A live (far future), GID_B expired (will be pruned), both published.
        var lg = try freshLedger(io, path_buf);
        try lg.commitConsumed(GID_A, FAR_FUTURE_MS, NOW_MS);
        try lg.commitConsumed(GID_B, NOW_MS + 1000, NOW_MS);
        try lg.markPublished(GID_A);
        try lg.markPublished(GID_B);
        lg.close();
        // Hand-construct the residue of a crash during the NEW scheme's
        // temp-write phase: the live log is still the OLD complete log (rename
        // never happened) and a stale partial .tmp sits beside it.
        const tf = dir.createFile(io, tmp_path, .{ .read = true, .truncate = true }) catch return error.TestUnexpectedResult;
        const garbage = [_]u8{ 0x01, 0xDE, 0xAD, 0xBE, 0xEF };
        tf.writePositionalAll(io, &garbage, 0) catch return error.TestUnexpectedResult;
        tf.sync(io) catch return error.TestUnexpectedResult;
        tf.close(io);
    }
    // Restart from the crash-residue: live log intact, stale temp present.
    var lg = gl.GrantLedger.open(io, path) catch return error.TestUnexpectedResult;
    defer lg.close();
    _ = try lg.recover();
    // Invariant (a): the live committed grant survived the interrupted prune.
    try std.testing.expect(lg.isConsumed(GID_A));
    // Run the prune the crash interrupted: it must drop the expired grant,
    // keep the live one, and clean the stale temp via atomic rename.
    try lg.pruneExpired(NOW_MS + 2000);
    try std.testing.expect(lg.isConsumed(GID_A)); // live grant kept
    try std.testing.expect(!lg.isConsumed(GID_B)); // expired grant dropped
    // The stale temp MUST be gone (rename reused it, or cleanup removed it).
    const still = dir.statFile(io, tmp_path, .{});
    try std.testing.expectError(error.FileNotFound, still);
    // Survives restart: the live grant is still consumed from the new log.
    lg.close();
    var lg2 = gl.GrantLedger.open(io, path) catch return error.TestUnexpectedResult;
    defer lg2.close();
    _ = try lg2.recover();
    try std.testing.expect(lg2.isConsumed(GID_A));
    try std.testing.expect(!lg2.isConsumed(GID_B));
    dir.deleteFile(io, path) catch {};
    dir.deleteFile(io, tmp_path) catch {};
}

test "MD3 flock: second open of the live log fails Locked; close releases it" {
    var ctx = IoCtx.init();
    ctx.io = ctx.threaded.io();
    const io = ctx.io;
    const dir = std.Io.Dir.cwd();

    const path_buf = tempPath("md3");
    const path = cstr(&path_buf);
    dir.deleteFile(io, path) catch {};
    var lg = try gl.GrantLedger.open(io, path);
    // flock is per open file description, so a second open of the same path,
    // even inside this same process, must fail fast (T9, BE-EXEC-01): the
    // alternative is two writers interleaving positional appends at stale
    // eofs and corrupting the log.
    try std.testing.expectError(error.Locked, gl.GrantLedger.open(io, path));
    // close releases the advisory lock: the log is openable again.
    lg.close();
    var lg2 = try gl.GrantLedger.open(io, path);
    lg2.close();
    dir.deleteFile(io, path) catch {};
}
