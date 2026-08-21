// grant_ledger.zig
//
// Durable consumed-grant and revocation ledger (SPEC.md BE-EXEC-01,
// BE-GRANT-01/01a, BE-GRANT-04, BE-REV-02; D-061). Non-surface, state over
// parsed values (D-018 lineage, placed ahead of code by D-061). This is the
// durable replacement for the D-059 in-memory consumed_registry stand-in in
// dispatch.zig: where that stand-in answered "is this grant_id spent?" from a
// process-local array that dies on restart, this unit answers it from an
// append log that survives restart, crash, and redeployment.
//
// Distinct from src/ledger.zig, which is the DAG hash ledger (BE-LEDGER-02/03):
// that unit stores envelope hashes for the member's history; this unit stores
// consumed grant_ids and revocations for the executor's single-shot gate.
//
// BE-DEP-01 forbids third-party dependencies, so there is no embedded
// database: the store is a hand-rolled append log over std.Io with an fsync
// barrier on every commit. The on-disk format is the two-phase scheme of
// D-061 ruling 1:
//
//   commit row    0x01 | [16] grant_id | u64 expiry_ms LE        (25 bytes)
//   published row 0x02 | [16] grant_id                            (17 bytes)
//   revoke row    0x03 | [32] sig_pubkey | u64 cert_expiry_ms LE (41 bytes)
//
// A commit row is appended and fsynced at check 11 of the grant verify
// routine (SPEC section 2: the only I/O step, last by obligation). A
// published tombstone is appended and fsynced once the Effect returns. A
// revoke row is appended and fsynced when a CA-signed revocation is recorded.
//
// I/O is positional (std.Io.File writePositionalAll / readPositionalAll): no
// shared seek cursor, so append = write at the tracked eof offset, then sync.
// The daemon is single-process (BE-EXEC-01), so there is no concurrency over
// the append + fsync sequence; eof is carried as a field instead of seeked.
//
// Recovery is a single forward scan (recover()): it rebuilds the consumed and
// revoked sets and collects orphan grants, a committed grant_id whose
// published tombstone never landed (a crash between the commit fsync and the
// effect publish). Per BE-GRANT-01a the caller turns each orphan into exactly
// one Effect with ok = false (cause interrupted) and then marks it published
// here. Recovery is idempotent for the consumed set: re-running it never
// re-adds a grant_id. Orphan emission is at-least-once until the caller
// tombstones each orphan with markPublished, which is fail-safe: the grant
// stays consumed either way (BE-GRANT-01), and a crash between recover and
// markPublished simply re-emits the orphan on the next restart.
//
// A partial trailing record (a crash mid-write, before the fsync) is
// discarded: such a grant was never durably committed, so treating it as
// absent is correct.
//
// Bounded resources (BE-EXEC-01): the in-memory consumed and revoked caches
// carry MAX_LIVE entries each. pruneExpired(now) compacts the log, dropping
// consumed grant_ids past their validity window (sound: SPEC section 2 check
// 10, expiry, runs before and independently of check 11, the ledger, so a
// pruned-and-now-expired grant is refused at check 10 on replay and cannot be
// un-spent). Revocations are never pruned (BE-REV-02: a revocation never
// expires within the certificate's life).

const std = @import("std");
const grant_trace = @import("grant_trace.zig");

// Declared bounds (SPEC.md BE-EXEC-01, D-061).
pub const GRANT_ID_LEN: usize = 16; // channel.LEN_GRANT_ID
pub const SIG_PUBKEY_LEN: usize = 32; // Ed25519 verifying key
pub const MAX_LIVE: usize = 1024; // bounded in-memory cache; pruneExpired bounds it

// On-disk record sizes (D-061 ruling 1).
const TAG_COMMIT: u8 = 0x01;
const TAG_PUBLISHED: u8 = 0x02;
const TAG_REVOKE: u8 = 0x03;
const TAG_FIRST_RECEIPT: u8 = 0x04; // F4: first-receipt time per grant_id
const COMMIT_LEN: usize = 1 + GRANT_ID_LEN + 8;
const PUBLISHED_LEN: usize = 1 + GRANT_ID_LEN;
const REVOKE_LEN: usize = 1 + SIG_PUBKEY_LEN + 8;
const FIRST_RECEIPT_LEN: usize = 1 + GRANT_ID_LEN + 8;

// MD3: exclusive advisory lock so a second daemon instance cannot interleave
// positional appends into one log (T9, BE-EXEC-01 single writer). std.c.flock
// does not exist in Zig 0.16, so the libc symbol is declared directly, the
// same pattern as src/listener.zig. The op bits are identical on macOS and
// Linux (BSD heritage).
const LOCK_EX: c_int = 2;
const LOCK_NB: c_int = 4;
const libc = struct {
    extern "c" fn flock(fd: c_int, operation: c_int) c_int;
};

pub const LedgerError = error{
    BadLog, // a committed record failed to parse outside the trailing partial
    ResourceExhausted, // live cache cap reached; pruneExpired did not free enough
    DiskError, // a file operation failed
    Locked, // MD3: another open file description holds the exclusive log lock
};

pub const OrphanGrant = struct {
    grant_id: [GRANT_ID_LEN]u8,
};

// F4: first-receipt entry. Maps grant_id to the time it was first received.
pub const FirstReceiptEntry = struct {
    grant_id: [GRANT_ID_LEN]u8,
    first_receipt_ms: u64,
};

// Recovery result (D-061). orphans borrows the ledger's internal orphan_buf
// and stays valid until the next mutating call (commitConsumed, markPublished,
// recover, pruneExpired, close). consumed_count and revoked_count are the
// rebuilt live-set sizes.
pub const Recovery = struct {
    orphans: []OrphanGrant,
    consumed_count: usize,
    revoked_count: usize,
};

pub const GrantLedger = struct {
    io: std.Io,
    file: std.Io.File,
    eof: u64,
    // Absolute path of the log, captured at open so pruneExpired can do an
    // atomic crash-safe rewrite via write-temp -> fsync -> rename (see below).
    path_buf: [128]u8 = [_]u8{0} ** 128,
    path_len: u8 = 0,
    consumed: [MAX_LIVE][GRANT_ID_LEN]u8 = undefined,
    consumed_len: usize = 0,
    revoked: [MAX_LIVE][SIG_PUBKEY_LEN]u8 = undefined,
    revoked_len: usize = 0,
    orphan_buf: [MAX_LIVE]OrphanGrant = undefined,
    orphan_len: usize = 0,
    // published witness set, rebuilt at recover so isConsumed answers from
    // memory and recover can find orphans in a single forward pass.
    published: [MAX_LIVE][GRANT_ID_LEN]u8 = undefined,
    published_len: usize = 0,
    // F4: first-receipt table. Maps grant_id -> first_receipt_ms. Persisted
    // durably so the T_recv expiry check (SPEC §8.2 check 10c) can actually
    // fire across restarts. Without this, first_receipt_ms = now_ms on every
    // delivery, making the T_recv anchor dead.
    first_receipt: [MAX_LIVE]FirstReceiptEntry = undefined,
    first_receipt_len: usize = 0,

    // open (D-061): create the log if absent, otherwise open read-write. Does
    // not scan; call recover() to rebuild the in-memory sets and collect
    // orphans. Single-process (BE-EXEC-01), so no concurrency concerns over
    // the positional append + sync sequence. eof is the current file length.
    pub fn open(io: std.Io, path: []const u8) LedgerError!GrantLedger {
        const dir = std.Io.Dir.cwd();
        const f = dir.createFile(io, path, .{ .read = true, .truncate = false }) catch return error.DiskError;
        // MD3: fail fast instead of silently sharing the log. flock is per
        // open file description, so even a second open() in the same process
        // collides; a distinct error, never silent takeover.
        if (libc.flock(f.handle, LOCK_EX | LOCK_NB) != 0) return error.Locked;
        const len = f.length(io) catch return error.DiskError;
        if (path.len > 128) return error.BadLog;
        var lg = GrantLedger{ .io = io, .file = f, .eof = len };
        @memcpy(lg.path_buf[0..path.len], path);
        lg.path_len = @intCast(path.len);
        return lg;
    }

    // MD3 read-only companion: opens the log WITHOUT the exclusive lock, for
    // audit views and test witnesses over the live file. Writer exclusivity
    // is preserved: the mutating ops (commitConsumed, markPublished,
    // commitRevocation, pruneExpired) write through the read-only handle and
    // fail with DiskError. Readers never block the daemon, and pruneExpired's
    // atomic rename means a concurrent reader sees either the old complete
    // log or the new one, never a torn write.
    pub fn openReadOnly(io: std.Io, path: []const u8) LedgerError!GrantLedger {
        const dir = std.Io.Dir.cwd();
        const f = dir.openFile(io, path, .{ .mode = .read_only }) catch return error.DiskError;
        const len = f.length(io) catch return error.DiskError;
        if (path.len > 128) return error.BadLog;
        var lg = GrantLedger{ .io = io, .file = f, .eof = len };
        @memcpy(lg.path_buf[0..path.len], path);
        lg.path_len = @intCast(path.len);
        return lg;
    }

    // recover (BE-GRANT-01a, D-061): single forward scan. Rebuilds consumed,
    // revoked, and published sets; orphans are consumed grants whose
    // published tombstone never landed. Does not tombstone orphans: the
    // caller publishes each interrupted Effect then markPublished, so a crash
    // between recover and markPublished re-emits the orphan (at-least-once,
    // fail-safe). A partial trailing record is discarded cleanly.
    pub fn recover(self: *GrantLedger) LedgerError!Recovery {
        // F2: heap-allocate buffer sized to actual file length. This avoids
        // both stack overflow (85KB worst-case) and silent truncation (25KB
        // fixed buffer). Recovery is a cold path (runs once at startup), so
        // heap use is acceptable. BE-WIRE-01's no-heap rule applies only to
        // the parser, not the ledger.
        const file_len = self.file.length(self.io) catch return error.DiskError;

        // Reset all live sets for a clean rebuild.
        self.consumed_len = 0;
        self.revoked_len = 0;
        self.published_len = 0;
        self.orphan_len = 0;
        self.first_receipt_len = 0;

        if (file_len > 0) {
            const allocator = std.heap.c_allocator;
            const buf = allocator.alloc(u8, @intCast(file_len)) catch return error.DiskError;
            defer allocator.free(buf);
            const n = self.file.readPositionalAll(self.io, buf, 0) catch return error.DiskError;

            var i: usize = 0;
            while (i < n) {
                const tag = buf[i];
                if (tag == TAG_COMMIT and i + COMMIT_LEN <= n) {
                    if (self.consumed_len >= MAX_LIVE) return error.ResourceExhausted;
                    @memcpy(&self.consumed[self.consumed_len], buf[i + 1 .. i + 1 + GRANT_ID_LEN]);
                    self.consumed_len += 1;
                    i += COMMIT_LEN;
                } else if (tag == TAG_PUBLISHED and i + PUBLISHED_LEN <= n) {
                    if (self.published_len >= MAX_LIVE) return error.ResourceExhausted;
                    @memcpy(&self.published[self.published_len], buf[i + 1 .. i + 1 + GRANT_ID_LEN]);
                    self.published_len += 1;
                    i += PUBLISHED_LEN;
                } else if (tag == TAG_REVOKE and i + REVOKE_LEN <= n) {
                    if (self.revoked_len >= MAX_LIVE) return error.ResourceExhausted;
                    @memcpy(&self.revoked[self.revoked_len], buf[i + 1 .. i + 1 + SIG_PUBKEY_LEN]);
                    self.revoked_len += 1;
                    i += REVOKE_LEN;
                } else if (tag == TAG_FIRST_RECEIPT and i + FIRST_RECEIPT_LEN <= n) {
                    // F4: rebuild first-receipt table from log.
                    if (self.first_receipt_len >= MAX_LIVE) return error.ResourceExhausted;
                    @memcpy(&self.first_receipt[self.first_receipt_len].grant_id, buf[i + 1 .. i + 1 + GRANT_ID_LEN]);
                    self.first_receipt[self.first_receipt_len].first_receipt_ms = std.mem.readInt(u64, buf[i + 1 + GRANT_ID_LEN ..][0..8], .little);
                    self.first_receipt_len += 1;
                    i += FIRST_RECEIPT_LEN;
                } else {
                    // Partial trailing record (crash mid-write before fsync): the
                    // grant was never durably committed. Discard and stop.
                    break;
                }
            }
        }

        // Orphans = consumed grants absent from the published witness set.
        for (0..self.consumed_len) |c| {
            const gid = self.consumed[c];
            var seen_pub = false;
            for (0..self.published_len) |p| {
                if (std.mem.eql(u8, &gid, &self.published[p])) {
                    seen_pub = true;
                    break;
                }
            }
            if (!seen_pub) {
                if (self.orphan_len >= MAX_LIVE) return error.ResourceExhausted;
                self.orphan_buf[self.orphan_len] = .{ .grant_id = gid };
                self.orphan_len += 1;
            }
        }

        return .{
            .orphans = self.orphan_buf[0..self.orphan_len],
            .consumed_count = self.consumed_len,
            .revoked_count = self.revoked_len,
        };
    }

    // commitConsumed (BE-GRANT-01, D-061): append a commit row and fsync
    // BEFORE returning. This is the check-11 durable commit: the effect MUST
    // NOT fire until this returns successfully. pruneExpired is run first to
    // keep the live cache bounded; if the cache is still full the commit
    // fails and the caller MUST refuse the effect (fail-safe: an uncommitted
    // grant is not spent, so the effect does not run).
    pub fn commitConsumed(self: *GrantLedger, grant_id: [GRANT_ID_LEN]u8, expiry_ms: u64, now_ms: u64) LedgerError!void {
        try self.pruneExpired(now_ms);
        if (self.consumedIndex(grant_id) != null) return; // already committed: idempotent
        if (self.consumed_len >= MAX_LIVE) return error.ResourceExhausted;
        var row: [COMMIT_LEN]u8 = undefined;
        row[0] = TAG_COMMIT;
        @memcpy(row[1 .. 1 + GRANT_ID_LEN], &grant_id);
        std.mem.writeInt(u64, row[1 + GRANT_ID_LEN ..][0..8], expiry_ms, .little);
        try self.appendSync(&row);
        if (grant_trace.enabled) grant_trace.emit(.commit_consumed_11, grant_trace.NO_PC, &grant_id, now_ms);
        @memcpy(&self.consumed[self.consumed_len], &grant_id);
        self.consumed_len += 1;
    }

    // markPublished (BE-GRANT-01a, D-061): append the published tombstone and
    // fsync. Called by the caller after the effect returns (normal path) or
    // after publishing the interrupted Effect for an orphan (recovery path).
    // Idempotent: a second call for an already-published grant is a no-op.
    pub fn markPublished(self: *GrantLedger, grant_id: [GRANT_ID_LEN]u8) LedgerError!void {
        if (self.publishedIndex(grant_id) != null) return;
        if (self.published_len >= MAX_LIVE) return error.ResourceExhausted;
        var row: [PUBLISHED_LEN]u8 = undefined;
        row[0] = TAG_PUBLISHED;
        @memcpy(row[1 .. 1 + GRANT_ID_LEN], &grant_id);
        try self.appendSync(&row);
        if (grant_trace.enabled) grant_trace.emit(.mark_published, grant_trace.NO_PC, &grant_id, 0);
        @memcpy(&self.published[self.published_len], &grant_id);
        self.published_len += 1;
    }

    // isConsumed (BE-GRANT-01): the single-shot replay gate. Answers from the
    // in-memory set, which is authoritative for the process lifetime because
    // the daemon is single-process (BE-EXEC-01) and every commit updates both
    // the log and the set atomically under the append+fsync+memwrite sequence.
    pub fn isConsumed(self: *GrantLedger, grant_id: [GRANT_ID_LEN]u8) bool {
        return self.consumedIndex(grant_id) != null;
    }

    // isPublished (BE-GRANT-01, post-effect witness): a consumed grant whose
    // markPublished tombstone landed. The post-hoc auditor (adversarial_audit,
    // SPEC section 11.5 R2) distinguishes an executed effect (consumed AND
    // published) from an interrupted one (consumed, not published) with this;
    // the in-flight seam (dispatch) uses it to detect orphan leakage.
    pub fn isPublished(self: *GrantLedger, grant_id: [GRANT_ID_LEN]u8) bool {
        return self.publishedIndex(grant_id) != null;
    }

    // commitRevocation (BE-REV-02): record a CA-signed revocation durably. A
    // revoked key stays revoked for the certificate's remaining life; revoke
    // rows are never pruned.
    pub fn commitRevocation(self: *GrantLedger, sig_pubkey: [SIG_PUBKEY_LEN]u8, cert_expiry_ms: u64) LedgerError!void {
        if (self.revokedIndex(sig_pubkey) != null) return; // idempotent
        if (self.revoked_len >= MAX_LIVE) return error.ResourceExhausted;
        var row: [REVOKE_LEN]u8 = undefined;
        row[0] = TAG_REVOKE;
        @memcpy(row[1 .. 1 + SIG_PUBKEY_LEN], &sig_pubkey);
        std.mem.writeInt(u64, row[1 + SIG_PUBKEY_LEN ..][0..8], cert_expiry_ms, .little);
        try self.appendSync(&row);
        @memcpy(&self.revoked[self.revoked_len], &sig_pubkey);
        self.revoked_len += 1;
    }

    // isRevoked (BE-REV-02): answers from the in-memory set rebuilt at recover.
    pub fn isRevoked(self: *GrantLedger, sig_pubkey: [SIG_PUBKEY_LEN]u8) bool {
        return self.revokedIndex(sig_pubkey) != null;
    }

    // F4: recordFirstReceipt. Persist the first time a grant_id is received.
    // Idempotent: if the grant_id already has a first-receipt entry, this is
    // a no-op. The first-receipt time is used by the T_recv expiry check
    // (SPEC §8.2 check 10c) to detect grants that have been in flight too long.
    pub fn recordFirstReceipt(self: *GrantLedger, grant_id: [GRANT_ID_LEN]u8, now_ms: u64) LedgerError!void {
        // Idempotent: if already recorded, skip.
        if (self.firstReceiptIndex(grant_id) != null) return;
        if (self.first_receipt_len >= MAX_LIVE) return error.ResourceExhausted;
        // Append to log durably.
        var row: [FIRST_RECEIPT_LEN]u8 = undefined;
        row[0] = TAG_FIRST_RECEIPT;
        @memcpy(row[1 .. 1 + GRANT_ID_LEN], &grant_id);
        std.mem.writeInt(u64, row[1 + GRANT_ID_LEN ..][0..8], now_ms, .little);
        try self.appendSync(&row);
        // Update in-memory table.
        @memcpy(&self.first_receipt[self.first_receipt_len].grant_id, &grant_id);
        self.first_receipt[self.first_receipt_len].first_receipt_ms = now_ms;
        self.first_receipt_len += 1;
    }

    // F4: getFirstReceipt. Returns the first-receipt time for a grant_id, or
    // null if not recorded. Used by dispatch to populate GrantContext.first_receipt_ms.
    pub fn getFirstReceipt(self: *const GrantLedger, grant_id: [GRANT_ID_LEN]u8) ?u64 {
        if (self.firstReceiptIndex(grant_id)) |idx| {
            return self.first_receipt[idx].first_receipt_ms;
        }
        return null;
    }

    fn firstReceiptIndex(self: *const GrantLedger, grant_id: [GRANT_ID_LEN]u8) ?usize {
        var i: usize = 0;
        while (i < self.first_receipt_len) : (i += 1) {
            if (std.mem.eql(u8, &self.first_receipt[i].grant_id, &grant_id)) return i;
        }
        return null;
    }

    // pruneExpired (BE-EXEC-01, D-061 ruling 4): compact the log, dropping
    // consumed grant_ids past their validity window. Sound because the expiry
    // check (section 2 check 10) runs before and independently of the ledger
    // check (check 11): a pruned grant replayed after its window is refused at
    // check 10 and never reaches the ledger. Revocations are never dropped.
    pub fn pruneExpired(self: *GrantLedger, now_ms: u64) LedgerError!void {
        // F2: heap-allocate buffer sized to actual file length.
        const file_len = self.file.length(self.io) catch return error.DiskError;
        if (file_len == 0) return; // nothing to prune
        const allocator = std.heap.c_allocator;
        const buf = allocator.alloc(u8, @intCast(file_len)) catch return error.DiskError;
        defer allocator.free(buf);
        const n = self.file.readPositionalAll(self.io, buf, 0) catch return error.DiskError;

        var live_consumed: [MAX_LIVE][GRANT_ID_LEN]u8 = undefined;
        var live_len: usize = 0;
        var i: usize = 0;
        // First pass: collect live consumed ids (within validity).
        while (i < n) {
            const tag = buf[i];
            if (tag == TAG_COMMIT and i + COMMIT_LEN <= n) {
                const gid = buf[i + 1 .. i + 1 + GRANT_ID_LEN];
                const expiry = std.mem.readInt(u64, buf[i + 1 + GRANT_ID_LEN ..][0..8], .little);
                if (expiry >= now_ms) {
                    if (live_len >= MAX_LIVE) return error.ResourceExhausted;
                    @memcpy(&live_consumed[live_len], gid);
                    live_len += 1;
                }
                i += COMMIT_LEN;
            } else if (tag == TAG_PUBLISHED and i + PUBLISHED_LEN <= n) {
                i += PUBLISHED_LEN;
            } else if (tag == TAG_REVOKE and i + REVOKE_LEN <= n) {
                i += REVOKE_LEN;
            } else if (tag == TAG_FIRST_RECEIPT and i + FIRST_RECEIPT_LEN <= n) {
                // F4: skip first-receipt rows in first pass (like published/revoke).
                i += FIRST_RECEIPT_LEN;
            } else {
                break;
            }
        }
        // Second pass: emit survivor rows in original order. A commit survives
        // iff it is in live_consumed; published rows survive iff their grant is
        // live; revoke rows always survive.
        const out = allocator.alloc(u8, @intCast(file_len)) catch return error.DiskError;
        defer allocator.free(out);
        var out_len: usize = 0;
        i = 0;
        while (i < n) {
            const tag = buf[i];
            if (tag == TAG_COMMIT and i + COMMIT_LEN <= n) {
                if (containsGrant(&live_consumed, live_len, buf[i + 1 .. i + 1 + GRANT_ID_LEN])) {
                    @memcpy(out[out_len..][0..COMMIT_LEN], buf[i .. i + COMMIT_LEN]);
                    out_len += COMMIT_LEN;
                }
                i += COMMIT_LEN;
            } else if (tag == TAG_PUBLISHED and i + PUBLISHED_LEN <= n) {
                if (containsGrant(&live_consumed, live_len, buf[i + 1 .. i + 1 + GRANT_ID_LEN])) {
                    @memcpy(out[out_len..][0..PUBLISHED_LEN], buf[i .. i + PUBLISHED_LEN]);
                    out_len += PUBLISHED_LEN;
                }
                i += PUBLISHED_LEN;
            } else if (tag == TAG_REVOKE and i + REVOKE_LEN <= n) {
                @memcpy(out[out_len..][0..REVOKE_LEN], buf[i .. i + REVOKE_LEN]);
                out_len += REVOKE_LEN;
                i += REVOKE_LEN;
            } else if (tag == TAG_FIRST_RECEIPT and i + FIRST_RECEIPT_LEN <= n) {
                // F4: first-receipt rows survive iff their grant is still live.
                if (containsGrant(&live_consumed, live_len, buf[i + 1 .. i + 1 + GRANT_ID_LEN])) {
                    @memcpy(out[out_len..][0..FIRST_RECEIPT_LEN], buf[i .. i + FIRST_RECEIPT_LEN]);
                    out_len += FIRST_RECEIPT_LEN;
                }
                i += FIRST_RECEIPT_LEN;
            } else {
                break;
            }
        }
        // Crash-safe atomic rewrite (BE-GRANT-01): the OLD scheme was
        // setLength(0) -> write -> sync on the live file, which is NOT atomic.
        // A crash between setLength(0) and the survivor write left an empty log,
        // so recover() rebuilt an empty consumed set and a still-valid grant was
        // un-spent -> the effect re-executed. The fix is write-temp -> fsync-temp
        // -> atomic rename(temp, live): POSIX rename is atomic within a directory,
        // so the live path always points at either the previous complete log or
        // the new complete log, never an empty one. A crash during temp-write
        // leaves the old log untouched; a crash during rename leaves old or new.
        const live_path = self.path_buf[0..self.path_len];
        if (self.path_len + 4 > 128) return error.BadLog; // ".tmp" suffix must fit
        var tmp_buf: [128]u8 = undefined;
        @memcpy(tmp_buf[0..self.path_len], live_path);
        tmp_buf[self.path_len] = '.';
        tmp_buf[self.path_len + 1] = 't';
        tmp_buf[self.path_len + 2] = 'm';
        tmp_buf[self.path_len + 3] = 'p';
        const tmp_path = tmp_buf[0 .. self.path_len + 4];
        const dir = std.Io.Dir.cwd();
        // F3: open the parent directory (not cwd) so we can fsync it after rename.
        // Dir.cwd() returns a special handle that cannot be fsynced on some systems.
        const last_slash = std.mem.lastIndexOfScalar(u8, live_path, '/') orelse {
            // No slash in path: file is in cwd, use "." as parent
            return error.DiskError; // TODO: handle cwd-relative paths
        };
        const parent_path = live_path[0..last_slash];
        var parent_dir = dir.openDir(self.io, parent_path, .{}) catch return error.DiskError;
        defer parent_dir.close(self.io);
        // Clean any stale temp from a prior aborted prune, then create fresh.
        dir.deleteFile(self.io, tmp_path) catch {};
        const tf = dir.createFile(self.io, tmp_path, .{ .read = true, .truncate = true }) catch return error.DiskError;
        if (out_len > 0) {
            tf.writePositionalAll(self.io, out[0..out_len], 0) catch {
                tf.close(self.io);
                return error.DiskError;
            };
        }
        // D-063 phase 1 of 4: survivor rows are durably in the temp file.
        if (grant_trace.enabled) grant_trace.emit(.prune_temp_written, grant_trace.NO_PC, live_path, now_ms);
        tf.sync(self.io) catch {
            tf.close(self.io);
            return error.DiskError;
        };
        // D-063 phase 2 of 4: temp file fsynced, safe to swap.
        if (grant_trace.enabled) grant_trace.emit(.prune_temp_synced, grant_trace.NO_PC, live_path, now_ms);
        tf.close(self.io);
        // Atomic swap: rename temp -> live. The old inode is unlinked; close
        // the stale handle and reopen the live path.
        dir.rename(tmp_path, dir, live_path, self.io) catch return error.DiskError;
        // F3: fsync the parent directory to make the rename durable. POSIX
        // only guarantees the rename is durable after the directory is synced;
        // without this, a power loss can roll back to the old inode.
        // Uses std.c.fsync (not fdatasync) because macOS returns EINVAL for
        // fdatasync on directory fds.
        if (std.c.fsync(parent_dir.handle) != 0) return error.DiskError;
        // D-063 phase 3 of 4: rename landed, live path points at the new log.
        if (grant_trace.enabled) grant_trace.emit(.prune_renamed, grant_trace.NO_PC, live_path, now_ms);
        self.file.close(self.io);
        self.file = dir.openFile(self.io, live_path, .{ .mode = .read_write }) catch return error.DiskError;
        // MD3: the close above released the lock with the old open file
        // description; re-acquire on the new handle. A second instance that
        // grabbed the live path inside the prune window surfaces Locked here.
        if (libc.flock(self.file.handle, LOCK_EX | LOCK_NB) != 0) return error.Locked;
        self.eof = out_len;
        self.file.sync(self.io) catch return error.DiskError;
        // D-063 phase 4 of 4: live handle reopened and directory state durable.
        if (grant_trace.enabled) grant_trace.emit(.prune_reopened, grant_trace.NO_PC, live_path, now_ms);
        // Rebuild the in-memory consumed set from survivors.
        self.consumed_len = live_len;
        @memcpy(self.consumed[0..live_len], live_consumed[0..live_len]);
    }

    pub fn close(self: *GrantLedger) void {
        self.file.close(self.io);
    }

    fn appendSync(self: *GrantLedger, row: []const u8) LedgerError!void {
        self.file.writePositionalAll(self.io, row, self.eof) catch return error.DiskError;
        self.file.sync(self.io) catch return error.DiskError;
        self.eof += row.len;
    }

    fn consumedIndex(self: *GrantLedger, grant_id: [GRANT_ID_LEN]u8) ?usize {
        for (0..self.consumed_len) |c| {
            if (std.mem.eql(u8, &self.consumed[c], &grant_id)) return c;
        }
        return null;
    }

    fn publishedIndex(self: *GrantLedger, grant_id: [GRANT_ID_LEN]u8) ?usize {
        for (0..self.published_len) |p| {
            if (std.mem.eql(u8, &self.published[p], &grant_id)) return p;
        }
        return null;
    }

    fn revokedIndex(self: *GrantLedger, sig_pubkey: [SIG_PUBKEY_LEN]u8) ?usize {
        for (0..self.revoked_len) |r| {
            if (std.mem.eql(u8, &self.revoked[r], &sig_pubkey)) return r;
        }
        return null;
    }
};

fn containsGrant(set: *[MAX_LIVE][GRANT_ID_LEN]u8, len: usize, gid: []const u8) bool {
    for (0..len) |i| {
        if (std.mem.eql(u8, &set[i], gid)) return true;
    }
    return false;
}
