// sync.zig
//
// Backfill engine (SPEC.md section 6.4, BE-SYNC-01..05). Non-surface, state
// over parsed values (D-018): consumes the SyncRequest/SyncResponse parsed
// by parser/sync.zig and applies admission (BE-SYNC-01), response bounds
// (BE-SYNC-02), walk budget (BE-SYNC-03), rate budget (BE-SYNC-04), and
// verify-before-adopt (BE-SYNC-05). Reuses, never re-implements:
// verify.requireMember for the member + not-revoked clauses,
// verify.verifyEnvelope for the signature clause, and the caller's ledger
// for storage this module never touches.
//
// Scope note, stated rather than implied: BE-SYNC-05's sender-role
// (BE-ENV-03) and membership (BE-CHAN-03) clauses key off the sender's
// certificate, and SPEC declares no certificate vehicle for historical
// senders inside a SyncResponse. Those clauses ride the live path where the
// envelope's signer is the session peer; applying them to backfilled
// history is a SPEC edit owed before code (D-029), not code before SPEC.
//
// Fixed-capacity arrays; overflow returns error. No allocation.
// Tripwire: non-surface, excluded from the M11 line budget (SPEC.md
// BE-SURF-03 non-surface list, placed ahead of its code by D-054).

const std = @import("std");
const verify = @import("verify.zig");
const parser = @import("parser.zig");

const sync_wire = parser.sync;

// ---------------------------------------------------------------------------
// Constants (SPEC section 6.4, rate budgets declared by D-054).
// ---------------------------------------------------------------------------

pub const MAX_RESPONSE_ENVELOPES: usize = 64; // BE-SYNC-02 responder ceiling
pub const MAX_RESPONSE_BYTES: usize = 1 << 20; // BE-SYNC-02: 1 MiB per response
pub const RESPONSE_HEADER: usize = 34; // version u8 | channel_id [32] | count u8
pub const WALK_MAX_DEPTH: usize = 128; // BE-SYNC-03 default maximum queue depth
pub const WALK_MAX_TOTAL: usize = 4096; // BE-SYNC-03 default envelopes examined
pub const RATE_WINDOW_MS: u64 = 10_000; // BE-SYNC-04 sliding window (D-054)
pub const SERVE_BUDGET: usize = 8; // BE-SYNC-04: served requests per peer per window
pub const ISSUE_BUDGET: usize = 4; // BE-SYNC-04: issued requests per peer per window
pub const MAX_TRACKED_PEERS: usize = 64; // fixed rate table; full refuses (fail closed)

pub const SyncError = error{
    NoSession, // BE-SYNC-01: no established session (BE-TR-01)
    NotMember, // BE-SYNC-01: peer does not carry the member group
    Revoked, // BE-SYNC-01: peer is in the grow-only revoked set
    RateLimited, // BE-SYNC-04: per-peer budget exhausted inside the window
    WalkExhausted, // BE-SYNC-03: depth or total bound reached; stop, surface, no retry
    BadEnvelope, // BE-SYNC-05: parse or signature verification failed
    BufferTooSmall, // BE-SYNC-02: caller scratch below the empty-response floor
};

// ---------------------------------------------------------------------------
// BE-SYNC-01 admission: established session, member, not revoked.
// ---------------------------------------------------------------------------

pub fn admit(
    session_established: bool,
    sender_cert: parser.session.Cert,
    genesis: parser.channel.ControlGenesis,
    ctx: verify.ChannelContext,
) SyncError!void {
    if (!session_established) return SyncError.NoSession;
    verify.requireMember(sender_cert, genesis, ctx) catch |err| switch (err) {
        error.SubjectRevoked => return SyncError.Revoked,
        error.NotMember => return SyncError.NotMember,
        // requireMember's error set is ChannelError but its body returns only
        // these two; the remaining arms are unreachable by construction.
        else => return SyncError.NotMember,
    };
}

// ---------------------------------------------------------------------------
// BE-SYNC-04 rate budget: sliding windows, both directions, per peer.
// ---------------------------------------------------------------------------

// One sliding window: a fixed ring of event timestamps. Admission iff fewer
// than `budget` recorded events lie inside (now_ms - window_ms, now_ms]; a
// refusal consumes no budget. now_ms is caller-supplied unix milliseconds
// (house convention: verify.checkExpiry). 0 marks an empty slot, so an event
// at millisecond 0 is unrecordable: before the epoch there are no requests.
pub const RateWindow = struct {
    stamps: [SERVE_BUDGET]u64 = [_]u64{0} ** SERVE_BUDGET,
    budget: usize,
    next: usize = 0,

    pub fn init(budget: usize) RateWindow {
        return .{ .budget = budget };
    }

    pub fn admit(self: *RateWindow, window_ms: u64, now_ms: u64) bool {
        var inside: usize = 0;
        for (self.stamps[0..self.budget]) |s| {
            if (s != 0 and now_ms >= s and now_ms - s < window_ms) inside += 1;
        }
        if (inside >= self.budget) return false;
        self.stamps[self.next] = now_ms;
        self.next = (self.next + 1) % self.budget;
        return true;
    }
};

// Per-peer windows in a fixed table keyed by the peer's 32-byte signature
// key. A full table cannot track a new peer, and an untracked peer cannot be
// budgeted, so a full table refuses new peers: fail closed, the house
// ceiling convention (refuse the new, never degrade the existing).
pub const RateTable = struct {
    peers: [MAX_TRACKED_PEERS][32]u8 = undefined,
    windows: [MAX_TRACKED_PEERS]RateWindow = undefined,
    budget: usize,
    used: usize = 0,

    pub fn init(budget: usize) RateTable {
        return .{ .budget = budget };
    }

    pub fn admit(self: *RateTable, peer: [32]u8, window_ms: u64, now_ms: u64) bool {
        var i: usize = 0;
        while (i < self.used) : (i += 1) {
            if (std.mem.eql(u8, &self.peers[i], &peer)) return self.windows[i].admit(window_ms, now_ms);
        }
        if (self.used >= MAX_TRACKED_PEERS) return false;
        self.peers[self.used] = peer;
        self.windows[self.used] = RateWindow.init(self.budget);
        self.used += 1;
        return self.windows[self.used - 1].admit(window_ms, now_ms);
    }
};

// ---------------------------------------------------------------------------
// BE-SYNC-02 response builder: hard bounds, truncated flag, stateless.
// ---------------------------------------------------------------------------

pub const ServeItem = struct {
    hash: [32]u8, // the envelope's BLAKE2s hash (ledger identity)
    wire: []const u8, // serialized envelope bytes as served
};

pub const BuildResult = struct {
    count: usize,
    truncated: bool,
    bytes_written: usize,
};

fn inHaveSet(req: sync_wire.SyncRequest, hash: *const [32]u8) bool {
    var i: usize = 0;
    while (i < req.have_count) : (i += 1) {
        const off = i * sync_wire.LEN_CHANNEL_ID;
        if (std.mem.eql(u8, req.have_hashes[off .. off + sync_wire.LEN_CHANNEL_ID], hash)) return true;
    }
    return false;
}

fn unservedRemain(req: sync_wire.SyncRequest, candidates: []const ServeItem, from: usize) bool {
    var j: usize = from;
    while (j < candidates.len) : (j += 1) {
        if (!inHaveSet(req, &candidates[j].hash)) return true;
    }
    return false;
}

// Stateless responder (BE-SYNC-02): everything derives from the request and
// the candidate list; nothing is retained between responses. Candidates are
// walked in caller order; hashes present in the have set are skipped;
// serving stops at min(max_envelopes, 64) envelopes or at the 1 MiB response
// ceiling, whichever binds first, and `truncated` is set exactly when
// unserved candidates remain. Continuation is a NEW request with an updated
// have set. The caller scratch bounds the response exactly like the protocol
// ceiling (whichever binds first); only the 35-byte empty-response floor is
// an error. Frame: version | channel_id | count | (u32 len, bytes)* | truncated.
pub fn buildResponse(
    out: []u8,
    req: sync_wire.SyncRequest,
    candidates: []const ServeItem,
) SyncError!BuildResult {
    if (out.len < RESPONSE_HEADER + 1) return SyncError.BufferTooSmall;
    const cap = @min(@as(usize, req.max_envelopes), MAX_RESPONSE_ENVELOPES);
    out[0] = req.version;
    @memcpy(out[1..][0..32], req.channel_id[0..32]);
    var pos: usize = RESPONSE_HEADER;
    var count: usize = 0;
    var i: usize = 0;
    while (i < candidates.len and count < cap) : (i += 1) {
        const item = candidates[i];
        if (inHaveSet(req, &item.hash)) continue;
        const need = 4 + item.wire.len;
        if (pos + need + 1 > MAX_RESPONSE_BYTES or pos + need + 1 > out.len) break;
        std.mem.writeInt(u32, out[pos..][0..4], @intCast(item.wire.len), .big);
        @memcpy(out[pos + 4 ..][0..item.wire.len], item.wire);
        pos += need;
        count += 1;
    }
    const truncated = unservedRemain(req, candidates, i);
    out[33] = @intCast(count);
    out[pos] = @intFromBool(truncated);
    return .{ .count = count, .truncated = truncated, .bytes_written = pos + 1 };
}

// ---------------------------------------------------------------------------
// BE-SYNC-03 walk budget: explicit queue, never recursion (BE-DEP-02).
// ---------------------------------------------------------------------------

// Pending parent hashes in a fixed ring bounded by WALK_MAX_DEPTH; total
// envelopes examined bounded by WALK_MAX_TOTAL per sync operation. On
// exhaustion the walk stops and `exhausted` surfaces the unresolved-history
// condition to the caller; there is no retry path in this module. A fresh
// walk is a fresh SyncRequest from the requester, which re-enters through
// the BE-SYNC-04 budget.
pub const WalkQueue = struct {
    items: [WALK_MAX_DEPTH][32]u8 = undefined,
    head: usize = 0,
    depth: usize = 0,
    examined: usize = 0,
    exhausted: bool = false,

    pub fn push(self: *WalkQueue, hash: [32]u8) SyncError!void {
        if (self.exhausted) return SyncError.WalkExhausted;
        if (self.depth >= WALK_MAX_DEPTH) {
            self.exhausted = true;
            return SyncError.WalkExhausted;
        }
        self.items[(self.head + self.depth) % WALK_MAX_DEPTH] = hash;
        self.depth += 1;
    }

    pub fn pop(self: *WalkQueue) ?[32]u8 {
        if (self.exhausted or self.depth == 0) return null;
        const hash = self.items[self.head];
        self.head = (self.head + 1) % WALK_MAX_DEPTH;
        self.depth -= 1;
        return hash;
    }

    // Count one envelope examined. The 4097th examination exhausts the
    // budget: the walk stops mid-stride, surfaces, and does not retry.
    pub fn noteExamined(self: *WalkQueue) SyncError!void {
        if (self.exhausted) return SyncError.WalkExhausted;
        self.examined += 1;
        if (self.examined > WALK_MAX_TOTAL) {
            self.exhausted = true;
            return SyncError.WalkExhausted;
        }
    }
};

// ---------------------------------------------------------------------------
// BE-SYNC-05 verify before adopt.
// ---------------------------------------------------------------------------

// A backfilled envelope passes the same signature verification as one
// received live before it may enter the local ledger: parse, then
// verify.verifyEnvelope (BE-ENV-02). This function verifies only; the ledger
// insert is the caller's next step and never a side effect here, so nothing
// unverified can cross into storage through this path.
pub fn adoptVerify(wire: []const u8) SyncError!parser.channel.Envelope {
    const env = parser.channel.parseEnvelope(wire) catch return SyncError.BadEnvelope;
    verify.verifyEnvelope(env) catch return SyncError.BadEnvelope;
    return env;
}

// ---------------------------------------------------------------------------
// SyncEngine: the per-node sync state.
// ---------------------------------------------------------------------------

pub const SyncEngine = struct {
    serve: RateTable, // BE-SYNC-04 requests served, budget SERVE_BUDGET
    issue: RateTable, // BE-SYNC-04 requests issued, budget ISSUE_BUDGET
    walk: WalkQueue, // BE-SYNC-03 budget of the current sync operation

    pub fn init() SyncEngine {
        return .{
            .serve = RateTable.init(SERVE_BUDGET),
            .issue = RateTable.init(ISSUE_BUDGET),
            .walk = .{},
        };
    }

    // BE-SYNC-04 served side: refuse the request that exhausts the budget.
    pub fn serveAdmit(self: *SyncEngine, peer: [32]u8, now_ms: u64) SyncError!void {
        if (!self.serve.admit(peer, RATE_WINDOW_MS, now_ms)) return SyncError.RateLimited;
    }

    // BE-SYNC-04 issuing side: symmetric budget, smaller by declaration.
    pub fn issueAdmit(self: *SyncEngine, peer: [32]u8, now_ms: u64) SyncError!void {
        if (!self.issue.admit(peer, RATE_WINDOW_MS, now_ms)) return SyncError.RateLimited;
    }
};
