// intent.zig
//
// Pending-intent state machine (SPEC.md BE-GRANT-01a/04/06/06a/06b/09/10).
// Non-surface, state over parsed values (D-018): consumes the Intent/Grant/
// Refusal structs the parser produced. Memory-only by obligation (BE-GRANT-04):
// every PENDING collapses to EXPIRED on restart, because presence-of-state is
// the dead-man's switch and no field here is ever written to disk. A process
// death IS the transition.
//
// Lifecycle (SPEC section 8.2):
//
//   PENDING --verify(check 7)--> EXECUTING --(effect completes)--> dead slot
//     |                               |
//     | T_pending (06a)               | crash (01a): interrupted Effect is
//     v                               v   published from the DURABLE grant
//   EXPIRED (dead slot)               ledger (BE-GRANT-01), not this table
//     |
//   PENDING --matched Refusal (09)--> REJECTED (terminal, 10)
//
// Restart (04) collapses every PENDING/EXECUTING: the table is memory-only, so
// a fresh Table after a crash holds none of either. The lock a PENDING or
// EXECUTING entry holds on its resource_id is released by the state itself:
// EXPIRED and REJECTED entries are ignored by the exclusivity lookup, so the
// resource is free the moment the entry leaves PENDING/EXECUTING.
//
// All tables are fixed-capacity arrays; overflow returns error. No allocation.
// now_ms is injected by the caller so expiry is testable without waiting.
// Plain error set (not coverage.Branch): this is executor state, not an M9
// parser module. Tripwire: non-surface, excluded from the M11 line budget
// (SPEC.md BE-SURF-03 non-surface list, placed ahead of creation by D-052).

const std = @import("std");
const channel = @import("parser/channel.zig");

const Intent = channel.Intent;
const Refusal = channel.Refusal;
const LEN_INTENT_ID = channel.LEN_INTENT_ID;
const MAX_RESOURCE = channel.MAX_RESOURCE;

// ---------------------------------------------------------------------------
// Constants (SPEC section 8.2).
// ---------------------------------------------------------------------------

pub const T_PENDING_MS: u64 = 900_000; // BE-GRANT-06a default 900s
pub const MAX_PENDING: usize = 256; // caller-sized pool; overflow is a refusal

// ---------------------------------------------------------------------------
// Admission refusal reasons. One class per BE-GRANT rule.
// ---------------------------------------------------------------------------

pub const IntentError = error{
    TableFull, // pending table at MAX_PENDING
    DuplicateIntentId, // BE-GRANT-06b: intent_id already held in PENDING
    ResourceHeld, // BE-GRANT-06: resource_id already in PENDING or EXECUTING
    NotPending, // transition attempted on a non-PENDING entry
};

// ---------------------------------------------------------------------------
// Outcome of applying a Refusal (BE-GRANT-09).
// ---------------------------------------------------------------------------

pub const RefusalOutcome = enum {
    rejected, // PENDING -> REJECTED, lock released
    no_match, // no PENDING intent matched; dropped per BE-GRANT-09
};

// ---------------------------------------------------------------------------
// Lifecycle states (SPEC section 8.2).
// ---------------------------------------------------------------------------

pub const State = enum {
    pending, // admitted, awaiting a Grant
    executing, // a Grant verified, effect started (BE-GRANT-03a)
    expired, // T_pending fired or restart collapse (BE-GRANT-06a/04)
    rejected, // a matched Refusal (BE-GRANT-09), terminal (BE-GRANT-10)
};

// ---------------------------------------------------------------------------
// Entry. Fixed-size copies: the table owns its bytes and does not borrow the
// parse buffer, which is released after admission (D-018, ledger.zig idiom).
// ---------------------------------------------------------------------------

pub const Entry = struct {
    intent_id: [LEN_INTENT_ID]u8, // copy of Intent.intent_id
    resource_id: [MAX_RESOURCE]u8, // copy of the canonical resource_id (section 8.4)
    resource_len: usize, // active length within resource_id
    state: State,
    admitted_ms: u64, // caller's monotonic-ms at admission (BE-GRANT-06a)
};

// ---------------------------------------------------------------------------
// The table.
// ---------------------------------------------------------------------------

pub const Table = struct {
    entries: [MAX_PENDING]Entry = undefined,
    len: usize = 0,

    pub fn init() Table {
        return .{};
    }

    // BE-GRANT-04: a fresh table holds nothing. Constructing one after a crash
    // is the restart collapse: every prior PENDING/EXECUTING is gone.

    // admit (BE-GRANT-06b + BE-GRANT-06): insert an intent as PENDING. Refuses
    // a duplicate intent_id (06b) and a resource already held (06) before any
    // state mutates. The resource lock is taken here, under the same frame that
    // later moves the entry to EXECUTING (BE-GRANT-03a): matchForGrant returns
    // the index, beginExecuting consumes it, no re-lookup can race between them.
    pub fn admit(self: *Table, intent: Intent, now_ms: u64) IntentError!void {
        if (self.findPendingByIntentId(intent.intent_id) != null) return error.DuplicateIntentId;
        if (self.findHeldByResource(intent.resource_id) != null) return error.ResourceHeld;
        if (self.len == MAX_PENDING) return error.TableFull;

        const e = &self.entries[self.len];
        @memcpy(e.intent_id[0..], intent.intent_id[0..LEN_INTENT_ID]);
        const rlen = @min(intent.resource_id.len, MAX_RESOURCE);
        @memcpy(e.resource_id[0..rlen], intent.resource_id[0..rlen]);
        e.resource_len = rlen;
        e.state = .pending;
        e.admitted_ms = now_ms;
        self.len += 1;
    }

    // matchForGrant (BE-GRANT-03 check 7): the single PENDING intent a Grant
    // binds to, by intent_id. BE-GRANT-06b guarantees at most one. Returns the
    // index so verify.zig moves it to EXECUTING in the same call frame.
    pub fn matchForGrant(self: *const Table, intent_id: []const u8) ?usize {
        return self.findPendingByIntentId(intent_id);
    }

    // beginExecuting (BE-GRANT-03a): PENDING -> EXECUTING under the same lock
    // acquisition as admission. The caller holds the index from matchForGrant.
    pub fn beginExecuting(self: *Table, idx: usize) IntentError!void {
        if (idx >= self.len) return error.NotPending;
        if (self.entries[idx].state != .pending) return error.NotPending;
        self.entries[idx].state = .executing;
    }

    // applyRefusal (BE-GRANT-09/10): a verified Refusal whose intent_id names a
    // PENDING intent transitions it to REJECTED and releases the lock. A Refusal
    // matching no PENDING intent is dropped (no_match). REJECTED is terminal
    // (BE-GRANT-10): no transition out of it exists in this module. The sig and
    // approver-role checks run first in verify.zig (BE-GRANT-09 parse half); this
    // method receives a Refusal already cleared for the state transition.
    pub fn applyRefusal(self: *Table, refusal: Refusal) RefusalOutcome {
        const idx = self.findPendingByIntentId(refusal.intent_id) orelse return .no_match;
        self.entries[idx].state = .rejected;
        return .rejected;
    }

    // expireTimeouts (BE-GRANT-06a): sweep every PENDING intent older than
    // T_pending on the caller's monotonic clock to EXPIRED, releasing the lock.
    // Returns the count collapsed. EXECUTING entries are left untouched: their
    // lock releases when the effect completes or on crash (BE-GRANT-01a).
    pub fn expireTimeouts(self: *Table, now_ms: u64) usize {
        var collapsed: usize = 0;
        for (self.entries[0..self.len]) |*e| {
            if (e.state == .pending and now_ms >= e.admitted_ms + T_PENDING_MS) {
                e.state = .expired;
                collapsed += 1;
            }
        }
        return collapsed;
    }

    // --- internal lookups --------------------------------------------------
    //
    // Both ignore EXPIRED/REJECTED entries: a dead slot holds no lock, so the
    // resource is free and the intent_id reusable the moment an entry leaves
    // PENDING/EXECUTING.

    fn findPendingByIntentId(self: *const Table, intent_id: []const u8) ?usize {
        if (intent_id.len != LEN_INTENT_ID) return null;
        for (self.entries[0..self.len], 0..) |e, i| {
            if (e.state == .pending and std.mem.eql(u8, e.intent_id[0..], intent_id)) return i;
        }
        return null;
    }

    fn findHeldByResource(self: *const Table, resource_id: []const u8) ?usize {
        for (self.entries[0..self.len], 0..) |e, i| {
            if ((e.state == .pending or e.state == .executing) and
                e.resource_len == resource_id.len and
                std.mem.eql(u8, e.resource_id[0..e.resource_len], resource_id)) return i;
        }
        return null;
    }
};
