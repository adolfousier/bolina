// intent_test.zig
//
// Foundational tests for the pending-intent state machine (src/intent.zig).
// Six markers bound here, literal values only (D-027): BE-GRANT-04/06/06a/06b/
// 09/10. BE-GRANT-01a (interrupted-Effect publication) is an executor
// integration over the durable grant ledger and lands with the verify.zig
// refusal hook. matchForGrant/beginExecuting support BE-GRANT-03 check 7 and
// BE-GRANT-03a but do not bind them: that routine lives in verify.zig.
//
// now_ms is injected, so the T_pending sweep is exercised without waiting.

const std = @import("std");
const intent = @import("intent.zig");
const channel = @import("parser/channel.zig");

const Intent = channel.Intent;
const Refusal = channel.Refusal;

// 16-byte intent_ids (static, never dangle; admit copies them into the entry).
const id_a = [_]u8{0xAA} ** 16;
const id_b = [_]u8{0xBB} ** 16;
const id_c = [_]u8{0xCC} ** 16;

fn intentWith(id: []const u8, resource: []const u8) Intent {
    return .{ .intent_id = id, .resource_id = resource, .action = "", .rationale = "" };
}

fn refusalWith(intent_id: []const u8) Refusal {
    return .{ .intent_id = intent_id, .note = "", .tbs = "", .sig = "", .wire = "" };
}

// ---------------------------------------------------------------------------
// BE-GRANT-04: fail-closed on restart. A fresh table holds nothing.
// ---------------------------------------------------------------------------

test "BE_GRANT_04 fresh table holds no pending state (restart collapse)" {
    var t = intent.Table.init();
    try std.testing.expectEqual(@as(usize, 0), t.len);
    try t.admit(intentWith(&id_a, "res-1"), 0);
    try std.testing.expectEqual(@as(usize, 1), t.len);

    // A restart is constructing a new table: every prior PENDING is gone.
    const restarted = intent.Table.init();
    try std.testing.expectEqual(@as(usize, 0), restarted.len);
}

// ---------------------------------------------------------------------------
// BE-GRANT-06b: intent_id uniqueness at admission.
// ---------------------------------------------------------------------------

test "BE_GRANT_06b duplicate intent_id refused at admission" {
    var t = intent.Table.init();
    try t.admit(intentWith(&id_a, "res-1"), 0);
    try std.testing.expectError(error.DuplicateIntentId, t.admit(intentWith(&id_a, "res-2"), 0));
}

// ---------------------------------------------------------------------------
// BE-GRANT-06: resource exclusivity. Reject a second holder, do not queue.
// ---------------------------------------------------------------------------

test "BE_GRANT_06 second intent on a held resource refused" {
    var t = intent.Table.init();
    try t.admit(intentWith(&id_a, "res-1"), 0);
    // Same resource_id, different intent_id: still refused.
    try std.testing.expectError(error.ResourceHeld, t.admit(intentWith(&id_b, "res-1"), 0));
    // A second, distinct resource admits fine.
    try t.admit(intentWith(&id_b, "res-2"), 0);
    try std.testing.expectEqual(@as(usize, 2), t.len);
}

// ---------------------------------------------------------------------------
// BE-GRANT-06a: pending timeout. PENDING -> EXPIRED after T_pending.
// ---------------------------------------------------------------------------

test "BE_GRANT_06a T_pending timeout expires pending and releases the lock" {
    var t = intent.Table.init();
    try t.admit(intentWith(&id_a, "res-1"), 0);

    // Just under the timeout: nothing collapses.
    try std.testing.expectEqual(@as(usize, 0), t.expireTimeouts(intent.T_PENDING_MS - 1));
    try std.testing.expectEqual(intent.State.pending, t.entries[0].state);

    // At the timeout (non-strict: now >= admitted + T): collapses to EXPIRED.
    // MD4: the sweep reclaims the dead slot itself, so EXPIRED is observable
    // as absence (len drops to zero), not as a corpse at entries[0].
    try std.testing.expectEqual(@as(usize, 1), t.expireTimeouts(intent.T_PENDING_MS));
    try std.testing.expectEqual(@as(usize, 0), t.len);

    // The lock is released: the resource can be re-admitted.
    try t.admit(intentWith(&id_b, "res-1"), 0);
}

// ---------------------------------------------------------------------------
// BE-GRANT-09: refusal semantics. A matched Refusal rejects; a non-match drops.
// ---------------------------------------------------------------------------

test "BE_GRANT_09 matched refusal rejects a pending intent" {
    var t = intent.Table.init();
    try t.admit(intentWith(&id_a, "res-1"), 0);

    try std.testing.expectEqual(intent.RefusalOutcome.rejected, t.applyRefusal(refusalWith(&id_a)));
    // MD4: terminal REJECTED leaves the table entirely; the observable
    // rejection is the reclaimed slot, not a corpse at entries[0].
    try std.testing.expectEqual(@as(usize, 0), t.len);

    // Lock released: the resource is free immediately, without T_pending.
    try t.admit(intentWith(&id_b, "res-1"), 0);
}

test "BE_GRANT_09 refusal matching no pending intent is dropped" {
    var t = intent.Table.init();
    try t.admit(intentWith(&id_a, "res-1"), 0);

    // No intent with id_b is pending: the Refusal is dropped, not buffered.
    try std.testing.expectEqual(intent.RefusalOutcome.no_match, t.applyRefusal(refusalWith(&id_b)));
    try std.testing.expectEqual(intent.State.pending, t.entries[0].state);
}

// ---------------------------------------------------------------------------
// BE-GRANT-10: REJECTED is terminal. No transition out of it exists.
// ---------------------------------------------------------------------------

test "BE_GRANT_10 rejected intent cannot re-enter executing" {
    var t = intent.Table.init();
    try t.admit(intentWith(&id_a, "res-1"), 0);
    _ = t.applyRefusal(refusalWith(&id_a)); // -> REJECTED

    // No pending intent matches id_a anymore: the only edge to EXECUTING is gone.
    try std.testing.expectEqual(@as(?usize, null), t.matchForGrant(&id_a));
}

// ---------------------------------------------------------------------------
// matchForGrant / beginExecuting: support BE-GRANT-03 check 7 and BE-GRANT-03a.
// The binding for those markers lives in verify.zig; these exercise the hooks.
// ---------------------------------------------------------------------------

test "matchForGrant returns the one pending intent, beginExecuting transitions it" {
    var t = intent.Table.init();
    try t.admit(intentWith(&id_a, "res-1"), 0);

    const idx = t.matchForGrant(&id_a) orelse return error.TestUnexpected;
    try t.beginExecuting(idx);
    try std.testing.expectEqual(intent.State.executing, t.entries[idx].state);

    // An unknown intent_id matches nothing.
    try std.testing.expectEqual(@as(?usize, null), t.matchForGrant(&id_b));
}

test "beginExecuting on a non-pending entry is refused" {
    var t = intent.Table.init();
    try t.admit(intentWith(&id_a, "res-1"), 0);
    const idx = t.matchForGrant(&id_a).?;
    try t.beginExecuting(idx); // pending -> executing
    // Already executing: not pending, so a second transition is refused.
    try std.testing.expectError(error.NotPending, t.beginExecuting(idx));
}

// ---------------------------------------------------------------------------
// MD4: dead slots free capacity, not just locks.
// ---------------------------------------------------------------------------

test "MD4 churn: expired generations never exhaust the table" {
    var t = intent.Table.init();
    // Three full generations of admissions through the expiry sweep. Before
    // compaction the corpses piled up: the MAX_PENDING+1st admit hit
    // TableFull forever, a capacity leak dressed as a bound. Now every sweep
    // reclaims the dead slots, so churn never exhausts the table.
    var gen: usize = 0;
    while (gen < 3) : (gen += 1) {
        var i: usize = 0;
        while (i < intent.MAX_PENDING) : (i += 1) {
            const seq: u128 = @intCast(gen * intent.MAX_PENDING + i + 1);
            var id: [16]u8 = undefined;
            std.mem.writeInt(u128, &id, seq, .little);
            var rbuf: [24]u8 = undefined;
            const r = std.fmt.bufPrint(&rbuf, "res-{d}", .{seq}) catch unreachable;
            try t.admit(intentWith(&id, r), 0);
        }
        try std.testing.expectEqual(intent.MAX_PENDING, t.len);
        _ = t.expireTimeouts(intent.T_PENDING_MS);
        try std.testing.expectEqual(@as(usize, 0), t.len);
    }
}
