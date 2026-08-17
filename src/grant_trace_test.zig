// grant_trace_test.zig
//
// bolina.grant-trace.v1 wiring tests (ZIG-TLA-CONFORMANCE-BRIEF section 6).
// The happy path asserts the EXACT ordered event sequence a conformance
// projector will consume; the negative controls assert the two stutter
// cases the brief names: a check-11 refusal emits neither
// commit_consumed_11 nor effect_start, and a resource conflict emits
// reject_resource_conflict. Event tests run only under -Dtrace=true
// (SkipZigTest otherwise): the default build keeps the instrumentation
// compiled out, which the first test asserts from the other side.

const std = @import("std");
const grant_trace = @import("grant_trace.zig");
const dispatch_mod = @import("dispatch.zig");
const resolver_mod = @import("resolver.zig");
const session = @import("parser/session.zig");
const channel = @import("parser/channel.zig");
const verify = @import("verify.zig");
const grant_ledger = @import("grant_ledger.zig");
const intent_mod = @import("intent.zig");
const cth = @import("cert_test_helpers.zig");
const dt = @import("dispatch_test.zig");

test "trace v1: default build keeps the instrumentation silent" {
    if (grant_trace.enabled) return error.SkipZigTest;
    grant_trace.emit(.begin_verify, grant_trace.NO_PC, "unobserved", 1);
    try std.testing.expectEqual(@as(usize, 0), grant_trace.snapshot().len);
    try std.testing.expectEqual(@as(usize, 0), grant_trace.overflow());
}

test "trace v1: happy path emits the full ordered prefix" {
    if (!grant_trace.enabled) return error.SkipZigTest;
    const sl = try dt.initSeamLedger("tracehappy");
    defer dt.closeSeamLedger(sl);
    grant_trace.reset();
    dt.effect_count = 0;
    dt.ensureGrantCerts();
    const executor_pub = cth.pubkeyOf(dt.EXECUTOR_PREFIX);
    var res = resolver_mod.Resolver.init(&executor_pub);
    var canonical_a_buf: [64]u8 = undefined;
    const canonical_a = dt.executorCanonical(&canonical_a_buf, "logs/deploy.log");
    try res.add(canonical_a);
    var d = dispatch_mod.Dispatch.init(res, &executor_pub, std.mem.zeroes(session.Cert), cth.trustedSet());
    const hooks = dispatch_mod.Hooks{ .execute_effect = &dt.testEffect, .cert_for_sender = &dt.grantPathCertHook, .on_rejected = &dt.noopRejected };
    const len_a = dt.buildIntentBodyId(&dt.intent_body_a, &dt.G_INTENT_ID, canonical_a, dt.ACTION);
    var a_sender: [32]u8 = undefined;
    var a_sig: [64]u8 = undefined;
    var a_tbs: [64]u8 = undefined;
    try std.testing.expectEqual(dispatch_mod.Outcome.intent_admitted, try d.dispatch(dt.agentEnvelopeSigned(dt.intent_body_a[0..len_a], &a_sender, &a_sig, &a_tbs), hooks, dt.GRANT_NOW_MS));
    try std.testing.expectEqual(dispatch_mod.Outcome.grant_executed, try d.dispatch(dt.grantEnvelopeSigned(dt.buildGrantWire(dt.G_INTENT_ID, canonical_a, dt.ACTION)), hooks, dt.GRANT_NOW_MS));

    const seq = grant_trace.snapshot();
    // 23 events: the 18-event v1 prefix, plus the Phase B plumbing (D-081):
    // check 11's commitConsumed runs pruneExpired FIRST (D-061 ruling 4),
    // so the four D-063 rename phases interleave before the commit row, and
    // publish_outcome lands between effect_return and mark_published.
    const prune_tags = [_]grant_trace.Tag{ .prune_temp_written, .prune_temp_synced, .prune_renamed, .prune_reopened };
    const expected = [_]grant_trace.Tag{ .receive_intent, .begin_verify } ++ ([_]grant_trace.Tag{.verify_check} ** 11) ++ prune_tags ++ [_]grant_trace.Tag{ .commit_consumed_11, .effect_start, .effect_return, .publish_outcome, .mark_published, .record_executing_witness };
    try std.testing.expectEqual(expected.len, seq.len);
    for (expected, seq) |want, got| try std.testing.expectEqual(want, got.tag);
    // Identity fingerprints: the admission event carries the intent id,
    // grant-path events carry the grant id, and the prune events carry the
    // ledger path (the prune is scoped to the log, not to any grant).
    const fp_intent = grant_trace.fingerprint(&dt.G_INTENT_ID);
    const fp_grant = grant_trace.fingerprint(&dt.G_GRANT_ID);
    const fp_path = grant_trace.fingerprint(sl.path);
    try std.testing.expectEqual(fp_intent, seq[0].id);
    var i: usize = 1;
    while (i < seq.len) : (i += 1) {
        switch (seq[i].tag) {
            .prune_temp_written, .prune_temp_synced, .prune_renamed, .prune_reopened => try std.testing.expectEqual(fp_path, seq[i].id),
            else => try std.testing.expectEqual(fp_grant, seq[i].id),
        }
    }
    // The four prune events share one id and arrive in D-063 phase order.
    try std.testing.expectEqual(fp_path, seq[13].id);
    try std.testing.expectEqual(grant_trace.Tag.prune_temp_written, seq[13].tag);
    try std.testing.expectEqual(grant_trace.Tag.prune_reopened, seq[16].tag);
    // verify_check pcs run 0..10 in order, none skipped, none repeated.
    var pc: usize = 0;
    while (pc < 11) : (pc += 1) try std.testing.expectEqual(@as(u8, @intCast(pc)), seq[2 + pc].pc);
    // seq counter strictly monotonic.
    i = 1;
    while (i < seq.len) : (i += 1) try std.testing.expect(seq[i - 1].seq < seq[i].seq);
    try std.testing.expectEqual(@as(usize, 0), grant_trace.overflow());
}

test "trace v1: check-11 refusal stutters before commit and effect" {
    if (!grant_trace.enabled) return error.SkipZigTest;
    const sl = try dt.initSeamLedger("tracereplay");
    defer dt.closeSeamLedger(sl);
    grant_trace.reset();
    dt.effect_count = 0;
    dt.ensureGrantCerts();
    const executor_pub = cth.pubkeyOf(dt.EXECUTOR_PREFIX);
    var res = resolver_mod.Resolver.init(&executor_pub);
    var canonical_a_buf: [64]u8 = undefined;
    var canonical_b_buf: [64]u8 = undefined;
    const canonical_a = dt.executorCanonical(&canonical_a_buf, "logs/deploy.log");
    try res.add(canonical_a);
    const canonical_b = dt.executorCanonical(&canonical_b_buf, "logs/archive.log");
    try res.add(canonical_b);
    var d = dispatch_mod.Dispatch.init(res, &executor_pub, std.mem.zeroes(session.Cert), cth.trustedSet());
    const hooks = dispatch_mod.Hooks{ .execute_effect = &dt.testEffect, .cert_for_sender = &dt.grantPathCertHook, .on_rejected = &dt.noopRejected };
    // Happy grant first (unasserted): commits G_GRANT_ID durably.
    const len_a = dt.buildIntentBodyId(&dt.intent_body_a, &dt.G_INTENT_ID, canonical_a, dt.ACTION);
    var a_sender: [32]u8 = undefined;
    var a_sig: [64]u8 = undefined;
    var a_tbs: [64]u8 = undefined;
    _ = try d.dispatch(dt.agentEnvelopeSigned(dt.intent_body_a[0..len_a], &a_sender, &a_sig, &a_tbs), hooks, dt.GRANT_NOW_MS);
    _ = try d.dispatch(dt.grantEnvelopeSigned(dt.buildGrantWire(dt.G_INTENT_ID, canonical_a, dt.ACTION)), hooks, dt.GRANT_NOW_MS);
    try std.testing.expectEqual(@as(usize, 1), dt.effect_count);
    // Fresh intent on a fresh resource; the reused grant_id hits check 11.
    grant_trace.reset();
    const len_b = dt.buildIntentBodyId(&dt.intent_body_b, &dt.G_INTENT_ID_B, canonical_b, dt.ACTION);
    _ = try d.dispatch(dt.agentEnvelopeSigned(dt.intent_body_b[0..len_b], &a_sender, &a_sig, &a_tbs), hooks, dt.GRANT_NOW_MS);
    try std.testing.expectError(verify.VerifyError.AlreadyConsumed, d.dispatch(dt.grantEnvelopeSigned(dt.buildGrantWire(dt.G_INTENT_ID_B, canonical_b, dt.ACTION)), hooks, dt.GRANT_NOW_MS));
    try std.testing.expectEqual(@as(usize, 1), dt.effect_count);

    // receive_intent(B), begin_verify, verify_check 0..10, then NOTHING:
    // no commit_consumed_11, no effect_start (brief: stutter, do not project).
    const seq = grant_trace.snapshot();
    try std.testing.expectEqual(@as(usize, 13), seq.len);
    try std.testing.expectEqual(grant_trace.Tag.receive_intent, seq[0].tag);
    try std.testing.expectEqual(grant_trace.Tag.begin_verify, seq[1].tag);
    var pc: usize = 0;
    while (pc < 11) : (pc += 1) {
        try std.testing.expectEqual(grant_trace.Tag.verify_check, seq[2 + pc].tag);
        try std.testing.expectEqual(@as(u8, @intCast(pc)), seq[2 + pc].pc);
    }
    for (seq) |ev| {
        try std.testing.expect(ev.tag != .commit_consumed_11);
        try std.testing.expect(ev.tag != .effect_start);
    }
}

test "trace v1: resource conflict emits the refusal event" {
    if (!grant_trace.enabled) return error.SkipZigTest;
    grant_trace.reset();
    dt.ensureGrantCerts();
    const executor_pub = cth.pubkeyOf(dt.EXECUTOR_PREFIX);
    var res = resolver_mod.Resolver.init(&executor_pub);
    var canonical_a_buf: [64]u8 = undefined;
    const canonical_a = dt.executorCanonical(&canonical_a_buf, "logs/deploy.log");
    try res.add(canonical_a);
    var d = dispatch_mod.Dispatch.init(res, &executor_pub, std.mem.zeroes(session.Cert), cth.trustedSet());
    const hooks = dispatch_mod.Hooks{ .execute_effect = &dt.testEffect, .cert_for_sender = &dt.grantPathCertHook, .on_rejected = &dt.noopRejected };
    const len_a = dt.buildIntentBodyId(&dt.intent_body_a, &dt.G_INTENT_ID, canonical_a, dt.ACTION);
    const len_b = dt.buildIntentBodyId(&dt.intent_body_b, &dt.G_INTENT_ID_B, canonical_a, dt.ACTION);
    var a_sender: [32]u8 = undefined;
    var a_sig: [64]u8 = undefined;
    var a_tbs: [64]u8 = undefined;
    _ = try d.dispatch(dt.agentEnvelopeSigned(dt.intent_body_a[0..len_a], &a_sender, &a_sig, &a_tbs), hooks, dt.GRANT_NOW_MS);
    // Same canonical resource: the table refuses the second admission.
    try std.testing.expectError(error.ResourceHeld, d.dispatch(dt.agentEnvelopeSigned(dt.intent_body_b[0..len_b], &a_sender, &a_sig, &a_tbs), hooks, dt.GRANT_NOW_MS));

    const seq = grant_trace.snapshot();
    try std.testing.expectEqual(@as(usize, 2), seq.len);
    try std.testing.expectEqual(grant_trace.Tag.receive_intent, seq[0].tag);
    try std.testing.expectEqual(grant_trace.Tag.reject_resource_conflict, seq[1].tag);
    try std.testing.expectEqual(grant_trace.fingerprint(&dt.G_INTENT_ID_B), seq[1].id);
}

test "trace v1: refused effect ends the trace in an unpublished orphan (brief 9.1)" {
    if (!grant_trace.enabled) return error.SkipZigTest;
    const sl = try dt.initSeamLedger("tracerefused");
    defer dt.closeSeamLedger(sl);
    grant_trace.reset();
    dt.effect_count = 0;
    dt.ensureGrantCerts();
    const executor_pub = cth.pubkeyOf(dt.EXECUTOR_PREFIX);
    var res = resolver_mod.Resolver.init(&executor_pub);
    var canonical_a_buf: [64]u8 = undefined;
    const canonical_a = dt.executorCanonical(&canonical_a_buf, "logs/deploy.log");
    try res.add(canonical_a);
    var d = dispatch_mod.Dispatch.init(res, &executor_pub, std.mem.zeroes(session.Cert), cth.trustedSet());
    const hooks = dispatch_mod.Hooks{ .execute_effect = &dt.refusingEffect, .cert_for_sender = &dt.grantPathCertHook, .on_rejected = &dt.noopRejected };
    const len_a = dt.buildIntentBodyId(&dt.intent_body_a, &dt.G_INTENT_ID, canonical_a, dt.ACTION);
    var a_sender: [32]u8 = undefined;
    var a_sig: [64]u8 = undefined;
    var a_tbs: [64]u8 = undefined;
    _ = try d.dispatch(dt.agentEnvelopeSigned(dt.intent_body_a[0..len_a], &a_sender, &a_sig, &a_tbs), hooks, dt.GRANT_NOW_MS);
    try std.testing.expectEqual(dispatch_mod.Outcome.effect_refused, try d.dispatch(dt.grantEnvelopeSigned(dt.buildGrantWire(dt.G_INTENT_ID, canonical_a, dt.ACTION)), hooks, dt.GRANT_NOW_MS));

    // Full prefix (intent, verify 0..10, the four D-063 prune phases that
    // commitConsumed runs first, commit, effect_start), then the refusal
    // tag instead of effect_return, then NOTHING: no publication attempt,
    // no executing witness. The durable orphan is the trace's last word.
    const seq = grant_trace.snapshot();
    const prune_tags = [_]grant_trace.Tag{ .prune_temp_written, .prune_temp_synced, .prune_renamed, .prune_reopened };
    const expected = [_]grant_trace.Tag{ .receive_intent, .begin_verify } ++ ([_]grant_trace.Tag{.verify_check} ** 11) ++ prune_tags ++ [_]grant_trace.Tag{ .commit_consumed_11, .effect_start, .effect_refused };
    try std.testing.expectEqual(expected.len, seq.len);
    for (expected, seq) |want, got| try std.testing.expectEqual(want, got.tag);
    for (seq) |ev| {
        try std.testing.expect(ev.tag != .mark_published);
        try std.testing.expect(ev.tag != .record_executing_witness);
        try std.testing.expect(ev.tag != .effect_return);
        try std.testing.expect(ev.tag != .publish_outcome);
    }
    try std.testing.expectEqual(@as(usize, 0), grant_trace.overflow());
}

// --- Phase B plumbing (D-081) ------------------------------------------------

var kill_io: ?std.Io = null;

fn killWritesEffect(grant: channel.Grant) verify.EffectOutcome {
    // Crash injection for the brief's Phase B window (crash between consume
    // and tombstone): the ledger handle is swapped for a read-only one while
    // the effect runs, so the markPublished append after effect_return fails
    // exactly like a lost tombstone write. D-080 ruling 1: control flow stays
    // fail-safe (D-061), evidence stays loud (mark_published_failed).
    _ = grant;
    if (kill_io) |io| dispatch_mod.seamBreakLedgerWrites(io);
    dt.effect_count += 1;
    return .fired;
}

test "trace v1: failed tombstone is preserved loud, never projected as success (D-080)" {
    if (!grant_trace.enabled) return error.SkipZigTest;
    const sl = try dt.initSeamLedger("tracekill");
    defer dt.closeSeamLedger(sl);
    defer kill_io = null;
    kill_io = sl.io;
    grant_trace.reset();
    dt.effect_count = 0;
    dt.ensureGrantCerts();
    const executor_pub = cth.pubkeyOf(dt.EXECUTOR_PREFIX);
    var res = resolver_mod.Resolver.init(&executor_pub);
    var canonical_a_buf: [64]u8 = undefined;
    const canonical_a = dt.executorCanonical(&canonical_a_buf, "logs/deploy.log");
    try res.add(canonical_a);
    var d = dispatch_mod.Dispatch.init(res, &executor_pub, std.mem.zeroes(session.Cert), cth.trustedSet());
    const hooks = dispatch_mod.Hooks{ .execute_effect = &killWritesEffect, .cert_for_sender = &dt.grantPathCertHook, .on_rejected = &dt.noopRejected };
    const len_a = dt.buildIntentBodyId(&dt.intent_body_a, &dt.G_INTENT_ID, canonical_a, dt.ACTION);
    var a_sender: [32]u8 = undefined;
    var a_sig: [64]u8 = undefined;
    var a_tbs: [64]u8 = undefined;
    _ = try d.dispatch(dt.agentEnvelopeSigned(dt.intent_body_a[0..len_a], &a_sender, &a_sig, &a_tbs), hooks, dt.GRANT_NOW_MS);
    // D-061/D-080: a failed tombstone is fail-safe; the dispatch succeeds.
    try std.testing.expectEqual(dispatch_mod.Outcome.grant_executed, try d.dispatch(dt.grantEnvelopeSigned(dt.buildGrantWire(dt.G_INTENT_ID, canonical_a, dt.ACTION)), hooks, dt.GRANT_NOW_MS));
    try std.testing.expectEqual(@as(usize, 1), dt.effect_count);

    const seq = grant_trace.snapshot();
    const prune_tags = [_]grant_trace.Tag{ .prune_temp_written, .prune_temp_synced, .prune_renamed, .prune_reopened };
    const expected = [_]grant_trace.Tag{ .receive_intent, .begin_verify } ++ ([_]grant_trace.Tag{.verify_check} ** 11) ++ prune_tags ++ [_]grant_trace.Tag{ .commit_consumed_11, .effect_start, .effect_return, .publish_outcome, .mark_published_failed, .record_executing_witness };
    try std.testing.expectEqual(expected.len, seq.len);
    for (expected, seq) |want, got| try std.testing.expectEqual(want, got.tag);
    // The failure is preserved but NEVER projected as success: the trace
    // holds mark_published_failed, and not one mark_published event.
    for (seq) |ev| try std.testing.expect(ev.tag != .mark_published);
    // The durable state on disk is the orphan: consumed yes, published no,
    // exactly one orphan for the next recovery to re-emit (BE-GRANT-01a).
    var view = try grant_ledger.GrantLedger.open(sl.io, sl.path);
    defer view.close();
    const r = try view.recover();
    try std.testing.expect(view.isConsumed(dt.G_GRANT_ID));
    try std.testing.expect(!view.isPublished(dt.G_GRANT_ID));
    try std.testing.expectEqual(@as(usize, 1), r.orphans.len);
}

test "trace v1: prune emits the four D-063 rename phases in order" {
    if (!grant_trace.enabled) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init_single_threaded;
    const io = threaded.io();
    const path = "/tmp/bolina_trace_prune.log";
    const dir = std.Io.Dir.cwd();
    dir.deleteFile(io, path) catch {};
    var lg = try grant_ledger.GrantLedger.open(io, path);
    const gid: [16]u8 = .{0x99} ** 16;
    // One live commit: every commitConsumed already prunes first (D-061
    // ruling 4), so reset after it and exercise the standalone prune.
    try lg.commitConsumed(gid, dt.GRANT_NOW_MS + 60_000, dt.GRANT_NOW_MS);
    grant_trace.reset();
    try lg.pruneExpired(dt.GRANT_NOW_MS);
    const seq = grant_trace.snapshot();
    const expected = [_]grant_trace.Tag{ .prune_temp_written, .prune_temp_synced, .prune_renamed, .prune_reopened };
    try std.testing.expectEqual(expected.len, seq.len);
    for (expected, seq) |want, got| try std.testing.expectEqual(want, got.tag);
    // All four carry the ledger-path fingerprint, with monotonic seq.
    const fp_path = grant_trace.fingerprint(path);
    var i: usize = 0;
    while (i < seq.len) : (i += 1) {
        try std.testing.expectEqual(fp_path, seq[i].id);
        if (i > 0) try std.testing.expect(seq[i - 1].seq < seq[i].seq);
    }
    // The live grant survived the rewrite (BE-GRANT-01, D-063).
    try std.testing.expect(lg.isConsumed(gid));
    lg.close();
    dir.deleteFile(io, path) catch {};
}

test "trace v1: pending-intent expiry emits expire_pending with the count" {
    if (!grant_trace.enabled) return error.SkipZigTest;
    var table = intent_mod.Table.init();
    const it = channel.Intent{
        .intent_id = &dt.G_INTENT_ID,
        .resource_id = "logs/deploy.log",
        .action = "append",
        .rationale = "phase b",
    };
    try table.admit(it, dt.GRANT_NOW_MS);
    grant_trace.reset();
    const collapsed = table.expireTimeouts(dt.GRANT_NOW_MS + intent_mod.T_PENDING_MS + 1);
    try std.testing.expectEqual(@as(usize, 1), collapsed);
    const seq = grant_trace.snapshot();
    try std.testing.expectEqual(@as(usize, 1), seq.len);
    try std.testing.expectEqual(grant_trace.Tag.expire_pending, seq[0].tag);
    try std.testing.expectEqual(@as(u8, 1), seq[0].pc);
    // A sweep that collapses nothing emits nothing.
    grant_trace.reset();
    try std.testing.expectEqual(@as(usize, 0), table.expireTimeouts(dt.GRANT_NOW_MS + intent_mod.T_PENDING_MS + 2));
    try std.testing.expectEqual(@as(usize, 0), grant_trace.snapshot().len);
}
