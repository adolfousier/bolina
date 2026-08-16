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
const verify = @import("verify.zig");
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
    const expected = [_]grant_trace.Tag{ .receive_intent, .begin_verify } ++ ([_]grant_trace.Tag{.verify_check} ** 11) ++ [_]grant_trace.Tag{ .commit_consumed_11, .effect_start, .effect_return, .mark_published, .record_executing_witness };
    try std.testing.expectEqual(expected.len, seq.len);
    for (expected, seq) |want, got| try std.testing.expectEqual(want, got.tag);
    // Identity fingerprints: the admission event carries the intent id,
    // every later event the grant id.
    const fp_intent = grant_trace.fingerprint(&dt.G_INTENT_ID);
    const fp_grant = grant_trace.fingerprint(&dt.G_GRANT_ID);
    try std.testing.expectEqual(fp_intent, seq[0].id);
    var i: usize = 1;
    while (i < seq.len) : (i += 1) try std.testing.expectEqual(fp_grant, seq[i].id);
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
