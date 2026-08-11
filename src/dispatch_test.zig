// dispatch_test.zig
//
// Phase A dispatch core seam tests (DAEMON-ESTIMATE.md phase A, D-059).
// Literal values throughout (D-027). The grant and refusal crypto happy
// paths live in verify_test.zig; these tests falsify what dispatch itself
// contributes: body_type routing, context assembly from pending state, and
// the declared outcomes.

const std = @import("std");
const dispatch_mod = @import("dispatch.zig");
const channel = @import("parser/channel.zig");
const session = @import("parser/session.zig");
const intent_mod = @import("intent.zig");
const resolver_mod = @import("resolver.zig");
const verify = @import("verify.zig");
const binding = @import("binding.zig");
const cth = @import("cert_test_helpers.zig");
const Ed = std.crypto.sign.Ed25519;

// Literal fixtures (D-027).
const SIGN_SEED: [32]u8 = .{0x07} ** 32;
const CHANNEL_ID: [32]u8 = .{0xCC} ** 32;
const EXECUTOR_PUBKEY: [32]u8 = .{0x42} ** 32; // resolver hashes bytes; no curve point needed
const INTENT_ID: [16]u8 = .{0x11} ** 16;
const GRANT_ID_FIX: [16]u8 = .{0x22} ** 16;
const MATCHLESS_INTENT_ID: [16]u8 = .{0x99} ** 16;
const ACTION = "restart-service";
const FIX_TBS = "fixture-envelope-tbs";

// Stable storage for the signed fixture envelope (single-threaded tests).
var fix_sender: [32]u8 = undefined;
var fix_sig: [64]u8 = undefined;

// signedEnvelope: verifyEnvelope is the BE-ENV-02 signature gate, so the
// fixture signs (DOMAIN_ENVELOPE || tbs) with a deterministic key.
fn signedEnvelope(body_type: u8, body: []const u8) channel.Envelope {
    const kp = Ed.KeyPair.generateDeterministic(SIGN_SEED) catch unreachable;
    fix_sender = Ed.PublicKey.toBytes(kp.public_key);
    var msg: [1 + FIX_TBS.len]u8 = undefined;
    msg[0] = channel.DOMAIN_ENVELOPE;
    @memcpy(msg[1..], FIX_TBS);
    const sig = Ed.KeyPair.sign(kp, &msg, null) catch unreachable;
    fix_sig = Ed.Signature.toBytes(sig);
    return .{
        .version = 2,
        .channel_id = &CHANNEL_ID,
        .sender = &fix_sender,
        .seq = 1,
        .parent_count = 0,
        .parents = "",
        .ts = 1000,
        .body_type = body_type,
        .body = body,
        .tbs = FIX_TBS,
        .sig = &fix_sig,
    };
}

// Hook fixtures (M10 shape: bare function pointers).
fn noopEffect(grant: channel.Grant) void {
    _ = grant;
}
fn noCert(sender: []const u8) ?session.Cert {
    _ = sender;
    return null;
}
fn noopRejected(intent_id: []const u8) void {
    _ = intent_id;
}
const TEST_HOOKS: dispatch_mod.Hooks = .{
    .execute_effect = noopEffect,
    .cert_for_sender = noCert,
    .on_rejected = noopRejected,
};

// Intent wire layout (SPEC 8.2, parseIntent): intent_id[16] | u16
// resource_len | resource | u32 action_len | action | u16 rationale_len |
// rationale. Big-endian lengths (house wire rule).
fn buildIntentBody(out: []u8, resource: []const u8, action: []const u8) usize {
    return buildIntentBodyId(out, &INTENT_ID, resource, action);
}

fn buildIntentBodyId(out: []u8, intent_id: []const u8, resource: []const u8, action: []const u8) usize {
    var n: usize = 0;
    @memcpy(out[n..][0..16], intent_id);
    n += 16;
    std.mem.writeInt(u16, out[n..][0..2], @intCast(resource.len), .big);
    n += 2;
    @memcpy(out[n..][0..resource.len], resource);
    n += resource.len;
    std.mem.writeInt(u32, out[n..][0..4], @intCast(action.len), .big);
    n += 4;
    @memcpy(out[n..][0..action.len], action);
    n += action.len;
    std.mem.writeInt(u16, out[n..][0..2], 0, .big);
    n += 2;
    return n;
}

// Canonical resource for the test executor: fp derived from EXECUTOR_PUBKEY
// exactly as BE-RES-06 declares, assembled into the section-8.4 grammar.
var canonical_buf: [resolver_mod.ID_MAX]u8 = undefined;

fn buildCanonical() []const u8 {
    var fp: [resolver_mod.FP_HEX_LEN]u8 = undefined;
    resolver_mod.executorFp(&EXECUTOR_PUBKEY, &fp);
    var n: usize = 0;
    @memcpy(canonical_buf[n..][0..4], "bol:");
    n += 4;
    @memcpy(canonical_buf[n..][0..resolver_mod.FP_HEX_LEN], &fp);
    n += resolver_mod.FP_HEX_LEN;
    const tail = "/logs/deploy.log";
    @memcpy(canonical_buf[n..][0..tail.len], tail);
    n += tail.len;
    return canonical_buf[0..n];
}

fn freshDispatch() dispatch_mod.Dispatch {
    var res = resolver_mod.Resolver.init(&EXECUTOR_PUBKEY);
    res.add(buildCanonical()) catch unreachable;
    return dispatch_mod.Dispatch.init(res, &EXECUTOR_PUBKEY, std.mem.zeroes(session.Cert), &.{});
}

test "DAEMON_A intent routes through resolveAndAdmit: canonical lock held" {
    var d = freshDispatch();
    var body: [256]u8 = undefined;
    const len = buildIntentBody(&body, buildCanonical(), ACTION);
    const out = try d.dispatch(signedEnvelope(channel.BODY_INTENT, body[0..len]), TEST_HOOKS, 1000);
    try std.testing.expectEqual(dispatch_mod.Outcome.intent_admitted, out);
    try std.testing.expectEqual(@as(usize, 1), d.intents.len);
    // The lock holds the CANONICAL bytes, never the proposal (BE-RES-01).
    const e = d.intents.entries[0];
    try std.testing.expectEqualStrings(buildCanonical(), e.resource_id[0..e.resource_len]);
    try std.testing.expectEqual(intent_mod.State.pending, e.state);
    // Sender seam recorded for GrantContext assembly (D-059).
    try std.testing.expectEqual(@as(usize, 1), d.senders_len);
    try std.testing.expectEqualStrings(ACTION, d.senders[0].action[0..d.senders[0].action_len]);
}

test "DAEMON_A unknown resource refuses at the seam, table untouched" {
    var d = freshDispatch();
    var body: [256]u8 = undefined;
    const ghost = "bol:c3efd641bfa0582f/files/ghost";
    const len = buildIntentBody(&body, ghost, ACTION);
    try std.testing.expectError(resolver_mod.ResolveError.UnknownResource, d.dispatch(signedEnvelope(channel.BODY_INTENT, body[0..len]), TEST_HOOKS, 1000));
    try std.testing.expectEqual(@as(usize, 0), d.intents.len);
    try std.testing.expectEqual(@as(usize, 0), d.senders_len);
}

test "DAEMON_A grant naming no pending intent refuses: no service" {
    var d = freshDispatch();
    // Grant wire layout (SPEC 8.1): parseable without valid signatures.
    var fix_grant_body: [256]u8 = undefined;
    var n: usize = 0;
    fix_grant_body[n] = 2; // version
    n += 1;
    @memcpy(fix_grant_body[n..][0..16], &GRANT_ID_FIX); // grant_id
    n += 16;
    @memcpy(fix_grant_body[n..][0..16], &MATCHLESS_INTENT_ID); // intent_id, matches nothing
    n += 16;
    @memset(fix_grant_body[n .. n + 96], 0x33); // approver, subject, executor
    n += 96;
    std.mem.writeInt(u16, fix_grant_body[n..][0..2], 4, .big);
    n += 2;
    @memcpy(fix_grant_body[n..][0..4], "res0");
    n += 4;
    @memset(fix_grant_body[n .. n + 32], 0x44); // action_digest
    n += 32;
    std.mem.writeInt(u64, fix_grant_body[n..][0..8], 9999, .big); // not_after
    n += 8;
    @memset(fix_grant_body[n .. n + 64], 0x55); // sig
    n += 64;
    try std.testing.expectError(dispatch_mod.DispatchError.NoPendingIntent, d.dispatch(signedEnvelope(channel.BODY_GRANT, fix_grant_body[0..n]), TEST_HOOKS, 1000));
    try std.testing.expectEqual(@as(usize, 0), d.intents.len);
}

test "DAEMON_A refusal without a session cert refuses at the seam" {
    var d = freshDispatch();
    // Refusal wire layout (SPEC 8.5): intent_id[16] | u16 note_len | note |
    // sig[64].
    var refusal_body: [128]u8 = undefined;
    var n: usize = 0;
    @memcpy(refusal_body[n..][0..16], &INTENT_ID);
    n += 16;
    std.mem.writeInt(u16, refusal_body[n..][0..2], 2, .big);
    n += 2;
    @memcpy(refusal_body[n..][0..2], "no");
    n += 2;
    @memset(refusal_body[n .. n + 64], 0x66);
    n += 64;
    try std.testing.expectError(dispatch_mod.DispatchError.UnknownSender, d.dispatch(signedEnvelope(channel.BODY_REFUSAL, refusal_body[0..n]), TEST_HOOKS, 1000));
}

test "DAEMON_A routing: utterance passes, control and effect recognized, unknown refused" {
    var d = freshDispatch();
    try std.testing.expectEqual(dispatch_mod.Outcome.utterance, try d.dispatch(signedEnvelope(channel.BODY_UTTERANCE, "hello"), TEST_HOOKS, 1000));
    try std.testing.expectEqual(dispatch_mod.Outcome.control, try d.dispatch(signedEnvelope(channel.BODY_CONTROL, ""), TEST_HOOKS, 1000));
    try std.testing.expectEqual(dispatch_mod.Outcome.effect, try d.dispatch(signedEnvelope(channel.BODY_EFFECT, ""), TEST_HOOKS, 1000));
    try std.testing.expectError(dispatch_mod.DispatchError.UnsupportedBody, d.dispatch(signedEnvelope(9, ""), TEST_HOOKS, 1000));
    // Routing alone changes nothing.
    try std.testing.expectEqual(@as(usize, 0), d.intents.len);
    try std.testing.expectEqual(@as(usize, 0), d.senders_len);
}

test "DAEMON_A bad body for the declared type refuses" {
    var d = freshDispatch();
    try std.testing.expectError(dispatch_mod.DispatchError.BadBody, d.dispatch(signedEnvelope(channel.BODY_INTENT, "abc"), TEST_HOOKS, 1000));
    try std.testing.expectEqual(@as(usize, 0), d.intents.len);
}

// ---------------------------------------------------------------------------
// Grant happy path through the session seam (D-059 correction): full crypto
// fixtures from the cert_test_helpers seed family. The approver signs the
// grant under DOMAIN_GRANT; every envelope carries a real DOMAIN_ENVELOPE
// signature; certs are CA-signed by buildCertInto.
// ---------------------------------------------------------------------------

const EXECUTOR_PREFIX: u8 = 0xE1;
const AGENT_PREFIX: u8 = 0xA1;
const APPROVER_PREFIX: u8 = 0xB1;
const GRANT_NOW_MS: u64 = 1_700_000_000_000; // inside both cert windows
const G_INTENT_ID: [16]u8 = .{0x71} ** 16;
const G_INTENT_ID_B: [16]u8 = .{0x72} ** 16;
const G_GRANT_ID: [16]u8 = .{0x81} ** 16;

var cert_agent_wire: [512]u8 = undefined;
var cert_approver_wire: [512]u8 = undefined;
var cert_agent: session.Cert = undefined;
var cert_approver: session.Cert = undefined;
var certs_inited: bool = false;

fn ensureGrantCerts() void {
    if (certs_inited) return;
    cert_agent = cth.buildCertInto(&cert_agent_wire, cth.pubkeyOf(AGENT_PREFIX), binding.ROLE_AGENT, &[_]u8{0xC2}, cth.CERT_NOT_BEFORE, cth.CERT_NOT_AFTER);
    cert_approver = cth.buildCertInto(&cert_approver_wire, cth.pubkeyOf(APPROVER_PREFIX), binding.ROLE_APPROVER, &[_]u8{ 0xC0, 0xC1 }, cth.PRIVILEGED_CERT_NOT_BEFORE, cth.PRIVILEGED_CERT_NOT_AFTER);
    certs_inited = true;
}

fn grantPathCertHook(sender: []const u8) ?session.Cert {
    ensureGrantCerts();
    if (sender.len == 32) {
        if (std.mem.eql(u8, sender, &cth.pubkeyOf(APPROVER_PREFIX))) return cert_approver;
        if (std.mem.eql(u8, sender, &cth.pubkeyOf(AGENT_PREFIX))) return cert_agent;
    }
    return null;
}

var effect_count: usize = 0;
var effect_grant_id: [16]u8 = undefined;

fn testEffect(grant: channel.Grant) void {
    effect_count += 1;
    @memcpy(&effect_grant_id, grant.grant_id);
}

var g_sender: [32]u8 = undefined;
var g_sig: [64]u8 = undefined;
var g_tbs: [64]u8 = undefined;
var grant_body: [512]u8 = undefined;
var g_canonical_buf: [64]u8 = undefined;
var intent_body_a: [128]u8 = undefined;
var intent_body_b: [128]u8 = undefined;

const G_TBS = "grant-envelope-tbs";

fn grantEnvelopeSigned(body: []const u8) channel.Envelope {
    const kp = cth.keypair(APPROVER_PREFIX);
    g_sender = Ed.PublicKey.toBytes(kp.public_key);
    @memcpy(g_tbs[0..G_TBS.len], G_TBS);
    var msg: [1 + G_TBS.len]u8 = undefined;
    msg[0] = channel.DOMAIN_ENVELOPE;
    @memcpy(msg[1..], G_TBS);
    const sig = Ed.KeyPair.sign(kp, &msg, null) catch unreachable;
    g_sig = Ed.Signature.toBytes(sig);
    return .{
        .version = 2,
        .channel_id = &CHANNEL_ID,
        .sender = &g_sender,
        .seq = 1,
        .parent_count = 0,
        .parents = "",
        .ts = 1000,
        .body_type = channel.BODY_GRANT,
        .body = body,
        .tbs = g_tbs[0..G_TBS.len],
        .sig = &g_sig,
    };
}

fn agentEnvelopeSigned(body: []const u8, buf_sender: *[32]u8, buf_sig: *[64]u8, buf_tbs: *[64]u8) channel.Envelope {
    const kp = cth.keypair(AGENT_PREFIX);
    buf_sender.* = Ed.PublicKey.toBytes(kp.public_key);
    @memcpy(buf_tbs[0..G_TBS.len], G_TBS);
    var msg: [1 + G_TBS.len]u8 = undefined;
    msg[0] = channel.DOMAIN_ENVELOPE;
    @memcpy(msg[1..], G_TBS);
    const sig = Ed.KeyPair.sign(kp, &msg, null) catch unreachable;
    buf_sig.* = Ed.Signature.toBytes(sig);
    return .{
        .version = 2,
        .channel_id = &CHANNEL_ID,
        .sender = buf_sender,
        .seq = 1,
        .parent_count = 0,
        .parents = "",
        .ts = 1000,
        .body_type = channel.BODY_INTENT,
        .body = body,
        .tbs = buf_tbs[0..G_TBS.len],
        .sig = buf_sig,
    };
}

fn executorCanonical(out: []u8, path: []const u8) []u8 {
    const executor_pub = cth.pubkeyOf(EXECUTOR_PREFIX);
    var fphex: [16]u8 = undefined;
    resolver_mod.executorFp(&executor_pub, &fphex);
    var n: usize = 0;
    @memcpy(out[n..][0..4], "bol:");
    n += 4;
    @memcpy(out[n..][0..16], &fphex);
    n += 16;
    out[n] = '/';
    n += 1;
    @memcpy(out[n..][0..path.len], path);
    n += path.len;
    return out[0..n];
}

fn buildGrantWire(intent_id: [16]u8, resource: []const u8, action: []const u8) []u8 {
    var n: usize = 0;
    grant_body[n] = 2;
    n += 1;
    @memcpy(grant_body[n..][0..16], &G_GRANT_ID);
    n += 16;
    @memcpy(grant_body[n..][0..16], &intent_id);
    n += 16;
    const approver = cth.pubkeyOf(APPROVER_PREFIX);
    const agent = cth.pubkeyOf(AGENT_PREFIX);
    const executor = cth.pubkeyOf(EXECUTOR_PREFIX);
    @memcpy(grant_body[n..][0..32], &approver);
    n += 32;
    @memcpy(grant_body[n..][0..32], &agent);
    n += 32;
    @memcpy(grant_body[n..][0..32], &executor);
    n += 32;
    std.mem.writeInt(u16, grant_body[n..][0..2], @intCast(resource.len), .big);
    n += 2;
    @memcpy(grant_body[n..][0..resource.len], resource);
    n += resource.len;
    const digest = verify.actionDigest(action);
    @memcpy(grant_body[n..][0..32], &digest);
    n += 32;
    std.mem.writeInt(u64, grant_body[n..][0..8], GRANT_NOW_MS + 3_600_000, .big);
    n += 8;
    var msg: [1 + 384]u8 = undefined;
    msg[0] = channel.DOMAIN_GRANT;
    @memcpy(msg[1..][0..n], grant_body[0..n]);
    const sig = Ed.KeyPair.sign(cth.keypair(APPROVER_PREFIX), msg[0 .. 1 + n], null) catch unreachable;
    const sig_bytes = Ed.Signature.toBytes(sig);
    @memcpy(grant_body[n..][0..64], &sig_bytes);
    n += 64;
    return grant_body[0..n];
}

test "DAEMON_A grant happy path: effect once inside the frame, replay refused by state" {
    dispatch_mod.resetConsumedRegistry();
    effect_count = 0;
    ensureGrantCerts();
    const executor_pub = cth.pubkeyOf(EXECUTOR_PREFIX);
    var res = resolver_mod.Resolver.init(&executor_pub);
    var canonical_a_buf: [64]u8 = undefined;
    const canonical_a = executorCanonical(&canonical_a_buf, "logs/deploy.log");
    try res.add(canonical_a);
    var d = dispatch_mod.Dispatch.init(res, &executor_pub, std.mem.zeroes(session.Cert), cth.trustedSet());
    const hooks = dispatch_mod.Hooks{ .execute_effect = &testEffect, .cert_for_sender = &grantPathCertHook, .on_rejected = &noopRejected };
    // 1. The agent admits the intent (envelope signed by the agent key).
    const len_a = buildIntentBodyId(&intent_body_a, &G_INTENT_ID, canonical_a, ACTION);
    var a_sender: [32]u8 = undefined;
    var a_sig: [64]u8 = undefined;
    var a_tbs: [64]u8 = undefined;
    const env_intent = agentEnvelopeSigned(intent_body_a[0..len_a], &a_sender, &a_sig, &a_tbs);
    try std.testing.expectEqual(dispatch_mod.Outcome.intent_admitted, try d.dispatch(env_intent, hooks, GRANT_NOW_MS));
    // 2. The approver grants it: the effect fires exactly once, inside the frame.
    const grant_wire = buildGrantWire(G_INTENT_ID, canonical_a, ACTION);
    const env_grant = grantEnvelopeSigned(grant_wire);
    try std.testing.expectEqual(dispatch_mod.Outcome.grant_executed, try d.dispatch(env_grant, hooks, GRANT_NOW_MS));
    try std.testing.expectEqual(@as(usize, 1), effect_count);
    try std.testing.expectEqual(G_GRANT_ID, effect_grant_id);
    // 3. The intent moved to EXECUTING.
    var found_executing = false;
    for (d.intents.entries[0..d.intents.len]) |e| {
        if (std.mem.eql(u8, &e.intent_id, &G_INTENT_ID) and e.state == .executing) found_executing = true;
    }
    try std.testing.expect(found_executing);
    // 4. Replay: EXECUTING state blocks the second pass, the effect stays fired once.
    const env_replay = grantEnvelopeSigned(grant_wire);
    try std.testing.expectError(dispatch_mod.DispatchError.NoPendingIntent, d.dispatch(env_replay, hooks, GRANT_NOW_MS));
    try std.testing.expectEqual(@as(usize, 1), effect_count);
}

test "DAEMON_A consumed registry: a reused grant_id refuses even against a fresh intent" {
    dispatch_mod.resetConsumedRegistry();
    effect_count = 0;
    ensureGrantCerts();
    const executor_pub = cth.pubkeyOf(EXECUTOR_PREFIX);
    var res = resolver_mod.Resolver.init(&executor_pub);
    var canonical_a_buf: [64]u8 = undefined;
    var canonical_b_buf: [64]u8 = undefined;
    const canonical_a = executorCanonical(&canonical_a_buf, "logs/deploy.log");
    try res.add(canonical_a);
    const canonical_b = executorCanonical(&canonical_b_buf, "logs/archive.log");
    try res.add(canonical_b);
    var d = dispatch_mod.Dispatch.init(res, &executor_pub, std.mem.zeroes(session.Cert), cth.trustedSet());
    const hooks = dispatch_mod.Hooks{ .execute_effect = &testEffect, .cert_for_sender = &grantPathCertHook, .on_rejected = &noopRejected };
    // Intent A admitted, granted: G_GRANT_ID committed to the registry.
    const len_a = buildIntentBodyId(&intent_body_a, &G_INTENT_ID, canonical_a, ACTION);
    var a_sender: [32]u8 = undefined;
    var a_sig: [64]u8 = undefined;
    var a_tbs: [64]u8 = undefined;
    try std.testing.expectEqual(dispatch_mod.Outcome.intent_admitted, try d.dispatch(agentEnvelopeSigned(intent_body_a[0..len_a], &a_sender, &a_sig, &a_tbs), hooks, GRANT_NOW_MS));
    try std.testing.expectEqual(dispatch_mod.Outcome.grant_executed, try d.dispatch(grantEnvelopeSigned(buildGrantWire(G_INTENT_ID, canonical_a, ACTION)), hooks, GRANT_NOW_MS));
    // Intent B admitted on a fresh resource.
    const len_b = buildIntentBodyId(&intent_body_b, &G_INTENT_ID_B, canonical_b, ACTION);
    try std.testing.expectEqual(dispatch_mod.Outcome.intent_admitted, try d.dispatch(agentEnvelopeSigned(intent_body_b[0..len_b], &a_sender, &a_sig, &a_tbs), hooks, GRANT_NOW_MS));
    // Same grant_id against the fresh intent: the consumed registry refuses.
    try std.testing.expectError(verify.VerifyError.AlreadyConsumed, d.dispatch(grantEnvelopeSigned(buildGrantWire(G_INTENT_ID_B, canonical_b, ACTION)), hooks, GRANT_NOW_MS));
    try std.testing.expectEqual(@as(usize, 1), effect_count);
}
