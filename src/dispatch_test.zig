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
const grant_ledger_mod = @import("grant_ledger.zig");
const Ed = std.crypto.sign.Ed25519;

// Literal fixtures (D-027).
const SIGN_SEED: [32]u8 = .{0x07} ** 32;
const CHANNEL_ID: [32]u8 = .{0xCC} ** 32;
const EXECUTOR_PUBKEY: [32]u8 = .{0x42} ** 32; // resolver hashes bytes; no curve point needed
const INTENT_ID: [16]u8 = .{0x11} ** 16;
const GRANT_ID_FIX: [16]u8 = .{0x22} ** 16;
const MATCHLESS_INTENT_ID: [16]u8 = .{0x99} ** 16;
pub const ACTION = "restart-service";
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
pub fn noopRejected(intent_id: []const u8) void {
    _ = intent_id;
}
const TEST_HOOKS: dispatch_mod.Hooks = .{
    .execute_effect = noopEffect,
    .cert_for_sender = noCert,
    .on_rejected = noopRejected,
};

// Durable consumed-ledger seam state (D-062): every test that drives a grant
// to check 11 runs the dispatch seam over a fresh ledger file under /tmp.
// The threaded io context must outlive the ledger's borrow, so the test owns
// the SeamLedger for its whole body.
pub const SeamLedger = struct {
    threaded: std.Io.Threaded,
    io: std.Io,
    path: []const u8,
};

pub fn initSeamLedger(comptime tag: []const u8) !SeamLedger {
    var threaded = std.Io.Threaded.init_single_threaded;
    const io = threaded.io();
    const path = "/tmp/bolina_dispatch_" ++ tag ++ ".log";
    const dir = std.Io.Dir.cwd();
    dir.deleteFile(io, path) catch {};
    var orphan_buf: [8]grant_ledger_mod.OrphanGrant = undefined;
    const n = try dispatch_mod.initDurableLedger(io, path, &orphan_buf);
    if (n != 0) return error.TestUnexpectedResult; // fresh file: no orphans
    return .{ .threaded = threaded, .io = io, .path = path };
}

pub fn closeSeamLedger(sl: SeamLedger) void {
    dispatch_mod.closeDurableLedger();
    const dir = std.Io.Dir.cwd();
    dir.deleteFile(sl.io, sl.path) catch {};
}

// Intent wire layout (SPEC 8.2, parseIntent): intent_id[16] | u16
// resource_len | resource | u32 action_len | action | u16 rationale_len |
// rationale. Big-endian lengths (house wire rule).
fn buildIntentBody(out: []u8, resource: []const u8, action: []const u8) usize {
    return buildIntentBodyId(out, &INTENT_ID, resource, action);
}

pub fn buildIntentBodyId(out: []u8, intent_id: []const u8, resource: []const u8, action: []const u8) usize {
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

pub const EXECUTOR_PREFIX: u8 = 0xE1;
pub const AGENT_PREFIX: u8 = 0xA1;
pub const APPROVER_PREFIX: u8 = 0xB1;
pub const GRANT_NOW_MS: u64 = 1_700_000_000_000; // inside both cert windows
pub const G_INTENT_ID: [16]u8 = .{0x71} ** 16;
pub const G_INTENT_ID_B: [16]u8 = .{0x72} ** 16;
pub const G_GRANT_ID: [16]u8 = .{0x81} ** 16;

var cert_agent_wire: [512]u8 = undefined;
var cert_approver_wire: [512]u8 = undefined;
var cert_agent: session.Cert = undefined;
var cert_approver: session.Cert = undefined;
var certs_inited: bool = false;

pub fn ensureGrantCerts() void {
    if (certs_inited) return;
    cert_agent = cth.buildCertInto(&cert_agent_wire, cth.pubkeyOf(AGENT_PREFIX), binding.ROLE_AGENT, &[_]u8{0xC2}, cth.CERT_NOT_BEFORE, cth.CERT_NOT_AFTER);
    cert_approver = cth.buildCertInto(&cert_approver_wire, cth.pubkeyOf(APPROVER_PREFIX), binding.ROLE_APPROVER, &[_]u8{ 0xC0, 0xC1 }, cth.PRIVILEGED_CERT_NOT_BEFORE, cth.PRIVILEGED_CERT_NOT_AFTER);
    certs_inited = true;
}

pub fn grantPathCertHook(sender: []const u8) ?session.Cert {
    ensureGrantCerts();
    if (sender.len == 32) {
        if (std.mem.eql(u8, sender, &cth.pubkeyOf(APPROVER_PREFIX))) return cert_approver;
        if (std.mem.eql(u8, sender, &cth.pubkeyOf(AGENT_PREFIX))) return cert_agent;
    }
    return null;
}

pub var effect_count: usize = 0;
var effect_grant_id: [16]u8 = undefined;

pub fn testEffect(grant: channel.Grant) void {
    effect_count += 1;
    @memcpy(&effect_grant_id, grant.grant_id);
}

var g_sender: [32]u8 = undefined;
var g_sig: [64]u8 = undefined;
var g_tbs: [64]u8 = undefined;
var grant_body: [512]u8 = undefined;
var g_canonical_buf: [64]u8 = undefined;
pub var intent_body_a: [128]u8 = undefined;
pub var intent_body_b: [128]u8 = undefined;

const G_TBS = "grant-envelope-tbs";

pub fn grantEnvelopeSigned(body: []const u8) channel.Envelope {
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

pub fn agentEnvelopeSigned(body: []const u8, buf_sender: *[32]u8, buf_sig: *[64]u8, buf_tbs: *[64]u8) channel.Envelope {
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

pub fn executorCanonical(out: []u8, path: []const u8) []u8 {
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

pub fn buildGrantWire(intent_id: [16]u8, resource: []const u8, action: []const u8) []u8 {
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

test "DAEMON_D grant happy path: effect once inside the frame, replay refused by state" {
    const sl = try initSeamLedger("happy");
    defer closeSeamLedger(sl);
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

test "DAEMON_D durable consumed ledger: a reused grant_id refuses even against a fresh intent" {
    const sl = try initSeamLedger("reused");
    defer closeSeamLedger(sl);
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

test "DAEMON_D durable seam: commit row and publish tombstone both on disk after the effect (BE-GRANT-01)" {
    const sl = try initSeamLedger("witness");
    defer closeSeamLedger(sl);
    effect_count = 0;
    ensureGrantCerts();
    const executor_pub = cth.pubkeyOf(EXECUTOR_PREFIX);
    var res = resolver_mod.Resolver.init(&executor_pub);
    var canonical_a_buf: [64]u8 = undefined;
    const canonical_a = executorCanonical(&canonical_a_buf, "logs/deploy.log");
    try res.add(canonical_a);
    var d = dispatch_mod.Dispatch.init(res, &executor_pub, std.mem.zeroes(session.Cert), cth.trustedSet());
    const hooks = dispatch_mod.Hooks{ .execute_effect = &testEffect, .cert_for_sender = &grantPathCertHook, .on_rejected = &noopRejected };
    const len_a = buildIntentBodyId(&intent_body_a, &G_INTENT_ID, canonical_a, ACTION);
    var a_sender: [32]u8 = undefined;
    var a_sig: [64]u8 = undefined;
    var a_tbs: [64]u8 = undefined;
    try std.testing.expectEqual(dispatch_mod.Outcome.intent_admitted, try d.dispatch(agentEnvelopeSigned(intent_body_a[0..len_a], &a_sender, &a_sig, &a_tbs), hooks, GRANT_NOW_MS));
    try std.testing.expectEqual(dispatch_mod.Outcome.grant_executed, try d.dispatch(grantEnvelopeSigned(buildGrantWire(G_INTENT_ID, canonical_a, ACTION)), hooks, GRANT_NOW_MS));
    try std.testing.expectEqual(@as(usize, 1), effect_count);
    // The durable witness: an independent ledger view over the same file
    // sees G_GRANT_ID consumed AND published (the tombstone landed after the
    // effect returned), so the next recovery reports zero orphans.
    var view = try grant_ledger_mod.GrantLedger.open(sl.io, sl.path);
    defer view.close();
    const r = try view.recover();
    try std.testing.expect(view.isConsumed(G_GRANT_ID));
    try std.testing.expectEqual(@as(usize, 0), r.orphans.len);
}

test "DAEMON_D durable seam: consumed grant survives restart, replay refused by the ledger (BE-GRANT-01)" {
    const sl = try initSeamLedger("restart");
    effect_count = 0;
    ensureGrantCerts();
    const executor_pub = cth.pubkeyOf(EXECUTOR_PREFIX);
    var canonical_a_buf: [64]u8 = undefined;
    var canonical_b_buf: [64]u8 = undefined;
    const canonical_a = executorCanonical(&canonical_a_buf, "logs/deploy.log");
    const canonical_b = executorCanonical(&canonical_b_buf, "logs/archive.log");
    var a_sender: [32]u8 = undefined;
    var a_sig: [64]u8 = undefined;
    var a_tbs: [64]u8 = undefined;
    // Run 1: intent A admitted, grant executes, G_GRANT_ID committed durably.
    {
        var res = resolver_mod.Resolver.init(&executor_pub);
        try res.add(canonical_a);
        var d = dispatch_mod.Dispatch.init(res, &executor_pub, std.mem.zeroes(session.Cert), cth.trustedSet());
        const hooks = dispatch_mod.Hooks{ .execute_effect = &testEffect, .cert_for_sender = &grantPathCertHook, .on_rejected = &noopRejected };
        const len_a = buildIntentBodyId(&intent_body_a, &G_INTENT_ID, canonical_a, ACTION);
        try std.testing.expectEqual(dispatch_mod.Outcome.intent_admitted, try d.dispatch(agentEnvelopeSigned(intent_body_a[0..len_a], &a_sender, &a_sig, &a_tbs), hooks, GRANT_NOW_MS));
        try std.testing.expectEqual(dispatch_mod.Outcome.grant_executed, try d.dispatch(grantEnvelopeSigned(buildGrantWire(G_INTENT_ID, canonical_a, ACTION)), hooks, GRANT_NOW_MS));
    }
    // Restart: close the ledger; fresh dispatch state, same durable file.
    dispatch_mod.closeDurableLedger();
    var orphan_buf: [8]grant_ledger_mod.OrphanGrant = undefined;
    const n = try dispatch_mod.initDurableLedger(sl.io, sl.path, &orphan_buf);
    try std.testing.expectEqual(@as(usize, 0), n); // published grant: no orphan
    defer closeSeamLedger(sl);
    // Run 2: a fresh intent B on a fresh resource, but the same grant_id.
    // Checks 1-10 pass against intent B; the durable ledger refuses at 11.
    var res2 = resolver_mod.Resolver.init(&executor_pub);
    try res2.add(canonical_b);
    var d2 = dispatch_mod.Dispatch.init(res2, &executor_pub, std.mem.zeroes(session.Cert), cth.trustedSet());
    const hooks2 = dispatch_mod.Hooks{ .execute_effect = &testEffect, .cert_for_sender = &grantPathCertHook, .on_rejected = &noopRejected };
    const len_b = buildIntentBodyId(&intent_body_b, &G_INTENT_ID_B, canonical_b, ACTION);
    try std.testing.expectEqual(dispatch_mod.Outcome.intent_admitted, try d2.dispatch(agentEnvelopeSigned(intent_body_b[0..len_b], &a_sender, &a_sig, &a_tbs), hooks2, GRANT_NOW_MS));
    try std.testing.expectError(verify.VerifyError.AlreadyConsumed, d2.dispatch(grantEnvelopeSigned(buildGrantWire(G_INTENT_ID_B, canonical_b, ACTION)), hooks2, GRANT_NOW_MS));
    try std.testing.expectEqual(@as(usize, 1), effect_count);
}

test "DAEMON_D durable seam: pending approval EXPIRES on restart, never restored (BE-GRANT-04)" {
    const sl = try initSeamLedger("pending");
    ensureGrantCerts();
    const executor_pub = cth.pubkeyOf(EXECUTOR_PREFIX);
    var canonical_a_buf: [64]u8 = undefined;
    const canonical_a = executorCanonical(&canonical_a_buf, "logs/deploy.log");
    var a_sender: [32]u8 = undefined;
    var a_sig: [64]u8 = undefined;
    var a_tbs: [64]u8 = undefined;
    // Run 1: the intent is admitted; the pending approval lives ONLY in the
    // in-memory table. No grant arrives, so nothing is committed to the log.
    {
        var res = resolver_mod.Resolver.init(&executor_pub);
        try res.add(canonical_a);
        var d = dispatch_mod.Dispatch.init(res, &executor_pub, std.mem.zeroes(session.Cert), cth.trustedSet());
        const hooks = dispatch_mod.Hooks{ .execute_effect = &testEffect, .cert_for_sender = &grantPathCertHook, .on_rejected = &noopRejected };
        const len_a = buildIntentBodyId(&intent_body_a, &G_INTENT_ID, canonical_a, ACTION);
        try std.testing.expectEqual(dispatch_mod.Outcome.intent_admitted, try d.dispatch(agentEnvelopeSigned(intent_body_a[0..len_a], &a_sender, &a_sig, &a_tbs), hooks, GRANT_NOW_MS));
    }
    // Restart: fresh dispatch state, recovered (empty) durable log.
    dispatch_mod.closeDurableLedger();
    var orphan_buf: [8]grant_ledger_mod.OrphanGrant = undefined;
    const n = try dispatch_mod.initDurableLedger(sl.io, sl.path, &orphan_buf);
    try std.testing.expectEqual(@as(usize, 0), n);
    defer closeSeamLedger(sl);
    // Run 2: the grant for intent A refuses at the intent match: the pending
    // approval was EXPIRED by the restart, not restored (BE-GRANT-04). The
    // durable ledger carries no pending row by design.
    var res2 = resolver_mod.Resolver.init(&executor_pub);
    try res2.add(canonical_a);
    var d2 = dispatch_mod.Dispatch.init(res2, &executor_pub, std.mem.zeroes(session.Cert), cth.trustedSet());
    const hooks2 = dispatch_mod.Hooks{ .execute_effect = &testEffect, .cert_for_sender = &grantPathCertHook, .on_rejected = &noopRejected };
    try std.testing.expectError(dispatch_mod.DispatchError.NoPendingIntent, d2.dispatch(grantEnvelopeSigned(buildGrantWire(G_INTENT_ID, canonical_a, ACTION)), hooks2, GRANT_NOW_MS));
}

test "DAEMON_D durable seam: crash residue surfaces one orphan; tombstone retires it (BE-GRANT-01a)" {
    // Construct the crash residue directly (D-061 ruling 2): a commit row for
    // G_GRANT_ID whose published tombstone never landed (a crash between the
    // commit fsync and the effect publish).
    var threaded = std.Io.Threaded.init_single_threaded;
    const io = threaded.io();
    const path = "/tmp/bolina_dispatch_orphan.log";
    const dir = std.Io.Dir.cwd();
    dir.deleteFile(io, path) catch {};
    {
        var lg = try grant_ledger_mod.GrantLedger.open(io, path);
        try lg.commitConsumed(G_GRANT_ID, GRANT_NOW_MS + 3_600_000, GRANT_NOW_MS);
        lg.close();
    }
    // Startup: recover surfaces exactly one orphan, grant_id intact.
    var orphan_buf: [8]grant_ledger_mod.OrphanGrant = undefined;
    const n = try dispatch_mod.initDurableLedger(io, path, &orphan_buf);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(G_GRANT_ID, orphan_buf[0].grant_id);
    // The caller publishes the interrupted Effect, then tombstones the orphan.
    try dispatch_mod.tombstoneOrphan(G_GRANT_ID);
    // Next restart: recovery is a no-op for that orphan.
    dispatch_mod.closeDurableLedger();
    const n2 = try dispatch_mod.initDurableLedger(io, path, &orphan_buf);
    try std.testing.expectEqual(@as(usize, 0), n2);
    dispatch_mod.closeDurableLedger();
    dir.deleteFile(io, path) catch {};
}

// ---------------------------------------------------------------------------
// Refusal happy path through the session seam: approver-signed refusal,
// DOMAIN_REFUSAL signature, REJECTED transition inside the verify frame,
// on_rejected fired exactly once. Plus the bad-signature gate test.
// ---------------------------------------------------------------------------

const R_INTENT_ID: [16]u8 = .{0x91} ** 16;
const R_NOTE = "resource quota exceeded";

var g_refusal_body: [160]u8 = undefined;
var r_sender: [32]u8 = undefined;
var r_sig: [64]u8 = undefined;
var r_tbs: [64]u8 = undefined;
var rejected_count: usize = 0;
var rejected_intent_id: [16]u8 = undefined;

fn testOnRejected(intent_id: []const u8) void {
    rejected_count += 1;
    @memcpy(&rejected_intent_id, intent_id);
}

fn buildRefusalWire(intent_id: [16]u8, note: []const u8) []u8 {
    var n: usize = 0;
    @memcpy(g_refusal_body[n..][0..16], &intent_id);
    n += 16;
    std.mem.writeInt(u16, g_refusal_body[n..][0..2], @intCast(note.len), .big);
    n += 2;
    @memcpy(g_refusal_body[n..][0..note.len], note);
    n += note.len;
    // tbs is every byte before sig; sign DOMAIN_REFUSAL || tbs (SPEC 5.4).
    var msg: [1 + 96]u8 = undefined;
    msg[0] = channel.DOMAIN_REFUSAL;
    @memcpy(msg[1..][0..n], g_refusal_body[0..n]);
    const sig = Ed.KeyPair.sign(cth.keypair(APPROVER_PREFIX), msg[0 .. 1 + n], null) catch unreachable;
    const sig_bytes = Ed.Signature.toBytes(sig);
    @memcpy(g_refusal_body[n..][0..64], &sig_bytes);
    n += 64;
    return g_refusal_body[0..n];
}

fn refusalEnvelopeSigned(body: []const u8) channel.Envelope {
    const kp = cth.keypair(APPROVER_PREFIX);
    r_sender = Ed.PublicKey.toBytes(kp.public_key);
    @memcpy(r_tbs[0..G_TBS.len], G_TBS);
    var msg: [1 + G_TBS.len]u8 = undefined;
    msg[0] = channel.DOMAIN_ENVELOPE;
    @memcpy(msg[1..], G_TBS);
    const sig = Ed.KeyPair.sign(kp, &msg, null) catch unreachable;
    r_sig = Ed.Signature.toBytes(sig);
    return .{
        .version = 2,
        .channel_id = &CHANNEL_ID,
        .sender = &r_sender,
        .seq = 1,
        .parent_count = 0,
        .parents = "",
        .ts = 1000,
        .body_type = channel.BODY_REFUSAL,
        .body = body,
        .tbs = r_tbs[0..G_TBS.len],
        .sig = &r_sig,
    };
}

test "DAEMON_A refusal happy path: REJECTED inside the frame, on_rejected once" {
    rejected_count = 0;
    ensureGrantCerts();
    const executor_pub = cth.pubkeyOf(EXECUTOR_PREFIX);
    var res = resolver_mod.Resolver.init(&executor_pub);
    var canonical_buf_r: [64]u8 = undefined;
    const canonical_r = executorCanonical(&canonical_buf_r, "logs/deploy.log");
    try res.add(canonical_r);
    var d = dispatch_mod.Dispatch.init(res, &executor_pub, std.mem.zeroes(session.Cert), cth.trustedSet());
    const hooks = dispatch_mod.Hooks{ .execute_effect = &testEffect, .cert_for_sender = &grantPathCertHook, .on_rejected = &testOnRejected };
    // 1. The agent admits the intent (envelope signed by the agent key).
    const len_i = buildIntentBodyId(&intent_body_a, &R_INTENT_ID, canonical_r, ACTION);
    var a_sender: [32]u8 = undefined;
    var a_sig: [64]u8 = undefined;
    var a_tbs: [64]u8 = undefined;
    try std.testing.expectEqual(dispatch_mod.Outcome.intent_admitted, try d.dispatch(agentEnvelopeSigned(intent_body_a[0..len_i], &a_sender, &a_sig, &a_tbs), hooks, GRANT_NOW_MS));
    // 2. The approver refuses it: REJECTED transition inside the verify frame.
    const refusal_wire = buildRefusalWire(R_INTENT_ID, R_NOTE);
    try std.testing.expectEqual(dispatch_mod.Outcome.refusal_applied, try d.dispatch(refusalEnvelopeSigned(refusal_wire), hooks, GRANT_NOW_MS));
    // 3. The intent is REJECTED; on_rejected fired exactly once, literal id.
    var found_rejected = false;
    for (d.intents.entries[0..d.intents.len]) |e| {
        if (std.mem.eql(u8, &e.intent_id, &R_INTENT_ID) and e.state == .rejected) found_rejected = true;
    }
    try std.testing.expect(found_rejected);
    try std.testing.expectEqual(@as(usize, 1), rejected_count);
    try std.testing.expectEqual(R_INTENT_ID, rejected_intent_id);
}

test "DAEMON_A bad envelope signature refused at the structural gate" {
    const executor_pub = cth.pubkeyOf(EXECUTOR_PREFIX);
    var res = resolver_mod.Resolver.init(&executor_pub);
    var canonical_buf_b: [64]u8 = undefined;
    const canonical_b = executorCanonical(&canonical_buf_b, "logs/deploy.log");
    try res.add(canonical_b);
    var d = dispatch_mod.Dispatch.init(res, &executor_pub, std.mem.zeroes(session.Cert), cth.trustedSet());
    const hooks = dispatch_mod.Hooks{ .execute_effect = &testEffect, .cert_for_sender = &grantPathCertHook, .on_rejected = &testOnRejected };
    const len_i = buildIntentBodyId(&intent_body_a, &R_INTENT_ID, canonical_b, ACTION);
    var a_sender: [32]u8 = undefined;
    var a_sig: [64]u8 = undefined;
    var a_tbs: [64]u8 = undefined;
    const env = agentEnvelopeSigned(intent_body_a[0..len_i], &a_sender, &a_sig, &a_tbs);
    a_sig[0] ^= 0xFF; // corrupt the envelope signature
    try std.testing.expectError(dispatch_mod.DispatchError.BadEnvelope, d.dispatch(env, hooks, GRANT_NOW_MS));
    try std.testing.expectEqual(@as(usize, 0), d.intents.len);
}

// ---------------------------------------------------------------------------
// F4 regression guard (RED-TEAM-10, adjudicated GAP not layering): the grant
// execution path does not consult revocation. GrantContext (verify.zig) has
// no is_revoked seam, so a key durably revoked in the ledger is ignored at
// the authority->effect checkpoint (the comment at verify.zig:454 says
// revocation is consulted "as of this use, not of cache fill"; the grant
// path IS a use, yet it does not consult). This test pins the CURRENT
// behavior. The Phase-B wiring HAS landed (D-063): is_revoked is now a
// GrantContext field, consulted at checks 3-4 and backed by
// grant_ledger.isRevoked durably. The grant below is now REFUSED with
// ApproverRevoked. This test guards against silent regression (removal of
// the is_revoked seam) and lifts F4 from DECLARED to TESTED.
// ---------------------------------------------------------------------------

test "F4 regression guard: revoked-approver grant REFUSED, BE-REV-02 wired at checks 3-4" {
    var threaded = std.Io.Threaded.init_single_threaded;
    const io = threaded.io();
    const path = "/tmp/bolina_dispatch_f4.log";
    const dir = std.Io.Dir.cwd();
    dir.deleteFile(io, path) catch {};
    const approver_pub = cth.pubkeyOf(APPROVER_PREFIX);
    // Pre-seed the durable ledger with the approver revocation, THEN open
    // the dispatch active ledger over it so recover() loads the revoked key
    // into the active cache. The ledger demonstrably HOLDS the revocation.
    {
        var lg = try grant_ledger_mod.GrantLedger.open(io, path);
        try lg.commitRevocation(approver_pub, cth.PRIVILEGED_CERT_NOT_AFTER);
        lg.close();
    }
    var orphan_buf: [8]grant_ledger_mod.OrphanGrant = undefined;
    const n = try dispatch_mod.initDurableLedger(io, path, &orphan_buf);
    try std.testing.expectEqual(@as(usize, 0), n); // a revoke row is not an orphan
    // Witness: the durable revocation is recorded and recoverable.
    {
        var view = try grant_ledger_mod.GrantLedger.open(io, path);
        defer view.close();
        _ = try view.recover();
        try std.testing.expect(view.isRevoked(approver_pub));
    }
    // Drive the grant happy path with the standard fixtures: the approver
    // whose key is durably revoked signs the grant. Now the grant is REFUSED.
    effect_count = 0;
    ensureGrantCerts();
    const executor_pub = cth.pubkeyOf(EXECUTOR_PREFIX);
    var res = resolver_mod.Resolver.init(&executor_pub);
    var f4_canonical_buf: [64]u8 = undefined;
    const canonical = executorCanonical(&f4_canonical_buf, "logs/deploy.log");
    try res.add(canonical);
    var d = dispatch_mod.Dispatch.init(res, &executor_pub, std.mem.zeroes(session.Cert), cth.trustedSet());
    const hooks = dispatch_mod.Hooks{ .execute_effect = &testEffect, .cert_for_sender = &grantPathCertHook, .on_rejected = &noopRejected };
    const len_a = buildIntentBodyId(&intent_body_a, &G_INTENT_ID, canonical, ACTION);
    var a_sender: [32]u8 = undefined;
    var a_sig: [64]u8 = undefined;
    var a_tbs: [64]u8 = undefined;
    try std.testing.expectEqual(dispatch_mod.Outcome.intent_admitted, try d.dispatch(agentEnvelopeSigned(intent_body_a[0..len_a], &a_sender, &a_sig, &a_tbs), hooks, GRANT_NOW_MS));
    const grant_wire = buildGrantWire(G_INTENT_ID, canonical, ACTION);
    try std.testing.expectError(verify.VerifyError.ApproverRevoked, d.dispatch(grantEnvelopeSigned(grant_wire), hooks, GRANT_NOW_MS));
    try std.testing.expectEqual(@as(usize, 0), effect_count); // F4: revoked approver, effect refused
    dispatch_mod.closeDurableLedger();
    dir.deleteFile(io, path) catch {};
}

// ---------------------------------------------------------------------------
// F4 subject guard (RED-TEAM-10 closeout, D-064 check 4): the grant path
// consults revocation for the SUBJECT too, not only the approver. A durably
// revoked subject cannot turn a grant into an effect: verify refuses with
// SubjectRevoked at check 4, after the approver checks pass. Literal binding
// test (D-027) for the check-4 half of the F4 wiring.
// ---------------------------------------------------------------------------

test "F4 subject guard: revoked-subject grant REFUSED, BE-REV-02 wired at check 4" {
    var threaded = std.Io.Threaded.init_single_threaded;
    const io = threaded.io();
    const path = "/tmp/bolina_dispatch_f4_subject.log";
    const dir = std.Io.Dir.cwd();
    dir.deleteFile(io, path) catch {};
    const subject_pub = cth.pubkeyOf(AGENT_PREFIX);
    // Pre-seed the durable ledger with the subject revocation, THEN open the
    // dispatch active ledger over it so recover() loads the revoked key into
    // the active cache. The approver stays unrevoked, so checks 1-3 pass and
    // check 4 is the refusal point.
    {
        var lg = try grant_ledger_mod.GrantLedger.open(io, path);
        try lg.commitRevocation(subject_pub, cth.PRIVILEGED_CERT_NOT_AFTER);
        lg.close();
    }
    var orphan_buf: [8]grant_ledger_mod.OrphanGrant = undefined;
    const n = try dispatch_mod.initDurableLedger(io, path, &orphan_buf);
    try std.testing.expectEqual(@as(usize, 0), n); // a revoke row is not an orphan
    effect_count = 0;
    ensureGrantCerts();
    const executor_pub = cth.pubkeyOf(EXECUTOR_PREFIX);
    var res = resolver_mod.Resolver.init(&executor_pub);
    var f4s_canonical_buf: [64]u8 = undefined;
    const canonical = executorCanonical(&f4s_canonical_buf, "logs/deploy.log");
    try res.add(canonical);
    var d = dispatch_mod.Dispatch.init(res, &executor_pub, std.mem.zeroes(session.Cert), cth.trustedSet());
    const hooks = dispatch_mod.Hooks{ .execute_effect = &testEffect, .cert_for_sender = &grantPathCertHook, .on_rejected = &noopRejected };
    const len_a = buildIntentBodyId(&intent_body_a, &G_INTENT_ID_B, canonical, ACTION);
    var a_sender: [32]u8 = undefined;
    var a_sig: [64]u8 = undefined;
    var a_tbs: [64]u8 = undefined;
    try std.testing.expectEqual(dispatch_mod.Outcome.intent_admitted, try d.dispatch(agentEnvelopeSigned(intent_body_a[0..len_a], &a_sender, &a_sig, &a_tbs), hooks, GRANT_NOW_MS));
    const grant_wire = buildGrantWire(G_INTENT_ID_B, canonical, ACTION);
    try std.testing.expectError(verify.VerifyError.SubjectRevoked, d.dispatch(grantEnvelopeSigned(grant_wire), hooks, GRANT_NOW_MS));
    try std.testing.expectEqual(@as(usize, 0), effect_count); // F4: revoked subject, effect refused
    dispatch_mod.closeDurableLedger();
    dir.deleteFile(io, path) catch {};
}

// ---------------------------------------------------------------------------
// F4 fail-safe (RED-TEAM-10 closeout, D-064 ruling 1): with NO durable ledger
// initialized, the grant checkpoint refuses every grant. The revocation set is
// part of the durable authority state; without it loaded, no grant may turn
// into an effect. isRevokedHook returns true (revoked) when the module slot is
// null, and check 3 fires before check 11's consumed-grant fail-safe (D-064
// ruling 3 ordering), so the refusal surfaces as ApproverRevoked. Literal
// binding test (D-027).
// ---------------------------------------------------------------------------

test "F4 fail-safe: no durable ledger, grant REFUSED before the effect (D-064 ruling 1)" {
    dispatch_mod.closeDurableLedger(); // module slot null regardless of prior tests
    effect_count = 0;
    ensureGrantCerts();
    const executor_pub = cth.pubkeyOf(EXECUTOR_PREFIX);
    var res = resolver_mod.Resolver.init(&executor_pub);
    var f4f_canonical_buf: [64]u8 = undefined;
    const canonical = executorCanonical(&f4f_canonical_buf, "logs/deploy.log");
    try res.add(canonical);
    var d = dispatch_mod.Dispatch.init(res, &executor_pub, std.mem.zeroes(session.Cert), cth.trustedSet());
    const hooks = dispatch_mod.Hooks{ .execute_effect = &testEffect, .cert_for_sender = &grantPathCertHook, .on_rejected = &noopRejected };
    const len_a = buildIntentBodyId(&intent_body_a, &G_INTENT_ID_B, canonical, ACTION);
    var a_sender: [32]u8 = undefined;
    var a_sig: [64]u8 = undefined;
    var a_tbs: [64]u8 = undefined;
    // Intent admission does not touch the ledger; it succeeds.
    try std.testing.expectEqual(dispatch_mod.Outcome.intent_admitted, try d.dispatch(agentEnvelopeSigned(intent_body_a[0..len_a], &a_sender, &a_sig, &a_tbs), hooks, GRANT_NOW_MS));
    const grant_wire = buildGrantWire(G_INTENT_ID_B, canonical, ACTION);
    try std.testing.expectError(verify.VerifyError.ApproverRevoked, d.dispatch(grantEnvelopeSigned(grant_wire), hooks, GRANT_NOW_MS));
    try std.testing.expectEqual(@as(usize, 0), effect_count); // no ledger: fail-safe refusal, effect never runs
}
