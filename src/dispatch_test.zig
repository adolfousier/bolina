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
    const Ed = std.crypto.sign.Ed25519;
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
    var n: usize = 0;
    @memcpy(out[n..][0..16], &INTENT_ID);
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
    var grant_body: [256]u8 = undefined;
    var n: usize = 0;
    grant_body[n] = 2; // version
    n += 1;
    @memcpy(grant_body[n..][0..16], &GRANT_ID_FIX); // grant_id
    n += 16;
    @memcpy(grant_body[n..][0..16], &MATCHLESS_INTENT_ID); // intent_id, matches nothing
    n += 16;
    @memset(grant_body[n .. n + 96], 0x33); // approver, subject, executor
    n += 96;
    std.mem.writeInt(u16, grant_body[n..][0..2], 4, .big);
    n += 2;
    @memcpy(grant_body[n..][0..4], "res0");
    n += 4;
    @memset(grant_body[n .. n + 32], 0x44); // action_digest
    n += 32;
    std.mem.writeInt(u64, grant_body[n..][0..8], 9999, .big); // not_after
    n += 8;
    @memset(grant_body[n .. n + 64], 0x55); // sig
    n += 64;
    try std.testing.expectError(dispatch_mod.DispatchError.NoPendingIntent, d.dispatch(signedEnvelope(channel.BODY_GRANT, grant_body[0..n]), TEST_HOOKS, 1000));
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
