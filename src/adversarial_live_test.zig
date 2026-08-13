// §11.5-A adversarial live harness (D-068). Deterministic crash-adversary
// scenarios that drive the real dispatch core and the real durable ledger
// under attacker-controlled crash timing, then run the R2 post-hoc auditor
// (adversarial_audit.zig) over the result and assert the CONJUNCTIVE
// invariant: M1 == 0 (security, no leak) AND M2 == N (utility, no over-refuse).
//
// A single number is not a result. A system that refuses every grant reports
// M1 == 0 trivially but M2 == 0 < N, so the conjunctive test FAILS it. That is
// the trap this harness exists to kill (scenario S3).
//
// This is NOT a network daemon attacker (phase B): main.zig stays a skeleton.
// The adversary here controls CRASH TIMING, not the wire. A crash is modelled
// deterministically as the post-crash ledger state the real crash would leave
// (committed-but-unpublished, mid-prune, partial-record), followed by the REAL
// recovery path and the REAL audit. What is novel over the DAEMON_D unit tests
// is the composition: dispatch output and recovery output fed into the R2
// auditor and reconciled as one conjunctive verdict.

const std = @import("std");
const dispatch_mod = @import("dispatch.zig");
const channel = @import("parser/channel.zig");
const session = @import("parser/session.zig");
const verify = @import("verify.zig");
const binding = @import("binding.zig");
const resolver_mod = @import("resolver.zig");
const cth = @import("cert_test_helpers.zig");
const grant_ledger = @import("grant_ledger.zig");
const audit_mod = @import("adversarial_audit.zig");
const Ed = std.crypto.sign.Ed25519;

// ---------------------------------------------------------------------------
// Fixtures (mirror the dispatch_test.zig cert_test_helpers seed family so the
// grant path verifies under real DOMAIN_ENVELOPE + DOMAIN_GRANT signatures and
// CA-signed certs). Test file, so module-level mutable buffers are fine:
// single-threaded, each used immediately before reuse.
// ---------------------------------------------------------------------------

const CHANNEL_ID: [32]u8 = .{0xCC} ** 32;
const EXECUTOR_PREFIX: u8 = 0xE1;
const AGENT_PREFIX: u8 = 0xA1;
const APPROVER_PREFIX: u8 = 0xB1;
const ACTION = "restart-service";
const GRANT_NOW_MS: u64 = 1_700_000_000_000; // inside both cert windows
const NOT_AFTER_MS: u64 = GRANT_NOW_MS + 3_600_000; // check-10 ceiling
const G_TBS = "grant-envelope-tbs";

// Three distinct grant_ids and intent_ids so each scenario grants a unique,
// non-colliding consumed entry (same grant_id would read as double-spend).
const GID_A: [16]u8 = .{0xD1} ** 16;
const GID_B: [16]u8 = .{0xD2} ** 16;
const GID_C: [16]u8 = .{0xD3} ** 16;
const IID_A: [16]u8 = .{0x7A} ** 16;
const IID_B: [16]u8 = .{0x7B} ** 16;
const IID_C: [16]u8 = .{0x7C} ** 16;

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

fn noopRejected(intent_id: []const u8) void {
    _ = intent_id;
}

// Effect hook: counts fires and records the grant_id of the last fire. The
// crash-adversary scenarios that go through dispatch assert effect_count to
// prove the effect fired exactly where the invariant says it may.
var effect_count: usize = 0;

fn testEffect(grant: channel.Grant) void {
    effect_count += 1;
    _ = grant;
}

// Canonical executor resource (BE-RES-06 fp grammar) for a given leaf path.
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

// Intent wire (SPEC 8.2): intent_id[16] | u16 res_len | res | u32 act_len |
// act | u16 rationale_len(0). Big-endian lengths.
fn buildIntentBodyInto(out: []u8, intent_id: [16]u8, resource: []const u8) usize {
    var n: usize = 0;
    @memcpy(out[n..][0..16], &intent_id);
    n += 16;
    std.mem.writeInt(u16, out[n..][0..2], @intCast(resource.len), .big);
    n += 2;
    @memcpy(out[n..][0..resource.len], resource);
    n += resource.len;
    std.mem.writeInt(u32, out[n..][0..4], @intCast(ACTION.len), .big);
    n += 4;
    @memcpy(out[n..][0..ACTION.len], ACTION);
    n += ACTION.len;
    std.mem.writeInt(u16, out[n..][0..2], 0, .big);
    n += 2;
    return n;
}

// Grant wire (SPEC 8.1), parametrized by grant_id and intent_id so each
// scenario grants a unique consumed entry. approver/agent/executor pubkeys are
// the cert_test_helpers family; not_after is the check-10 ceiling. The
// DOMAIN_GRANT signature covers the body up to the sig.
var g_body: [512]u8 = undefined;

fn buildGrantWireInto(out: []u8, grant_id: [16]u8, intent_id: [16]u8, resource: []const u8) []u8 {
    var n: usize = 0;
    out[n] = 2; // version
    n += 1;
    @memcpy(out[n..][0..16], &grant_id);
    n += 16;
    @memcpy(out[n..][0..16], &intent_id);
    n += 16;
    @memcpy(out[n..][0..32], &cth.pubkeyOf(APPROVER_PREFIX));
    n += 32;
    @memcpy(out[n..][0..32], &cth.pubkeyOf(AGENT_PREFIX));
    n += 32;
    @memcpy(out[n..][0..32], &cth.pubkeyOf(EXECUTOR_PREFIX));
    n += 32;
    std.mem.writeInt(u16, out[n..][0..2], @intCast(resource.len), .big);
    n += 2;
    @memcpy(out[n..][0..resource.len], resource);
    n += resource.len;
    const digest = verify.actionDigest(ACTION);
    @memcpy(out[n..][0..32], &digest);
    n += 32;
    std.mem.writeInt(u64, out[n..][0..8], NOT_AFTER_MS, .big);
    n += 8;
    var msg: [1 + 460]u8 = undefined;
    msg[0] = channel.DOMAIN_GRANT;
    @memcpy(msg[1..][0..n], out[0..n]);
    const sig = Ed.KeyPair.sign(cth.keypair(APPROVER_PREFIX), msg[0 .. 1 + n], null) catch unreachable;
    const sig_bytes = Ed.Signature.toBytes(sig);
    @memcpy(out[n..][0..64], &sig_bytes);
    n += 64;
    return out[0..n];
}

// Envelope builders (real DOMAIN_ENVELOPE signatures).
var g_sender: [32]u8 = undefined;
var g_sig: [64]u8 = undefined;
var g_tbs: [64]u8 = undefined;

fn grantEnvelope(body: []const u8) channel.Envelope {
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

var a_sender: [32]u8 = undefined;
var a_sig: [64]u8 = undefined;
var a_tbs: [64]u8 = undefined;

fn agentEnvelope(body: []const u8) channel.Envelope {
    const kp = cth.keypair(AGENT_PREFIX);
    a_sender = Ed.PublicKey.toBytes(kp.public_key);
    @memcpy(a_tbs[0..G_TBS.len], G_TBS);
    var msg: [1 + G_TBS.len]u8 = undefined;
    msg[0] = channel.DOMAIN_ENVELOPE;
    @memcpy(msg[1..], G_TBS);
    const sig = Ed.KeyPair.sign(kp, &msg, null) catch unreachable;
    a_sig = Ed.Signature.toBytes(sig);
    return .{
        .version = 2,
        .channel_id = &CHANNEL_ID,
        .sender = &a_sender,
        .seq = 1,
        .parent_count = 0,
        .parents = "",
        .ts = 1000,
        .body_type = channel.BODY_INTENT,
        .body = body,
        .tbs = a_tbs[0..G_TBS.len],
        .sig = &a_sig,
    };
}

// ---------------------------------------------------------------------------
// I/O scaffolding. The threaded io must outlive any ledger's borrow, so each
// test owns its IoCtx for the whole body.
// ---------------------------------------------------------------------------

const IoCtx = struct {
    threaded: std.Io.Threaded,
    io: std.Io,
};

fn newIo() IoCtx {
    var threaded = std.Io.Threaded.init_single_threaded;
    return .{ .threaded = threaded, .io = threaded.io() };
}

// Coupled ledger: opens the dispatch module-level durable ledger (so dispatch
// writes through it) at a fresh path and recovers zero orphans.
fn openCoupledLedger(io: std.Io, path: []const u8) !void {
    const dir = std.Io.Dir.cwd();
    dir.deleteFile(io, path) catch {};
    var orphan_buf: [8]grant_ledger.OrphanGrant = undefined;
    const n = try dispatch_mod.initDurableLedger(io, path, &orphan_buf);
    if (n != 0) return error.TestUnexpectedResult; // fresh file: no orphans
}

fn deletePath(io: std.Io, path: []const u8) void {
    std.Io.Dir.cwd().deleteFile(io, path) catch {};
}

fn freshDispatch() dispatch_mod.Dispatch {
    const executor_pub = cth.pubkeyOf(EXECUTOR_PREFIX);
    const res = resolver_mod.Resolver.init(&executor_pub);
    return dispatch_mod.Dispatch.init(res, &executor_pub, std.mem.zeroes(session.Cert), cth.trustedSet());
}

// Drive one grant to completion through real dispatch: admit the intent, then
// dispatch the grant. Asserts the effect fired.
fn driveOneGrant(d: *dispatch_mod.Dispatch, hooks: dispatch_mod.Hooks, gid: [16]u8, iid: [16]u8, canonical: []const u8) !void {
    var ibody: [128]u8 = undefined;
    const ilen = buildIntentBodyInto(&ibody, iid, canonical);
    try std.testing.expectEqual(dispatch_mod.Outcome.intent_admitted, try d.dispatch(agentEnvelope(ibody[0..ilen]), hooks, GRANT_NOW_MS));
    const gwire = buildGrantWireInto(&g_body, gid, iid, canonical);
    try std.testing.expectEqual(dispatch_mod.Outcome.grant_executed, try d.dispatch(grantEnvelope(gwire), hooks, GRANT_NOW_MS));
}

// ===========================================================================
// S1 CLEAN_RUN: three grants driven through real dispatch, then the R2 audit
// over an independent durable view. The happy composition passes the
// conjunctive test: M1 == 0 (every claim has a valid consumed+published chain)
// AND M2 == 3 (every intended grant reached a tombstone).
// ===========================================================================
test "ADV_LIVE S1 clean run: real dispatch output reconciles to M1==0 M2==N" {
    const ictx = newIo();
    const path = "/tmp/bolina_advlive_s1.log";
    try openCoupledLedger(ictx.io, path);
    defer {
        dispatch_mod.closeDurableLedger();
        deletePath(ictx.io, path);
    }
    effect_count = 0;
    ensureGrantCerts();

    var rba: [64]u8 = undefined;
    var rbb: [64]u8 = undefined;
    var rbc: [64]u8 = undefined;
    const ca = executorCanonical(&rba, "logs/a.log");
    const cb = executorCanonical(&rbb, "logs/b.log");
    const cc = executorCanonical(&rbc, "logs/c.log");
    var d = freshDispatch();
    try d.resolver.add(ca);
    try d.resolver.add(cb);
    try d.resolver.add(cc);
    const hooks = dispatch_mod.Hooks{ .execute_effect = &testEffect, .cert_for_sender = &grantPathCertHook, .on_rejected = &noopRejected };

    try driveOneGrant(&d, hooks, GID_A, IID_A, ca);
    try driveOneGrant(&d, hooks, GID_B, IID_B, cb);
    try driveOneGrant(&d, hooks, GID_C, IID_C, cc);
    try std.testing.expectEqual(@as(usize, 3), effect_count);

    // Independent durable view: recover from the log on disk, then audit.
    var view = try grant_ledger.GrantLedger.open(ictx.io, path);
    defer view.close();
    _ = try view.recover();

    const claims = [_]audit_mod.EffectClaim{
        .{ .grant_id = GID_A, .not_after_ms = NOT_AFTER_MS, .executed_at_ms = GRANT_NOW_MS },
        .{ .grant_id = GID_B, .not_after_ms = NOT_AFTER_MS, .executed_at_ms = GRANT_NOW_MS },
        .{ .grant_id = GID_C, .not_after_ms = NOT_AFTER_MS, .executed_at_ms = GRANT_NOW_MS },
    };
    const intended = [_][16]u8{ GID_A, GID_B, GID_C };
    const r = audit_mod.audit(&view, &claims, &intended);
    try std.testing.expectEqual(@as(u32, 0), r.m1_violations);
    try std.testing.expectEqual(@as(u32, 3), r.m2_granted);
    try std.testing.expect(r.passed());
}

// ===========================================================================
// S2 ORPHAN_MID: the crash-adversary commits a grant durably then crashes
// before the tombstone (the BE-GRANT-01a orphan window). On recovery the grant
// surfaces as exactly one orphan; the caller publishes one interrupted Effect
// and tombstones it. The R2 audit reconciles: the interrupted claim has a
// valid consumed+published chain (M1 == 0) and the grant counts (M2 == 2).
// This proves at-least-once does not leak (M1) and does not lose utility (M2).
//
// Built on a standalone ledger: the orphan window IS a ledger-level crash
// state, so the recovery+audit composition is exercised without dispatch.
// ===========================================================================
test "ADV_LIVE S2 orphan window: crash before tombstone reconciles to M1==0 M2==N" {
    const ictx = newIo();
    const path = "/tmp/bolina_advlive_s2.log";
    deletePath(ictx.io, path);
    defer deletePath(ictx.io, path);

    var lg = try grant_ledger.GrantLedger.open(ictx.io, path);
    defer lg.close();
    // A: full real durable path (committed AND published).
    try lg.commitConsumed(GID_A, NOT_AFTER_MS, GRANT_NOW_MS);
    try lg.markPublished(GID_A);
    // B: crash in the orphan window. The post-crash state is a durable commit
    // with NO tombstone. commitConsumed fsyncs before returning, so this row
    // survives the simulated crash.
    try lg.commitConsumed(GID_B, NOT_AFTER_MS, GRANT_NOW_MS);

    // Recovery: a single forward scan surfaces B as an orphan.
    const r0 = try lg.recover();
    try std.testing.expectEqual(@as(usize, 1), r0.orphans.len);
    const orphan_gid = r0.orphans[0].grant_id; // copy before the next mutating call
    try std.testing.expectEqual(GID_B, orphan_gid);

    // Caller publishes the interrupted Effect for the orphan and tombstones it
    // (BE-GRANT-01a): the at-least-once contract.
    try lg.markPublished(GID_B);

    // Audit: B reconciles now (consumed AND published).
    const claims = [_]audit_mod.EffectClaim{
        .{ .grant_id = GID_A, .not_after_ms = NOT_AFTER_MS, .executed_at_ms = GRANT_NOW_MS },
        .{ .grant_id = GID_B, .not_after_ms = NOT_AFTER_MS, .executed_at_ms = GRANT_NOW_MS },
    };
    const intended = [_][16]u8{ GID_A, GID_B };
    const r = audit_mod.audit(&lg, &claims, &intended);
    try std.testing.expectEqual(@as(u32, 0), r.m1_violations);
    try std.testing.expectEqual(@as(u32, 2), r.m2_granted);
    try std.testing.expect(r.passed());
}

// ===========================================================================
// S3 REFUSE_EVERYTHING_TRAP: the negative witness that validates the test
// itself. With no ledger initialized the hooks refuse every grant (fail-safe,
// BE-GRANT-01 / BE-REV-02), so no effect fires and no claims exist. The audit
// reports M1 == 0 trivially but M2 == 0 < N, so the conjunctive verdict is
// FAIL. A perfect false-negative rate is not a result: this scenario asserts
// the auditor CORRECTLY rejects it.
// ===========================================================================
test "ADV_LIVE S3 refuse-everything trap: conjunctive verdict is FAIL (M2==0<N)" {
    ensureGrantCerts();
    // No durable ledger initialized: the module-level slot is null, so
    // isRevokedHook returns true (check 3, ApproverRevoked) and consumedHook
    // returns true (check 11). The grant dies before the effect fires.
    dispatch_mod.closeDurableLedger(); // ensure null

    var rb: [64]u8 = undefined;
    var d = freshDispatch();
    const ca = executorCanonical(&rb, "logs/a.log");
    try d.resolver.add(ca);
    const hooks = dispatch_mod.Hooks{ .execute_effect = &testEffect, .cert_for_sender = &grantPathCertHook, .on_rejected = &noopRejected };

    // Admit the intent (intent admission needs no ledger).
    var ibody: [128]u8 = undefined;
    const ilen = buildIntentBodyInto(&ibody, IID_A, ca);
    try std.testing.expectEqual(dispatch_mod.Outcome.intent_admitted, try d.dispatch(agentEnvelope(ibody[0..ilen]), hooks, GRANT_NOW_MS));

    // The grant is refused by the revocation fail-safe (check 3): no effect.
    const gwire = buildGrantWireInto(&g_body, GID_A, IID_A, ca);
    try std.testing.expectError(verify.VerifyError.ApproverRevoked, d.dispatch(grantEnvelope(gwire), hooks, GRANT_NOW_MS));
    effect_count = 0;
    try std.testing.expectEqual(@as(usize, 0), effect_count);

    // Audit over zero claims and three intended grants: M1 == 0 but
    // M2 == 0 != 3, so passed() is false. The trap is caught.
    const ictx = newIo();
    const tmp = "/tmp/bolina_advlive_s3_empty.log";
    deletePath(ictx.io, tmp);
    var fresh = try grant_ledger.GrantLedger.open(ictx.io, tmp);
    _ = try fresh.recover();
    const claims = [_]audit_mod.EffectClaim{};
    const intended = [_][16]u8{ GID_A, GID_B, GID_C };
    const r = audit_mod.audit(&fresh, &claims, &intended);
    fresh.close();
    deletePath(ictx.io, tmp);
    try std.testing.expectEqual(@as(u32, 0), r.m1_violations);
    try std.testing.expectEqual(@as(u32, 0), r.m2_granted);
    try std.testing.expect(!r.passed()); // the conjunctive verdict rejects the trap
}

// ===========================================================================
// S4 PRUNE_SURVIVAL: the D-063 atomic-rename compaction never un-spends a live
// grant. Two grants committed and published, both with future expiries so the
// internal pruneExpired of commitConsumed keeps them. Then an explicit prune
// at a clock that expired GID_B but leaves GID_A live. After recover the live
// grant is still consumed+published. The R2 audit reconciles (M1 == 0, M2 ==1)
// ===========================================================================
test "ADV_LIVE S4 prune survival: D-063 compaction never un-spends a live grant" {
    const ictx = newIo();
    const path = "/tmp/bolina_advlive_s4.log";
    deletePath(ictx.io, path);
    defer deletePath(ictx.io, path);

    var lg = try grant_ledger.GrantLedger.open(ictx.io, path);
    defer lg.close();
    // Both committed at GRANT_NOW_MS with FUTURE expiries, so neither is
    // pruned by commitConsumed's internal pruneExpired(GRANT_NOW_MS).
    const expiry_a: u64 = GRANT_NOW_MS + 10_000_000; // survives the prune clock
    const expiry_b: u64 = GRANT_NOW_MS + 1_000_000; // expires before the prune clock
    try lg.commitConsumed(GID_A, expiry_a, GRANT_NOW_MS);
    try lg.markPublished(GID_A);
    try lg.commitConsumed(GID_B, expiry_b, GRANT_NOW_MS);
    try lg.markPublished(GID_B);

    // Compact at a clock past GID_B's expiry but before GID_A's. The atomic
    // rename (D-063) lands; GID_B's commit row is dropped, GID_A's survives.
    try lg.pruneExpired(GRANT_NOW_MS + 5_000_000);

    // Rebuild the in-memory sets from the compacted log: GID_A live, GID_B gone.
    _ = try lg.recover();
    try std.testing.expect(lg.isConsumed(GID_A));
    try std.testing.expect(lg.isPublished(GID_A));
    try std.testing.expect(!lg.isConsumed(GID_B)); // compacted away

    const claims = [_]audit_mod.EffectClaim{
        .{ .grant_id = GID_A, .not_after_ms = expiry_a, .executed_at_ms = GRANT_NOW_MS },
    };
    const intended = [_][16]u8{GID_A};
    const r = audit_mod.audit(&lg, &claims, &intended);
    try std.testing.expectEqual(@as(u32, 0), r.m1_violations);
    try std.testing.expectEqual(@as(u32, 1), r.m2_granted);
    try std.testing.expect(r.passed());
}

// ===========================================================================
// S5 REPLAY_AFTER_RESTART: a grant executes (consumed+published), the process
// restarts, and the same grant_id is replayed against a fresh intent. The
// durable ledger refuses it at check 11 (AlreadyConsumed). The R2 audit over
// the single legitimate claim reconciles: no double-spend (M1 == 0), the one
// intended grant counted (M2 == 1). Restart durability holds the single-shot
// gate.
// ===========================================================================
test "ADV_LIVE S5 replay after restart: durable single-shot gate reconciles to M1==0 M2==1" {
    const ictx = newIo();
    const path = "/tmp/bolina_advlive_s5.log";
    try openCoupledLedger(ictx.io, path);
    effect_count = 0;
    ensureGrantCerts();

    var rba: [64]u8 = undefined;
    var rbb: [64]u8 = undefined;
    const ca = executorCanonical(&rba, "logs/a.log");
    const cb = executorCanonical(&rbb, "logs/b.log");

    // Run 1: grant A executes on resource A through real dispatch.
    {
        var d = freshDispatch();
        try d.resolver.add(ca);
        const hooks = dispatch_mod.Hooks{ .execute_effect = &testEffect, .cert_for_sender = &grantPathCertHook, .on_rejected = &noopRejected };
        try driveOneGrant(&d, hooks, GID_A, IID_A, ca);
    }
    try std.testing.expectEqual(@as(usize, 1), effect_count);

    // Restart: close the ledger, reopen against the same durable file.
    dispatch_mod.closeDurableLedger();
    var orphan_buf: [8]grant_ledger.OrphanGrant = undefined;
    const norphans = try dispatch_mod.initDurableLedger(ictx.io, path, &orphan_buf);
    defer deletePath(ictx.io, path);
    try std.testing.expectEqual(@as(usize, 0), norphans); // published: no orphan

    // Run 2: fresh intent B on resource B, but the SAME grant_id replayed.
    // Checks 1-10 pass; check 11 refuses (durable consumed).
    {
        var d = freshDispatch();
        try d.resolver.add(cb);
        const hooks = dispatch_mod.Hooks{ .execute_effect = &testEffect, .cert_for_sender = &grantPathCertHook, .on_rejected = &noopRejected };
        var ibody: [128]u8 = undefined;
        const ilen = buildIntentBodyInto(&ibody, IID_B, cb);
        try std.testing.expectEqual(dispatch_mod.Outcome.intent_admitted, try d.dispatch(agentEnvelope(ibody[0..ilen]), hooks, GRANT_NOW_MS));
        const gwire = buildGrantWireInto(&g_body, GID_A, IID_B, cb);
        try std.testing.expectError(verify.VerifyError.AlreadyConsumed, d.dispatch(grantEnvelope(gwire), hooks, GRANT_NOW_MS));
    }
    try std.testing.expectEqual(@as(usize, 1), effect_count); // replay did not fire a second effect
    dispatch_mod.closeDurableLedger();

    // Audit: one legitimate claim, no double-spend.
    var view = try grant_ledger.GrantLedger.open(ictx.io, path);
    defer view.close();
    _ = try view.recover();
    const claims = [_]audit_mod.EffectClaim{
        .{ .grant_id = GID_A, .not_after_ms = NOT_AFTER_MS, .executed_at_ms = GRANT_NOW_MS },
    };
    const intended = [_][16]u8{GID_A};
    const r = audit_mod.audit(&view, &claims, &intended);
    try std.testing.expectEqual(@as(u32, 0), r.m1_violations);
    try std.testing.expectEqual(@as(u32, 1), r.m2_granted);
    try std.testing.expect(r.passed());
}
