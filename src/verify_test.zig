// verify_test.zig
//
// Grounded in the canonical cross-implementation vectors (test/vectors.json,
// structures grant and envelope_intent). The wire bytes are the exact bytes the
// Zig generator and the Python cryptography verifier agreed on under M3. If the
// verifier disagrees with them, the verifier is wrong.
//
// Naming follows the build.zig M1 registry convention: test "BE_<CLASS>_<NN>".

const std = @import("std");
const parser = @import("parser.zig");
const verify = @import("verify.zig");
const binding = @import("binding.zig");
const intent_mod = @import("intent.zig");
const cth = @import("cert_test_helpers.zig");

const Ed = std.crypto.sign.Ed25519;

fn decodeHex(comptime hex: []const u8) [hex.len / 2]u8 {
    var b: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&b, hex) catch unreachable;
    return b;
}

// The canonical Intent envelope (280 bytes: TBS 216 + sig 64), signed by the
// agent over domain tag 0x02. Same vector parser_test.zig parses.
const ENVELOPE_HEX =
    "026d14f9d827a8ec4ad1c5b7a34076f5f0ff41eaffce1cf37959e63df6cceb59ce" ++
    "020bd427446b723424d80d2cad352ba3df3649d0ef8faae0ca7eb25443941b29" ++
    "0000000000000001" ++
    "00" ++
    "0000018bcfe58f10" ++
    "02" ++
    "00000081" ++
    "0102030405060708090a0b0c0d0e0f10" ++
    "0024" ++
    "626f6c3a633365666436343162666130353832662f6c6f67732f6465706c6f792e6c6f67" ++
    "0000001a" ++
    "6170742d67657420696e7374616c6c202d792073716c69746533" ++
    "002b" ++
    "496e7374616c6c2073716c69746520666f72206c6f63616c20736368656d6120696e7370656374696f6e2e" ++
    "3d96e79606b694f286bac4ae1836c351a9ba817bae9a26d14a9844593293bec16d07c18cb44f19e4a77c75c9bc4cbe8eeb6f9c9376da85a74b3abf38e6e0ec02";

// The canonical Grant (271 bytes: TBS 207 + sig 64), signed by the approver
// over domain tag 0x04. Fields mirror SPEC 8.1.
const GRANT_HEX =
    "02" ++ // version = 2
    "1112131415161718191a1b1c1d1e1f20" ++ // grant_id
    "0102030405060708090a0b0c0d0e0f10" ++ // intent_id
    "adc14011f82d1c56d956aa4f9d73d8858361a606048525e0d08c638dc75dd8c7" ++ // approver
    "020bd427446b723424d80d2cad352ba3df3649d0ef8faae0ca7eb25443941b29" ++ // subject (the agent)
    "882d0ea3b2864e7a587f3e698cea4459998312e655e05fa5e8b5119d8baac8cd" ++ // executor
    "0024" ++
    "626f6c3a633365666436343162666130353832662f6c6f67732f6465706c6f792e6c6f67" ++ // resource_id
    "61a0be1fa7039021e3a6d10a38e41e21873abd4668419d6b45dfcd56686d60c3" ++ // action_digest
    "0000018bcfe65260" ++ // not_after = 1700000060000
    "1596e79d1bea7d11be9a99a7d7b898f9ae6771d15957186f5e8687b8c1f7ae524b95633a7cee4f0c9d89db7f0616d3310535e58814b781831461c26775a4d405";

const EXECUTOR_HEX = "882d0ea3b2864e7a587f3e698cea4459998312e655e05fa5e8b5119d8baac8cd";
const EXECUTOR_BYTES = decodeHex(EXECUTOR_HEX);
const ACTION = "apt-get install -y sqlite3";

// Clock context that makes the canonical grant valid: now is before not_after
// (1700000060000), within T_recv of first receipt, and not_after within T_max.
const NOW_MS: u64 = 1700000000000;
const FIRST_RECEIPT_MS: u64 = 1699999900000; // 100s before now, inside T_recv
const T_MAX_S: u64 = 3600;
const T_RECV_S: u64 = 300;

// Ledger hooks. Function pointers cannot capture state, so the counting hook
// records through a package-level variable the ordering test reads back. That
// variable is written by more than one test block, so it is safe only because
// build.zig pins the test module to single_threaded. Do not remove that pin
// without first giving each callback double per-test storage.
var ledger_calls: usize = 0;

fn ledgerFresh(grant_id: []const u8, not_after_ms: u64, now_ms: u64) bool {
    _ = grant_id;
    _ = not_after_ms;
    _ = now_ms;
    return false;
}

fn ledgerSpent(grant_id: []const u8, not_after_ms: u64, now_ms: u64) bool {
    _ = grant_id;
    _ = not_after_ms;
    _ = now_ms;
    return true;
}

fn ledgerCounting(grant_id: []const u8, not_after_ms: u64, now_ms: u64) bool {
    _ = grant_id;
    _ = not_after_ms;
    _ = now_ms;
    ledger_calls += 1;
    return false;
}

// BE-GRANT-01a model: a durable ledger that COMMITS the grant_id on its first
// consultation, exactly as a durable write outlives a restart. The first read
// is fresh (returns false) and flips to consumed; every later read reports
// consumed. This is the single-shot ledger of BE-GRANT-01 with the crash
// durability of BE-GRANT-01a made load-bearing for the interrupted-effect test.
var one_shot_consumed: bool = false;

fn ledgerDurableCommit(grant_id: []const u8, not_after_ms: u64, now_ms: u64) bool {
    _ = grant_id;
    _ = not_after_ms;
    _ = now_ms;
    if (one_shot_consumed) return true;
    one_shot_consumed = true;
    return false;
}

// Effect callback the routine invokes on success. Named `recordEffect`, not
// `execute`, deliberately: M10 keys its call-graph grep on the invocation
// `execute(` in src/verify.zig, and a same-named callback here would add a
// second hit and break the wall for the wrong reason. Function pointers cannot
// capture state, so the call count and the grant_id the routine handed it are
// recorded through package-level variables the tests read back. Several test
// blocks write these, so they carry the same single_threaded dependency as
// ledger_calls above.
var effect_calls: usize = 0;
var effect_grant_id: []const u8 = &[_]u8{};

fn recordEffect(grant: parser.channel.Grant) verify.EffectOutcome {
    effect_calls += 1;
    effect_grant_id = grant.grant_id;
    return .fired;
}

fn resetEffect() void {
    effect_calls = 0;
    effect_grant_id = &[_]u8{};
}

// The grant always arrives inside a body_type=3 envelope whose sender is the
// approver (BE-GRANT-03 check 1). The canonical vector is the bare grant, so
// the tests synthesize that envelope around it; verifyGrantThen only reads
// body_type and sender from it.
fn grantEnvelope(grant: parser.channel.Grant) parser.channel.Envelope {
    return .{
        .version = 2,
        .channel_id = &[_]u8{},
        .sender = grant.approver,
        .seq = 0,
        .parent_count = 0,
        .parents = &[_]u8{},
        .ts = 0,
        .body_type = parser.channel.BODY_GRANT,
        .body = &[_]u8{},
        .tbs = &[_]u8{},
        .sig = &[_]u8{},
    };
}

// F13: default tables owned at file scope so the context handed out by
// baseContext points at storage that outlives the helper's frame (pointers
// into a returned-from frame dangle). Reset on every call: pre-F13
// baseContext was stateless per call and tests rely on fresh state.
var default_intent_table = intent_mod.Table.init();
var default_sender_entries: [1]verify.SenderTable.Entry = undefined;
var default_sender_table: verify.SenderTable = .{ .entries = &default_sender_entries, .len = 0 };

fn baseContext(action: []const u8, hook: *const fn ([]const u8, u64, u64) bool) verify.GrantContext {
    // F13: create intent and sender tables for the test. The routine owns its
    // lookups, so we need to populate the tables with the test data.
    default_intent_table = intent_mod.Table.init();
    default_intent_table.admit(.{
        .intent_id = &cth.INTENT_ID,
        .resource_id = cth.RESOURCE_ID,
        .action = action,
        .rationale = &[_]u8{},
    }, NOW_MS) catch unreachable;

    @memcpy(&default_sender_entries[0].intent_id, &cth.INTENT_ID);
    @memcpy(&default_sender_entries[0].sender, &cth.SUBJECT_PUB);
    const action_len = @min(action.len, verify.SenderTable.MAX_ACTION);
    @memcpy(default_sender_entries[0].action[0..action_len], action[0..action_len]);
    default_sender_entries[0].action_len = action_len;
    default_sender_table = .{
        .entries = &default_sender_entries,
        .len = 1,
    };

    return .{
        .own_pubkey = &EXECUTOR_BYTES,
        .trusted_ca_keys = cth.trustedSet(),
        .approver_cert = cth.approverCert(),
        .subject_cert = cth.subjectCert(),
        .intent_table = &default_intent_table,
        .sender_table = &default_sender_table,
        .now_ms = NOW_MS,
        .first_receipt_ms = FIRST_RECEIPT_MS,
        .t_max_s = T_MAX_S,
        .t_recv_s = T_RECV_S,
        .already_consumed = hook,
        .is_revoked = &revokedNo,
    };
}

test "BE_ENV_02 envelope sig verifies against sender before body" {
    const env_bytes = decodeHex(ENVELOPE_HEX);
    const env = try parser.channel.parseEnvelope(&env_bytes);
    try verify.verifyEnvelope(env);
}

test "BE_ENV_02 corrupted envelope sig is discarded" {
    var env_bytes = decodeHex(ENVELOPE_HEX);
    env_bytes[220] ^= 0xff; // flip one byte inside the 64-byte sig (216..280)
    const env = try parser.channel.parseEnvelope(&env_bytes);
    try std.testing.expectError(error.BadSignature, verify.verifyEnvelope(env));
}

test "BE_GRANT_03 canonical grant verifies end to end" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.channel.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    const ctx = baseContext(ACTION, &ledgerFresh);
    resetEffect();
    _ = try verify.verifyGrantThen(env, &grant, ctx, &recordEffect);
    // The effect ran exactly once, on the grant the routine verified, by value.
    try std.testing.expectEqual(@as(usize, 1), effect_calls);
    try std.testing.expectEqualSlices(u8, grant.grant_id, effect_grant_id);
}

test "BE_GRANT_03 version other than 2 refused first" {
    var grant_bytes = decodeHex(GRANT_HEX);
    grant_bytes[0] = 3; // version field; flipping it also breaks the sig, but
    const grant = try parser.channel.parseGrant(&grant_bytes); // check 0 runs before check 2
    const env = grantEnvelope(grant);
    const ctx = baseContext(ACTION, &ledgerFresh);
    resetEffect();
    try std.testing.expectError(error.BadVersion, verify.verifyGrantThen(env, &grant, ctx, &recordEffect));
    // A refused grant does not reach the effect (BE-GRANT-03b call boundary).
    try std.testing.expectEqual(@as(usize, 0), effect_calls);
}

test "BE_GRANT_03 grant not delivered as body_type 3 envelope refused" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.channel.parseGrant(&grant_bytes);
    var env = grantEnvelope(grant);
    env.body_type = parser.channel.BODY_INTENT; // wrong delivery path
    const ctx = baseContext(ACTION, &ledgerFresh);
    resetEffect();
    try std.testing.expectError(error.BadEnvelopeBinding, verify.verifyGrantThen(env, &grant, ctx, &recordEffect));
    try std.testing.expectEqual(@as(usize, 0), effect_calls);
}

test "BE_GRANT_03 envelope sender not the approver refused" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.channel.parseGrant(&grant_bytes);
    var env = grantEnvelope(grant);
    env.sender = grant.subject; // delivered by the agent, not the approver
    const ctx = baseContext(ACTION, &ledgerFresh);
    resetEffect();
    try std.testing.expectError(error.BadEnvelopeBinding, verify.verifyGrantThen(env, &grant, ctx, &recordEffect));
    try std.testing.expectEqual(@as(usize, 0), effect_calls);
}

test "BE_GRANT_03 corrupted grant sig is refused" {
    var grant_bytes = decodeHex(GRANT_HEX);
    grant_bytes[210] ^= 0xff; // inside the 64-byte sig (207..271)
    const grant = try parser.channel.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    const ctx = baseContext(ACTION, &ledgerFresh);
    resetEffect();
    try std.testing.expectError(error.BadSignature, verify.verifyGrantThen(env, &grant, ctx, &recordEffect));
    try std.testing.expectEqual(@as(usize, 0), effect_calls);
}

test "BE_GRANT_03 executor mismatch refused" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.channel.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    var ctx = baseContext(ACTION, &ledgerFresh);
    ctx.own_pubkey = grant.subject; // this executor is not the named one
    resetEffect();
    try std.testing.expectError(error.WrongExecutor, verify.verifyGrantThen(env, &grant, ctx, &recordEffect));
    try std.testing.expectEqual(@as(usize, 0), effect_calls);
}

test "BE_GRANT_02 action digest must match byte for byte" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.channel.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    // Approving "apt-get install -y sqlite3" does not approve a different
    // command: the recomputed digest over other bytes must not match.
    const ctx = baseContext("apt-get install -y postgresql", &ledgerFresh);
    resetEffect();
    try std.testing.expectError(error.ActionDigestMismatch, verify.verifyGrantThen(env, &grant, ctx, &recordEffect));
    try std.testing.expectEqual(@as(usize, 0), effect_calls);
}

test "BE_GRANT_05 not_after in the past is refused" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.channel.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    var ctx = baseContext(ACTION, &ledgerFresh);
    ctx.now_ms = grant.not_after + 1; // clock is past the expiry
    resetEffect();
    try std.testing.expectError(error.Expired, verify.verifyGrantThen(env, &grant, ctx, &recordEffect));
    // An expired grant must not run its effect: this is the use-it-later hole
    // the round 4 restatement removes, and a load-bearing kill for the
    // callback-before-checks mutant.
    try std.testing.expectEqual(@as(usize, 0), effect_calls);
}

test "BE_GRANT_05 not_after beyond T_max from receipt is refused" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.channel.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    var ctx = baseContext(ACTION, &ledgerFresh);
    // First receipt far enough back that not_after exceeds receipt + T_max.
    ctx.first_receipt_ms = grant.not_after - (T_MAX_S * 1000) - 1;
    resetEffect();
    try std.testing.expectError(error.Expired, verify.verifyGrantThen(env, &grant, ctx, &recordEffect));
    try std.testing.expectEqual(@as(usize, 0), effect_calls);
}

test "BE_GRANT_05 more than T_recv since first receipt is refused" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.channel.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    var ctx = baseContext(ACTION, &ledgerFresh);
    ctx.now_ms = FIRST_RECEIPT_MS + (T_RECV_S * 1000) + 1;
    resetEffect();
    try std.testing.expectError(error.Expired, verify.verifyGrantThen(env, &grant, ctx, &recordEffect));
    try std.testing.expectEqual(@as(usize, 0), effect_calls);
}

// Boundary tests for the non-strict not_after bound (BE-GRANT-05, SPEC pinned
// at now_ms >= not_after). The instant of expiry is denied, not granted; the
// last millisecond before it is the final valid moment.
test "BE_GRANT_05 not_after exact instant is refused (boundary deny)" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.channel.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    var ctx = baseContext(ACTION, &ledgerFresh);
    ctx.now_ms = grant.not_after; // equal, not strictly past
    resetEffect();
    try std.testing.expectError(error.Expired, verify.verifyGrantThen(env, &grant, ctx, &recordEffect));
    try std.testing.expectEqual(@as(usize, 0), effect_calls);
}

test "BE_GRANT_05 not_after minus 1ms is accepted (boundary deny)" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.channel.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    var ctx = baseContext(ACTION, &ledgerFresh);
    ctx.now_ms = grant.not_after - 1; // the last valid millisecond
    // first_receipt is far enough inside T_recv that the receipt bound still
    // holds at this now_ms, so the only boundary in play is not_after.
    resetEffect();
    _ = try verify.verifyGrantThen(env, &grant, ctx, &recordEffect);
    try std.testing.expectEqual(@as(usize, 1), effect_calls);
}

// T_max and T_recv boundary-allow tests. Each refuse condition is strict
// ("more than"), so the exact-equal instant is allowed. These kill the
// WRONG-OPERATOR mutants on the T_max and T_recv comparisons in the mutation
// harness (tools/mutation-test.py): a >= mutant would refuse at equality.
test "BE_GRANT_05 not_after exactly T_max from receipt is accepted (boundary)" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.channel.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    var ctx = baseContext(ACTION, &ledgerFresh);
    // not_after sits exactly first_receipt + T_max. "More than T_max" is the
    // refuse condition, so equality is allowed. now is well inside T_recv and
    // before not_after, so T_max is the only boundary in play.
    ctx.first_receipt_ms = grant.not_after - (T_MAX_S * 1000);
    ctx.now_ms = ctx.first_receipt_ms + 150_000; // 150s, inside T_recv (300s)
    resetEffect();
    _ = try verify.verifyGrantThen(env, &grant, ctx, &recordEffect);
    try std.testing.expectEqual(@as(usize, 1), effect_calls);
}

test "BE_GRANT_05 now exactly T_recv since receipt is accepted (boundary)" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.channel.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    var ctx = baseContext(ACTION, &ledgerFresh);
    // now sits exactly first_receipt + T_recv. "More than T_recv" is the refuse
    // condition, so equality is allowed. not_after is within T_max and ahead of
    // now, so T_recv is the only boundary in play.
    ctx.first_receipt_ms = grant.not_after - (T_MAX_S * 1000 / 2);
    ctx.now_ms = ctx.first_receipt_ms + (T_RECV_S * 1000);
    resetEffect();
    _ = try verify.verifyGrantThen(env, &grant, ctx, &recordEffect);
    try std.testing.expectEqual(@as(usize, 1), effect_calls);
}

test "BE_GRANT_01 already-consumed grant_id refused" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.channel.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    const ctx = baseContext(ACTION, &ledgerSpent);
    resetEffect();
    try std.testing.expectError(error.AlreadyConsumed, verify.verifyGrantThen(env, &grant, ctx, &recordEffect));
    // A consumed grant does not re-run its effect: the ledger commit is the last
    // check and runs before the callback, so single-shot holds even when the
    // effect itself never got to run. Kill for the callback-before-ledger mutant.
    try std.testing.expectEqual(@as(usize, 0), effect_calls);
}

test "BE_GRANT_01 ledger hook runs last, after expiry" {
    ledger_calls = 0;
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.channel.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    // Make expiry fail (check 10). The ledger (check 11) must not be
    // reached, proving the I/O step is ordered after every compute check.
    var ctx = baseContext(ACTION, &ledgerCounting);
    ctx.now_ms = grant.not_after + 1;
    resetEffect();
    try std.testing.expectError(error.Expired, verify.verifyGrantThen(env, &grant, ctx, &recordEffect));
    try std.testing.expectEqual(@as(usize, 0), ledger_calls);
    try std.testing.expectEqual(@as(usize, 0), effect_calls);

    // Same hook, a valid grant: now the ledger IS consulted exactly once and
    // the effect runs exactly once, after it.
    ledger_calls = 0;
    resetEffect();
    const ok_ctx = baseContext(ACTION, &ledgerCounting);
    _ = try verify.verifyGrantThen(env, &grant, ok_ctx, &recordEffect);
    try std.testing.expectEqual(@as(usize, 1), ledger_calls);
    try std.testing.expectEqual(@as(usize, 1), effect_calls);
}

// ---------------------------------------------------------------------------
// BE-GRANT-01a (crash during execution). The durable commit of BE-GRANT-01 is
// check 11, the last check, and it runs BEFORE execute. So a grant whose
// effect is interrupted by a crash (process death after the commit, before the
// Effect is published) is left spent: the durable commit survived the restart,
// and on replay the ledger reports the grant_id consumed. The verify routine
// refuses it with AlreadyConsumed and the effect callback never fires a second
// time. An interrupted grant is never silently retried (SPEC 8.4, 01a).
//
// ledgerDurableCommit models the durable ledger: the first consultation is
// fresh and flips to consumed, exactly as a durable write outlives a restart.
// The first call is normal processing; the crash is the gap between the two
// calls; the second call is the post-restart replay.
// (Publishing an ok=false, cause=interrupted Effect and releasing the resource
// lock on that restart are executor/recovery-layer concerns driven by the
// durable grant ledger, documented at the intent.zig header boundary. This
// binds the verify-layer invariant: commit-before-execute => not retried.)
// ---------------------------------------------------------------------------

test "BE_GRANT_01a interrupted effect leaves grant_id spent, never retried" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.channel.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    const ctx = baseContext(ACTION, &ledgerDurableCommit);

    // Normal processing: the grant verifies, the durable ledger commits it
    // (hook flips fresh -> consumed), and the effect is attempted once.
    one_shot_consumed = false;
    resetEffect();
    _ = try verify.verifyGrantThen(env, &grant, ctx, &recordEffect);
    try std.testing.expectEqual(@as(usize, 1), effect_calls);
    try std.testing.expect(one_shot_consumed);

    // Crash gap: the process died after the durable commit, before the Effect
    // was published. The commit survived the restart (one_shot_consumed still
    // true). Post-restart replay: the grant_id is now consumed, so
    // AlreadyConsumed is returned and the effect is NOT retried: still one
    // callback invocation, not two.
    try std.testing.expectError(error.AlreadyConsumed, verify.verifyGrantThen(env, &grant, ctx, &recordEffect));
    try std.testing.expectEqual(@as(usize, 1), effect_calls);
}

// BE-GRANT-03b call boundary. The effect runs once, inside the routine's frame,
// only after every check and the ledger commit pass. This is the property the
// storable capability used to defend with a seal; the window is gone, so the
// call graph is the wall (M10). A grant that fails any check must not run the
// effect at all.
test "BE_GRANT_03b valid grant runs the effect exactly once with matching fields" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.channel.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    const ctx = baseContext(ACTION, &ledgerFresh);
    resetEffect();
    _ = try verify.verifyGrantThen(env, &grant, ctx, &recordEffect);
    try std.testing.expectEqual(@as(usize, 1), effect_calls);
    // The grant reached the effect by value: its fields are the routine's, not
    // a storable handle the caller can keep and mutate.
    try std.testing.expectEqualSlices(u8, grant.grant_id, effect_grant_id);
    try std.testing.expectEqualSlices(u8, grant.action_digest, grant.action_digest);
}

// ---------------------------------------------------------------------------
// Folded checks 3, 4, 6, 7, 8 (D-008 provisional debt retired). The cert store
// and pending-intent table the slice used to defer are now supplied through
// GrantContext, so the routine models the full twelve-check chain. Each test
// invalidates exactly one folded check and confirms the grant is refused there
// before the effect runs.
// ---------------------------------------------------------------------------

test "BE_GRANT_03 check 3 approver cert without approver role refused" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.channel.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    var ctx = baseContext(ACTION, &ledgerFresh);
    // Approver-positioned cert that carries the agent role, not approver.
    var wire: [512]u8 = undefined;
    ctx.approver_cert = cth.buildCertInto(
        &wire,
        cth.APPROVER_PUB,
        binding.ROLE_AGENT,
        &[_]u8{0xc0},
        cth.CERT_NOT_BEFORE,
        cth.CERT_NOT_AFTER,
    );
    resetEffect();
    try std.testing.expectError(error.BadApproverCert, verify.verifyGrantThen(env, &grant, ctx, &recordEffect));
    try std.testing.expectEqual(@as(usize, 0), effect_calls);
}

test "BE_GRANT_03 check 4 subject cert without agent role refused" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.channel.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    var ctx = baseContext(ACTION, &ledgerFresh);
    var wire: [512]u8 = undefined;
    ctx.subject_cert = cth.buildCertInto(
        &wire,
        cth.SUBJECT_PUB,
        binding.ROLE_EXECUTOR,
        &[_]u8{0xc0},
        cth.PRIVILEGED_CERT_NOT_BEFORE,
        cth.PRIVILEGED_CERT_NOT_AFTER,
    );
    resetEffect();
    try std.testing.expectError(error.BadSubjectCert, verify.verifyGrantThen(env, &grant, ctx, &recordEffect));
    try std.testing.expectEqual(@as(usize, 0), effect_calls);
}

// ---------------------------------------------------------------------------
// D-085 scope binding (checks 3a and 4a). A v3 cert carries scope_ids;
// scopeCoversResource walks ancestor prefixes hashing each and checking
// against the cert's scope_ids. Check 3a gates on the approver cert, check
// 4a gates on the subject cert. v2 certs skip these checks entirely (version
// guard). Positive: cert v3 with scope covering the resource's org prefix
// grants access. Negative: cert v3 with a sibling scope refuses.
// ---------------------------------------------------------------------------

// Compute scope_id = BLAKE2s(prefix)[0..8] at runtime.
fn scopeIdOf(prefix: []const u8) [8]u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.blake2.Blake2s256.hash(prefix, &hash, .{});
    return hash[0..8].*;
}

test "BE_GRANT_03 check 3a v3 cert with scope covering resource is accepted" {
    // scope_id derived from the resource's org prefix (everything before the
    // first '/'). scopeCoversResource walks ancestors and hashes each; this
    // scope_id matches the org-level ancestor.
    const org_prefix = cth.RESOURCE_ID[0..std.mem.indexOf(u8, cth.RESOURCE_ID, "/").?];
    const covering_scope = scopeIdOf(org_prefix);

    var appr_wire: [512]u8 = undefined;
    const scoped_appr = cth.buildCertScopedInto(
        &appr_wire,
        cth.APPROVER_PUB,
        binding.ROLE_APPROVER,
        &[_]u8{ 0xc0, 0xc1 },
        cth.PRIVILEGED_CERT_NOT_BEFORE,
        cth.PRIVILEGED_CERT_NOT_AFTER,
        3, // version 3: scope checks fire
        &covering_scope,
    );
    var subj_wire: [512]u8 = undefined;
    const scoped_subj = cth.buildCertScopedInto(
        &subj_wire,
        cth.SUBJECT_PUB,
        binding.ROLE_AGENT,
        &[_]u8{0xc2},
        cth.CERT_NOT_BEFORE,
        cth.CERT_NOT_AFTER,
        3,
        &covering_scope,
    );

    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.channel.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    var ctx = baseContext(ACTION, &ledgerFresh);
    ctx.approver_cert = scoped_appr;
    ctx.subject_cert = scoped_subj;
    resetEffect();
    _ = try verify.verifyGrantThen(env, &grant, ctx, &recordEffect);
    try std.testing.expectEqual(@as(usize, 1), effect_calls);
}

test "BE_GRANT_03 check 3a v3 approver cert with non-covering scope is refused" {
    // A sibling scope: "bol:other_org" is not an ancestor of the resource.
    const sibling_scope = scopeIdOf("bol:other_org");

    var appr_wire: [512]u8 = undefined;
    const scoped_appr = cth.buildCertScopedInto(
        &appr_wire,
        cth.APPROVER_PUB,
        binding.ROLE_APPROVER,
        &[_]u8{ 0xc0, 0xc1 },
        cth.PRIVILEGED_CERT_NOT_BEFORE,
        cth.PRIVILEGED_CERT_NOT_AFTER,
        3,
        &sibling_scope,
    );

    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.channel.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    var ctx = baseContext(ACTION, &ledgerFresh);
    ctx.approver_cert = scoped_appr;
    // subject cert stays v2 (scope checks skipped for v2)
    resetEffect();
    try std.testing.expectError(error.ApproverOutOfScope, verify.verifyGrantThen(env, &grant, ctx, &recordEffect));
    try std.testing.expectEqual(@as(usize, 0), effect_calls);
}

test "BE_GRANT_03 check 4a v3 subject cert with non-covering scope is refused" {
    const sibling_scope = scopeIdOf("bol:other_org");

    var subj_wire: [512]u8 = undefined;
    const scoped_subj = cth.buildCertScopedInto(
        &subj_wire,
        cth.SUBJECT_PUB,
        binding.ROLE_AGENT,
        &[_]u8{0xc2},
        cth.CERT_NOT_BEFORE,
        cth.CERT_NOT_AFTER,
        3,
        &sibling_scope,
    );

    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.channel.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    var ctx = baseContext(ACTION, &ledgerFresh);
    ctx.subject_cert = scoped_subj;
    // approver cert stays v2 (scope checks skipped for v2)
    resetEffect();
    try std.testing.expectError(error.SubjectOutOfScope, verify.verifyGrantThen(env, &grant, ctx, &recordEffect));
    try std.testing.expectEqual(@as(usize, 0), effect_calls);
}

test "BE_GRANT_03 check 6 subject not the pending intent sender refused" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.channel.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    // F13: modify the sender table to have a different sender (not the grant's subject).
    var intent_table = intent_mod.Table.init();
    intent_table.admit(.{
        .intent_id = &cth.INTENT_ID,
        .resource_id = cth.RESOURCE_ID,
        .action = ACTION,
        .rationale = &[_]u8{},
    }, NOW_MS) catch unreachable;
    var sender_entries: [1]verify.SenderTable.Entry = undefined;
    @memcpy(&sender_entries[0].intent_id, &cth.INTENT_ID);
    @memcpy(&sender_entries[0].sender, &cth.APPROVER_PUB); // not the grant's subject
    const action_len = @min(ACTION.len, verify.SenderTable.MAX_ACTION);
    @memcpy(sender_entries[0].action[0..action_len], ACTION[0..action_len]);
    sender_entries[0].action_len = action_len;
    const sender_table = verify.SenderTable{
        .entries = &sender_entries,
        .len = 1,
    };
    var ctx = baseContext(ACTION, &ledgerFresh);
    ctx.intent_table = &intent_table;
    ctx.sender_table = &sender_table;
    resetEffect();
    try std.testing.expectError(error.WrongSubject, verify.verifyGrantThen(env, &grant, ctx, &recordEffect));
    try std.testing.expectEqual(@as(usize, 0), effect_calls);
}

test "BE_GRANT_03 check 7 intent_id matching no pending intent refused" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.channel.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    // F13: modify the intent table to have a different intent_id (no match).
    var intent_table = intent_mod.Table.init();
    const wrong = decodeHex("ffffffffffffffffffffffffffffffff");
    intent_table.admit(.{
        .intent_id = &wrong,
        .resource_id = cth.RESOURCE_ID,
        .action = ACTION,
        .rationale = &[_]u8{},
    }, NOW_MS) catch unreachable;
    var sender_entries: [1]verify.SenderTable.Entry = undefined;
    @memcpy(&sender_entries[0].intent_id, &wrong);
    @memcpy(&sender_entries[0].sender, &cth.SUBJECT_PUB);
    const action_len = @min(ACTION.len, verify.SenderTable.MAX_ACTION);
    @memcpy(sender_entries[0].action[0..action_len], ACTION[0..action_len]);
    sender_entries[0].action_len = action_len;
    const sender_table = verify.SenderTable{
        .entries = &sender_entries,
        .len = 1,
    };
    var ctx = baseContext(ACTION, &ledgerFresh);
    ctx.intent_table = &intent_table;
    ctx.sender_table = &sender_table;
    resetEffect();
    try std.testing.expectError(error.NoMatchingIntent, verify.verifyGrantThen(env, &grant, ctx, &recordEffect));
    try std.testing.expectEqual(@as(usize, 0), effect_calls);
}

test "BE_GRANT_03 check 8 resource_id mismatch refused" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.channel.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    // F13: modify the intent table to have a different resource_id.
    var intent_table = intent_mod.Table.init();
    intent_table.admit(.{
        .intent_id = &cth.INTENT_ID,
        .resource_id = "bol:other/resource",
        .action = ACTION,
        .rationale = &[_]u8{},
    }, NOW_MS) catch unreachable;
    var sender_entries: [1]verify.SenderTable.Entry = undefined;
    @memcpy(&sender_entries[0].intent_id, &cth.INTENT_ID);
    @memcpy(&sender_entries[0].sender, &cth.SUBJECT_PUB);
    const action_len = @min(ACTION.len, verify.SenderTable.MAX_ACTION);
    @memcpy(sender_entries[0].action[0..action_len], ACTION[0..action_len]);
    sender_entries[0].action_len = action_len;
    const sender_table = verify.SenderTable{
        .entries = &sender_entries,
        .len = 1,
    };
    var ctx = baseContext(ACTION, &ledgerFresh);
    ctx.intent_table = &intent_table;
    ctx.sender_table = &sender_table;
    resetEffect();
    try std.testing.expectError(error.WrongResource, verify.verifyGrantThen(env, &grant, ctx, &recordEffect));
    try std.testing.expectEqual(@as(usize, 0), effect_calls);
}

// ---------------------------------------------------------------------------
// Channel control verification (SPEC 6.1b, 6.1c). The channel layer runs over
// parsed ControlGenesis/Control bodies and caller-verified certs: the cert
// chain (BE-ID-02..04) is the caller's job (D-018 boundary), so these tests
// build minimal Cert literals carrying only the scope_ids / sig_pubkey the
// channel checks read. genesis_exists and is_revoked are package-level hooks
// mirroring GrantContext.already_consumed.

// GENESIS: member_group=0xAA*8, admin_group=0xBB*8, name="test", one ca_key.
const CHAN_GENESIS_HEX =
    "01" ++ "0004" ++ "74657374" ++ // version, name_len, "test"
    "aaaaaaaaaaaaaaaa" ++ "bbbbbbbbbbbbbbbb" ++ // member_group, admin_group
    "01" ++ "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" ++ // ca_count=1, one 32-byte key
    "01"; // match_rule (byte equality, BE-GEN-04)

// action_type=3 (outside the {1,2} set) and action_type=2 (Revoke), empty body.
const CHAN_CONTROL_BAD_HEX = "01" ++ "03" ++ "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" ++ "0000";
const CHAN_REVOKE_HEX = "01" ++ "02" ++ "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" ++ "0000";

const CHAN_MEMBER_GROUP = [_]u8{0xaa} ** parser.session.LEN_SCOPE_ID; // 8 bytes
const CHAN_ADMIN_GROUP = [_]u8{0xbb} ** parser.session.LEN_SCOPE_ID; // 8 bytes
const CHAN_SENDER_PUB = [_]u8{0xdd} ** parser.LEN_PUBKEY; // 32 bytes
const WRONG_ID = [_]u8{0xff} ** 32;

fn genesisExistsNo(_: []const u8) bool {
    return false;
}
fn genesisExistsYes(_: []const u8) bool {
    return true;
}
fn revokedNo(_: []const u8) bool {
    return false;
}
fn revokedYes(_: []const u8) bool {
    return true;
}

// A Cert literal carrying only the fields the channel layer reads. scope_count,
// scope_ids, and sig_pubkey drive every membership / admin check; the cert
// chain is verified before these run, so the remaining fields are inert dummies.
fn channelCert(groups: []const u8, pubkey: []const u8) parser.session.Cert {
    return .{
        .version = 2,
        .role_bits = 0,
        .sig_pubkey = pubkey,
        .kex_pubkey = "",
        .not_before = 0,
        .not_after = 0,
        .name = "",
        .scope_count = @intCast(groups.len / parser.session.LEN_SCOPE_ID),
        .scope_ids = groups,
        .ca_sig_count = 0,
        .ca_sigs = "",
        .tbs = "",
    };
}

// channel_id = BLAKE2s(name || ca_key_0) (SPEC 6.1b). Independent computation
// of the derivation the verifier runs; not a copy of the code under test.
fn deriveChannelId(name: []const u8, ca_key_0: []const u8) [32]u8 {
    var hasher = std.crypto.hash.blake2.Blake2s256.init(.{});
    hasher.update(name);
    hasher.update(ca_key_0);
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

fn chanCtx(genesis_yes: bool, revoked_yes: bool) verify.ChannelContext {
    return .{
        .genesis_exists = if (genesis_yes) &genesisExistsYes else &genesisExistsNo,
        .is_revoked = if (revoked_yes) &revokedYes else &revokedNo,
    };
}

test "BE_GEN_04 genesis match_rule != 1 is refused" {
    var bytes = decodeHex(CHAN_GENESIS_HEX);
    bytes[56] = 0x02; // match_rule: only byte equality (1) is defined
    const genesis = try parser.channel.parseControlGenesis(&bytes);
    const admin = channelCert(&CHAN_ADMIN_GROUP, &CHAN_SENDER_PUB);
    try std.testing.expectError(error.BadMatchRule, verify.verifyControlGenesis(genesis, admin, &WRONG_ID, chanCtx(false, false)));
}

test "BE_GEN_03 genesis from a non-admin cert is refused" {
    const genesis = try parser.channel.parseControlGenesis(&decodeHex(CHAN_GENESIS_HEX));
    const non_admin = channelCert(&CHAN_MEMBER_GROUP, &CHAN_SENDER_PUB); // carries member, not admin
    try std.testing.expectError(error.GenesisNotAdmin, verify.verifyControlGenesis(genesis, non_admin, &WRONG_ID, chanCtx(false, false)));
}

test "BE_GEN_03 genesis with a mismatched channel_id is refused" {
    const genesis = try parser.channel.parseControlGenesis(&decodeHex(CHAN_GENESIS_HEX));
    const admin = channelCert(&CHAN_ADMIN_GROUP, &CHAN_SENDER_PUB);
    try std.testing.expectError(error.BadChannelId, verify.verifyControlGenesis(genesis, admin, &WRONG_ID, chanCtx(false, false)));
}

test "BE_GEN_01 a second genesis for a known channel_id is refused" {
    const genesis = try parser.channel.parseControlGenesis(&decodeHex(CHAN_GENESIS_HEX));
    const admin = channelCert(&CHAN_ADMIN_GROUP, &CHAN_SENDER_PUB);
    const channel_id = deriveChannelId("test", &[_]u8{0xcc} ** 32);
    try std.testing.expectError(error.DuplicateGenesis, verify.verifyControlGenesis(genesis, admin, &channel_id, chanCtx(true, false)));
}

test "BE_CTRL_01 control action_type outside 1,2 is refused" {
    const control = try parser.channel.parseControl(&decodeHex(CHAN_CONTROL_BAD_HEX));
    const genesis = try parser.channel.parseControlGenesis(&decodeHex(CHAN_GENESIS_HEX));
    const sender = channelCert(&CHAN_MEMBER_GROUP, &CHAN_SENDER_PUB);
    try std.testing.expectError(error.BadActionType, verify.verifyControl(control, genesis, sender));
}

test "BE_CTRL_02 revoke from a non-admin cert is refused" {
    const control = try parser.channel.parseControl(&decodeHex(CHAN_REVOKE_HEX));
    const genesis = try parser.channel.parseControlGenesis(&decodeHex(CHAN_GENESIS_HEX));
    const non_admin = channelCert(&CHAN_MEMBER_GROUP, &CHAN_SENDER_PUB); // member, not admin
    try std.testing.expectError(error.RevokeNotAdmin, verify.verifyControl(control, genesis, non_admin));
}

test "BE_CHAN_02 a revoked subject is refused before the group check" {
    const genesis = try parser.channel.parseControlGenesis(&decodeHex(CHAN_GENESIS_HEX));
    const member = channelCert(&CHAN_MEMBER_GROUP, &CHAN_SENDER_PUB);
    try std.testing.expectError(error.SubjectRevoked, verify.requireMember(member, genesis, chanCtx(false, true)));
}

test "BE_CHAN_01 a cert without member_group is refused" {
    const genesis = try parser.channel.parseControlGenesis(&decodeHex(CHAN_GENESIS_HEX));
    const non_member = channelCert(&CHAN_ADMIN_GROUP, &CHAN_SENDER_PUB); // admin, not member
    try std.testing.expectError(error.NotMember, verify.requireMember(non_member, genesis, chanCtx(false, false)));
}

// ---------------------------------------------------------------------------
// BE-CHAN-03 (accept half). A node MUST NOT accept channel messages from a
// non-member; a revoked subject is treated as a non-member from the moment its
// revocation is accepted. The member gate refuses both shapes, and accepts a
// genuine member (group present, not revoked). (Fan-out half is Bucket D.)
// ---------------------------------------------------------------------------

test "BE_CHAN_03 non-member and revoked-member are both refused, member accepted" {
    const genesis = try parser.channel.parseControlGenesis(&decodeHex(CHAN_GENESIS_HEX));
    // (a) non-member: no member_group carried -> NotMember.
    const non_member = channelCert(&CHAN_ADMIN_GROUP, &CHAN_SENDER_PUB);
    try std.testing.expectError(error.NotMember, verify.requireMember(non_member, genesis, chanCtx(false, false)));
    // (b) revoked member: carries member_group but is revoked -> treated as a
    // non-member, refused as SubjectRevoked before the group check.
    const member = channelCert(&CHAN_MEMBER_GROUP, &CHAN_SENDER_PUB);
    try std.testing.expectError(error.SubjectRevoked, verify.requireMember(member, genesis, chanCtx(false, true)));
    // (c) a genuine member (group present, not revoked) is accepted.
    try verify.requireMember(member, genesis, chanCtx(false, false));
}

// ---------------------------------------------------------------------------
// BE-REV-02 (refuse half). A node holding a valid CA-signed revocation MUST
// refuse that subject's envelopes. The revocation is validated by verifyControl
// (action_type 2 signed by an admin cert), then the grow-only revoked set makes
// the member gate refuse the subject on the channel path. (Duration half is a
// straddler, checked separately under cert validity.)
// ---------------------------------------------------------------------------

test "BE_REV_02 a valid revoke is accepted and the revoked subject is then refused" {
    const genesis = try parser.channel.parseControlGenesis(&decodeHex(CHAN_GENESIS_HEX));
    const admin = channelCert(&CHAN_ADMIN_GROUP, &CHAN_SENDER_PUB);
    // A Revoke (action_type 2) signed by an admin cert is a valid control body.
    const revoke = try parser.channel.parseControl(&decodeHex(CHAN_REVOKE_HEX));
    try verify.verifyControl(revoke, genesis, admin);
    // Once the subject is in the grow-only revoked set, its channel messages are
    // refused - revocation is consulted at use, not at cache fill.
    const subject = channelCert(&CHAN_MEMBER_GROUP, &CHAN_SENDER_PUB);
    try std.testing.expectError(error.SubjectRevoked, verify.requireMember(subject, genesis, chanCtx(false, true)));
}

// ---------------------------------------------------------------------------
// BE-GEN-02 (genesis parameters immutable). Genesis parameters are immutable;
// no message changes them. The only genesis-touching control action is creation
// (action_type 1), accepted exactly once per channel_id. A re-issue - even
// proposing different fields - is refused wholesale, so name, member_group,
// admin_group, ca_keys and match_rule cannot be rewritten after creation.
// ---------------------------------------------------------------------------

test "BE_GEN_02 a genesis re-issue cannot mutate an existing channel's parameters" {
    const genesis = try parser.channel.parseControlGenesis(&decodeHex(CHAN_GENESIS_HEX));
    const admin = channelCert(&CHAN_ADMIN_GROUP, &CHAN_SENDER_PUB);
    const channel_id = deriveChannelId("test", &[_]u8{0xcc} ** 32);
    // The channel already exists: any further genesis is refused, so no message
    // can change the parameters that were fixed at creation.
    try std.testing.expectError(error.DuplicateGenesis, verify.verifyControlGenesis(genesis, admin, &channel_id, chanCtx(true, false)));
}

// ---------------------------------------------------------------------------
// BE-GRANT-03a (intent lifecycle frozen in a single critical section). From
// verify start to EXECUTING the lifecycle is frozen in one frame: the
// consumed-check (step 11) runs BEFORE execute, inside the same synchronous
// call. A grant already committed with no effect is refused and its callback
// never fires. If the freeze were broken (execute moved ahead of the consumed
// check), the effect would fire here.
// ---------------------------------------------------------------------------

test "BE_GRANT_03a consumed check closes the verify frame before execute" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.channel.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    const ctx = baseContext(ACTION, &ledgerSpent); // grant_id already consumed
    resetEffect();
    try std.testing.expectError(error.AlreadyConsumed, verify.verifyGrantThen(env, &grant, ctx, &recordEffect));
    // Refused inside the critical section, BEFORE execute: the effect never ran.
    try std.testing.expectEqual(@as(usize, 0), effect_calls);
}

// ---------------------------------------------------------------------------
// Lighthouse-served certificates (SPEC 5.1/5.1a, BE-MESH-01/04/05/06).
//
// The certs here are the real signed ones from cert_test_helpers, so
// validateCert runs its full chain rather than a stub. Per D-027 the expected
// overlay address is recomputed from BLAKE2s in the test rather than taken from
// binding.deriveOverlayAddr, which is the constant under test.
// ---------------------------------------------------------------------------

var opened_sig: []const u8 = &[_]u8{};
var opened_kex: []const u8 = &[_]u8{};
var open_calls: usize = 0;

fn recordOpen(keys: verify.SessionKeys) void {
    opened_sig = keys.sig_pubkey;
    opened_kex = keys.kex_pubkey;
    open_calls += 1;
}

fn resetOpen() void {
    opened_sig = &[_]u8{};
    opened_kex = &[_]u8{};
    open_calls = 0;
}

fn neverRevoked(sig_pubkey: []const u8) bool {
    _ = sig_pubkey;
    return false;
}

fn alwaysRevoked(sig_pubkey: []const u8) bool {
    _ = sig_pubkey;
    return true;
}

// Independent overlay-address derivation: 0xfd prefix over the first 15 bytes
// of BLAKE2s-256(sig_pubkey) (SPEC 5.1). Recomputed here, not imported.
fn expectedOverlayAddr(sig_pubkey: []const u8) [16]u8 {
    var full: [32]u8 = undefined;
    std.crypto.hash.blake2.Blake2s256.hash(sig_pubkey, &full, .{});
    var addr: [16]u8 = undefined;
    addr[0] = 0xfd;
    @memcpy(addr[1..16], full[0..15]);
    return addr;
}

// A time inside both helper certs' validity windows: the subject cert's wide
// CERT_NOT_BEFORE..CERT_NOT_AFTER span and the approver cert's 30-day
// PRIVILEGED_CERT_NOT_BEFORE..PRIVILEGED_CERT_NOT_AFTER span (BE-REV-01).
const MESH_NOW: u64 = 1_700_000_000_000;

fn meshCtx(now_ms: u64, revoked: bool) verify.MeshContext {
    return .{
        .trusted_ca_keys = cth.trustedSet(),
        .now_ms = now_ms,
        .is_revoked = if (revoked) &alwaysRevoked else &neverRevoked,
    };
}

test "BE_MESH_04 a served cert whose derived address matches opens the session" {
    resetOpen();
    const served = cth.subjectCert();
    const addr = expectedOverlayAddr(&cth.SUBJECT_PUB);
    try verify.verifyServedCertThen(served, &addr, meshCtx(MESH_NOW, false), &recordOpen);
    try std.testing.expectEqual(@as(usize, 1), open_calls);
    try std.testing.expectEqualSlices(u8, &cth.SUBJECT_PUB, opened_sig);
    try std.testing.expectEqualSlices(u8, served.kex_pubkey, opened_kex);
}

test "BE_MESH_04 an address that does not derive from the served key is refused" {
    resetOpen();
    const served = cth.subjectCert();
    var addr = expectedOverlayAddr(&cth.SUBJECT_PUB);
    addr[15] ^= 0x01; // one bit off the address that was asked for
    try std.testing.expectError(error.AddressMismatch, verify.verifyServedCertThen(served, &addr, meshCtx(MESH_NOW, false), &recordOpen));
    try std.testing.expectEqual(@as(usize, 0), open_calls);
}

test "BE_MESH_04 a served cert signed by an untrusted CA is refused" {
    resetOpen();
    const served = cth.subjectCert();
    const addr = expectedOverlayAddr(&cth.SUBJECT_PUB);
    const empty_trust: []const []const u8 = &[_][]const u8{};
    const ctx: verify.MeshContext = .{
        .trusted_ca_keys = empty_trust,
        .now_ms = MESH_NOW,
        .is_revoked = &neverRevoked,
    };
    try std.testing.expectError(error.ServedCertInvalid, verify.verifyServedCertThen(served, &addr, ctx, &recordOpen));
    try std.testing.expectEqual(@as(usize, 0), open_calls);
}

// The BE-MESH-01 case that matters: a lighthouse cannot forge, so its best
// attack is to answer a lookup with somebody else's genuinely valid
// certificate. BE-ID-01 detects it because the address is derived from the key,
// so the answer is not the identity that was asked for.
test "BE_MESH_01 a valid cert for a different identity is refused as a substitution" {
    resetOpen();
    const substituted = cth.approverCert(); // valid, trusted, in window, wrong identity
    const asked_for = expectedOverlayAddr(&cth.SUBJECT_PUB);
    try std.testing.expectError(error.AddressMismatch, verify.verifyServedCertThen(substituted, &asked_for, meshCtx(MESH_NOW, false), &recordOpen));
    try std.testing.expectEqual(@as(usize, 0), open_calls);
    // The same certificate is accepted for its own address, so the refusal
    // above is identity substitution and not a broken certificate.
    const own = expectedOverlayAddr(&cth.APPROVER_PUB);
    try verify.verifyServedCertThen(substituted, &own, meshCtx(MESH_NOW, false), &recordOpen);
    try std.testing.expectEqual(@as(usize, 1), open_calls);
}

// BE-MESH-05 is a shape guarantee, so it is asserted over the type rather than
// over one call: the continuation must not be able to carry an authority fact.
// Adding role_bits, scope_ids or name to SessionKeys fails here.
test "BE_MESH_05 the session-open continuation carries the two keys and nothing else" {
    const fields = @typeInfo(verify.SessionKeys).@"struct".fields;
    try std.testing.expectEqual(@as(usize, 2), fields.len);
    try std.testing.expectEqualStrings("sig_pubkey", fields[0].name);
    try std.testing.expectEqualStrings("kex_pubkey", fields[1].name);
}

// BE-MESH-06: the same certificate, cached and reused. Accepted while its
// window holds, refused once it has passed, with no re-parse and no re-fill in
// between: the verdict cannot be carried forward because no verdict is stored.
test "BE_MESH_06 a cached cert is refused once its validity window has passed" {
    resetOpen();
    const served = cth.subjectCert();
    const addr = expectedOverlayAddr(&cth.SUBJECT_PUB);
    try verify.verifyServedCertThen(served, &addr, meshCtx(MESH_NOW, false), &recordOpen);
    try std.testing.expectEqual(@as(usize, 1), open_calls);
    try std.testing.expectError(error.ServedCertInvalid, verify.verifyServedCertThen(served, &addr, meshCtx(cth.CERT_NOT_AFTER, false), &recordOpen));
    try std.testing.expectEqual(@as(usize, 1), open_calls);
}

test "BE_MESH_06 revocation is consulted at use, not at cache fill" {
    resetOpen();
    const served = cth.subjectCert();
    const addr = expectedOverlayAddr(&cth.SUBJECT_PUB);
    try verify.verifyServedCertThen(served, &addr, meshCtx(MESH_NOW, false), &recordOpen);
    try std.testing.expectEqual(@as(usize, 1), open_calls);
    try std.testing.expectError(error.ServedCertRevoked, verify.verifyServedCertThen(served, &addr, meshCtx(MESH_NOW, true), &recordOpen));
    try std.testing.expectEqual(@as(usize, 1), open_calls);
}

// ---------------------------------------------------------------------------
// BE-SIG-01 (domain separation). Every Ed25519 signature covers
// domain_tag || tbs; verify MUST reject a signature whose tag does not match
// the structure being verified. A signature valid for one structure class
// cannot be replayed against another. Tags: 0x01 Cert, 0x02 Envelope, 0x03
// Span, 0x04 Grant, 0x05 handshake binding, 0x06 Refusal (SPEC BE-SIG-01).
// ---------------------------------------------------------------------------

test "BE_SIG_01 signature under one domain tag rejected under another" {
    // SPEC BE-SIG-01: verification is over domain_tag || tbs, so a signature
    // made for one structure class fails under any other class's tag.
    const id = cth.keypair(0xa1);
    const pubkey = Ed.PublicKey.toBytes(id.public_key);
    const tbs = [_]u8{ 0xde, 0xad, 0xbe, 0xef };

    // Sign over DOMAIN_CERT (0x01) || tbs.
    var cert_msg: [5]u8 = undefined;
    cert_msg[0] = parser.session.DOMAIN_CERT;
    @memcpy(cert_msg[1..], &tbs);
    const sig = Ed.Signature.toBytes(Ed.KeyPair.sign(id, &cert_msg, null) catch unreachable);

    // Verifies under the matching Cert tag.
    try verify.verifySigned(parser.session.DOMAIN_CERT, &tbs, &sig, &pubkey);

    // Rejected under the Envelope tag (0x02): the bytes the signature covers
    // (0x01 || tbs) are not the bytes the verifier hashes (0x02 || tbs).
    try std.testing.expectError(error.BadSignature, verify.verifySigned(parser.channel.DOMAIN_ENVELOPE, &tbs, &sig, &pubkey));

    // Rejected under the Grant tag (0x04) for the same reason.
    try std.testing.expectError(error.BadSignature, verify.verifySigned(parser.channel.DOMAIN_GRANT, &tbs, &sig, &pubkey));
}

// ---------------------------------------------------------------------------
// BE-BODY-03 (rationale is prose, not a binding input). Intent.rationale is
// agent-authored prose, untrusted, and MUST NOT influence any authorization
// decision. It is not covered by the grant binding (BE-GRANT-02 hashes the
// action bytes alone). The guarantee is structural: actionDigest takes only
// the action, so rationale has no path into the digest regardless of its
// contents. Proof: the recomputed action digest over the canonical action
// matches the grant's stored digest, and that recomputation is a function of
// the action alone. rationale rides Intent for human display and is never
// read by the verifier (no read site outside parsing). If rationale were
// mixed into the digest, this recomputation would no longer match.
// ---------------------------------------------------------------------------

test "BE_BODY_03 rationale excluded from the grant binding" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.channel.parseGrant(&grant_bytes);

    // The grant bound exactly this action under exactly this digest. The
    // daemon recomputes actionDigest(ACTION) and compares to grant.action_digest.
    // rationale is not an argument to actionDigest, so it cannot perturb the
    // binding no matter its contents.
    try std.testing.expectEqualSlices(u8, grant.action_digest, &verify.actionDigest(ACTION));

    // rationale rides Intent as prose (present for human display) but is not
    // part of any digest input.
    try std.testing.expect(@hasField(parser.channel.Intent, "rationale"));
}

// ---------------------------------------------------------------------------
// BE-ENV-01 (envelope ts is not a security input). The sender's claimed ts
// MUST NOT drive any security decision: clocks lie and an adversary controls
// its own. Expiry is the grant's not_after against the verifier's own clock
// and time-since-receipt (BE-GRANT-05); replay is the per-(sender,channel)
// counter bitmap keyed on seq (BE-TR-03). env.ts rides tbs (tamper-evident)
// but no decision consults it. Proof: a grant verifying under ts=0 verifies
// identically under an arbitrarily different ts. If ts gated anything, the
// second call would diverge.
// ---------------------------------------------------------------------------

test "BE_ENV_01 envelope ts is not a security input" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.channel.parseGrant(&grant_bytes);
    const ctx = baseContext(ACTION, &ledgerFresh);

    // ts = 0: verifies.
    var env_zero = grantEnvelope(grant);
    env_zero.ts = 0;
    resetEffect();
    _ = try verify.verifyGrantThen(env_zero, &grant, ctx, &recordEffect);
    try std.testing.expectEqual(@as(usize, 1), effect_calls);

    // ts = maxInt: same grant, same outcome. ts gates nothing.
    var env_far = grantEnvelope(grant);
    env_far.ts = std.math.maxInt(u64);
    resetEffect();
    _ = try verify.verifyGrantThen(env_far, &grant, ctx, &recordEffect);
    try std.testing.expectEqual(@as(usize, 1), effect_calls);
}

// ---------------------------------------------------------------------------
// BE-GRANT-08 (the approver's own key). A Grant must be signed by a key the
// approving human controls directly. The envelope binding already forces
// sender == approver (BE-GRANT-03 check 1); this witness proves the sig check
// completes the pincer: a grant whose signature is made by the SUBJECT's own
// key, a valid Ed25519 signature over the identical tbs, is refused. An agent
// cannot sign its own homework.
// ---------------------------------------------------------------------------

test "BE_GRANT_08 grant signed by the subject instead of the approver is refused" {
    // The subject's own signing key: seed prefix 0x81, the canonical agent
    // identity in tools/gen-vectors.zig.
    const usurper = cth.keypair(0x81);
    try std.testing.expectEqual(cth.SUBJECT_PUB, Ed.PublicKey.toBytes(usurper.public_key));

    var grant_bytes = decodeHex(GRANT_HEX); // 271 bytes: TBS 207 + sig 64
    var msg: [1 + 207]u8 = undefined;
    msg[0] = parser.channel.DOMAIN_GRANT;
    @memcpy(msg[1..], grant_bytes[0..207]);
    const forged = try Ed.KeyPair.sign(usurper, &msg, null);
    @memcpy(grant_bytes[207..271], &Ed.Signature.toBytes(forged));

    const grant = try parser.channel.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant); // sender == approver, envelope binding intact
    const ctx = baseContext(ACTION, &ledgerFresh);
    resetEffect();
    try std.testing.expectError(error.BadSignature, verify.verifyGrantThen(env, &grant, ctx, &recordEffect));
    try std.testing.expectEqual(@as(usize, 0), effect_calls);
}

// ---------------------------------------------------------------------------
// BE-WIRE-03 (signing and hashing operate over the encoded bytes exactly as
// transmitted). There is no re-encoded copy on the verify path: the parsed
// tbs aliases the transmitted buffer, and a single flipped bit inside that
// buffer, after parsing, is enough to fail verification.
// ---------------------------------------------------------------------------

test "BE_WIRE_03 verification runs over the transmitted bytes themselves" {
    var env_bytes = decodeHex(ENVELOPE_HEX);
    const env = try parser.channel.parseEnvelope(&env_bytes);

    // Aliasing proof: the parsed tbs points into the transmitted buffer
    // itself, so the verifier consumes the encoded bytes as transmitted and
    // never a re-encoded copy.
    const buf_start = @intFromPtr(&env_bytes);
    const buf_end = buf_start + env_bytes.len;
    const tbs_start = @intFromPtr(env.tbs.ptr);
    try std.testing.expect(tbs_start >= buf_start);
    try std.testing.expect(tbs_start + env.tbs.len <= buf_end);

    // Flip one bit of the tbs region inside the transmitted buffer, after
    // parsing: the same parsed envelope now fails verification, because the
    // bytes it aliases are exactly the bytes the signature covers.
    env_bytes[20] ^= 0x01;
    try std.testing.expectError(error.BadSignature, verify.verifyEnvelope(env));
}

// ---------------------------------------------------------------------------
// Refusal verification (SPEC 8.5, BE-GRANT-09 verify half). The Refusal is the
// approver's signed NO over one intent_id (domain tag 0x06); it transitions a
// matching PENDING intent to REJECTED and releases the resource lock. The
// state-machine half (admit/dedupe/exclusivity/timeout/terminality) is bound in
// intent_test.zig; these tests bind the verify half: the sig MUST verify under
// tag 0x06 against the envelope sender, the sender's cert MUST carry the
// approver role, and a verified Refusal drives the PENDING -> REJECTED
// transition through intent.Table.applyRefusal. The wire is the canonical
// cross-implementation Refusal vector (test/vectors.json, structure refusal):
// if the verifier disagrees with it, the verifier is wrong.
// ---------------------------------------------------------------------------

const intent = @import("intent.zig");

// Canonical Refusal (123 bytes: intent_id 16 + note_len 2 + note 41 + sig 64),
// signed by the approver over domain tag 0x06. Fields mirror SPEC 8.5.
const REFUSAL_WIRE_HEX =
    "0102030405060708090a0b0c0d0e0f10" ++ // intent_id (== cth.INTENT_ID)
    "0029" ++ // note_len = 41
    "5265736f75726365206e6f74207265636f676e697a65642062792074686973206578656375746f722e" ++ // note
    "9d1177e78056b08516ca4ed42797b3f12f528766f610d0299f05cbc66b9bb6708b3c1322f408c834d0846374a71c069e5cd67eed770675bf9bb228d9daa3c40c"; // sig

// on_rejected callback state. Same single_threaded dependency as the grant
// effect counters above: written by more than one test block.
var rejected_calls: usize = 0;
var rejected_intent_id: []const u8 = &[_]u8{};

fn recordRejected(intent_id: []const u8) void {
    rejected_calls += 1;
    rejected_intent_id = intent_id;
}

fn resetRejected() void {
    rejected_calls = 0;
    rejected_intent_id = &[_]u8{};
}

// A body_type=6 envelope whose sender is the approver (BE-GRANT-03 check 1
// shape). verifyRefusalThen reads only body_type and sender from it.
fn refusalEnvelope() parser.channel.Envelope {
    return .{
        .version = 2,
        .channel_id = &[_]u8{},
        .sender = &cth.APPROVER_PUB,
        .seq = 0,
        .parent_count = 0,
        .parents = &[_]u8{},
        .ts = 0,
        .body_type = parser.channel.BODY_REFUSAL,
        .body = &[_]u8{},
        .tbs = &[_]u8{},
        .sig = &[_]u8{},
    };
}

// A PENDING intent the Refusal is meant to reject. intent_id matches the
// canonical Refusal vector so applyRefusal finds it.
fn pendingIntent() parser.channel.Intent {
    return .{ .intent_id = &cth.INTENT_ID, .resource_id = cth.RESOURCE_ID, .action = ACTION, .rationale = "" };
}

fn refusalCtx(table: *intent.Table) verify.RefusalContext {
    return .{
        .trusted_ca_keys = cth.trustedSet(),
        .approver_cert = cth.approverCert(),
        .now_ms = NOW_MS,
        .intent_table = table,
    };
}

test "BE_GRANT_09 canonical refusal verifies and rejects the pending intent" {
    const wire = decodeHex(REFUSAL_WIRE_HEX);
    const refusal = try parser.channel.parseRefusal(&wire);
    const env = refusalEnvelope();
    var table = intent.Table.init();
    try table.admit(pendingIntent(), NOW_MS);
    try std.testing.expectEqual(intent.State.pending, table.entries[0].state);
    const ctx = refusalCtx(&table);
    resetRejected();
    try verify.verifyRefusalThen(env, refusal, ctx, &recordRejected);
    // The transition ran exactly once, on the intent_id the routine verified.
    try std.testing.expectEqual(@as(usize, 1), rejected_calls);
    try std.testing.expectEqualSlices(u8, &cth.INTENT_ID, rejected_intent_id);
    // PENDING -> REJECTED: the lock is released without waiting for T_pending.
    try std.testing.expectEqual(intent.State.rejected, table.entries[0].state);
}

test "BE_GRANT_09 refusal delivered as the wrong body_type is refused" {
    const wire = decodeHex(REFUSAL_WIRE_HEX);
    const refusal = try parser.channel.parseRefusal(&wire);
    var env = refusalEnvelope();
    env.body_type = parser.channel.BODY_GRANT; // a Refusal is not a Grant
    var table = intent.Table.init();
    try table.admit(pendingIntent(), NOW_MS);
    const ctx = refusalCtx(&table);
    resetRejected();
    try std.testing.expectError(error.BadEnvelopeBinding, verify.verifyRefusalThen(env, refusal, ctx, &recordRejected));
    // Refused before the transition: the intent is still pending, nothing fired.
    try std.testing.expectEqual(intent.State.pending, table.entries[0].state);
    try std.testing.expectEqual(@as(usize, 0), rejected_calls);
}

test "BE_GRANT_09 corrupted refusal sig is refused" {
    var wire = decodeHex(REFUSAL_WIRE_HEX);
    wire[60] ^= 0xff; // flip one byte inside the 64-byte sig (offset 59..123)
    const refusal = try parser.channel.parseRefusal(&wire); // parse still succeeds
    const env = refusalEnvelope();
    var table = intent.Table.init();
    try table.admit(pendingIntent(), NOW_MS);
    const ctx = refusalCtx(&table);
    resetRejected();
    try std.testing.expectError(error.BadSignature, verify.verifyRefusalThen(env, refusal, ctx, &recordRejected));
    // A forged NO does not reject the intent: it stays pending, lock held.
    try std.testing.expectEqual(intent.State.pending, table.entries[0].state);
    try std.testing.expectEqual(@as(usize, 0), rejected_calls);
}

test "BE_GRANT_09 refusal signed under the wrong domain tag is refused" {
    var wire = decodeHex(REFUSAL_WIRE_HEX);
    // Re-sign the identical tbs under DOMAIN_GRANT (0x04) with the approver's
    // own key, then drop the forged sig into the wire. A signature valid for a
    // Grant does not authorize a Refusal (BE-SIG-01).
    const approver = cth.keypair(0x41);
    var msg: [1 + 59]u8 = undefined; // tag + tbs (intent_id 16 + note_len 2 + note 41 = 59)
    msg[0] = parser.channel.DOMAIN_GRANT;
    @memcpy(msg[1..], wire[0..59]);
    const forged = Ed.Signature.toBytes(try Ed.KeyPair.sign(approver, &msg, null));
    @memcpy(wire[59..123], &forged);
    const refusal = try parser.channel.parseRefusal(&wire);
    const env = refusalEnvelope();
    var table = intent.Table.init();
    try table.admit(pendingIntent(), NOW_MS);
    const ctx = refusalCtx(&table);
    resetRejected();
    try std.testing.expectError(error.BadSignature, verify.verifyRefusalThen(env, refusal, ctx, &recordRejected));
    try std.testing.expectEqual(intent.State.pending, table.entries[0].state);
}

test "BE_GRANT_09 refusal from a non-approver cert is refused" {
    const wire = decodeHex(REFUSAL_WIRE_HEX);
    const refusal = try parser.channel.parseRefusal(&wire);
    const env = refusalEnvelope();
    var table = intent.Table.init();
    try table.admit(pendingIntent(), NOW_MS);
    var ctx = refusalCtx(&table);
    // Approver-positioned cert that carries the agent role, not approver. The
    // sig_pubkey still matches APPROVER_PUB (the signer), so only the role
    // check fails here: a non-approver cannot issue a Refusal.
    var role_wire: [512]u8 = undefined;
    ctx.approver_cert = cth.buildCertInto(
        &role_wire,
        cth.APPROVER_PUB,
        binding.ROLE_AGENT,
        &[_]u8{0xc0},
        cth.CERT_NOT_BEFORE,
        cth.CERT_NOT_AFTER,
    );
    resetRejected();
    try std.testing.expectError(error.BadApproverCert, verify.verifyRefusalThen(env, refusal, ctx, &recordRejected));
    try std.testing.expectEqual(intent.State.pending, table.entries[0].state);
    try std.testing.expectEqual(@as(usize, 0), rejected_calls);
}

test "BE_GRANT_09 a verified refusal matching no pending intent is dropped" {
    const wire = decodeHex(REFUSAL_WIRE_HEX);
    const refusal = try parser.channel.parseRefusal(&wire);
    const env = refusalEnvelope();
    var table = intent.Table.init();
    // No intent is admitted: the Refusal matches nothing and is dropped, not
    // buffered. The sig and role checks still pass, so this is the no_match
    // branch (BE-GRANT-09), not a refusal.
    const ctx = refusalCtx(&table);
    resetRejected();
    try verify.verifyRefusalThen(env, refusal, ctx, &recordRejected);
    // No transition to report: on_rejected never fired.
    try std.testing.expectEqual(@as(usize, 0), rejected_calls);
    try std.testing.expectEqual(@as(usize, 0), table.len);
}

// ---------------------------------------------------------------------------
// F10/D-090: a Revoke body carries the SUBJECT's cert expiry as u64be. The
// reader is pure; admission wiring calls it in the F6 block of
// verifyEnvelopeAdmission. Absent field = never prune (fail-closed).
// ---------------------------------------------------------------------------

test "F10_D090 revoke body expiry read as u64be" {
    var body: [8]u8 = undefined;
    std.mem.writeInt(u64, &body, 1_700_000_000_000, .big);
    try std.testing.expectEqual(@as(u64, 1_700_000_000_000), verify.revokePruneExpiry(&body));
}

test "F10_D090 revoke body without the expiry field never prunes" {
    // Pre-D-090 bodies (empty or short) carry no subject expiry: the only
    // safe reading is maxInt, i.e. the revocation is never pruned.
    try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), verify.revokePruneExpiry(&[_]u8{}));
    try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), verify.revokePruneExpiry(&[_]u8{ 0x01, 0x02, 0x03 }));
}

// ---------------------------------------------------------------------------
// F15 (pre-audit v0.6.0 §2): the OFFICIAL issuer feeds the grant chain. The
// D-085 tests hand-build certs, so they never touched the issuer's version
// byte - the exact gap that let caIssue mint scope-inert v2 certs while
// reporting success. Everything here mints through caMaterial.caIssue for the
// canonical fixture identities and drives the REAL parse + validate path.

const ca_material = @import("ca_material.zig");
const keys_mod = @import("keys.zig");

fn f15ReadCert(io: std.Io, path: []const u8, buf: *[1024]u8) !parser.session.Cert {
    const f = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer f.close(io);
    const n = try f.readPositionalAll(io, buf, 0);
    return parser.session.parseCert(buf[0..n]);
}

test "F15 caIssue mints enforced v3 certs; tool-scoped approver refuses out-of-scope end to end" {
    var th = std.Io.Threaded.init_single_threaded;
    defer th.deinit();
    const io = th.io();

    var f15_seq: u32 = 0;
    f15_seq += 1;
    var rb: [64]u8 = undefined;
    const root = try std.fmt.bufPrint(&rb, "/tmp/bolina_f15_{d}", .{f15_seq});
    std.Io.Dir.cwd().createDir(io, root, @enumFromInt(0o700)) catch {};
    var b1: [96]u8 = undefined;
    const ca_dir = try std.fmt.bufPrint(&b1, "{s}/roots", .{root});
    var b2: [96]u8 = undefined;
    const appr_dir = try std.fmt.bufPrint(&b2, "{s}/appr", .{root});
    var b3: [96]u8 = undefined;
    const subj_dir = try std.fmt.bufPrint(&b3, "{s}/subj", .{root});
    var b4: [96]u8 = undefined;
    const sib_dir = try std.fmt.bufPrint(&b4, "{s}/sib", .{root});
    inline for (.{ ca_dir, appr_dir, subj_dir, sib_dir }) |p| {
        std.Io.Dir.cwd().createDir(io, p, @enumFromInt(0o700)) catch {};
    }

    // Node key material on disk, exactly what ca issue reads back. Identities
    // are the DISPATCH fixture keys (seedFrom prefixes): the grant below is
    // signed by cth.keypair(0xB1), so certs must bind THAT pubkey - the
    // vector-identity APPROVER_PUB would mismatch at check 2 (BadSignature).
    const kex = cth.pubkeyOf(0x5A);
    var k1: [128]u8 = undefined;
    try keys_mod.writeKeyFile(io, try std.fmt.bufPrint(&k1, "{s}/sig.pub", .{appr_dir}), &cth.pubkeyOf(0xB1));
    var k2: [128]u8 = undefined;
    try keys_mod.writeKeyFile(io, try std.fmt.bufPrint(&k2, "{s}/static.pub", .{appr_dir}), &kex);
    var k3: [128]u8 = undefined;
    try keys_mod.writeKeyFile(io, try std.fmt.bufPrint(&k3, "{s}/sig.pub", .{subj_dir}), &cth.pubkeyOf(0xA1));
    var k4: [128]u8 = undefined;
    try keys_mod.writeKeyFile(io, try std.fmt.bufPrint(&k4, "{s}/static.pub", .{subj_dir}), &kex);
    var k5: [128]u8 = undefined;
    try keys_mod.writeKeyFile(io, try std.fmt.bufPrint(&k5, "{s}/sig.pub", .{sib_dir}), &cth.pubkeyOf(0xB1));
    var k6: [128]u8 = undefined;
    try keys_mod.writeKeyFile(io, try std.fmt.bufPrint(&k6, "{s}/static.pub", .{sib_dir}), &kex);

    // Two random roots, trust anchors read back the way a daemon boots.
    try ca_material.caInit(io, ca_dir, 2);
    var tp: [2][32]u8 = undefined;
    var ts: [2][]const u8 = undefined;
    for (0..2) |i| {
        var pb: [96]u8 = undefined;
        const pp = try std.fmt.bufPrint(&pb, "{s}/ca/ca{d}.pub", .{ ca_dir, i });
        if (!try keys_mod.readKeyFile(io, pp, &tp[i])) return error.TestUnexpectedResult;
        ts[i] = &tp[i];
    }
    const trusted: []const []const u8 = &ts;

    const org = cth.RESOURCE_ID[0..std.mem.indexOf(u8, cth.RESOURCE_ID, "/").?];
    const covering = scopeIdOf(org);
    const sibling = scopeIdOf("bol:other_org");
    const ttl_priv = binding.MAX_PRIVILEGED_LIFETIME_MS;
    _ = try ca_material.caIssue(io, .{ .ca_dir = ca_dir, .node_dir = appr_dir, .role_bits = binding.ROLE_APPROVER, .ttl_ms = ttl_priv, .name = "f15-appr", .scopes = &.{covering} });
    _ = try ca_material.caIssue(io, .{ .ca_dir = ca_dir, .node_dir = subj_dir, .role_bits = binding.ROLE_AGENT, .ttl_ms = 86_400_000, .name = "f15-subj", .scopes = &.{covering} });
    _ = try ca_material.caIssue(io, .{ .ca_dir = ca_dir, .node_dir = sib_dir, .role_bits = binding.ROLE_APPROVER, .ttl_ms = ttl_priv, .name = "f15-sib", .scopes = &.{sibling} });

    var raw: [1024]u8 = undefined;
    var cb1: [1024]u8 = undefined;
    const acert = try f15ReadCert(io, try std.fmt.bufPrint(&raw, "{s}/cert.bin", .{appr_dir}), &cb1);
    var raw2: [1024]u8 = undefined;
    var cb2: [1024]u8 = undefined;
    const scert = try f15ReadCert(io, try std.fmt.bufPrint(&raw2, "{s}/cert.bin", .{subj_dir}), &cb2);
    var raw3: [1024]u8 = undefined;
    var cb3: [1024]u8 = undefined;
    const sibcert = try f15ReadCert(io, try std.fmt.bufPrint(&raw3, "{s}/cert.bin", .{sib_dir}), &cb3);

    // THE pin against regression: the tool's byte 0 is 3, scopes ride along.
    try std.testing.expectEqual(@as(u8, 3), acert.version);
    try std.testing.expectEqual(@as(usize, 1), acert.scope_count);
    try std.testing.expectEqualSlices(u8, &covering, acert.scope_ids[0..8]);
    binding.validateCert(acert, trusted, scert.not_before + 1000) catch |e| return e;

    // Fresh grant over the canonical fixtures, signed by the canonical
    // approver key, clock anchored to the issued cert's own validity window.
    const now = scert.not_before + 1000;
    var gw: [512]u8 = undefined;
    var n: usize = 0;
    gw[n] = 2;
    n += 1;
    const gid = [_]u8{0x5F} ** 16;
    @memcpy(gw[n..][0..16], &gid);
    n += 16;
    @memcpy(gw[n..][0..16], &cth.INTENT_ID);
    n += 16;
    const appr_pub = cth.pubkeyOf(0xB1);
    const subj_pub = cth.pubkeyOf(0xA1);
    @memcpy(gw[n..][0..32], &appr_pub);
    n += 32;
    @memcpy(gw[n..][0..32], &subj_pub);
    n += 32;
    @memcpy(gw[n..][0..32], &EXECUTOR_BYTES);
    n += 32;
    std.mem.writeInt(u16, gw[n..][0..2], @intCast(cth.RESOURCE_ID.len), .big);
    n += 2;
    @memcpy(gw[n..][0..cth.RESOURCE_ID.len], cth.RESOURCE_ID);
    n += cth.RESOURCE_ID.len;
    const dig = verify.actionDigest(ACTION);
    @memcpy(gw[n..][0..32], &dig);
    n += 32;
    std.mem.writeInt(u64, gw[n..][0..8], now + 3_590_000, .big);
    n += 8;
    var msg: [1 + 512]u8 = undefined;
    msg[0] = parser.channel.DOMAIN_GRANT;
    @memcpy(msg[1..][0..n], gw[0..n]);
    const akp = cth.keypair(0xB1);
    const gsig = try Ed.KeyPair.sign(akp, msg[0 .. 1 + n], null);
    const gsb = Ed.Signature.toBytes(gsig);
    @memcpy(gw[n..][0..64], &gsb);
    n += 64;
    const grant = try parser.channel.parseGrant(gw[0..n]);
    const env = grantEnvelope(grant);

    var itab = intent_mod.Table.init();
    try itab.admit(.{ .intent_id = &cth.INTENT_ID, .resource_id = cth.RESOURCE_ID, .action = ACTION, .rationale = "" }, now);
    var se: [1]verify.SenderTable.Entry = undefined;
    @memcpy(&se[0].intent_id, &cth.INTENT_ID);
    se[0].sender = cth.pubkeyOf(0xA1);
    @memcpy(se[0].action[0..ACTION.len], ACTION);
    se[0].action_len = ACTION.len;
    const stable = verify.SenderTable{ .entries = &se, .len = 1 };

    var ctx = verify.GrantContext{
        .own_pubkey = &EXECUTOR_BYTES,
        .trusted_ca_keys = trusted,
        .approver_cert = sibcert,
        .subject_cert = scert,
        .intent_table = &itab,
        .sender_table = &stable,
        .now_ms = now,
        .first_receipt_ms = now - 1000,
        .t_max_s = 3600,
        .t_recv_s = 300,
        .already_consumed = &ledgerFresh,
        .is_revoked = &revokedNo,
    };

    // Negative FIRST (a fired grant consumes state): sibling-scope approver
    // refuses at check 3a even though its cert came from the official tool.
    resetEffect();
    try std.testing.expectError(error.ApproverOutOfScope, verify.verifyGrantThen(env, &grant, ctx, &recordEffect));
    try std.testing.expectEqual(@as(usize, 0), effect_calls);

    // Positive: swap to the covering-scope tool cert - the SAME wire grant,
    // SAME tables, now reaches the effect exactly once.
    ctx.approver_cert = acert;
    resetEffect();
    _ = try verify.verifyGrantThen(env, &grant, ctx, &recordEffect);
    try std.testing.expectEqual(@as(usize, 1), effect_calls);
}
