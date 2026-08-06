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
// records through a package-level variable the ordering test reads back.
var ledger_calls: usize = 0;

fn ledgerFresh(grant_id: []const u8) bool {
    _ = grant_id;
    return false;
}

fn ledgerSpent(grant_id: []const u8) bool {
    _ = grant_id;
    return true;
}

fn ledgerCounting(grant_id: []const u8) bool {
    _ = grant_id;
    ledger_calls += 1;
    return false;
}

// The grant always arrives inside a body_type=3 envelope whose sender is the
// approver (BE-GRANT-03 check 1). The canonical vector is the bare grant, so
// the tests synthesize that envelope around it; verifyGrant only reads
// body_type and sender from it.
fn grantEnvelope(grant: parser.Grant) parser.Envelope {
    return .{
        .version = 2,
        .channel_id = &[_]u8{},
        .sender = grant.approver,
        .seq = 0,
        .parent_count = 0,
        .parents = &[_]u8{},
        .ts = 0,
        .body_type = parser.BODY_GRANT,
        .body = &[_]u8{},
        .tbs = &[_]u8{},
        .sig = &[_]u8{},
    };
}

fn baseContext(action: []const u8, hook: *const fn ([]const u8) bool) verify.GrantContext {
    return .{
        .own_pubkey = &EXECUTOR_BYTES,
        .intent_action = action,
        .now_ms = NOW_MS,
        .first_receipt_ms = FIRST_RECEIPT_MS,
        .t_max_s = T_MAX_S,
        .t_recv_s = T_RECV_S,
        .already_consumed = hook,
    };
}

test "BE_ENV_02 envelope sig verifies against sender before body" {
    const env_bytes = decodeHex(ENVELOPE_HEX);
    const env = try parser.parseEnvelope(&env_bytes);
    try verify.verifyEnvelope(env);
}

test "BE_ENV_02 corrupted envelope sig is discarded" {
    var env_bytes = decodeHex(ENVELOPE_HEX);
    env_bytes[220] ^= 0xff; // flip one byte inside the 64-byte sig (216..280)
    const env = try parser.parseEnvelope(&env_bytes);
    try std.testing.expectError(error.BadSignature, verify.verifyEnvelope(env));
}

test "BE_GRANT_03 canonical grant verifies end to end" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    var slot: verify.CapSlot = undefined;
    const ctx = baseContext(ACTION, &ledgerFresh);
    const verified = try verify.verifyGrant(env, &grant, ctx, &slot);
    try std.testing.expectEqualSlices(u8, grant.grant_id, (try verify.grantOf(verified)).grant_id);
}

test "BE_GRANT_03 version other than 2 refused first" {
    var grant_bytes = decodeHex(GRANT_HEX);
    grant_bytes[0] = 3; // version field; flipping it also breaks the sig, but
    const grant = try parser.parseGrant(&grant_bytes); // check 0 runs before check 2
    const env = grantEnvelope(grant);
    var slot: verify.CapSlot = undefined;
    const ctx = baseContext(ACTION, &ledgerFresh);
    try std.testing.expectError(error.BadVersion, verify.verifyGrant(env, &grant, ctx, &slot));
}

test "BE_GRANT_03 grant not delivered as body_type 3 envelope refused" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.parseGrant(&grant_bytes);
    var env = grantEnvelope(grant);
    var slot: verify.CapSlot = undefined;
    env.body_type = parser.BODY_INTENT; // wrong delivery path
    const ctx = baseContext(ACTION, &ledgerFresh);
    try std.testing.expectError(error.BadEnvelopeBinding, verify.verifyGrant(env, &grant, ctx, &slot));
}

test "BE_GRANT_03 envelope sender not the approver refused" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.parseGrant(&grant_bytes);
    var env = grantEnvelope(grant);
    var slot: verify.CapSlot = undefined;
    env.sender = grant.subject; // delivered by the agent, not the approver
    const ctx = baseContext(ACTION, &ledgerFresh);
    try std.testing.expectError(error.BadEnvelopeBinding, verify.verifyGrant(env, &grant, ctx, &slot));
}

test "BE_GRANT_03 corrupted grant sig is refused" {
    var grant_bytes = decodeHex(GRANT_HEX);
    grant_bytes[210] ^= 0xff; // inside the 64-byte sig (207..271)
    const grant = try parser.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    var slot: verify.CapSlot = undefined;
    const ctx = baseContext(ACTION, &ledgerFresh);
    try std.testing.expectError(error.BadSignature, verify.verifyGrant(env, &grant, ctx, &slot));
}

test "BE_GRANT_03 executor mismatch refused" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    var slot: verify.CapSlot = undefined;
    var ctx = baseContext(ACTION, &ledgerFresh);
    ctx.own_pubkey = grant.subject; // this executor is not the named one
    try std.testing.expectError(error.WrongExecutor, verify.verifyGrant(env, &grant, ctx, &slot));
}

test "BE_GRANT_02 action digest must match byte for byte" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    var slot: verify.CapSlot = undefined;
    // Approving "apt-get install -y sqlite3" does not approve a different
    // command: the recomputed digest over other bytes must not match.
    const ctx = baseContext("apt-get install -y postgresql", &ledgerFresh);
    try std.testing.expectError(error.ActionDigestMismatch, verify.verifyGrant(env, &grant, ctx, &slot));
}

test "BE_GRANT_05 not_after in the past is refused" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    var slot: verify.CapSlot = undefined;
    var ctx = baseContext(ACTION, &ledgerFresh);
    ctx.now_ms = grant.not_after + 1; // clock is past the expiry
    try std.testing.expectError(error.Expired, verify.verifyGrant(env, &grant, ctx, &slot));
}

test "BE_GRANT_05 not_after beyond T_max from receipt is refused" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    var slot: verify.CapSlot = undefined;
    var ctx = baseContext(ACTION, &ledgerFresh);
    // First receipt far enough back that not_after exceeds receipt + T_max.
    ctx.first_receipt_ms = grant.not_after - (T_MAX_S * 1000) - 1;
    try std.testing.expectError(error.Expired, verify.verifyGrant(env, &grant, ctx, &slot));
}

test "BE_GRANT_05 more than T_recv since first receipt is refused" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    var slot: verify.CapSlot = undefined;
    var ctx = baseContext(ACTION, &ledgerFresh);
    ctx.now_ms = FIRST_RECEIPT_MS + (T_RECV_S * 1000) + 1;
    try std.testing.expectError(error.Expired, verify.verifyGrant(env, &grant, ctx, &slot));
}

// Boundary tests for the non-strict not_after bound (BE-GRANT-05, SPEC pinned
// at now_ms >= not_after). The instant of expiry is denied, not granted; the
// last millisecond before it is the final valid moment.
test "BE_GRANT_05 not_after exact instant is refused (boundary deny)" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    var slot: verify.CapSlot = undefined;
    var ctx = baseContext(ACTION, &ledgerFresh);
    ctx.now_ms = grant.not_after; // equal, not strictly past
    try std.testing.expectError(error.Expired, verify.verifyGrant(env, &grant, ctx, &slot));
}

test "BE_GRANT_05 not_after minus 1ms is accepted (boundary deny)" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    var slot: verify.CapSlot = undefined;
    var ctx = baseContext(ACTION, &ledgerFresh);
    ctx.now_ms = grant.not_after - 1; // the last valid millisecond
    // first_receipt is far enough inside T_recv that the receipt bound still
    // holds at this now_ms, so the only boundary in play is not_after.
    const verified = try verify.verifyGrant(env, &grant, ctx, &slot);
    try std.testing.expectEqualSlices(u8, grant.grant_id, (try verify.grantOf(verified)).grant_id);
}

// T_max and T_recv boundary-allow tests. Each refuse condition is strict
// ("more than"), so the exact-equal instant is allowed. These kill the
// WRONG-OPERATOR mutants on the T_max and T_recv comparisons in the mutation
// harness (tools/mutation-test.py): a >= mutant would refuse at equality.
test "BE_GRANT_05 not_after exactly T_max from receipt is accepted (boundary)" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    var slot: verify.CapSlot = undefined;
    var ctx = baseContext(ACTION, &ledgerFresh);
    // not_after sits exactly first_receipt + T_max. "More than T_max" is the
    // refuse condition, so equality is allowed. now is well inside T_recv and
    // before not_after, so T_max is the only boundary in play.
    ctx.first_receipt_ms = grant.not_after - (T_MAX_S * 1000);
    ctx.now_ms = ctx.first_receipt_ms + 150_000; // 150s, inside T_recv (300s)
    const verified = try verify.verifyGrant(env, &grant, ctx, &slot);
    try std.testing.expectEqualSlices(u8, grant.grant_id, (try verify.grantOf(verified)).grant_id);
}

test "BE_GRANT_05 now exactly T_recv since receipt is accepted (boundary)" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    var slot: verify.CapSlot = undefined;
    var ctx = baseContext(ACTION, &ledgerFresh);
    // now sits exactly first_receipt + T_recv. "More than T_recv" is the refuse
    // condition, so equality is allowed. not_after is within T_max and ahead of
    // now, so T_recv is the only boundary in play.
    ctx.first_receipt_ms = grant.not_after - (T_MAX_S * 1000 / 2);
    ctx.now_ms = ctx.first_receipt_ms + (T_RECV_S * 1000);
    const verified = try verify.verifyGrant(env, &grant, ctx, &slot);
    try std.testing.expectEqualSlices(u8, grant.grant_id, (try verify.grantOf(verified)).grant_id);
}

test "BE_GRANT_01 already-consumed grant_id refused" {
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    var slot: verify.CapSlot = undefined;
    const ctx = baseContext(ACTION, &ledgerSpent);
    try std.testing.expectError(error.AlreadyConsumed, verify.verifyGrant(env, &grant, ctx, &slot));
}

test "BE_GRANT_01 ledger hook runs last, after expiry" {
    ledger_calls = 0;
    const grant_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.parseGrant(&grant_bytes);
    const env = grantEnvelope(grant);
    var slot: verify.CapSlot = undefined;
    // Make expiry fail (check 10). The ledger (check 11) must not be
    // reached, proving the I/O step is ordered after every compute check.
    var ctx = baseContext(ACTION, &ledgerCounting);
    ctx.now_ms = grant.not_after + 1;
    try std.testing.expectError(error.Expired, verify.verifyGrant(env, &grant, ctx, &slot));
    try std.testing.expectEqual(@as(usize, 0), ledger_calls);

    // Same hook, a valid grant: now the ledger IS consulted exactly once.
    ledger_calls = 0;
    const ok_ctx = baseContext(ACTION, &ledgerCounting);
    _ = try verify.verifyGrant(env, &grant, ok_ctx, &slot);
    try std.testing.expectEqual(@as(usize, 1), ledger_calls);
}

// BE-GRANT-03c TOCTOU seal. The capability is sealed over the exact grant bytes
// the routine verified; grantOf recomputes the seal over the LIVE bytes (the
// caller's buffer, aliased by slot.wire) and refuses on any mismatch. A caller
// that mutates its own buffer between verification and consumption must not
// reach the effect reading stale-approved bytes.
test "BE_GRANT_03c seal refuses after post-verification mutation (TOCTOU)" {
    var wire_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.parseGrant(&wire_bytes);
    const env = grantEnvelope(grant);
    var slot: verify.CapSlot = undefined;
    const ctx = baseContext(ACTION, &ledgerFresh);
    const verified = try verify.verifyGrant(env, &grant, ctx, &slot);

    // Tamper with a byte the seal covers, AFTER the capability was already
    // verified over the original bytes. slot.wire aliases this buffer live, so
    // the recomputed seal must diverge and grantOf must refuse with Tampered.
    wire_bytes[40] ^= 0xff;
    try std.testing.expectError(error.Tampered, verify.grantOf(verified));
}

// Control for the TOCTOU test above. The seal over unmutated bytes still
// matches the frozen seal, so grantOf succeeds and returns the re-parsed grant.
// This proves the tamper test refuses because the bytes changed, not because
// the accessor never accepts.
test "BE_GRANT_03c seal accepts unmutated bytes (control)" {
    var wire_bytes = decodeHex(GRANT_HEX);
    const grant = try parser.parseGrant(&wire_bytes);
    const env = grantEnvelope(grant);
    var slot: verify.CapSlot = undefined;
    const ctx = baseContext(ACTION, &ledgerFresh);
    const verified = try verify.verifyGrant(env, &grant, ctx, &slot);

    const out = try verify.grantOf(verified);
    try std.testing.expectEqualSlices(u8, grant.grant_id, out.grant_id);
}
