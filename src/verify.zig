// verify.zig
//
// LANGUAGE.md section 4 implementation slice, item 2: Ed25519 verification and
// the Grant verifier (SPEC.md section 8.1, BE-GRANT-03).
//
// The parser (parser.zig) is total and zero-heap (BE-WIRE-01/02). This module
// adds the cryptographic layer on top of it:
//
//   * BE-ENV-02: an envelope's sig MUST verify against its sender (domain tag
//     0x02) before the body is interpreted; on failure the envelope is
//     discarded.
//   * BE-GRANT-03: a single verification routine runs every enforceable check
//     in the enumerated order and refuses on the first failure. The checks that
//     need external state the slice does not model (certificate validity for
//     checks 3 and 4, the pending-intent table for checks 6, 7 and 8) are left
//     to the executor to wire around this routine. Check 11 (the BE-GRANT-01
//     durable ledger) is exposed as a hook supplied by the caller and, by the
//     shape of this function, it is always the last thing that runs.
//
// Verification is zero-heap. Ed25519 is checked with the stdlib's streaming
// Verifier so the domain tag and the to-be-signed region are fed as two
// separate chunks; no buffer is allocated to prepend the tag (BE-SIG-01).

const std = @import("std");
const parser = @import("parser.zig");

const Ed = std.crypto.sign.Ed25519;
const B2s = std.crypto.hash.blake2.Blake2s256;

// ---------------------------------------------------------------------------
// Errors. One distinct class per failed BE check so tests assert the reason a
// capability was refused, not a generic "invalid".
// ---------------------------------------------------------------------------

pub const VerifyError = error{
    BadVersion, // BE-GRANT-03 check 0: Grant.version != 2
    BadEnvelopeBinding, // BE-GRANT-03 check 1: not body_type=3, or sender != approver
    BadSignature, // BE-ENV-02 / check 2: sig does not verify
    MalformedKey, // a pubkey is not a valid curve point (cannot verify at all)
    WrongExecutor, // BE-GRANT-03 check 5: executor != this executor's key
    ActionDigestMismatch, // BE-GRANT-02 / check 9: BLAKE2s(action) != action_digest
    Expired, // BE-GRANT-05 / check 10: any of the three expiry conditions
    AlreadyConsumed, // BE-GRANT-01 / check 11: grant_id already in the ledger
};

// ---------------------------------------------------------------------------
// Low-level signature check (BE-SIG-01 domain separation).
//
// Verifies `sig` over (domain_tag || tbs) against `pubkey`. The streaming
// Verifier lets us feed the one-byte tag and then the tbs region as two chunks,
// so no allocation is needed to build the tagged message.
// ---------------------------------------------------------------------------

pub fn verifySigned(tag: u8, tbs: []const u8, sig: []const u8, pubkey: []const u8) VerifyError!void {
    if (pubkey.len != parser.LEN_PUBKEY) return error.MalformedKey;
    if (sig.len != parser.LEN_SIG) return error.BadSignature;

    const pk = Ed.PublicKey.fromBytes(pubkey[0..parser.LEN_PUBKEY].*) catch return error.MalformedKey;
    const signature = Ed.Signature.fromBytes(sig[0..parser.LEN_SIG].*);
    // A non-canonical R or an identity element in the signature is a bad sig.
    var v = signature.verifier(pk) catch return error.BadSignature;

    const tag_bytes = [1]u8{tag};
    v.update(&tag_bytes);
    v.update(tbs);
    v.verify() catch return error.BadSignature;
}

// ---------------------------------------------------------------------------
// Envelope signature (BE-ENV-02).
// ---------------------------------------------------------------------------

pub fn verifyEnvelope(env: parser.Envelope) VerifyError!void {
    try verifySigned(parser.DOMAIN_ENVELOPE, env.tbs, env.sig, env.sender);
}

// ---------------------------------------------------------------------------
// BE-GRANT-02 helper: recompute the binding digest over the intent's action.
// ---------------------------------------------------------------------------

pub fn actionDigest(action: []const u8) [parser.LEN_ACTION_DIGEST]u8 {
    var out: [parser.LEN_ACTION_DIGEST]u8 = undefined;
    B2s.hash(action, &out, .{});
    return out;
}

// ---------------------------------------------------------------------------
// BE-GRANT-05 (bounded expiry). Refuses if ANY of the three conditions holds:
//   (a) not_after is already past on the executor's clock,
//   (b) not_after lies more than T_max beyond first receipt (an approver may
//       not mint long-lived authority by writing a distant timestamp),
//   (c) more than T_recv has elapsed since first receipt of this grant_id
//       (redelivery does not restart this budget).
// All values are unix milliseconds; t_max_s and t_recv_s are whole seconds.
// ---------------------------------------------------------------------------

fn checkExpiry(not_after: u64, now_ms: u64, first_receipt_ms: u64, t_max_s: u64, t_recv_s: u64) VerifyError!void {
    const t_max_ms = t_max_s * 1000;
    const t_recv_ms = t_recv_s * 1000;
    if (now_ms > not_after) return error.Expired;
    if (not_after > first_receipt_ms + t_max_ms) return error.Expired;
    if (now_ms > first_receipt_ms + t_recv_ms) return error.Expired;
}

// ---------------------------------------------------------------------------
// GrantContext: the inputs the executor supplies for the checks this routine
// can enforce without external state. Checks 3/4 (certificates) and 6/7/8
// (pending-intent matching) are not modeled here; the executor wires them in.
// ---------------------------------------------------------------------------

pub const GrantContext = struct {
    // Check 5: this executor's own sig_pubkey.
    own_pubkey: []const u8,
    // Check 9 (BE-GRANT-02): the pending intent's action bytes, re-hashed here.
    intent_action: []const u8,
    // Check 10 (BE-GRANT-05): the executor's clock and the grant's receipt time.
    now_ms: u64,
    first_receipt_ms: u64,
    t_max_s: u64, // default 3600
    t_recv_s: u64, // default 300
    // Check 11 (BE-GRANT-01): the consumed-grant ledger hook. Returns true if
    // the grant_id is ALREADY consumed. This is the only check that performs
    // I/O, and it runs last. The slice supplies an in-memory stand-in; a real
    // executor commits the grant_id durably before the effect is attempted.
    already_consumed: *const fn (grant_id: []const u8) bool,
};

// ---------------------------------------------------------------------------
// VerifiedGrant: the capability this routine produces (BE-GRANT-03b).
//
// opaque {} is the forgery wall. It has no fields and no size, so no code
// anywhere can construct one by value: the struct-literal mint that a plain
// public-field struct would allow is a compile error. The ONLY way to obtain
// a *const VerifiedGrant is the verification routine below, and the ONLY way
// to fabricate the pointer is @ptrCast, confined to the two boundary
// functions here (verifyGrant, grantOf) and gated mechanically by M8
// (tools/prumo-verify, CONTRIBUTING.md). test/negative_capability.zig is the
// canary: it tries the old struct-literal mint and MUST fail to compile; the
// `zig build negative` step asserts on it.
//
// The backing data is the caller's Grant (parser slices alias the input bytes,
// never the heap, BE-WIRE-01), so the capability carries no allocation.
// ---------------------------------------------------------------------------

pub const VerifiedGrant = opaque {};

// Boundary accessor (the @ptrCast here is one of exactly two in the module;
// M8). Consumers read the grant through this, never by constructing the
// capability.
pub fn grantOf(v: *const VerifiedGrant) *const parser.Grant {
    return @ptrCast(@alignCast(v));
}

// ---------------------------------------------------------------------------
// verifyGrant: the single BE-GRANT-03 verification routine (slice subset).
//
// Checks run in the enumerated order and refuse on the first failure. The
// ledger hook (check 11) is the last statement, so any earlier refusal short-
// circuits before the durable commit would happen, matching the normative
// ordering from RED-TEAM-08 (F3).
// ---------------------------------------------------------------------------

pub fn verifyGrant(env: parser.Envelope, grant_ptr: *const parser.Grant, ctx: GrantContext) VerifyError!*const VerifiedGrant {
    const grant = grant_ptr.*;
    // 0. Grant.version must be 2 (RED-TEAM-08 F6: the field is read, not ignored).
    if (grant.version != 2) return error.BadVersion;

    // 1. The grant arrived as a body_type=3 envelope whose sender is the approver.
    if (env.body_type != parser.BODY_GRANT) return error.BadEnvelopeBinding;
    if (!std.mem.eql(u8, env.sender, grant.approver)) return error.BadEnvelopeBinding;

    // 2. Grant.sig verifies against Grant.approver (domain tag 0x04).
    try verifySigned(parser.DOMAIN_GRANT, grant.tbs, grant.sig, grant.approver);

    // 3 and 4 (approver/subject certificate validity) and 6, 7, 8 (subject,
    // intent_id and resource_id matching against the pending intent) require a
    // certificate store and the executor's pending-intent table. The executor
    // performs those around this routine; they are omitted from the slice.

    // 5. Grant.executor equals this executor's own sig_pubkey.
    if (!std.mem.eql(u8, grant.executor, ctx.own_pubkey)) return error.WrongExecutor;

    // 9. Grant.action_digest equals BLAKE2s recomputed over the intent's action
    //    bytes (BE-GRANT-02). Exact match, no partial or semantic matching.
    const digest = actionDigest(ctx.intent_action);
    if (!std.mem.eql(u8, &digest, grant.action_digest)) return error.ActionDigestMismatch;

    // 10. Expiry passes all three conditions of BE-GRANT-05.
    try checkExpiry(grant.not_after, ctx.now_ms, ctx.first_receipt_ms, ctx.t_max_s, ctx.t_recv_s);

    // 11. grant_id is not already consumed (BE-GRANT-01). Only I/O step; last.
    if (ctx.already_consumed(grant.grant_id)) return error.AlreadyConsumed;

    // Boundary constructor (the @ptrCast here is one of exactly two in the
    // module; M8). The pointer aliases the caller's Grant storage directly.
    return @ptrCast(grant_ptr);
}
