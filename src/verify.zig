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
//     in the enumerated order and refuses on the first failure. The certificate
//     chain (checks 3 and 4) and the pending-intent match (checks 6, 7 and 8)
//     are folded in via the GrantContext: the caller supplies the approver and
//     subject certs, the trusted CA set, and the pending-intent fields. Check
//     11 (the BE-GRANT-01 durable ledger) is exposed as a hook supplied by the
//     caller and, by the shape of this function, it is always the last thing
//     that runs.
//   * BE-GRANT-03b (round 4 restatement): verification is a call, not a value.
//     The routine does not hand back a capability. It runs the checks, commits
//     the ledger (check 11), and invokes the effect itself, inside its own
//     frame, passing the grant by value. No value representing a verified
//     grant exists outside that call, so there is nothing to keep, replay,
//     seal, or use after the routine returns. The forgery wall of the earlier
//     draft (an opaque capability type plus two pointer-mint casts) left with
//     the window: with no capability value, there is nothing to forge, and the
//     pointer-minting builtin set is empty across the whole tree (M8). The
//     single reach path to the effect is the callback invocation in this
//     routine, which the call-graph wall M10 makes load-bearing.
//
// Verification is zero-heap. Ed25519 is checked with the stdlib's streaming
// Verifier so the domain tag and the to-be-signed region are fed as two
// separate chunks; no buffer is allocated to prepend the tag (BE-SIG-01). The
// grant the routine verifies is the caller's parsed struct, read by value; the
// effect runs on that value inside the frame, never on a storable handle.

const std = @import("std");
const parser = @import("parser.zig");
const binding = @import("binding.zig");

const Ed = std.crypto.sign.Ed25519;
const B2s = std.crypto.hash.blake2.Blake2s256;

// ---------------------------------------------------------------------------
// Errors. One distinct class per failed BE check so tests assert the reason a
// grant was refused, not a generic "invalid".
// ---------------------------------------------------------------------------

pub const VerifyError = error{
    BadVersion, // BE-GRANT-03 check 0: Grant.version != 2
    BadEnvelopeBinding, // BE-GRANT-03 check 1: not body_type=3, or sender != approver
    BadSignature, // BE-ENV-02 / check 2: sig does not verify
    MalformedKey, // a pubkey is not a valid curve point (cannot verify at all)
    BadApproverCert, // BE-GRANT-03 check 3: approver cert invalid, wrong role, or not the grant's approver
    BadSubjectCert, // BE-GRANT-03 check 4: subject cert invalid, wrong role, or not the grant's subject
    WrongExecutor, // BE-GRANT-03 check 5: executor != this executor's key
    WrongSubject, // BE-GRANT-03 check 6: subject != pending intent's sender
    NoMatchingIntent, // BE-GRANT-03 check 7: intent_id matches no pending intent
    WrongResource, // BE-GRANT-03 check 8: resource_id != pending intent's canonical resource_id
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
    if (sig.len != parser.channel.LEN_SIG) return error.BadSignature;

    const pk = Ed.PublicKey.fromBytes(pubkey[0..parser.LEN_PUBKEY].*) catch return error.MalformedKey;
    const signature = Ed.Signature.fromBytes(sig[0..parser.channel.LEN_SIG].*);
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

pub fn verifyEnvelope(env: parser.channel.Envelope) VerifyError!void {
    try verifySigned(parser.channel.DOMAIN_ENVELOPE, env.tbs, env.sig, env.sender);
}

// ---------------------------------------------------------------------------
// BE-GRANT-02 helper: recompute the binding digest over the intent's action.
// ---------------------------------------------------------------------------

pub fn actionDigest(action: []const u8) [parser.channel.LEN_ACTION_DIGEST]u8 {
    var out: [parser.channel.LEN_ACTION_DIGEST]u8 = undefined;
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
    // (a) non-strict: a Grant whose not_after equals the current millisecond is
    // refused. Capability boundaries are denied at the instant of expiry, not
    // granted (BE-GRANT-05, SPEC pinned at now_ms >= not_after).
    if (now_ms >= not_after) return error.Expired;
    if (not_after > first_receipt_ms + t_max_ms) return error.Expired;
    if (now_ms > first_receipt_ms + t_recv_ms) return error.Expired;
}

// ---------------------------------------------------------------------------
// GrantContext: every input the verification routine needs. The certificate
// chain (binding.zig) validates checks 3 and 4; the pending-intent fields
// drive checks 6, 7 and 8; the ledger hook is check 11. The certificate
// store and pending-intent table the slice used to defer to the executor are
// now supplied here, so the routine models the full twelve-check chain.
// ---------------------------------------------------------------------------

pub const GrantContext = struct {
    // Check 5: this executor's own sig_pubkey.
    own_pubkey: []const u8,
    // Checks 3 and 4 (BE-ID-02/03/04): the approver and subject certs, the
    // local CA trust set, and the executor's clock used for cert validity.
    trusted_ca_keys: []const []const u8,
    approver_cert: parser.session.Cert,
    subject_cert: parser.session.Cert,
    // Checks 6, 7 and 8: the pending intent's sender, id, and canonical
    // resource_id, matched against the grant.
    intent_sender: []const u8,
    pending_intent_id: []const u8,
    pending_resource_id: []const u8,
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
// verifyGrantThen: the single BE-GRANT-03 verification routine (slice subset).
//
// Checks run in the enumerated order and refuse on the first failure. The
// ledger hook (check 11) is the last check, so any earlier refusal short-
// circuits before the durable commit would happen, matching the normative
// ordering from RED-TEAM-08 (F3). On success the effect runs: the caller's
// callback is invoked ONCE, inside this frame, with the grant passed by value.
// No verified-grant value leaves the routine, so there is nothing to keep,
// replay, or use later (BE-GRANT-03b, round 4 restatement).
//
// Single-shot ordering (BE-GRANT-01): the durable ledger commit is the last
// check and runs BEFORE the callback. A failed effect therefore leaves the
// grant_id spent: the commit is already durable, and a failed effect is the
// interrupted case of BE-GRANT-01a, never retried, never un-consumed. Pinned
// here so the first reader who hits a failed effect does not "fix" it into a
// retry (Daniel, round 4).
// ---------------------------------------------------------------------------

pub fn verifyGrantThen(env: parser.channel.Envelope, grant_ptr: *const parser.channel.Grant, ctx: GrantContext, execute: *const fn (parser.channel.Grant) void) VerifyError!void {
    const grant = grant_ptr.*;
    // 0. Grant.version must be 2 (RED-TEAM-08 F6: the field is read, not ignored).
    if (grant.version != 2) return error.BadVersion;

    // 1. The grant arrived as a body_type=3 envelope whose sender is the approver.
    if (env.body_type != parser.channel.BODY_GRANT) return error.BadEnvelopeBinding;
    if (!std.mem.eql(u8, env.sender, grant.approver)) return error.BadEnvelopeBinding;

    // 2. Grant.sig verifies against Grant.approver (domain tag 0x04).
    try verifySigned(parser.channel.DOMAIN_GRANT, grant.tbs, grant.sig, grant.approver);

    // 3. Approver certificate valid NOW and carries the approver role (BE-ID-02,
    //    BE-ID-04). The cert binds the identity that signed the grant, so its
    //    sig_pubkey must equal Grant.approver. validateCert runs the full chain
    //    (role constraints, approver quorum, validity window, CA signatures,
    //    trust set); a single failure class reports the refusal.
    binding.validateCert(ctx.approver_cert, ctx.trusted_ca_keys, ctx.now_ms) catch return error.BadApproverCert;
    if ((ctx.approver_cert.role_bits & binding.ROLE_APPROVER) == 0) return error.BadApproverCert;
    if (!std.mem.eql(u8, ctx.approver_cert.sig_pubkey, grant.approver)) return error.BadApproverCert;

    // 4. Subject certificate valid NOW and carries the agent role. Its identity
    //    key is the subject the grant authorizes.
    binding.validateCert(ctx.subject_cert, ctx.trusted_ca_keys, ctx.now_ms) catch return error.BadSubjectCert;
    if ((ctx.subject_cert.role_bits & binding.ROLE_AGENT) == 0) return error.BadSubjectCert;
    if (!std.mem.eql(u8, ctx.subject_cert.sig_pubkey, grant.subject)) return error.BadSubjectCert;

    // 5. Grant.executor equals this executor's own sig_pubkey.
    if (!std.mem.eql(u8, grant.executor, ctx.own_pubkey)) return error.WrongExecutor;

    // 6. The grant's subject is the pending intent's sender.
    if (!std.mem.eql(u8, grant.subject, ctx.intent_sender)) return error.WrongSubject;

    // 7. intent_id matches the pending intent.
    if (!std.mem.eql(u8, grant.intent_id, ctx.pending_intent_id)) return error.NoMatchingIntent;

    // 8. resource_id matches the pending intent's canonical resource_id.
    if (!std.mem.eql(u8, grant.resource_id, ctx.pending_resource_id)) return error.WrongResource;

    // 9. Grant.action_digest equals BLAKE2s recomputed over the intent's action
    //    bytes (BE-GRANT-02). Exact match, no partial or semantic matching.
    const digest = actionDigest(ctx.intent_action);
    if (!std.mem.eql(u8, &digest, grant.action_digest)) return error.ActionDigestMismatch;

    // 10. Expiry passes all three conditions of BE-GRANT-05.
    try checkExpiry(grant.not_after, ctx.now_ms, ctx.first_receipt_ms, ctx.t_max_s, ctx.t_recv_s);

    // 11. grant_id is not already consumed (BE-GRANT-01). Only I/O step; last.
    if (ctx.already_consumed(grant.grant_id)) return error.AlreadyConsumed;

    // The effect runs inside this frame on the verified grant (BE-GRANT-03b).
    // The ledger commit above is durable before this call, so a failed effect
    // leaves grant_id spent (BE-GRANT-01a interrupted), never retried. This
    // single invocation is the only reach path to the effect in the tree, which
    // the call-graph wall M10 makes load-bearing.
    execute(grant);
}
