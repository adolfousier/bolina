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
//   * BE-GRANT-03c: the capability is sealed by content at verification time,
//     a keyed digest over the exact grant bytes the routine verified (the key
//     generated at startup, module-private, never exported). The sole accessor
//     recomputes the digest over the LIVE bytes and refuses on mismatch, then
//     re-parses those bytes and returns the result by value. This is the TOCTOU
//     seal: verify A over bytes B, and consumption at T+n must still read bytes
//     B, not whatever the caller wrote into the buffer it owns between the two.
//     A language without aliasing discipline pays for that with a runtime check
//     at every access (LANGUAGE.md section 4.1, cost two).
//
// Verification is zero-heap. Ed25519 is checked with the stdlib's streaming
// Verifier so the domain tag and the to-be-signed region are fed as two
// separate chunks; no buffer is allocated to prepend the tag (BE-SIG-01). The
// capability seal is zero-heap too: it lives in a caller-provided slot, never
// on the heap.

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
    Tampered, // BE-GRANT-03c: capability seal no longer matches the live bytes
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
    // (a) non-strict: a Grant whose not_after equals the current millisecond is
    // refused. Capability boundaries are denied at the instant of expiry, not
    // granted (BE-GRANT-05, SPEC pinned at now_ms >= not_after).
    if (now_ms >= not_after) return error.Expired;
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
// Module-private seal key (BE-GRANT-03c).
//
// Generated once per process from the platform CSPRNG (arc4random_buf on
// darwin/bsd), never exported, never derived from any caller input. A caller
// cannot compute a valid seal without it, so a capability whose seal was not
// produced by verifyGrant is refused at access even if its backing slot is
// hand-filled. Filled lazily through a cmpxchg once-guard: the first
// verification pays the fill and every later one reads a stable key. state is
// 0 (uninitialized), 1 (a thread is filling), 2 (ready); the acquire/release
// pairing makes the key bytes visible to any reader that observes state 2.
// ---------------------------------------------------------------------------

var seal_key: [32]u8 = undefined;
var seal_state: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

fn sealKey() []const u8 {
    if (seal_state.load(.acquire) == 2) return &seal_key;
    if (seal_state.cmpxchgStrong(0, 1, .acq_rel, .acquire) == null) {
        std.c.arc4random_buf(&seal_key, seal_key.len);
        seal_state.store(2, .release);
    } else {
        while (seal_state.load(.acquire) != 2) std.atomic.spinLoopHint();
    }
    return &seal_key;
}

fn sealOver(bytes: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    B2s.hash(bytes, &out, .{ .key = sealKey() });
    return out;
}

// ---------------------------------------------------------------------------
// CapSlot: caller-owned, zero-heap storage for one capability (BE-GRANT-03c).
//
// The capability type is opaque {}, so no code can construct a VerifiedGrant by
// value or name the bytes it aliases; the sealed bytes live here, in a slot the
// caller declares and keeps alive for as long as it holds the capability.
// verifyGrant fills the slot and returns an opaque pointer aliasing it; grantOf
// casts that pointer back. The only two @ptrCast in the module are those two
// boundary casts (M8). The fields carry:
//
//   seal : the keyed digest frozen at verification time over `wire`.
//   wire : the exact grant bytes the routine verified (the caller's buffer,
//          read live at every access, not a copy).
//
// grantOf returns the re-parsed grant BY VALUE, so there is no capability-owned
// parsed cache to mutate and no need for mutable access to the slot: the
// capability pointer is const and stays const. Because Zig 0.16 exposes struct
// fields across modules (there is no field privacy), a determined caller can
// write these fields by hand. That does not help it forge: without the
// module-private key it cannot compute a `seal` that matches `wire`, so grantOf
// refuses, and the opaque pointer it would need to turn a slot into a usable
// capability is gated by M8 regardless.
// ---------------------------------------------------------------------------

pub const CapSlot = struct {
    seal: [32]u8,
    wire: []const u8,
};

// ---------------------------------------------------------------------------
// VerifiedGrant: the capability this routine produces (BE-GRANT-03b).
//
// opaque {} is the forgery wall. It has no fields and no value, so no code can
// construct one by value: the struct-literal mint a public-field struct would
// allow is a compile error. The ONLY way to obtain a *const VerifiedGrant is
// the verification routine below, and the ONLY way to fabricate the pointer is
// @ptrCast, confined to the two boundary functions here (verifyGrant, grantOf)
// and gated mechanically by M8 (tools/prumo-verify, CONTRIBUTING.md).
// test/negative_capability.zig is the canary: it tries the value mint and MUST
// fail to compile; the `zig build negative` step asserts on it. The capability
// aliases a caller-owned CapSlot (zero-heap; the caller keeps both alive for the
// same lifetime), never the heap.
// ---------------------------------------------------------------------------

pub const VerifiedGrant = opaque {};

// ---------------------------------------------------------------------------
// grantOf: the sole accessor (BE-GRANT-03c).
//
// Recomputes the keyed digest over the LIVE wire bytes and refuses on any
// mismatch (the caller's buffer changed between verification and consumption).
// Only then does it re-parse those bytes and return the result by value, so the
// consumer reads data freshly derived from the sealed bytes, never the caller's
// mutable parsed struct. A write to the caller's struct or buffer after
// verification cannot reach the consumer except by changing `wire`, which the
// seal detects. Comparison is constant-time (timing_safe): the digest is a
// secret-derived authenticator and the comparison must not leak on mismatch.
// The cast back to the slot is const-to-const, so no qualifier is discarded and
// no @constCast (or any builtin beyond the two @ptrCast) is needed.
// ---------------------------------------------------------------------------

pub fn grantOf(v: *const VerifiedGrant) VerifyError!parser.Grant {
    const slot: *const CapSlot = @ptrCast(@alignCast(v));
    const recomputed = sealOver(slot.wire);
    if (!std.crypto.timing_safe.eql([32]u8, recomputed, slot.seal)) return error.Tampered;
    // The seal matched, so `wire` is byte-identical to what verifyGrant sealed
    // and re-parsing it must succeed. A failure here means the bytes moved
    // between the seal check and the parse (concurrent mutation), which is
    // tampering by another name.
    return parser.parseGrant(slot.wire) catch return error.Tampered;
}

// ---------------------------------------------------------------------------
// verifyGrant: the single BE-GRANT-03 verification routine (slice subset).
//
// Checks run in the enumerated order and refuse on the first failure. The
// ledger hook (check 11) is the last statement, so any earlier refusal short-
// circuits before the durable commit would happen, matching the normative
// ordering from RED-TEAM-08 (F3). On success the caller's slot is filled with
// the sealed content (the live wire bytes and the keyed digest over them) and
// an opaque capability aliasing that slot is returned.
// ---------------------------------------------------------------------------

pub fn verifyGrant(env: parser.Envelope, grant_ptr: *const parser.Grant, ctx: GrantContext, slot: *CapSlot) VerifyError!*const VerifiedGrant {
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

    // Seal the exact grant bytes the routine verified (BE-GRANT-03c). wire is
    // the caller's buffer, borrowed live; the capability's seal is recomputed
    // over the same bytes at every access, so a post-verification write is
    // detected, not honored. The boundary constructor below is one of exactly
    // two @ptrCast in the module (M8).
    slot.wire = grant_ptr.wire;
    slot.seal = sealOver(grant_ptr.wire);
    return @ptrCast(slot);
}
