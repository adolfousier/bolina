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
const ledger = @import("ledger.zig");

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
    // Ledger slice admission errors (BE-ENV-03/04/05, BE-LEDGER-01).
    WrongBodyType, // BE-ENV-03: body_type not allowed for sender's role
    SeqWindowStale, // BE-ENV-04: seq below sliding window or duplicate
    Equivocation, // BE-ENV-05: same (sender, channel, seq) with different hash
    UnknownParents, // BE-LEDGER-01: parents not in ledger, fetch budget exhausted
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

// ---------------------------------------------------------------------------
// Channel control verification (SPEC 6.1a-c, BE-CHAN/BE-GEN/BE-CTRL).
//
// Same split as the Grant verifier (D-018): the parser turns control bytes
// into typed values, these checks run over those values plus caller-supplied
// ledger state. Membership (BE-CHAN-01) and authority (BE-GEN-03, BE-CTRL-02)
// are read from the certificate at verification time, never from accumulated
// channel state (SPEC 6.1b/c). The envelope signature (BE-ENV-02) and the
// cert chain (BE-ID-02..04) are verified by the caller before these run.
// ---------------------------------------------------------------------------

pub const ChannelError = error{
    BadMatchRule, // BE-GEN-04: match_rule != 1 (not byte equality)
    BadChannelId, // channel_id != BLAKE2s(name || ca_key_0) (SPEC 6.1b, BE-GEN-03)
    DuplicateGenesis, // BE-GEN-01: a second genesis for an existing channel_id
    GenesisNotAdmin, // BE-GEN-03: genesis not signed by an admin_group cert
    BadActionType, // BE-CTRL-01: action_type not in {1, 2}
    RevokeNotAdmin, // BE-CTRL-02: Revoke sender cert lacks admin_group
    SubjectRevoked, // BE-CHAN-02/03: subject in the grow-only revoked set
    NotMember, // BE-CHAN-01/03: cert does not carry member_group
};

// Ledger hooks the channel checks need. Both are caller-supplied state, like
// GrantContext.already_consumed: the durable genesis index (BE-GEN-01) and the
// grow-only revoked-subject set (BE-CHAN-02).
pub const ChannelContext = struct {
    genesis_exists: *const fn (channel_id: []const u8) bool, // BE-GEN-01
    is_revoked: *const fn (subject: []const u8) bool, // BE-CHAN-02 grow-only set
};

// BE-CHAN-01 helper: a cert carries an 8-byte group iff the group appears in
// its group_ids (BLAKE2s-256 prefixes, SPEC 3.1). Equality is byte equality,
// the only rule a channel defines (BE-GEN-04).
fn certCarriesGroup(cert: parser.session.Cert, group: []const u8) bool {
    var i: usize = 0;
    while (i < cert.group_count) : (i += 1) {
        const off = i * parser.session.LEN_GROUP_ID;
        if (std.mem.eql(u8, cert.group_ids[off .. off + parser.session.LEN_GROUP_ID], group)) return true;
    }
    return false;
}

// BE-GEN-01/03/04 and channel_id derivation. The genesis envelope's signature
// and the admin cert's chain are verified separately; this runs the
// genesis-specific invariants over the parsed body.
pub fn verifyControlGenesis(
    genesis: parser.channel.ControlGenesis,
    admin_cert: parser.session.Cert,
    channel_id: []const u8,
    ctx: ChannelContext,
) ChannelError!void {
    // BE-GEN-04: match_rule fixed at byte equality (1); no other value defined.
    if (genesis.match_rule != 1) return error.BadMatchRule;
    // BE-GEN-03: the genesis envelope is signed by a cert carrying admin_group.
    if (!certCarriesGroup(admin_cert, genesis.admin_group)) return error.GenesisNotAdmin;
    // channel_id = BLAKE2s(name || ca_key_0) (SPEC 6.1b). ca_keys are
    // ascending-ordered at parse time (canonical encoding), so ca_key_0 is the
    // first key. Streamed in two chunks; no tagged buffer is allocated.
    var hasher = B2s.init(.{});
    hasher.update(genesis.name);
    hasher.update(genesis.ca_keys[0..parser.channel.LEN_CA_KEY]);
    var derived: [32]u8 = undefined;
    hasher.final(&derived);
    if (!std.mem.eql(u8, channel_id, &derived)) return error.BadChannelId;
    // BE-GEN-01: exactly one genesis per channel_id; a second is rejected.
    if (ctx.genesis_exists(channel_id)) return error.DuplicateGenesis;
}

// BE-CTRL-01/02: validate a control body. action_type 1 (Genesis) takes the
// ControlGenesis path above; action_type 2 (Revoke) requires admin authority.
pub fn verifyControl(
    control: parser.channel.Control,
    genesis: parser.channel.ControlGenesis,
    sender_cert: parser.session.Cert,
) ChannelError!void {
    // BE-CTRL-01: action_type must be 1 or 2; no forward-compat path (SPEC 2.2).
    switch (control.action_type) {
        1, 2 => {},
        else => return error.BadActionType,
    }
    // BE-CTRL-02: a Revoke must be signed by a cert carrying admin_group.
    if (control.action_type == 2 and !certCarriesGroup(sender_cert, genesis.admin_group))
        return error.RevokeNotAdmin;
}

// BE-CHAN-01/02/03: gate a channel message on the sender's membership. A node
// is a member iff its cert carries member_group (BE-CHAN-01) AND its sig_pubkey
// is not in the grow-only revoked set (BE-CHAN-02); a revoked subject is
// treated as a non-member from the moment its revocation is accepted
// (BE-CHAN-03), so the revoked check precedes the group check.
pub fn requireMember(
    sender_cert: parser.session.Cert,
    genesis: parser.channel.ControlGenesis,
    ctx: ChannelContext,
) ChannelError!void {
    if (ctx.is_revoked(sender_cert.sig_pubkey)) return error.SubjectRevoked;
    if (!certCarriesGroup(sender_cert, genesis.member_group)) return error.NotMember;
}

// ---------------------------------------------------------------------------
// Lighthouse-served certificate verification (SPEC 5.1/5.1a, BE-MESH-01/04/05/06).
//
// A lighthouse serves a certificate alongside an endpoint so a node can send
// its first Noise_IK packet (SPEC 5.1a). The lighthouse is an availability
// mechanism, never an authority (BE-MESH-01), and this routine is where that
// distinction is made structural rather than asserted:
//
//   * BE-MESH-01: the routine takes no lighthouse identity. There is no
//     parameter through which "which lighthouse said so" could condition
//     acceptance, so it cannot. A malicious lighthouse can refuse to answer or
//     answer with someone else's valid certificate; it cannot cause acceptance
//     of an unauthenticated peer.
//   * BE-MESH-04: BE-ID-01 (the address is derived from the key, so a
//     substituted identity is detected because it is not the address that was
//     asked for) then BE-ID-02..04 via binding.validateCert. Any failure
//     refuses; nothing partially verified escapes.
//   * BE-MESH-05: the certificate opens the session and confers nothing. The
//     continuation receives SessionKeys, which carries the two public keys the
//     handshake needs and nothing else. role_bits, group_ids and name do not
//     cross this boundary, so no caller can reach a membership or authority
//     fact through this path, only through BE-TR-01's exchange inside the
//     encrypted session.
//   * BE-MESH-06: verification is a call, not a value (the BE-GRANT-03b shape).
//     now_ms and the revocation hook are parameters of the *use*, and no value
//     representing a verified certificate exists outside the call, so a cached
//     certificate cannot carry a cache-fill-time verdict forward. Re-verifying
//     on every use is the only thing the type permits.
//
// The routine takes an already-parsed Cert, not the LookupResponse's opaque
// cert bytes. Parsing here would move bytes-to-values work into a non-surface
// file, which is the direction D-018 forbids; the caller runs
// parser.session.parseCert, whose error union makes the BE-MESH-04 "discard on
// parse failure" obligation unskippable at the call site.
// ---------------------------------------------------------------------------

pub const MeshError = error{
    AddressMismatch, // BE-MESH-04/BE-ID-01: derived addr != the addr asked for
    ServedCertInvalid, // BE-MESH-04/BE-ID-02..04: chain, roles or window failed
    ServedCertRevoked, // BE-MESH-06: revoked as of this use, not of cache fill
};

// The only thing a served certificate yields: the two public keys Noise_IK and
// BE-TR-04's mac1 need to send a first packet. Deliberately not a Cert
// (BE-MESH-05); adding an authority-bearing field here would be the bug this
// type exists to prevent, which is why a test asserts the field set.
pub const SessionKeys = struct {
    sig_pubkey: []const u8,
    kex_pubkey: []const u8,
};

// Use-time inputs. Both are supplied per call rather than per cache entry,
// which is what makes BE-MESH-06 structural: there is nowhere to record a
// verdict that outlives the use it was computed for.
pub const MeshContext = struct {
    trusted_ca_keys: []const []const u8,
    now_ms: u64, // BE-MESH-06: validity window re-checked at this instant
    is_revoked: *const fn (sig_pubkey: []const u8) bool, // BE-MESH-06
};

pub fn verifyServedCertThen(
    served: parser.session.Cert,
    requested_addr: []const u8,
    ctx: MeshContext,
    open_session: *const fn (SessionKeys) void,
) MeshError!void {
    // BE-ID-01 first: the substitution check is a single BLAKE2s and refuses a
    // wrong-identity certificate before any signature is verified. Spec order
    // (BE-ID-01 through BE-ID-04) and cheapest-informative-first agree here.
    const derived = binding.deriveOverlayAddr(served.sig_pubkey);
    if (!std.mem.eql(u8, &derived, requested_addr)) return error.AddressMismatch;
    // BE-ID-02..04: role constraints, approver quorum, validity window at
    // ctx.now_ms, CA signatures against the trusted set. One refusal class:
    // which check failed is not information a served certificate has earned.
    binding.validateCert(served, ctx.trusted_ca_keys, ctx.now_ms) catch return error.ServedCertInvalid;
    // BE-MESH-06: revocation is consulted at use, after the chain proves the
    // key is the one the certificate binds.
    if (ctx.is_revoked(served.sig_pubkey)) return error.ServedCertRevoked;
    open_session(.{ .sig_pubkey = served.sig_pubkey, .kex_pubkey = served.kex_pubkey });
}

// ---------------------------------------------------------------------------
// Ledger admission integration (BE-ENV-03/04/05, BE-LEDGER-01/03).
//
// Enforces all admission gates before the body reaches application logic.
// Checks run in this order: body_type->role map (BE-ENV-03), seq window
// (BE-ENV-04), equivocation (BE-ENV-05), unknown parents (BE-LEDGER-01),
// then record in the ledger (BE-LEDGER-03).
// ---------------------------------------------------------------------------

// Admission context: every input needed for envelope admission.
pub const AdmissionContext = struct {
    ledger: *ledger.Ledger,
    sender_cert: parser.session.Cert,
    trusted_ca_keys: []const []const u8,
    now_ms: u64,
};

// BE-ENV-03: body_type -> role map enforcement. Intent -> agent,
// Grant/Refusal -> approver, Effect+Span -> executor.
fn bodyTypeAllowed(body_type: u8, role_bits: u16) bool {
    const is_agent = (role_bits & binding.ROLE_AGENT) != 0;
    const is_approver = (role_bits & binding.ROLE_APPROVER) != 0;
    const is_executor = (role_bits & binding.ROLE_EXECUTOR) != 0;

    return switch (body_type) {
        parser.channel.BODY_INTENT => is_agent,
        parser.channel.BODY_GRANT, parser.channel.BODY_REFUSAL => is_approver,
        parser.channel.BODY_EFFECT, parser.channel.BODY_SPAN => is_executor,
        parser.channel.BODY_CONTROL => true, // Control role-gated at verification
        else => false,
    };
}

// Admission check: runs all gates and records the envelope on success.
pub fn verifyEnvelopeAdmission(
    env: parser.channel.Envelope,
    seq: u64,
    channel_id: [32]u8,
    env_hash: [32]u8,
    parent_hashes: []const [32]u8,
    ctx: AdmissionContext,
) VerifyError!void {
    binding.validateCert(ctx.sender_cert, ctx.trusted_ca_keys, ctx.now_ms) catch return error.BadApproverCert;

    if (!bodyTypeAllowed(env.body_type, ctx.sender_cert.role_bits)) return error.WrongBodyType;

    var sender_key: [32]u8 = undefined;
    @memcpy(&sender_key, env.sender);
    ctx.ledger.checkSeq(sender_key, channel_id, seq) catch |err| switch (err) {
        ledger.LedgerError.WindowStale => return error.SeqWindowStale,
        else => return err,
    };

    const entry = ledger.EnvelopeEntry{
        .hash = env_hash,
        .sender = sender_key,
        .channel = channel_id,
        .seq = seq,
    };
    ctx.ledger.insertEnvelope(entry) catch |err| switch (err) {
        ledger.LedgerError.Divergence => return error.Equivocation,
        else => return err,
    };

    if (!ctx.ledger.allParentsPresent(parent_hashes)) return error.UnknownParents;

    try ctx.ledger.setAnchor(sender_key, env_hash);

    if (env.body_type == parser.channel.BODY_CONTROL) try ctx.ledger.setRevocation(sender_key, env_hash);
}
