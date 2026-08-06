// evidence.zig
//
// LANGUAGE.md section 4 implementation slice, item 3: the attestation verdict
// layer (SPEC.md section 7). The parser (parser.zig) is total and zero-heap;
// verify.zig adds the cryptographic checks. This module answers the question
// section 7 opens with: what is a claim worth, and who decides?
//
// The answer is BE-EVID-02: the RECEIVER decides, by recomputing. A claim's
// confidence is never the sender's number. It is
//   min(stated, ceiling(strongest matching supporting span)),
// and the ceiling is a pure function of HOW the span was observed (method_id,
// section 7.4), never a field the producer chose. With BE-EVID-01, only an
// executor's key can sign a verifying span, so this is the load-bearing
// difference from "the model cites its sources": here the sources are not
// produced by the model.
//
// BE-EVID-09 forces three states, not two. Supported (a number), Unresolved
// (no number, pending backfill of the publishing Effect), and Unsupported
// (0.00 with a marker). The Unresolved/Unsupported split is what stops network
// latency from looking like dishonesty (BE-EVID-02b): "I have no proof" and "I
// have not yet received the proof" must not render alike.
//
// This module is pure and zero-heap (BE-WIRE-01): resolveClaim borrows the
// caller's parsed Claim and Span slices and returns a value, allocating
// nothing. The three facts that depend on state this slice does not model (the
// certificate store for BE-EVID-01, the local ledger for BE-EVID-02b/09/09b,
// and the causal DAG for BE-EVID-05) are supplied as function-pointer hooks in
// ResolveContext, the same shape GrantContext takes in verify.zig. Tests supply
// deterministic stubs; the real cert store, ledger and DAG are the repayments
// named in DECISION-LOG.

const std = @import("std");
const parser = @import("parser.zig");
const verify = @import("verify.zig");

// ---------------------------------------------------------------------------
// Evidence class is derived, never declared (SPEC 7.4, BE-EVID-11/12/15).
//
// The class is a pure function of method_id, fixed in the table below and
// computed by the receiver. An executor cannot raise a claim's ceiling by
// relabelling an inference as a DirectObservation: method_id is a compile-time
// constant of the executor code path (BE-EVID-11), never an argument, and the
// receiver never trusts a transmitted class. BE-EVID-13 sends any method_id the
// table does not name to the Inference floor, so an unknown mechanism gets the
// lowest ceiling, never the benefit of the doubt.
// ---------------------------------------------------------------------------

pub const EvidenceClass = enum {
    direct_observation, // method_id 1..4, ceiling 242 (0.95)
    expert_testimony, // method_id 7, ceiling 216 (0.85)
    documentation, // method_id 5..6, ceiling 191 (0.75)
    inference, // method_id 8 and unknown, ceiling 165 (0.65)
};

pub fn classOf(method_id: u8) EvidenceClass {
    return switch (method_id) {
        1, 2, 3, 4 => .direct_observation,
        5, 6 => .documentation,
        7 => .expert_testimony,
        8 => .inference,
        // BE-EVID-13: any method_id outside the table is Inference (0.65).
        else => .inference,
    };
}

// Normative ceilings (SPEC 7.2). The integers are normative, the decimals are
// not: 0.95 x 255 = 242.25, and rounding up would let a claim present above its
// declared cap by one least-significant bit. This layer compares integers
// directly and never converts to float, so "round toward zero" is the identity
// operation here (BE-EVID-15 names this mapping for the cross-impl vectors).
pub fn ceilingQ8(class: EvidenceClass) u8 {
    return switch (class) {
        .direct_observation => 242,
        .expert_testimony => 216,
        .documentation => 191,
        .inference => 165,
    };
}

// ---------------------------------------------------------------------------
// Volatility (SPEC 7.1, BE-EVID-06). Only the value 2 means stable; the value
// 1 and every value this version does not recognize degrade to volatile. Fail
// closed: a forgotten field or a future value applies the stricter rule, not
// the looser one.
// ---------------------------------------------------------------------------

pub fn isVolatile(volatility: u8) bool {
    return volatility != 2;
}

// ---------------------------------------------------------------------------
// BE-EVID-02: the receiver recomputes from the strongest support.
//
// effective = min(stated, ceiling(strongest matching supporting span)). The
// sender's number is an upper-bound request, never an accepted fact. Strongest,
// not weakest: each span supports the claim on its own (the supports are
// disjunctive, and BE-EVID-03 forces them to the same subject), so a chain rule
// would reward hiding evidence (SPEC 7.2). Exposed as a standalone pure helper
// so the rule is testable in isolation (M1 bijection, BE-EVID-04 determinism).
// ---------------------------------------------------------------------------

pub fn effectiveConfidence(stated_q8: u8, strongest_ceiling_q8: u8) u8 {
    return @min(stated_q8, strongest_ceiling_q8);
}

// ---------------------------------------------------------------------------
// BE-EVID-10: bounded piggyback (SPEC 7.5). An Utterance carries at most 32
// claims and 64 spans and is rejected past either. The Utterance grammar is
// deferred to RED-TEAM-09 F1, so this check is exposed for the future parser to
// call once the wire shape is fixed; the bound itself is settled here.
// ---------------------------------------------------------------------------

pub const MAX_UTTERANCE_CLAIMS: usize = 32;
pub const MAX_UTTERANCE_SPANS: usize = 64;

pub fn checkBounds(claim_count: usize, span_count: usize) bool {
    return claim_count <= MAX_UTTERANCE_CLAIMS and span_count <= MAX_UTTERANCE_SPANS;
}

// ---------------------------------------------------------------------------
// Hooks: the three facts that depend on state this slice does not model.
//
// role_of (BE-EVID-01): does the certificate carry the executor role for this
//   pubkey? Repayment: the cert store (BE-ROLE-02). An agent holds no executor
//   key, so it cannot manufacture a verifying span.
// resolve_origin (BE-EVID-02b/09/09b): where does the span's origin land?
//   Three states, because Unresolved (absent, pending) and a non-Effect origin
//   (BE-EVID-09b, drops out) must not be confused: collapsing them would render
//   a fully-evidenced claim waiting on backfill identical to a malformed one.
//   Repayment: the local ledger (SPEC 6.4).
// is_superseded (BE-EVID-05/05a): is this volatile span superseded by a later
//   Effect on the same resource_id that is a STRICT causal descendant of the
//   span's own origin Effect and a causal ancestor of the claim? Strict descent
//   (BE-EVID-05a) so a span is not superseded by the Effect that published it.
//   Repayment: the causal DAG (src/dag.zig). This module calls it only for
//   volatile spans; stable spans are never superseded (BE-EVID-07).
// ---------------------------------------------------------------------------

pub const Role = enum {
    none, // no cert, or the cert carries no recognized role
    executor, // BE-EVID-01: the cert carries the executor role
};

pub const OriginState = enum {
    effect, // origin resolves to an Effect envelope in the local ledger
    absent, // origin not yet in the ledger (BE-EVID-02b: pending resolution)
    non_effect, // origin resolves to a non-Effect body (BE-EVID-09b: cannot support)
};

pub const ResolveContext = struct {
    role_of: *const fn (pubkey: []const u8) Role,
    resolve_origin: *const fn (origin_hash: []const u8) OriginState,
    is_superseded: *const fn (
        resource_id: []const u8,
        origin: []const u8,
        claim_envelope: []const u8,
    ) bool,
};

// ---------------------------------------------------------------------------
// BE-EVID-09: three states, not two. A claim resolves to exactly one.
// ---------------------------------------------------------------------------

// F1/F2/F3 (round-4 review): a claim's verdict carries a resolution record so
// the state is a SUMMARY of the evidence walk, not a substitute for it. Every
// cited span lands in exactly one terminal bucket: a span that fails a check is
// COUNTED (cited-but-not-inline, sig/role failure, subject mismatch, superseded,
// non-effect origin), never silently dropped. The inverse of R3 (every failure
// records a cause): a mutation that drops a span silently shifts a count, which
// a test asserting the record catches.

pub const ResolutionRecord = struct {
    cited: usize = 0, // total span_ids the claim cites
    inline_spans: usize = 0, // cited spans present in the envelope (BE-EVID-08 pass)
    supportable: usize = 0, // inline spans with valid sig + executor role (BE-EVID-01 pass)
    subject_matched: usize = 0, // supportable spans with resource_id == subject (BE-EVID-03 pass)
    superseded: usize = 0, // subject_matched spans superseded by a later Effect (BE-EVID-05)
    unresolved: usize = 0, // subject_matched spans whose origin is absent, pending (BE-EVID-02b)
    non_effect: usize = 0, // subject_matched spans whose origin is a non-Effect body (BE-EVID-09b)
};

pub const Supported = struct {
    effective_q8: u8, // min(stated, strongest RESOLVED ceiling), BE-EVID-02; fail-closed
    pending_stronger: bool, // F1: a supporting span is pending; the number may rise on backfill
    record: ResolutionRecord,
};

pub const ClaimState = union(enum) {
    supported: Supported, // strongest resolved, non-superseded span; F1 flag if evidence is pending
    unresolved: ResolutionRecord, // valid matching evidence, origin not yet in the ledger (BE-EVID-02b)
    unsupported: ResolutionRecord, // no supporting span; 0.00 with the "no mechanical confirmation" marker (BE-EVID-02a)
};

// ---------------------------------------------------------------------------
// resolveClaim: the receiver's recomputation for one claim.
//
// Walks every span_id the claim cites, matches each against the spans the
// Utterance carried inline (BE-EVID-08: a referenced span absent from the same
// envelope supports nothing), and classifies each match:
//
//   sig fails or no executor role (BE-EVID-01)        -> ignored
//   subject mismatch (BE-EVID-03)                      -> ignored
//   origin resolves to an Effect                        -> candidate
//       volatile and superseded (BE-EVID-05)           -> ignored (contributes zero)
//       otherwise contributes its class ceiling        -> strongest tracker
//   origin absent (BE-EVID-02b)                         -> unresolved flag
//   origin resolves to a non-Effect body (BE-EVID-09b) -> ignored
//
// Three-state assembly (BE-EVID-09/09a): if any span contributes, the claim is
// Supported at min(stated, strongest ceiling). Otherwise, if any valid matching
// span is unresolved (absent), the claim is Unresolved. Otherwise Unsupported.
//
// A claim whose only valid matching spans are superseded or non-Effect is
// Unsupported, not Unresolved. BE-EVID-05 names the 0.00 outcome for a
// superseded-only claim explicitly, and BE-EVID-09b drops a non-Effect-origin
// span out of both states, so both take precedence over the looser "Unsupported
// only when no valid matching span" line in BE-EVID-09a. See DECISION-LOG
// D-015 and RED-TEAM-09 O5: this is a spec-ambiguity resolution, not a
// guarantee change (no rule's stated outcome is altered).
// ---------------------------------------------------------------------------

fn matchSpan(spans: []const parser.channel.Span, span_id: []const u8) ?parser.channel.Span {
    for (spans) |s| {
        if (std.mem.eql(u8, s.span_id, span_id)) return s;
    }
    return null;
}

fn spanSupportable(span: parser.channel.Span, ctx: ResolveContext) bool {
    // BE-EVID-01 conjunct 1: sig verifies against executor (domain tag 0x03).
    verify.verifySigned(parser.channel.DOMAIN_SPAN, span.tbs, span.sig, span.executor) catch return false;
    // BE-EVID-01 conjunct 2: the cert carries the executor role.
    return ctx.role_of(span.executor) == .executor;
}

pub fn resolveClaim(
    claim: parser.channel.Claim,
    spans: []const parser.channel.Span,
    ctx: ResolveContext,
    claim_envelope: []const u8,
) ClaimState {
    var rec = ResolutionRecord{};
    var strongest_ceiling: u8 = 0;
    var has_unresolved = false;

    var i: usize = 0;
    while (i < claim.span_count) : (i += 1) {
        rec.cited += 1;
        const sid = claim.span_ids[i * parser.channel.LEN_SPAN_REF .. (i + 1) * parser.channel.LEN_SPAN_REF];
        const span = matchSpan(spans, sid) orelse continue; // BE-EVID-08: cited but not inline (counted as cited)
        rec.inline_spans += 1;

        if (!spanSupportable(span, ctx)) continue; // BE-EVID-01 fail (counted as inline)
        rec.supportable += 1;

        if (!std.mem.eql(u8, span.resource_id, claim.subject)) continue; // BE-EVID-03 fail (counted as supportable)
        rec.subject_matched += 1;

        switch (ctx.resolve_origin(span.origin)) {
            .effect => {
                // BE-EVID-05: only volatile spans can be superseded; stable
                // spans stay valid indefinitely (BE-EVID-07), so the DAG hook
                // is never consulted for them.
                if (isVolatile(span.volatility) and ctx.is_superseded(span.resource_id, span.origin, claim_envelope)) {
                    rec.superseded += 1; // BE-EVID-05: counted, contributes zero
                    continue;
                }
                const ceil = ceilingQ8(classOf(span.method_id));
                if (ceil > strongest_ceiling) strongest_ceiling = ceil;
            },
            .absent => {
                rec.unresolved += 1; // BE-EVID-02b: origin pending
                has_unresolved = true;
            },
            .non_effect => {
                rec.non_effect += 1; // BE-EVID-09b: counted, drops out of both states
                continue;
            },
        }
    }

    if (strongest_ceiling > 0) {
        // F1: the number stays fail-closed (min of stated and the strongest
        // RESOLVED ceiling); pending_stronger says an unresolved span exists and
        // the number can rise when its origin lands above the current strongest.
        return .{ .supported = .{
            .effective_q8 = effectiveConfidence(claim.confidence_q8, strongest_ceiling),
            .pending_stronger = has_unresolved,
            .record = rec,
        } };
    }
    if (has_unresolved) return .{ .unresolved = rec };
    return .{ .unsupported = rec };
}
