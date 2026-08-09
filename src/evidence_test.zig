// evidence_test.zig
//
// Grounds the attestation layer (src/evidence.zig, SPEC.md section 7) against
// real Ed25519-signed spans: the sig path of BE-EVID-01 is exercised by the
// same streaming verifier verify.zig uses, not stubbed. The three hooks
// (role_of, resolve_origin, is_superseded) are the designed function-pointer
// boundary this slice leaves open for the cert store, ledger and causal DAG;
// deterministic stubs stand in for them, the same shape GrantContext takes in
// verify_test.zig. Shared fixtures and hook stubs live in evidence_test_helpers
// (CODE.md: one home for test helpers, never copy-pasted).
//
// Naming follows the build.zig M1 registry convention: test "BE_<CLASS>_<NN>".

const std = @import("std");
const parser = @import("parser.zig");
const evidence = @import("evidence.zig");
const H = @import("evidence_test_helpers.zig");

// ===========================================================================
// BE-EVID-01: a span is valid only if sig verifies against executor AND the
// cert carries the executor role.
// ===========================================================================

test "BE_EVID_01 span supports only with verifying sig and executor role" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const kp = H.executorKeypair();
    const sid = H.idOf(0x21);

    const w = try H.spanWire(a, sid, H.idOf(0x31), H.SUBJECT, 1, 1, H.seedFrom(0xa1), kp);
    const span = try parser.channel.parseSpan(w);
    const spans: []const parser.channel.Span = &.{span};

    // valid sig + executor role -> supported at the DirectObservation ceiling.
    var claim = try H.buildClaim(a, "deploy ok", H.SUBJECT, 242, &.{sid});
    try H.expectSupported(
        evidence.resolveClaim(claim, spans, H.ctx(&H.roleExecutor, &H.originEffect, &H.neverSuperseded), &H.ENV),
        242,
    );

    // tampered sig: flip one byte inside the 64-byte sig region, re-parse. The
    // sig no longer verifies against executor, so the span counts for nothing.
    const w_bad = try a.dupe(u8, w);
    w_bad[w_bad.len - 1] ^= 0xff;
    const span_bad = try parser.channel.parseSpan(w_bad);
    const spans_bad: []const parser.channel.Span = &.{span_bad};
    claim = try H.buildClaim(a, "deploy ok", H.SUBJECT, 242, &.{sid});
    try H.expectState(
        evidence.resolveClaim(claim, spans_bad, H.ctx(&H.roleExecutor, &H.originEffect, &H.neverSuperseded), &H.ENV),
        .unsupported,
    );

    // valid sig but the cert carries no executor role -> unsupported.
    claim = try H.buildClaim(a, "deploy ok", H.SUBJECT, 242, &.{sid});
    try H.expectState(
        evidence.resolveClaim(claim, spans, H.ctx(&H.roleNone, &H.originEffect, &H.neverSuperseded), &H.ENV),
        .unsupported,
    );
}

// ===========================================================================
// BE-EVID-02: the receiver recomputes min(stated, ceiling(strongest support)).
// ===========================================================================

test "BE_EVID_02 receiver recomputes min of stated and strongest ceiling" {
    // Pure helper: min against the strongest matching ceiling.
    try std.testing.expectEqual(@as(u8, 200), evidence.effectiveConfidence(200, 242));
    try std.testing.expectEqual(@as(u8, 165), evidence.effectiveConfidence(255, 165));
    try std.testing.expectEqual(@as(u8, 100), evidence.effectiveConfidence(100, 242));

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const kp = H.executorKeypair();
    const sid = H.idOf(0x21);
    const span = try parser.channel.parseSpan(try H.spanWire(a, sid, H.idOf(0x31), H.SUBJECT, 1, 1, H.seedFrom(0xa1), kp));
    const spans: []const parser.channel.Span = &.{span};

    // method_id 1 -> DirectObservation ceiling 242. Stated 200 -> effective 200.
    var claim = try H.buildClaim(a, "deploy ok", H.SUBJECT, 200, &.{sid});
    try H.expectSupported(
        evidence.resolveClaim(claim, spans, H.ctx(&H.roleExecutor, &H.originEffect, &H.neverSuperseded), &H.ENV),
        200,
    );
    // Stated above the ceiling -> capped at the ceiling (sender's number is a
    // request, never an accepted fact).
    claim = try H.buildClaim(a, "deploy ok", H.SUBJECT, 255, &.{sid});
    try H.expectSupported(
        evidence.resolveClaim(claim, spans, H.ctx(&H.roleExecutor, &H.originEffect, &H.neverSuperseded), &H.ENV),
        242,
    );
}

// ===========================================================================
// BE-EVID-02a: no valid matching span is 0.00, not a floor.
// ===========================================================================

test "BE_EVID_02a no matching span is zero not a floor" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const kp = H.executorKeypair();
    const sid = H.idOf(0x21);

    // A claim that cites no span at all.
    var claim = try H.buildClaim(a, "hunch", H.SUBJECT, 242, &.{});
    try H.expectState(
        evidence.resolveClaim(claim, &.{}, H.ctx(&H.roleExecutor, &H.originEffect, &H.neverSuperseded), &H.ENV),
        .unsupported,
    );

    // A claim that cites a span about a different subject (BE-EVID-03 fail) has
    // no matching support, so it is 0.00 with the marker, never the Inference
    // floor.
    const span = try parser.channel.parseSpan(try H.spanWire(a, sid, H.idOf(0x31), "bol:other/res", 1, 1, H.seedFrom(0xa1), kp));
    const spans: []const parser.channel.Span = &.{span};
    claim = try H.buildClaim(a, "hunch", H.SUBJECT, 242, &.{sid});
    try H.expectState(
        evidence.resolveClaim(claim, spans, H.ctx(&H.roleExecutor, &H.originEffect, &H.neverSuperseded), &H.ENV),
        .unsupported,
    );
}

// ===========================================================================
// BE-EVID-02b: a valid span whose origin is not yet in the ledger is
// indeterminate (pending), never zero.
// ===========================================================================

test "BE_EVID_02b unresolved origin is indeterminate not zero" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const kp = H.executorKeypair();
    const sid = H.idOf(0x21);
    const span = try parser.channel.parseSpan(try H.spanWire(a, sid, H.idOf(0x31), H.SUBJECT, 1, 1, H.seedFrom(0xa1), kp));
    const spans: []const parser.channel.Span = &.{span};
    const claim = try H.buildClaim(a, "deploy ok", H.SUBJECT, 242, &.{sid});
    try H.expectState(
        evidence.resolveClaim(claim, spans, H.ctx(&H.roleExecutor, &H.originAbsent, &H.neverSuperseded), &H.ENV),
        .unresolved,
    );
}

// ===========================================================================
// BE-EVID-03: a span supports a claim only if resource_id == subject.
// ===========================================================================

test "BE_EVID_03 span supports only when resource equals subject" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const kp = H.executorKeypair();
    const sid = H.idOf(0x21);

    // resource_id == subject -> supported.
    const span = try parser.channel.parseSpan(try H.spanWire(a, sid, H.idOf(0x31), H.SUBJECT, 1, 1, H.seedFrom(0xa1), kp));
    const spans: []const parser.channel.Span = &.{span};
    var claim = try H.buildClaim(a, "deploy ok", H.SUBJECT, 242, &.{sid});
    try H.expectSupported(
        evidence.resolveClaim(claim, spans, H.ctx(&H.roleExecutor, &H.originEffect, &H.neverSuperseded), &H.ENV),
        242,
    );

    // resource_id != subject -> the span does not raise the ceiling; with no
    // other support the claim is unsupported.
    const span_other = try parser.channel.parseSpan(try H.spanWire(a, sid, H.idOf(0x31), "bol:other/res", 1, 1, H.seedFrom(0xa1), kp));
    const spans_other: []const parser.channel.Span = &.{span_other};
    claim = try H.buildClaim(a, "deploy ok", H.SUBJECT, 242, &.{sid});
    try H.expectState(
        evidence.resolveClaim(claim, spans_other, H.ctx(&H.roleExecutor, &H.originEffect, &H.neverSuperseded), &H.ENV),
        .unsupported,
    );
}

// ===========================================================================
// BE-EVID-04: ceiling arithmetic is computed by a deterministic routine with
// no model in the loop. The helper is pure: identical inputs, identical output.
// ===========================================================================

test "BE_EVID_04 confidence arithmetic is deterministic" {
    try std.testing.expectEqual(
        evidence.effectiveConfidence(220, 216),
        evidence.effectiveConfidence(220, 216),
    );
    try std.testing.expectEqual(@as(u8, 216), evidence.effectiveConfidence(220, 216));
    // classOf and ceilingQ8 are pure functions of method_id / class.
    try std.testing.expectEqual(evidence.EvidenceClass.inference, evidence.classOf(8));
    try std.testing.expectEqual(evidence.ceilingQ8(.inference), evidence.ceilingQ8(evidence.classOf(99)));
}

// ===========================================================================
// BE-EVID-05: a superseded volatile span stops supporting (contributes zero).
// ===========================================================================

test "BE_EVID_05 superseded volatile span stops supporting" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const kp = H.executorKeypair();
    const sid = H.idOf(0x21);

    // volatile (1), not superseded -> supported.
    const span = try parser.channel.parseSpan(try H.spanWire(a, sid, H.idOf(0x31), H.SUBJECT, 1, 1, H.seedFrom(0xa1), kp));
    const spans: []const parser.channel.Span = &.{span};
    var claim = try H.buildClaim(a, "deploy ok", H.SUBJECT, 242, &.{sid});
    try H.expectSupported(
        evidence.resolveClaim(claim, spans, H.ctx(&H.roleExecutor, &H.originEffect, &H.neverSuperseded), &H.ENV),
        242,
    );

    // volatile, superseded -> the support is gone; 0.00 with the marker.
    claim = try H.buildClaim(a, "deploy ok", H.SUBJECT, 242, &.{sid});
    try H.expectState(
        evidence.resolveClaim(claim, spans, H.ctx(&H.roleExecutor, &H.originEffect, &H.alwaysSuperseded), &H.ENV),
        .unsupported,
    );
}

// ===========================================================================
// BE-EVID-06: an unrecognized volatility value is treated as volatile.
// ===========================================================================

test "BE_EVID_06 unrecognized volatility is volatile" {
    try std.testing.expect(evidence.isVolatile(1)); // declared volatile
    try std.testing.expect(!evidence.isVolatile(2)); // declared stable
    try std.testing.expect(evidence.isVolatile(0)); // unrecognized
    try std.testing.expect(evidence.isVolatile(99)); // unrecognized

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const kp = H.executorKeypair();
    const sid = H.idOf(0x21);
    // volatility 99 (unrecognized) degrades to volatile, so a superseding
    // Effect removes the support.
    const span = try parser.channel.parseSpan(try H.spanWire(a, sid, H.idOf(0x31), H.SUBJECT, 1, 99, H.seedFrom(0xa1), kp));
    const spans: []const parser.channel.Span = &.{span};
    const claim = try H.buildClaim(a, "deploy ok", H.SUBJECT, 242, &.{sid});
    try H.expectState(
        evidence.resolveClaim(claim, spans, H.ctx(&H.roleExecutor, &H.originEffect, &H.alwaysSuperseded), &H.ENV),
        .unsupported,
    );
}

// ===========================================================================
// BE-EVID-07: distance is not a substitute. A stable span is never superseded,
// so the DAG hook is never consulted for it (BE-EVID-05 is volatile-only).
// ===========================================================================

test "BE_EVID_07 stable span is never superseded" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const kp = H.executorKeypair();
    const sid = H.idOf(0x21);
    // stable (2) span; the hook claims everything is superseded, but a stable
    // span stays valid indefinitely, so it still supports.
    const span = try parser.channel.parseSpan(try H.spanWire(a, sid, H.idOf(0x31), H.SUBJECT, 2, 2, H.seedFrom(0xa1), kp));
    const spans: []const parser.channel.Span = &.{span};
    const claim = try H.buildClaim(a, "deploy ok", H.SUBJECT, 242, &.{sid});
    try H.expectSupported(
        evidence.resolveClaim(claim, spans, H.ctx(&H.roleExecutor, &H.originEffect, &H.alwaysSuperseded), &H.ENV),
        242,
    );
}

// ===========================================================================
// BE-EVID-08: a referenced span not carried inline in the same envelope
// supports nothing (push, not pull).
// ===========================================================================

test "BE_EVID_08 referenced span not carried inline supports nothing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const kp = H.executorKeypair();
    const sid = H.idOf(0x21);
    // Build the span so the bytes are well-formed, but hand resolveClaim an
    // empty span set: the cited span_id is not inline, so it cannot support.
    _ = try parser.channel.parseSpan(try H.spanWire(a, sid, H.idOf(0x31), H.SUBJECT, 1, 1, H.seedFrom(0xa1), kp));
    const claim = try H.buildClaim(a, "deploy ok", H.SUBJECT, 242, &.{sid});
    try H.expectState(
        evidence.resolveClaim(claim, &.{}, H.ctx(&H.roleExecutor, &H.originEffect, &H.neverSuperseded), &H.ENV),
        .unsupported,
    );
}

// ===========================================================================
// BE-EVID-09: three states. Supported, Unresolved, Unsupported.
// ===========================================================================

test "BE_EVID_09 three states supported unresolved unsupported" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const kp = H.executorKeypair();
    const sid = H.idOf(0x21);
    const span = try parser.channel.parseSpan(try H.spanWire(a, sid, H.idOf(0x31), H.SUBJECT, 1, 1, H.seedFrom(0xa1), kp));
    const spans: []const parser.channel.Span = &.{span};
    var claim = try H.buildClaim(a, "deploy ok", H.SUBJECT, 242, &.{sid});

    // Supported: resolved, non-superseded support.
    try H.expectSupported(
        evidence.resolveClaim(claim, spans, H.ctx(&H.roleExecutor, &H.originEffect, &H.neverSuperseded), &H.ENV),
        242,
    );
    // Unresolved: valid matching evidence, origin absent.
    try H.expectState(
        evidence.resolveClaim(claim, spans, H.ctx(&H.roleExecutor, &H.originAbsent, &H.neverSuperseded), &H.ENV),
        .unresolved,
    );
    // Unsupported: no valid matching span (subject mismatch here).
    claim = try H.buildClaim(a, "deploy ok", "bol:other/res", 242, &.{sid});
    try H.expectState(
        evidence.resolveClaim(claim, spans, H.ctx(&H.roleExecutor, &H.originEffect, &H.neverSuperseded), &H.ENV),
        .unsupported,
    );
}

// ===========================================================================
// BE-EVID-09a: mixed resolution composes per span. Resolved non-superseded
// spans support at the strongest ceiling; unresolved ones contribute nothing
// yet and do not demote a supported claim.
// ===========================================================================

test "BE_EVID_09a mixed resolution composes per span" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const kp = H.executorKeypair();

    // Two spans, same subject, different origins. One resolves (ExpertTestimony
    // method_id 7, ceiling 216), one is absent (pending).
    const sid_resolved = H.idOf(0x21);
    const sid_pending = H.idOf(0x22);
    const origin_resolved = H.seedFrom(0xa1);
    const origin_pending = H.seedFrom(0xa2);

    const span1 = try parser.channel.parseSpan(try H.spanWire(a, sid_resolved, H.idOf(0x31), H.SUBJECT, 7, 1, origin_resolved, kp));
    const span2 = try parser.channel.parseSpan(try H.spanWire(a, sid_pending, H.idOf(0x32), H.SUBJECT, 1, 1, origin_pending, kp));
    const spans: []const parser.channel.Span = &.{ span1, span2 };

    // The resolved span supports at 216; the pending one contributes nothing,
    // so the claim is Supported (NOT demoted to Unresolved).
    var claim = try H.buildClaim(a, "deploy ok", H.SUBJECT, 242, &.{ sid_resolved, sid_pending });
    try H.expectSupported(
        evidence.resolveClaim(claim, spans, H.ctx(&H.roleExecutor, &H.origin09a, &H.neverSuperseded), &H.ENV),
        216,
    );

    // Every cited span pending -> Unresolved (originAbsent maps all to absent).
    claim = try H.buildClaim(a, "deploy ok", H.SUBJECT, 242, &.{ sid_resolved, sid_pending });
    try H.expectState(
        evidence.resolveClaim(claim, spans, H.ctx(&H.roleExecutor, &H.originAbsent, &H.neverSuperseded), &H.ENV),
        .unresolved,
    );
}

// ===========================================================================
// BE-EVID-09b: a span whose origin resolves to a non-Effect body cannot
// support; it falls out of Supported AND Unresolved alike.
// ===========================================================================

test "BE_EVID_09b origin not resolving to an effect cannot support" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const kp = H.executorKeypair();
    const sid = H.idOf(0x21);

    // Sole span, origin resolves to a non-Effect -> unsupported (not unresolved).
    const span = try parser.channel.parseSpan(try H.spanWire(a, sid, H.idOf(0x31), H.SUBJECT, 1, 1, H.seedFrom(0xa1), kp));
    const spans: []const parser.channel.Span = &.{span};
    var claim = try H.buildClaim(a, "deploy ok", H.SUBJECT, 242, &.{sid});
    try H.expectState(
        evidence.resolveClaim(claim, spans, H.ctx(&H.roleExecutor, &H.originNonEffect, &H.neverSuperseded), &H.ENV),
        .unsupported,
    );

    // Mixed: one Effect-origin span (supports) + one non-Effect-origin span
    // (drops out). The claim is Supported at the Effect span's ceiling; the
    // non-Effect span contributes nothing and does not demote.
    const sid_eff = H.idOf(0x22);
    const span_eff = try parser.channel.parseSpan(try H.spanWire(a, sid_eff, H.idOf(0x33), H.SUBJECT, 1, 1, H.seedFrom(0xa3), kp));
    const spans_mixed: []const parser.channel.Span = &.{ span, span_eff };
    claim = try H.buildClaim(a, "deploy ok", H.SUBJECT, 242, &.{ sid, sid_eff });
    try H.expectSupported(
        evidence.resolveClaim(claim, spans_mixed, H.ctx(&H.roleExecutor, &H.origin09b, &H.neverSuperseded), &H.ENV),
        242,
    );
}

// ===========================================================================
// BE-EVID-10: bounded piggyback. An Utterance past 32 claims or 64 spans is
// rejected; the exact bounds are accepted.
// ===========================================================================

test "BE_EVID_10 utterance bounds reject past 32 claims or 64 spans" {
    try std.testing.expect(evidence.checkBounds(0, 0));
    try std.testing.expect(evidence.checkBounds(32, 64)); // exact bounds
    try std.testing.expect(!evidence.checkBounds(33, 64)); // one claim over
    try std.testing.expect(!evidence.checkBounds(32, 65)); // one span over
    try std.testing.expectEqual(@as(usize, 32), evidence.MAX_UTTERANCE_CLAIMS);
    try std.testing.expectEqual(@as(usize, 64), evidence.MAX_UTTERANCE_SPANS);
}

// ===========================================================================
// BE-EVID-13: an unknown method_id falls to the Inference floor (0.65).
// ===========================================================================

test "BE_EVID_13 unknown method id falls to the inference floor" {
    try std.testing.expectEqual(evidence.EvidenceClass.inference, evidence.classOf(8));
    try std.testing.expectEqual(evidence.EvidenceClass.inference, evidence.classOf(0));
    try std.testing.expectEqual(evidence.EvidenceClass.inference, evidence.classOf(255));
    try std.testing.expectEqual(@as(u8, 165), evidence.ceilingQ8(.inference));

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const kp = H.executorKeypair();
    const sid = H.idOf(0x21);
    // method_id 200 is outside the table -> Inference ceiling 165. Stated 255
    // is capped to 165.
    const span = try parser.channel.parseSpan(try H.spanWire(a, sid, H.idOf(0x31), H.SUBJECT, 200, 1, H.seedFrom(0xa1), kp));
    const spans: []const parser.channel.Span = &.{span};
    const claim = try H.buildClaim(a, "guess", H.SUBJECT, 255, &.{sid});
    try H.expectSupported(
        evidence.resolveClaim(claim, spans, H.ctx(&H.roleExecutor, &H.originEffect, &H.neverSuperseded), &H.ENV),
        165,
    );
}

// ===========================================================================
// BE-EVID-15: the method_id -> class -> ceiling mapping is fixed and must
// appear in the cross-implementation vectors.
// ===========================================================================

test "BE_EVID_15 method id to class to ceiling mapping is fixed" {
    try std.testing.expectEqual(evidence.EvidenceClass.direct_observation, evidence.classOf(1));
    try std.testing.expectEqual(evidence.EvidenceClass.direct_observation, evidence.classOf(4));
    try std.testing.expectEqual(evidence.EvidenceClass.documentation, evidence.classOf(5));
    try std.testing.expectEqual(evidence.EvidenceClass.documentation, evidence.classOf(6));
    try std.testing.expectEqual(evidence.EvidenceClass.expert_testimony, evidence.classOf(7));
    try std.testing.expectEqual(evidence.EvidenceClass.inference, evidence.classOf(8));
    // Normative integer ceilings (SPEC 7.2), decimals are not normative.
    try std.testing.expectEqual(@as(u8, 242), evidence.ceilingQ8(.direct_observation));
    try std.testing.expectEqual(@as(u8, 216), evidence.ceilingQ8(.expert_testimony));
    try std.testing.expectEqual(@as(u8, 191), evidence.ceilingQ8(.documentation));
    try std.testing.expectEqual(@as(u8, 165), evidence.ceilingQ8(.inference));
}

// ===========================================================================
// BE-EVID-11: the code path decides, not a parameter. method_id is a
// compile-time constant of the executor code path; the requester cannot name
// the method, the wire carries no class, and the receiver's resolution entry
// point takes neither class nor confidence override as an argument. The class
// derives from the fixed table, evaluated at compile time.
// ===========================================================================

fn fieldNamed(comptime T: type, comptime needle: []const u8) bool {
    const fields = @typeInfo(T).@"struct".fields;
    inline for (fields) |f| {
        if (std.mem.indexOf(u8, f.name, needle) != null) return true;
    }
    return false;
}

test "BE_EVID_11 no interface accepts method, class, or confidence" {
    // The Intent requests an action and cannot name, hint at, or constrain
    // the observation method: no method, class, or confidence field exists.
    try std.testing.expect(!comptime fieldNamed(parser.channel.Intent, "method"));
    try std.testing.expect(!comptime fieldNamed(parser.channel.Intent, "class"));
    try std.testing.expect(!comptime fieldNamed(parser.channel.Intent, "confidence"));

    // The wire Span carries the code path's method_id byte but no class or
    // confidence field: there is no transmitted class for a receiver to trust.
    try std.testing.expect(!comptime fieldNamed(parser.channel.Span, "class"));
    try std.testing.expect(!comptime fieldNamed(parser.channel.Span, "confidence"));

    // The class table is a compile-time constant: classOf evaluates for all
    // 256 method_id values at comptime, so no runtime state can influence
    // the derivation. This block failing to compile IS the failure mode.
    comptime {
        var i: usize = 0;
        while (i < 256) : (i += 1) {
            _ = evidence.classOf(@as(u8, @intCast(i)));
        }
    }

    // classOf is the sole producer of classes and the ceiling map is its sole
    // consumer: the class value stays inside the fixed table pair.
    const cls_out = @typeInfo(@TypeOf(evidence.classOf)).@"fn".return_type orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(evidence.EvidenceClass, cls_out);

    // resolveClaim, the single public receiver entry point, consumes claims,
    // spans, hooks, and envelope bytes only: no EvidenceClass parameter, so
    // the class can only be derived internally from method_id via classOf.
    inline for (@typeInfo(@TypeOf(evidence.resolveClaim)).@"fn".params) |p| {
        if (p.type) |pt| {
            try std.testing.expect(pt != evidence.EvidenceClass);
            try std.testing.expect(pt != *const evidence.EvidenceClass);
            try std.testing.expect(pt != ?evidence.EvidenceClass);
        }
    }
}

// ===========================================================================
// BE-EVID-14: capture is a precondition. Node-side slice of the executor
// obligation (SPEC: not receiver-verifiable, logged narrow in D-050): the
// wire format gives the digest no empty encoding. It is a fixed 32-byte
// field, and a span truncated inside it is refused, never parsed short.
// ===========================================================================

test "BE_EVID_14 digest is fixed 32 bytes and truncation is refused" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const kp = H.executorKeypair();

    const w = try H.spanWire(a, H.idOf(0x22), H.idOf(0x32), H.SUBJECT, 1, 1, H.seedFrom(0xa2), kp);
    const span = try parser.channel.parseSpan(w);

    // The parsed digest is exactly 32 bytes: the fixed take allows no empty
    // or short encoding to exist on the wire.
    try std.testing.expectEqual(@as(usize, 32), span.digest.len);

    // Truncate inside the digest region: the span is refused outright rather
    // than parsed with a shortened digest.
    const digest_off = @intFromPtr(span.digest.ptr) - @intFromPtr(w.ptr);
    const cut = try a.dupe(u8, w[0 .. digest_off + 10]);
    try std.testing.expectError(error.Truncated, parser.channel.parseSpan(cut));
}
