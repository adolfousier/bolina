// evidence_record_test.zig
//
// Resolution-record coverage for the attestation layer (src/evidence.zig,
// SPEC.md section 7). Round-4 review, item 4: the inverse of R3. resolveClaim
// is a verdict routine, so every cited span that fails a check is COUNTED into
// a terminal bucket instead of silently dropped. A mutation that drops a span
// shifts a count, which these assertions catch. Shared fixtures and hook stubs
// live in evidence_test_helpers (CODE.md: one home for test helpers).
//
// Naming follows the build.zig M1 registry convention: test "BE_<CLASS>_<NN>".

const std = @import("std");
const parser = @import("parser.zig");
const evidence = @import("evidence.zig");
const H = @import("evidence_test_helpers.zig");

// ===========================================================================
// BE-EVID-16: the resolution record counts every cited span. F1/F2/F3
// (round-4 review) each named a span class the old walk discarded silently;
// the record now lands each in a terminal bucket a mutant cannot drop without
// shifting a count.
// ===========================================================================

test "BE_EVID_16 resolution record counts every cited span" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const kp = H.executorKeypair();

    // F2: a cited span not carried inline is COUNTED (cited=1, inline=0), not
    // silently dropped. BE-EVID-08 exists so an absent span is attributable to
    // the sender; the record now carries that attribution.
    const sid_orphan = H.idOf(0x21);
    _ = try parser.channel.parseSpan(try H.spanWire(a, sid_orphan, H.idOf(0x31), H.SUBJECT, 1, 1, H.seedFrom(0xa1), kp));
    const claim_o = try H.buildClaim(a, "deploy ok", H.SUBJECT, 242, &.{sid_orphan});
    const r2 = evidence.resolveClaim(claim_o, &.{}, H.ctx(&H.roleExecutor, &H.originEffect, &H.neverSuperseded), &H.ENV);
    try H.expectState(r2, .unsupported);
    try std.testing.expectEqual(@as(usize, 1), r2.unsupported.cited);
    try std.testing.expectEqual(@as(usize, 0), r2.unsupported.inline_spans);

    // F3: a span whose origin resolves to a non-Effect body is COUNTED
    // (non_effect=1). A sender citing garbage no longer vanishes with no trace.
    const sid_ne = H.idOf(0x22);
    const span_ne = try parser.channel.parseSpan(try H.spanWire(a, sid_ne, H.idOf(0x32), H.SUBJECT, 1, 1, H.seedFrom(0xa1), kp));
    const spans_ne: []const parser.channel.Span = &.{span_ne};
    const claim_ne = try H.buildClaim(a, "deploy ok", H.SUBJECT, 242, &.{sid_ne});
    const r3 = evidence.resolveClaim(claim_ne, spans_ne, H.ctx(&H.roleExecutor, &H.originNonEffect, &H.neverSuperseded), &H.ENV);
    try H.expectState(r3, .unsupported);
    try std.testing.expectEqual(@as(usize, 1), r3.unsupported.cited);
    try std.testing.expectEqual(@as(usize, 1), r3.unsupported.subject_matched);
    try std.testing.expectEqual(@as(usize, 1), r3.unsupported.non_effect);

    // F1: a supported claim with a pending span carries pending_stronger=true
    // and records one unresolved span; the number stays fail-closed at the
    // strongest RESOLVED ceiling. A mutant that drops the pending span shifts
    // unresolved 1->0 and pending_stronger true->false.
    const sid_resolved = H.idOf(0x23);
    const sid_pending = H.idOf(0x24);
    const origin_resolved = H.seedFrom(0xa1);
    const origin_pending = H.seedFrom(0xa2);
    const span_r = try parser.channel.parseSpan(try H.spanWire(a, sid_resolved, H.idOf(0x33), H.SUBJECT, 7, 1, origin_resolved, kp));
    const span_p = try parser.channel.parseSpan(try H.spanWire(a, sid_pending, H.idOf(0x34), H.SUBJECT, 1, 1, origin_pending, kp));
    const spans_mp: []const parser.channel.Span = &.{ span_r, span_p };
    const claim_mp = try H.buildClaim(a, "deploy ok", H.SUBJECT, 242, &.{ sid_resolved, sid_pending });
    const r1 = evidence.resolveClaim(claim_mp, spans_mp, H.ctx(&H.roleExecutor, &H.origin09a, &H.neverSuperseded), &H.ENV);
    try H.expectSupported(r1, 216);
    try std.testing.expect(r1.supported.pending_stronger);
    try std.testing.expectEqual(@as(usize, 2), r1.supported.record.cited);
    try std.testing.expectEqual(@as(usize, 1), r1.supported.record.unresolved);

    // Sanity: a supported claim with no pending span carries pending_stronger=false.
    const claim_only = try H.buildClaim(a, "deploy ok", H.SUBJECT, 242, &.{sid_resolved});
    const r1b = evidence.resolveClaim(claim_only, &.{span_r}, H.ctx(&H.roleExecutor, &H.originEffect, &H.neverSuperseded), &H.ENV);
    try H.expectSupported(r1b, 216);
    try std.testing.expect(!r1b.supported.pending_stronger);
}
