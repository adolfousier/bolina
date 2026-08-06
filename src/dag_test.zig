// dag_test.zig
//
// Grounds the causal DAG (src/dag.zig) that backs BE-EVID-05 supersession.
// Two layers: the DAG primitives (ancestry on diamonds and deep chains, cycle
// rejection, strict-descendant enforcement, BE-EVID-05a) tested directly with
// caller-owned Dag values, and one end-to-end test that wires the DAG into
// evidence.resolveClaim to show a superseded volatile span drops a claim to
// 0.00 while a stable span on the same DAG is unaffected.
//
// The end-to-end test is the only writer to its package-level Dag and effect
// candidate, so there is no cross-test data race on shared state (the lesson
// from evidence_test's parallel-thread hook globals).

const std = @import("std");
const parser = @import("parser.zig");
const evidence = @import("evidence.zig");
const dag = @import("dag.zig");
const H = @import("evidence_test_helpers.zig");

fn n(seed: u8) dag.Node {
    return H.seedFrom(seed);
}

// ===========================================================================
// BE-EVID-05a: a superseding Effect must be a STRICT causal descendant of the
// span's origin Effect. The DAG encodes this directly: isAncestor is strict by
// construction (a node is never its own ancestor), so the origin Effect can
// never supersede its own span, and an Effect that is not a descendant does
// not supersede.
// ===========================================================================

test "BE_EVID_05a strict causal descendant enforced" {
    var d: dag.Dag = .{};
    const o = n(0xb1);
    const e = n(0xb2); // the later Effect on the same resource
    const c = n(0xb3); // the claim envelope
    try d.insert(o, e); // o happened-before e
    try d.insert(e, c); // e happened-before c (e is visible at the claim)

    // e is a strict descendant of o, and an ancestor of c: it supersedes.
    try std.testing.expect(d.supersedes(o, e, c));

    // Strict: the origin is never its own ancestor, so it cannot supersede
    // itself (BE-EVID-05a).
    try std.testing.expect(!d.supersedes(o, o, c));
    try std.testing.expect(!d.isAncestor(o, o));

    // Reverse direction: o is not a descendant of e.
    try std.testing.expect(!d.isAncestor(e, o));

    // Transitive: o is an ancestor of c through e.
    try std.testing.expect(d.isAncestor(o, c));
}

// ===========================================================================
// Diamond DAG: ancestry must hold across multiple paths and never claim a
// sibling relationship. o -> {a, b} -> d.
// ===========================================================================

test "diamond DAG ancestry across paths and siblings" {
    var d: dag.Dag = .{};
    const o = n(0x01);
    const a = n(0x02);
    const b = n(0x03);
    const dd = n(0x04);
    try d.insert(o, a);
    try d.insert(o, b);
    try d.insert(a, dd);
    try d.insert(b, dd);

    try std.testing.expect(d.isAncestor(o, dd)); // through either path
    try std.testing.expect(d.isAncestor(a, dd));
    try std.testing.expect(d.isAncestor(b, dd));
    try std.testing.expect(d.isAncestor(o, a));
    try std.testing.expect(d.isAncestor(o, b));
    // Siblings are not ancestors of each other.
    try std.testing.expect(!d.isAncestor(a, b));
    try std.testing.expect(!d.isAncestor(b, a));
    // A child is never an ancestor of its parent.
    try std.testing.expect(!d.isAncestor(dd, o));
}

// ===========================================================================
// Deep chain: ancestry must resolve without recursion so a long chain cannot
// overflow the stack. o -> n1 -> n2 -> ... -> n40 -> target.
// ===========================================================================

test "deep chain ancestry without recursion" {
    var d: dag.Dag = .{};
    var prev = n(0x10);
    var i: u8 = 0x11;
    while (i < 0x40) : (i += 1) {
        const cur = n(i);
        try d.insert(prev, cur);
        prev = cur;
    }
    const root = n(0x10);
    const target = n(0x3f);
    try std.testing.expect(d.isAncestor(root, target));
    try std.testing.expect(!d.isAncestor(target, root));
}

// ===========================================================================
// Cycle prevention: an edge that would close a loop is rejected at insert, so
// the graph stays acyclic without trusting insertion order.
// ===========================================================================

test "cycle edges are rejected at insert" {
    var d: dag.Dag = .{};
    const a = n(0x20);
    const b = n(0x21);
    try d.insert(a, b); // a -> b
    // b -> a would close the cycle: child (a) is already an ancestor of the
    // would-be parent (b).
    try std.testing.expectError(error.Cyclic, d.insert(b, a));
    // Self-loop is rejected too (BE-EVID-05a strict).
    try std.testing.expectError(error.Cyclic, d.insert(a, a));
    // The graph is still usable after a rejected insert.
    try std.testing.expect(d.isAncestor(a, b));
}

// ===========================================================================
// Supersession needs both conjuncts: the effect must be a strict descendant of
// the origin AND a strict ancestor of the claim. Either missing means no
// supersession.
// ===========================================================================

test "supersession requires descendant of origin and ancestor of claim" {
    var d: dag.Dag = .{};
    const o = n(0xb1);
    const e = n(0xb2);
    const c = n(0xb3);
    const sib = n(0xb4); // sibling of e: child of o, not an ancestor of c

    try d.insert(o, e);
    try d.insert(e, c);
    try d.insert(o, sib); // sib is a descendant of o but not an ancestor of c

    // Full chain: supersedes.
    try std.testing.expect(d.supersedes(o, e, c));
    // sib descends from o but is not visible at c, so it does not supersede.
    try std.testing.expect(!d.supersedes(o, sib, c));
}

// ===========================================================================
// BE-EVID-05 end-to-end: wiring the DAG into evidence.resolveClaim, a
// superseded volatile span drops the claim to 0.00, while a stable span on the
// identical DAG is unaffected (evidence.zig never consults the DAG hook for a
// stable span, BE-EVID-07). This is the only test that writes the package-level
// Dag and effect candidate, so it cannot race with another test.
// ===========================================================================

var sup_dag: dag.Dag = .{};
var sup_effect: dag.Node = std.mem.zeroes(dag.Node);

fn dagHook(resource: []const u8, origin: []const u8, claim_env: []const u8) bool {
    _ = resource; // resource matching is the production resource-index concern;
    // this hook tests the causal predicate with a fixed candidate effect.
    const o = dag.nodeFromSlice(origin) catch return false;
    const c = dag.nodeFromSlice(claim_env) catch return false;
    return sup_dag.supersedes(o, sup_effect, c);
}

test "BE_EVID_05 superseded volatile span drops claim stable span unaffected" {
    const a = std.testing.allocator;

    // Causal chain: origin o -> effect e -> claim c. The effect e is a strict
    // descendant of the span's origin and visible at the claim, so a volatile
    // span published at o is superseded.
    const o = n(0xb1);
    const e = n(0xb2);
    const c = n(0xb3);
    sup_dag = .{}; // fresh caller-owned DAG
    try sup_dag.insert(o, e);
    try sup_dag.insert(e, c);
    sup_effect = e;
    const claim_env = c;

    const kp = H.executorKeypair();
    const sid = H.idOf(0x21);

    // Volatile span (volatility 1) at origin o: the DAG hook fires, the span is
    // superseded, and the claim drops to 0.00 (Unsupported).
    {
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const al = arena.allocator();
        const span = try parser.parseSpan(try H.spanWire(al, sid, H.idOf(0x31), H.SUBJECT, 1, 1, o, kp));
        const spans: []const parser.Span = &.{span};
        const claim = try H.buildClaim(al, "deploy ok", H.SUBJECT, 242, &.{sid});
        try H.expectState(
            evidence.resolveClaim(claim, spans, H.ctx(&H.roleExecutor, &H.originEffect, &dagHook), &claim_env),
            .unsupported,
        );
    }

    // Stable span (volatility 2) at the SAME origin, on the SAME DAG: the hook
    // is never consulted (BE-EVID-07), so the span still supports at 242.
    {
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const al = arena.allocator();
        const span = try parser.parseSpan(try H.spanWire(al, sid, H.idOf(0x31), H.SUBJECT, 1, 2, o, kp));
        const spans: []const parser.Span = &.{span};
        const claim = try H.buildClaim(al, "deploy ok", H.SUBJECT, 242, &.{sid});
        try H.expectSupported(
            evidence.resolveClaim(claim, spans, H.ctx(&H.roleExecutor, &H.originEffect, &dagHook), &claim_env),
            242,
        );
    }

    // Non-strict effect: an effect that is NOT a descendant of o does not
    // supersede, so even a volatile span stays supported. Rebuild the DAG so e
    // is unrelated to o.
    sup_dag = .{};
    try sup_dag.insert(n(0xc1), e); // e descends from a different origin
    sup_effect = e;
    {
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const al = arena.allocator();
        const span = try parser.parseSpan(try H.spanWire(al, sid, H.idOf(0x31), H.SUBJECT, 1, 1, o, kp));
        const spans: []const parser.Span = &.{span};
        const claim = try H.buildClaim(al, "deploy ok", H.SUBJECT, 242, &.{sid});
        try H.expectSupported(
            evidence.resolveClaim(claim, spans, H.ctx(&H.roleExecutor, &H.originEffect, &dagHook), &claim_env),
            242,
        );
    }
}
