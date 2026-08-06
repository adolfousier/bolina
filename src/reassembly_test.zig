// reassembly_test.zig
//
// Tests for the fragment reassembly state machine (src/reassembly.zig, SPEC.md
// section 4.4 BE-TR-05 limits table and section 4.5 Fragmentation). One test
// binds the spec item by name (BE_TR_05); the rest use descriptive names so
// they cannot name an undeclared BE item and become orphans under the M1
// bijection. Tests use small generic instantiations (PeerReassembler(4, 16) and
// (16, 16)) so the limits are exercisable without production-sized structures.

const std = @import("std");
const ras = @import("reassembly.zig");

const testing = std.testing;

test "BE_TR_05 out-of-order fragments reassemble then the message completes" {
    var pr = ras.PeerReassembler(4, 16).init();
    // 3-fragment message, delivered out of order (index 1, then 0, then 2).
    try testing.expectEqual(ras.PeerEvent.partial, pr.ingest(1_000, 0xAA, 1, 3, 100));
    try testing.expectEqual(ras.PeerEvent.partial, pr.ingest(1_000, 0xAA, 0, 3, 100));
    try testing.expectEqual(ras.PeerEvent.complete, pr.ingest(1_000, 0xAA, 2, 3, 100));
    // On completion the context and its bytes are released to the peer budget.
    try testing.expectEqual(@as(u8, 0), pr.activeContexts());
    try testing.expectEqual(@as(usize, 0), pr.bytesInUse());
}

test "fragments delivered in reverse accumulate bytes and complete on the last" {
    var pr = ras.PeerReassembler(4, 16).init();
    const total: u16 = 8;
    try testing.expectEqual(ras.PeerEvent.partial, pr.ingest(5_000, 0xBB, 7, total, 200));
    try testing.expectEqual(ras.PeerEvent.partial, pr.ingest(5_000, 0xBB, 6, total, 200));
    try testing.expectEqual(ras.PeerEvent.partial, pr.ingest(5_000, 0xBB, 5, total, 200));
    try testing.expectEqual(ras.PeerEvent.partial, pr.ingest(5_000, 0xBB, 4, total, 200));
    // Mid-flight: one open context holding 4 * 200 bytes.
    try testing.expectEqual(@as(u8, 1), pr.activeContexts());
    try testing.expectEqual(@as(usize, 800), pr.bytesInUse());
    try testing.expectEqual(ras.PeerEvent.partial, pr.ingest(5_000, 0xBB, 3, total, 200));
    try testing.expectEqual(ras.PeerEvent.partial, pr.ingest(5_000, 0xBB, 2, total, 200));
    try testing.expectEqual(ras.PeerEvent.partial, pr.ingest(5_000, 0xBB, 1, total, 200));
    try testing.expectEqual(ras.PeerEvent.complete, pr.ingest(5_000, 0xBB, 0, total, 200));
    try testing.expectEqual(@as(u8, 0), pr.activeContexts());
    try testing.expectEqual(@as(usize, 0), pr.bytesInUse());
}

test "a duplicate fragment index is counted once and changes nothing" {
    var pr = ras.PeerReassembler(4, 16).init();
    try testing.expectEqual(ras.PeerEvent.partial, pr.ingest(1_000, 0xCC, 0, 4, 100));
    try testing.expectEqual(@as(usize, 100), pr.bytesInUse());
    // Re-send index 0 of the same message: counted once, no byte accounting.
    try testing.expectEqual(ras.PeerEvent.duplicate, pr.ingest(1_000, 0xCC, 0, 4, 100));
    try testing.expectEqual(@as(usize, 100), pr.bytesInUse());
    // The remaining fragments still complete the message.
    try testing.expectEqual(ras.PeerEvent.partial, pr.ingest(1_000, 0xCC, 1, 4, 100));
    try testing.expectEqual(ras.PeerEvent.partial, pr.ingest(1_000, 0xCC, 2, 4, 100));
    try testing.expectEqual(ras.PeerEvent.complete, pr.ingest(1_000, 0xCC, 3, 4, 100));
}

test "exceeding the per-peer context limit drops the new message, not the session" {
    var pr = ras.PeerReassembler(4, 16).init();
    // Open 4 distinct incomplete contexts, each one fragment of a 4-fragment msg.
    var m: u64 = 0;
    while (m < 4) : (m += 1) {
        try testing.expectEqual(ras.PeerEvent.partial, pr.ingest(1_000, m, 0, 4, 100));
    }
    try testing.expectEqual(@as(u8, 4), pr.activeContexts());
    // A 5th distinct message cannot get a context: drop the message.
    try testing.expectEqual(ras.PeerEvent.message_dropped, pr.ingest(1_000, 4, 0, 4, 100));
    // The 4 open contexts are untouched and the session is alive.
    try testing.expectEqual(@as(u8, 4), pr.activeContexts());
    try testing.expectEqual(ras.PeerEvent.partial, pr.ingest(1_000, 0, 1, 4, 100));
}

test "exceeding the per-peer memory budget drops the message, not the session" {
    // MAX_MESSAGE (1 MiB) caps each context; reaching the 8 MiB peer budget
    // needs more than 8 contexts each near the per-message ceiling.
    var pr = ras.PeerReassembler(16, 16).init();
    var m: u64 = 0;
    while (m < 8) : (m += 1) {
        try testing.expectEqual(ras.PeerEvent.partial, pr.ingest(1_000, m, 0, 2, 1048576)); // 1 MiB as a literal, never the module constant under test
    }
    try testing.expectEqual(@as(usize, 8388608), pr.bytesInUse()); // exactly 8 MiB as a literal
    // A 9th context's fragment would push the peer past 8 MiB: drop the message.
    try testing.expectEqual(ras.PeerEvent.message_dropped, pr.ingest(1_000, 8, 0, 2, 1048576)); // 1 MiB as a literal
    // The 8 existing contexts survive: the session is alive.
    try testing.expectEqual(@as(u8, 8), pr.activeContexts());
}

test "an incomplete context older than 30 seconds is evicted on sweep" {
    var pr = ras.PeerReassembler(4, 16).init();
    try testing.expectEqual(ras.PeerEvent.partial, pr.ingest(1_000, 0xDD, 0, 4, 100));
    try testing.expectEqual(@as(u8, 1), pr.activeContexts());
    // 29s later: within the incomplete timeout, nothing evicted.
    try testing.expectEqual(@as(u8, 0), pr.evictExpired(1_000 + 29_000));
    try testing.expectEqual(@as(u8, 1), pr.activeContexts());
    // At 30s the incomplete timeout fires and the context is torn down.
    try testing.expectEqual(@as(u8, 1), pr.evictExpired(1_000 + 30_000));
    try testing.expectEqual(@as(u8, 0), pr.activeContexts());
    try testing.expectEqual(@as(usize, 0), pr.bytesInUse());
}

test "NodeCapacity admits sessions up to the node ceiling then refuses" {
    var nc = ras.NodeCapacity.init();
    var i: u16 = 0;
    while (i < ras.SESSIONS_PER_NODE) : (i += 1) {
        try testing.expectEqual(ras.NodeEvent.admitted, nc.tryAdmitSession());
    }
    try testing.expectEqual(ras.SESSIONS_PER_NODE, nc.sessions);
    // One over the ceiling: refused (a capacity condition, surfaced not absorbed).
    try testing.expectEqual(ras.NodeEvent.refused, nc.tryAdmitSession());
    // Releasing a session reopens exactly one slot.
    nc.releaseSession();
    try testing.expectEqual(ras.NodeEvent.admitted, nc.tryAdmitSession());
    try testing.expectEqual(ras.NodeEvent.refused, nc.tryAdmitSession());
}

test "NodeCapacity memory gate accepts under the ceiling and rejects over it" {
    var nc = ras.NodeCapacity.init();
    try testing.expect(nc.withinMemory(ras.MEMORY_PER_NODE));
    nc.addBytes(ras.MEMORY_PER_NODE);
    // Full: any further addition is over the node ceiling.
    try testing.expect(!nc.withinMemory(1));
    // Releasing half reopens that much headroom.
    nc.releaseBytes(ras.MEMORY_PER_NODE / 2);
    try testing.expect(nc.withinMemory(ras.MEMORY_PER_NODE / 2));
    try testing.expect(!nc.withinMemory(ras.MEMORY_PER_NODE / 2 + 1));
}
