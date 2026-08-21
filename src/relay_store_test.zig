// relay_store_test.zig
//
// BE-MESH-03 binding tests (SPEC.md section 5.2a store-and-forward clause,
// D-058). Literal values throughout (D-027). The store is file-scope static
// state: 1024 slots with 2048-byte bodies do not live on the test stack.

const std = @import("std");
const rs = @import("relay_store.zig");

// Literal fixtures (D-027).
const ADDR_A: [16]u8 = .{ 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0 };
const ADDR_B: [16]u8 = .{ 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0 };
const BODY_ONE = "opaque-ciphertext-body-one";
const BODY_TWO = "opaque-ciphertext-body-two";
const SENDER_INDEX: u32 = 7;

var store: rs.Store = undefined;

test "BE_MESH_03 store drains byte-for-byte: opacity holds (BE-MESH-02)" {
    store.reset();
    try store.store(ADDR_A, SENDER_INDEX, BODY_ONE, 1000);
    try std.testing.expectEqual(@as(usize, 1), store.count);
    const d = store.drainNext(ADDR_A, 2000) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(SENDER_INDEX, d.sender_index);
    try std.testing.expectEqualStrings(BODY_ONE, d.body);
    try std.testing.expect(store.drainNext(ADDR_A, 2000) == null);
    try std.testing.expectEqual(@as(usize, 0), store.count);
}

test "BE_MESH_03 declared body cap refuses oversized bodies" {
    store.reset();
    var big: [rs.MAX_BODY + 1]u8 = undefined;
    @memset(&big, 0x5A);
    try std.testing.expectError(rs.StoreError.BodyTooLarge, store.store(ADDR_A, 1, &big, 0));
    try std.testing.expectEqual(@as(usize, 0), store.count);
    // Boundary: exactly MAX_BODY stores fine and drains intact.
    try store.store(ADDR_A, 1, big[0..rs.MAX_BODY], 0);
    const d = store.drainNext(ADDR_A, 1) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(rs.MAX_BODY, d.body.len);
}

test "BE_MESH_03 per-recipient packet quota is 64, refusal counts, queue untouched" {
    store.reset();
    for (0..rs.MAX_PER_RECIPIENT) |i| {
        try store.store(ADDR_A, @intCast(i), "pkt", @intCast(i));
    }
    try std.testing.expectError(rs.StoreError.RecipientQuota, store.store(ADDR_A, 99, "pkt", 64));
    try std.testing.expectEqual(@as(u64, 1), store.refused_quota);
    try std.testing.expectEqual(@as(usize, 64), store.count); // refusal stores nothing
    // Live forwarding is never blocked: a different recipient still stores.
    try store.store(ADDR_B, 1, "pkt", 65);
    try std.testing.expectEqual(@as(usize, 65), store.count);
}

test "BE_MESH_03 global cap is 1024 slots across recipients" {
    store.reset();
    var addr: [16]u8 = ADDR_A;
    for (0..16) |r| {
        addr[0] = @intCast(r);
        for (0..64) |i| {
            try store.store(addr, @intCast(i), "x", @intCast(r * 64 + i));
        }
    }
    try std.testing.expectEqual(@as(usize, rs.MAX_STORED), store.count);
    addr[0] = 200;
    try std.testing.expectError(rs.StoreError.StoreFull, store.store(addr, 1, "x", 2000));
    try std.testing.expectEqual(@as(u64, 1), store.refused_quota);
}

test "BE_MESH_03 TTL expires at 120 seconds on the caller clock, lazily" {
    store.reset();
    try store.store(ADDR_A, 1, BODY_ONE, 0);
    // One ms before expiry: still deliverable.
    const early = store.drainNext(ADDR_A, rs.TTL_MS - 1) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings(BODY_ONE, early.body);
    // Re-store: at the expiry boundary the lazy purge drops it.
    try store.store(ADDR_A, 1, BODY_ONE, 0);
    try std.testing.expect(store.drainNext(ADDR_A, rs.TTL_MS) == null);
    try std.testing.expectEqual(@as(usize, 0), store.count);
}

test "BE_MESH_03 drain order is storage order and recipients are isolated" {
    store.reset();
    try store.store(ADDR_A, 1, BODY_TWO, 500);
    try store.store(ADDR_A, 2, BODY_ONE, 100); // stored later, earlier clock: drains first
    try store.store(ADDR_B, 3, BODY_TWO, 50);
    const first = store.drainNext(ADDR_A, 600) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings(BODY_ONE, first.body);
    try std.testing.expectEqual(@as(u32, 2), first.sender_index);
    const second = store.drainNext(ADDR_A, 600) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings(BODY_TWO, second.body);
    try std.testing.expect(store.drainNext(ADDR_A, 600) == null);
    // ADDR_B untouched by ADDR_A's drain.
    try std.testing.expectEqual(@as(usize, 1), store.count);
    const b = store.drainNext(ADDR_B, 600) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u32, 3), b.sender_index);
}
