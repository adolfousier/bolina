// session_test.zig
//
// Tests for the transport session layer (src/session.zig, SPEC 4.2/4.3,
// BE-TR-02/03/05): rekey rotation and its bounds, replay and reorder behavior
// of the sealed transport frame, the 512-session node ceiling with
// refuse-new, and zeroization.

const std = @import("std");
const testing = std.testing;
const session = @import("session.zig");
const noise = @import("noise.zig");
const replay = @import("replay.zig");
const reassembly = @import("reassembly.zig");

fn result(send_fill: u8, recv_fill: u8, hash_fill: u8) noise.HandshakeResult {
    return .{
        .send_key = [_]u8{send_fill} ** noise.KEYLEN,
        .recv_key = [_]u8{recv_fill} ** noise.KEYLEN,
        .handshake_hash = [_]u8{hash_fill} ** noise.HASHLEN,
    };
}

// Two tables holding the same session seen from each side: A sends under 0x11
// and receives under 0x22; B is the mirror.
fn pairTables(a: *session.SessionTable, b: *session.SessionTable, now_ms: u64) !struct { u32, u32 } {
    const ia = try a.admit(7, result(0x11, 0x22, 0xAA), now_ms);
    const ib = try b.admit(9, result(0x22, 0x11, 0xAA), now_ms);
    a.slots[ia].peer_index = ib;
    b.slots[ib].peer_index = ia;
    return .{ ia, ib };
}

test "BE_TR_02 rekey rotation zeroes the old state and restarts the epoch" {
    var t = session.SessionTable.init();
    const i = try t.admit(4, result(0x33, 0x44, 0xBB), 1_000);
    var s = t.lookup(i).?;

    // Advance some state under the old key so rotation has something to reset.
    var pkt: [session.HEADER_SIZE + 4 + noise.TAGLEN]u8 = undefined;
    _ = try s.seal(&pkt, &[4]u8{ 1, 2, 3, 4 });
    try testing.expectEqual(@as(u64, 1), s.send.counter);

    const fresh = result(0x55, 0x66, 0xCC);
    s.rotate(fresh, 5_000);

    try testing.expectEqualSlices(u8, &fresh.send_key, &s.send.key);
    try testing.expectEqualSlices(u8, &fresh.recv_key, &s.recv.key);
    try testing.expectEqualSlices(u8, &fresh.handshake_hash, &s.handshake_hash);
    try testing.expectEqual(@as(u64, 0), s.send.counter);
    try testing.expectEqual(@as(u64, 5_000), s.key_epoch_ms);
    // A fresh window: nothing seen, not even seeded.
    try testing.expect(!s.recv.window.initialized);
    // The binding flag survives rotation; binding.zig owns that policy.
    try testing.expect(!s.bound);
}

test "BE_TR_02 zeroization wipes key material" {
    var cs = session.CipherState{ .key = [_]u8{0x99} ** noise.KEYLEN, .counter = 42 };
    cs.zero();
    try testing.expectEqualSlices(u8, &std.mem.zeroes([noise.KEYLEN]u8), &cs.key);
    try testing.expectEqual(@as(u64, 0), cs.counter);

    var rs = session.RecvState{ .key = [_]u8{0x88} ** noise.KEYLEN, .window = replay.ReplayWindow.init() };
    _ = rs.window.check(5); // dirty the window
    rs.zero();
    try testing.expectEqualSlices(u8, &std.mem.zeroes([noise.KEYLEN]u8), &rs.key);
    try testing.expect(!rs.window.initialized);
}

test "BE_TR_02 seal refuses at the 2^48 message bound" {
    var t = session.SessionTable.init();
    const i = try t.admit(1, result(0x11, 0x22, 0xAA), 0);
    const s = t.lookup(i).?;

    s.send.counter = session.REKEY_AFTER_MESSAGES - 1;
    var pkt: [session.HEADER_SIZE + noise.TAGLEN]u8 = undefined;
    _ = try s.seal(&pkt, &[0]u8{}); // the last legal message
    try testing.expectEqual(session.REKEY_AFTER_MESSAGES, s.send.counter);
    try testing.expectError(session.Error.RekeyRequired, s.seal(&pkt, &[0]u8{}));
    try testing.expect(s.dueForRekey(0));
}

test "BE_TR_02 rekey is due at 120 seconds and not a millisecond before" {
    var t = session.SessionTable.init();
    const i = try t.admit(1, result(0x11, 0x22, 0xAA), 1_000);
    const s = t.lookup(i).?;

    try testing.expect(!s.dueForRekey(1_000 + session.REKEY_AFTER_MS - 1));
    try testing.expect(s.dueForRekey(1_000 + session.REKEY_AFTER_MS));
}

test "transport frame layout matches SPEC 4.1a and a keepalive is 32 bytes" {
    var t = session.SessionTable.init();
    const i = try t.admit(0x01020304, result(0x11, 0x22, 0xAA), 0);
    const s = t.lookup(i).?;

    var keepalive: [session.HEADER_SIZE + noise.TAGLEN]u8 = undefined;
    const n = try s.seal(&keepalive, &[0]u8{});
    try testing.expectEqual(@as(usize, 32), n);
    try testing.expectEqual(@as(u8, 4), keepalive[0]);
    try testing.expectEqual(@as(u8, 0), keepalive[1]);
    try testing.expectEqual(@as(u8, 0), keepalive[2]);
    try testing.expectEqual(@as(u8, 0), keepalive[3]);
    try testing.expectEqual(@as(u32, 0x01020304), std.mem.readInt(u32, keepalive[4..8], .big));
    try testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, keepalive[8..16], .big));
}

test "BE_TR_03 reordered transport packets open and a replay is refused" {
    var ta = session.SessionTable.init();
    var tb = session.SessionTable.init();
    const r = try pairTables(&ta, &tb, 0);
    const a = ta.lookup(r[0]).?;
    const b = tb.lookup(r[1]).?;

    // A seals three packets; B opens them out of order (0, 2, 1).
    var p0: [session.HEADER_SIZE + 3 + noise.TAGLEN]u8 = undefined;
    var p1: [session.HEADER_SIZE + 3 + noise.TAGLEN]u8 = undefined;
    var p2: [session.HEADER_SIZE + 3 + noise.TAGLEN]u8 = undefined;
    const n0 = try a.seal(&p0, &[3]u8{ 'x', '0', '0' });
    const n1 = try a.seal(&p1, &[3]u8{ 'x', '1', '1' });
    const n2 = try a.seal(&p2, &[3]u8{ 'x', '2', '2' });

    var out: [64]u8 = undefined;
    const parser = @import("parser.zig");
    const h0 = try parser.parseDataPacketHeader(p0[0..n0]);
    const h2 = try parser.parseDataPacketHeader(p2[0..n2]);
    const h1 = try parser.parseDataPacketHeader(p1[0..n1]);
    try testing.expectEqual(@as(usize, 3), try b.open(p0[0..n0], h0, &out));
    try testing.expectEqual(@as(usize, 3), try b.open(p2[0..n2], h2, &out));
    try testing.expectEqual(@as(usize, 3), try b.open(p1[0..n1], h1, &out));

    // A replay of packet 2 (valid tag, seen counter) is refused.
    try testing.expectError(session.Error.Replay, b.open(p2[0..n2], h2, &out));
}

test "BE_TR_03 a counter below the window floor is refused" {
    var ta = session.SessionTable.init();
    var tb = session.SessionTable.init();
    const r = try pairTables(&ta, &tb, 0);
    const a = ta.lookup(r[0]).?;
    const b = tb.lookup(r[1]).?;
    const parser = @import("parser.zig");

    var pkt: [session.HEADER_SIZE + 1 + noise.TAGLEN]u8 = undefined;
    var out: [64]u8 = undefined;

    // Advance B's window far enough that counter 0 falls below the floor.
    const top = replay.WINDOW_BITS + 100;
    a.send.counter = top;
    const n_top = try a.seal(&pkt, &[1]u8{0x77});
    const h_top = try parser.parseDataPacketHeader(pkt[0..n_top]);
    try testing.expectEqual(@as(usize, 1), try b.open(pkt[0..n_top], h_top, &out));

    // A packet sealed at counter 0 is now below B's window: Replay, not a
    // decryption failure.
    a.send.counter = 0;
    const n_old = try a.seal(&pkt, &[1]u8{0x00});
    const h_old = try parser.parseDataPacketHeader(pkt[0..n_old]);
    try testing.expectError(session.Error.Replay, b.open(pkt[0..n_old], h_old, &out));
}

test "a tampered transport payload fails the AEAD tag" {
    var ta = session.SessionTable.init();
    var tb = session.SessionTable.init();
    const r = try pairTables(&ta, &tb, 0);
    const a = ta.lookup(r[0]).?;
    const b = tb.lookup(r[1]).?;
    const parser = @import("parser.zig");

    var pkt: [session.HEADER_SIZE + 2 + noise.TAGLEN]u8 = undefined;
    const n = try a.seal(&pkt, &[2]u8{ 5, 6 });
    pkt[n - 1] ^= 0x01; // flip a tag byte
    const h = try parser.parseDataPacketHeader(pkt[0..n]);
    var out: [64]u8 = undefined;
    try testing.expectError(session.Error.DecryptFailed, b.open(pkt[0..n], h, &out));
}

test "BE_TR_05 the node session ceiling refuses new sessions without degrading existing" {
    var t = session.SessionTable.init();
    var i: usize = 0;
    while (i < session.MAX_SESSIONS) : (i += 1) {
        _ = try t.admit(@intCast(i), result(0x11, 0x22, 0xAA), 0);
    }
    try testing.expectEqual(@as(usize, session.MAX_SESSIONS), t.count);
    try testing.expectError(session.Error.NodeCapacity, t.admit(999, result(0x11, 0x22, 0xAA), 0));

    // Existing sessions still work after the refusal.
    const s = t.lookup(0).?;
    var pkt: [session.HEADER_SIZE + noise.TAGLEN]u8 = undefined;
    _ = try s.seal(&pkt, &[0]u8{});

    // Releasing one slot admits exactly one new session.
    t.release(0);
    try testing.expectEqual(@as(usize, session.MAX_SESSIONS - 1), t.count);
    _ = try t.admit(999, result(0x11, 0x22, 0xAA), 0);
    try testing.expectError(session.Error.NodeCapacity, t.admit(998, result(0x11, 0x22, 0xAA), 0));
}

test "release zeroes the whole slot" {
    var t = session.SessionTable.init();
    const i = try t.admit(4, result(0x33, 0x44, 0xBB), 1_000);
    t.release(i);
    try testing.expect(t.lookup(i) == null);
    const slot = t.slots[i];
    try testing.expectEqualSlices(u8, &std.mem.zeroes([noise.KEYLEN]u8), &slot.send.key);
    try testing.expectEqualSlices(u8, &std.mem.zeroes([noise.KEYLEN]u8), &slot.recv.key);
    try testing.expectEqualSlices(u8, &std.mem.zeroes([noise.HASHLEN]u8), &slot.handshake_hash);
    try testing.expect(!slot.in_use);
}

test "lookup rejects a stale or out-of-range receiver index" {
    var t = session.SessionTable.init();
    try testing.expect(t.lookup(0) == null); // never admitted
    try testing.expect(t.lookup(session.MAX_SESSIONS) == null); // out of range
    try testing.expect(t.lookup(std.math.maxInt(u32)) == null);
    const i = try t.admit(1, result(0x11, 0x22, 0xAA), 0);
    try testing.expect(t.lookup(i) != null);
}

test "session ceiling agrees with the reassembly declaration" {
    // BE-TR-05 states the limits in one table because they must agree; the
    // two modules declaring them must never drift.
    try testing.expectEqual(@as(u16, session.MAX_SESSIONS), reassembly.SESSIONS_PER_NODE);
}
