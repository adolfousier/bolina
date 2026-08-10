// sync_test.zig
//
// Tests for the backfill slice (SPEC.md section 6.4, BE-SYNC-01..05). This
// commit carries the compile vehicle for parser/sync.zig and sync.zig:
// round-trip sanity over both wire parsers and the engine's initial state.
// The literal BE_SYNC_01..05 marker tests land with the ratchet bump (SPEC
// section 11.1), not here.

const std = @import("std");
const parser = @import("parser.zig");
const sync = @import("sync.zig");

const sync_wire = parser.sync;

fn writeU16(out: []u8, v: u16) void {
    std.mem.writeInt(u16, out[0..2], v, .big);
}

fn writeU32(out: []u8, v: u32) void {
    std.mem.writeInt(u32, out[0..4], v, .big);
}

test "sync request round trip" {
    // version | channel_id | have_count=2 | 2 hashes | max_envelopes=64
    var wire: [1 + 32 + 1 + 64 + 2]u8 = undefined;
    wire[0] = 0;
    var i: usize = 0;
    while (i < 32) : (i += 1) wire[1 + i] = @intCast(i);
    wire[33] = 2;
    i = 0;
    while (i < 64) : (i += 1) wire[34 + i] = @intCast(i + 32);
    writeU16(wire[98..100], 64);

    const req = try sync_wire.parseSyncRequest(&wire);
    try std.testing.expectEqual(@as(u8, 0), req.version);
    try std.testing.expectEqualSlices(u8, wire[1..33], req.channel_id);
    try std.testing.expectEqual(@as(u8, 2), req.have_count);
    try std.testing.expectEqualSlices(u8, wire[34..98], req.have_hashes);
    try std.testing.expectEqual(@as(u16, 64), req.max_envelopes);
}

test "sync response round trip" {
    // version | channel_id | count=2 | (len=3, aaa) (len=2, bb) | truncated=1
    var wire: [1 + 32 + 1 + 7 + 6 + 1]u8 = undefined;
    wire[0] = 0;
    var i: usize = 0;
    while (i < 32) : (i += 1) wire[1 + i] = @intCast(255 - i);
    wire[33] = 2;
    writeU32(wire[34..38], 3);
    @memcpy(wire[38..41], "aaa");
    writeU32(wire[41..45], 2);
    @memcpy(wire[45..47], "bb");
    wire[47] = 1;

    const resp = try sync_wire.parseSyncResponse(&wire);
    try std.testing.expectEqual(@as(u8, 2), resp.envelope_count);
    try std.testing.expect(resp.truncated);
    // Re-walk the flat items region exactly as the adopt path does.
    var pos: usize = 0;
    var seen: usize = 0;
    while (pos < resp.items.len) : (seen += 1) {
        const len = std.mem.readInt(u32, resp.items[pos..][0..4], .big);
        pos += 4 + @as(usize, len);
    }
    try std.testing.expectEqual(@as(usize, 2), seen);
    try std.testing.expectEqual(resp.items.len, pos);
}

test "sync engine initial state" {
    var eng = sync.SyncEngine.init();
    try std.testing.expectEqual(@as(usize, 0), eng.walk.depth);
    try std.testing.expectEqual(@as(usize, 0), eng.walk.examined);
    try std.testing.expect(!eng.walk.exhausted);
    // First admissions on a fresh budget always pass.
    try eng.serveAdmit([_]u8{1} ** 32, 1_000);
    try eng.issueAdmit([_]u8{2} ** 32, 1_000);
}
