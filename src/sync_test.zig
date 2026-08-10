// sync_test.zig
//
// Literal tests for the backfill slice (SPEC.md section 6.4, BE-SYNC-01..05,
// D-027 discipline: one named test per declared marker, asserting the marker
// text literally). Round-trip sanity for the two wire parsers rides along.

const std = @import("std");
const parser = @import("parser.zig");
const verify = @import("verify.zig");
const sync = @import("sync.zig");

const sync_wire = parser.sync;

fn writeU16(out: []u8, v: u16) void {
    std.mem.writeInt(u16, out[0..2], v, .big);
}

fn writeU32(out: []u8, v: u32) void {
    std.mem.writeInt(u32, out[0..4], v, .big);
}

fn decodeHex(comptime hex: []const u8) [hex.len / 2]u8 {
    var b: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&b, hex) catch unreachable;
    return b;
}

test "sync request round trip" {
    var wire: [1 + 32 + 1 + 64 + 2]u8 = undefined;
    wire[0] = 1;
    var i: usize = 0;
    while (i < 32) : (i += 1) wire[1 + i] = @intCast(i);
    wire[33] = 2;
    i = 0;
    while (i < 64) : (i += 1) wire[34 + i] = @intCast(i);
    writeU16(wire[98..100], 12);
    const req = try sync_wire.parseSyncRequest(&wire);
    try std.testing.expectEqual(@as(u8, 1), req.version);
    try std.testing.expectEqualSlices(u8, wire[1..33], req.channel_id);
    try std.testing.expectEqual(@as(u8, 2), req.have_count);
    try std.testing.expectEqualSlices(u8, wire[34..98], req.have_hashes);
    try std.testing.expectEqual(@as(u16, 12), req.max_envelopes);
    // Truncated max_envelopes field: cursor end, not malformed.
    try std.testing.expectError(error.Truncated, sync_wire.parseSyncRequest(wire[0..99]));
    // Trailing byte after max_envelopes: parse failure.
    var long: [wire.len + 1]u8 = undefined;
    @memcpy(long[0..wire.len], &wire);
    long[wire.len] = 0;
    try std.testing.expectError(error.TrailingBytes, sync_wire.parseSyncRequest(&long));
}

test "sync response round trip" {
    var wire: [1 + 32 + 1 + 13 + 1]u8 = undefined;
    wire[0] = 0;
    var i: usize = 0;
    while (i < 32) : (i += 1) wire[1 + i] = @intCast(i);
    wire[33] = 2;
    writeU32(wire[34..38], 3);
    @memcpy(wire[38..41], "aaa");
    writeU32(wire[41..45], 2);
    @memcpy(wire[45..47], "bb");
    wire[47] = 1;
    const resp = try sync_wire.parseSyncResponse(&wire);
    try std.testing.expectEqual(@as(u8, 0), resp.version);
    try std.testing.expectEqual(@as(u8, 2), resp.envelope_count);
    try std.testing.expect(resp.truncated);
    var pos: usize = 0;
    var seen: usize = 0;
    while (pos < resp.items.len) : (seen += 1) {
        const len = std.mem.readInt(u32, resp.items[pos..][0..4], .big);
        pos += 4 + @as(usize, len);
    }
    try std.testing.expectEqual(@as(usize, 2), seen);
    // Truncated flag is declared 0/1: anything above is malformed.
    var bad_trunc = wire;
    bad_trunc[47] = 2;
    try std.testing.expectError(error.Malformed, sync_wire.parseSyncResponse(&bad_trunc));
}

// ---------------------------------------------------------------------------
// BE_SYNC_01 — admission.
// ---------------------------------------------------------------------------

// GENESIS: member_group=0xAA*8, admin_group=0xBB*8 (same canonical vector as
// verify_test.zig).
const CHAN_GENESIS_HEX = "01" ++ "0004" ++ "74657374" ++
    "aaaaaaaaaaaaaaaa" ++ "bbbbbbbbbbbbbbbb" ++ "01" ++
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" ++ "01";
const CHAN_MEMBER_GROUP = [_]u8{0xaa} ** parser.session.LEN_GROUP_ID;
const CHAN_OTHER_GROUP = [_]u8{0xee} ** parser.session.LEN_GROUP_ID;
const PEER_PUB = [_]u8{0xdd} ** 32;

fn syncCert(groups: []const u8) parser.session.Cert {
    return .{ .version = 2, .role_bits = 0, .sig_pubkey = &PEER_PUB, .kex_pubkey = "", .not_before = 0, .not_after = 0, .name = "", .group_count = @intCast(groups.len / parser.session.LEN_GROUP_ID), .group_ids = groups, .ca_sig_count = 0, .ca_sigs = "", .tbs = "" };
}

fn revokedNo(_: []const u8) bool {
    return false;
}
fn revokedYes(_: []const u8) bool {
    return true;
}
fn genesisNo(_: []const u8) bool {
    return false;
}

fn syncCtx(revoked_yes: bool) verify.ChannelContext {
    return .{ .genesis_exists = &genesisNo, .is_revoked = if (revoked_yes) &revokedYes else &revokedNo };
}

test "BE_SYNC_01 admission requires an established session, member, not revoked" {
    const genesis = try parser.channel.parseControlGenesis(&decodeHex(CHAN_GENESIS_HEX));
    const member = syncCert(&CHAN_MEMBER_GROUP);
    const outsider = syncCert(&CHAN_OTHER_GROUP);
    // No established session: refuse.
    try std.testing.expectError(sync.SyncError.NoSession, sync.admit(false, member, genesis, syncCtx(false)));
    // Established session but the peer does not carry the member group: refuse.
    try std.testing.expectError(sync.SyncError.NotMember, sync.admit(true, outsider, genesis, syncCtx(false)));
    // Member but revoked: refuse.
    try std.testing.expectError(sync.SyncError.Revoked, sync.admit(true, member, genesis, syncCtx(true)));
    // Established session, member, not revoked: admit.
    try sync.admit(true, member, genesis, syncCtx(false));
}

// ---------------------------------------------------------------------------
// BE_SYNC_02 — stateless response bounds.
// ---------------------------------------------------------------------------

fn syncReq(channel_id: []const u8, have: []const u8, have_count: u8, max_envelopes: u16) sync_wire.SyncRequest {
    return .{ .version = 0, .channel_id = channel_id, .have_count = have_count, .have_hashes = have, .max_envelopes = max_envelopes };
}

test "BE_SYNC_02 response binds at min(max_envelopes,64), at 1 MiB, truncated exact, stateless" {
    const channel_id = [_]u8{0x11} ** 32;
    var wires: [70][1]u8 = undefined;
    var items: [70]sync.ServeItem = undefined;
    for (0..70) |i| {
        wires[i][0] = @intCast(i);
        var h: [32]u8 = [_]u8{0} ** 32;
        h[0] = @intCast(i);
        items[i] = .{ .hash = h, .wire = &wires[i] };
    }
    var out: [4096]u8 = undefined;

    // Responder cap binds: 70 candidates, max_envelopes=100 -> 64 served, truncated.
    const r64 = try sync.buildResponse(&out, syncReq(&channel_id, &[_]u8{}, 0, 100), &items);
    try std.testing.expectEqual(@as(usize, 64), r64.count);
    try std.testing.expect(r64.truncated);

    // Requester cap binds: min(max_envelopes, 64) = 10.
    const r10 = try sync.buildResponse(&out, syncReq(&channel_id, &[_]u8{}, 0, 10), &items);
    try std.testing.expectEqual(@as(usize, 10), r10.count);
    try std.testing.expect(r10.truncated);

    // Candidates exhausted: nothing remains, truncated stays 0.
    const r5 = try sync.buildResponse(&out, syncReq(&channel_id, &[_]u8{}, 0, 64), items[0..5]);
    try std.testing.expectEqual(@as(usize, 5), r5.count);
    try std.testing.expect(!r5.truncated);

    // Have-set skip: the hash the requester already holds is not served.
    const rskip = try sync.buildResponse(&out, syncReq(&channel_id, &items[2].hash, 1, 64), items[0..5]);
    try std.testing.expectEqual(@as(usize, 4), rskip.count);
    try std.testing.expect(!rskip.truncated); // the only unserved item was in the have set
    var pos: usize = 34;
    var served2: bool = false;
    var k: usize = 0;
    while (k < rskip.count) : (k += 1) {
        const len = std.mem.readInt(u32, out[pos..][0..4], .big);
        if (len == 1 and out[pos + 4] == 2) served2 = true;
        pos += 4 + @as(usize, len);
    }
    try std.testing.expect(!served2);

    // Byte cap binds: 16 x 65536-byte envelopes cannot fit under 1 MiB framing;
    // 15 bind first and the 16th sets truncated.
    const big = try std.testing.allocator.alloc(u8, 65536);
    defer std.testing.allocator.free(big);
    @memset(big, 0x5a);
    var big_items: [16]sync.ServeItem = undefined;
    for (0..16) |i| {
        var h: [32]u8 = [_]u8{0} ** 32;
        h[0] = @intCast(0x80 + i);
        big_items[i] = .{ .hash = h, .wire = big };
    }
    const out_big = try std.testing.allocator.alloc(u8, sync.MAX_RESPONSE_BYTES);
    defer std.testing.allocator.free(out_big);
    const r1m = try sync.buildResponse(out_big, syncReq(&channel_id, &[_]u8{}, 0, 64), &big_items);
    try std.testing.expectEqual(@as(usize, 15), r1m.count);
    try std.testing.expect(r1m.truncated);
    try std.testing.expect(r1m.bytes_written <= sync.MAX_RESPONSE_BYTES);

    // Stateless responder: same request twice into fresh buffers on both
    // sides, byte-identical output, nothing carried between builds.
    var outA: [4096]u8 = undefined;
    var outB: [4096]u8 = undefined;
    const first = try sync.buildResponse(&outA, syncReq(&channel_id, &[_]u8{}, 0, 100), &items);
    const again = try sync.buildResponse(&outB, syncReq(&channel_id, &[_]u8{}, 0, 100), &items);
    try std.testing.expectEqual(@as(usize, 64), first.count);
    try std.testing.expect(first.truncated);
    try std.testing.expectEqual(first.bytes_written, again.bytes_written);
    try std.testing.expectEqualSlices(u8, outA[0..first.bytes_written], outB[0..again.bytes_written]);
}

// ---------------------------------------------------------------------------
// BE_SYNC_03 — bounded walk, surface, no retry.
// ---------------------------------------------------------------------------

test "BE_SYNC_03 walk stops at depth 128 and total 4096, surfaces unresolved, never retries" {
    var q = sync.WalkQueue{};
    var h: [32]u8 = [_]u8{0} ** 32;
    for (0..128) |i| {
        h[0] = @intCast(i);
        try q.push(h);
    }
    try std.testing.expectError(sync.SyncError.WalkExhausted, q.push(h)); // 129th
    try std.testing.expect(q.exhausted); // unresolved-history surfaced
    try std.testing.expect(q.pop() == null); // stop: nothing drains, no retry
    try std.testing.expectError(sync.SyncError.WalkExhausted, q.push(h)); // latched

    var q2 = sync.WalkQueue{};
    for (0..4096) |_| try q2.noteExamined();
    try std.testing.expectError(sync.SyncError.WalkExhausted, q2.noteExamined()); // 4097th attempt
    try std.testing.expect(q2.exhausted);
    try std.testing.expectEqual(@as(usize, 4096), q2.examined); // stopped at the bound
    try std.testing.expectError(sync.SyncError.WalkExhausted, q2.noteExamined()); // latched
}

// ---------------------------------------------------------------------------
// BE_SYNC_04 — per-peer sliding-window budgets.
// ---------------------------------------------------------------------------

test "BE_SYNC_04 9th serve refused, window slides, issue symmetric at 4, fail closed" {
    var eng = sync.SyncEngine.init();
    const peerA = [_]u8{0xA1} ** 32;
    const peerB = [_]u8{0xB2} ** 32;
    const peerC = [_]u8{0xC3} ** 32;
    const t0: u64 = 1_000_000;

    var i: usize = 0;
    while (i < 8) : (i += 1) try eng.serveAdmit(peerA, t0);
    try std.testing.expectError(sync.SyncError.RateLimited, eng.serveAdmit(peerA, t0)); // 9th
    try eng.serveAdmit(peerB, t0); // per-peer: B unaffected
    try eng.serveAdmit(peerA, t0 + sync.RATE_WINDOW_MS); // window slides: t0 events expired

    i = 0;
    while (i < 4) : (i += 1) try eng.issueAdmit(peerC, t0);
    try std.testing.expectError(sync.SyncError.RateLimited, eng.issueAdmit(peerC, t0)); // 5th

    // Fail closed: a peer the full table cannot track is refused.
    var eng2 = sync.SyncEngine.init();
    var p: [32]u8 = [_]u8{0} ** 32;
    i = 0;
    while (i < sync.MAX_TRACKED_PEERS) : (i += 1) {
        p[0] = @intCast(i + 1);
        try eng2.serveAdmit(p, t0);
    }
    p[0] = 0xff;
    try std.testing.expectError(sync.SyncError.RateLimited, eng2.serveAdmit(p, t0));
}

// ---------------------------------------------------------------------------
// BE_SYNC_05 — verify before adopt.
// ---------------------------------------------------------------------------

// Canonical intent envelope (test/vectors.json; same bytes verify_test.zig
// grounds on): agent-signed over domain 0x02.
const ENVELOPE_HEX =
    "026d14f9d827a8ec4ad1c5b7a34076f5f0ff41eaffce1cf37959e63df6cceb59ce" ++
    "020bd427446b723424d80d2cad352ba3df3649d0ef8faae0ca7eb25443941b29" ++
    "0000000000000001" ++
    "00" ++
    "0000018bcfe58f10" ++
    "02" ++
    "00000081" ++
    "0102030405060708090a0b0c0d0e0f10" ++
    "0024" ++
    "626f6c3a633365666436343162666130353832662f6c6f67732f6465706c6f792e6c6f67" ++
    "0000001a" ++
    "6170742d67657420696e7374616c6c202d792073716c69746533" ++
    "002b" ++
    "496e7374616c6c2073716c69746520666f72206c6f63616c20736368656d6120696e7370656374696f6e2e" ++
    "3d96e79606b694f286bac4ae1836c351a9ba817bae9a26d14a9844593293bec16d07c18cb44f19e4a77c75c9bc4cbe8eeb6f9c9376da85a74b3abf38e6e0ec02";

test "BE_SYNC_05 backfilled envelope passes the live signature check before adopt" {
    const wire = decodeHex(ENVELOPE_HEX);
    const env = try sync.adoptVerify(&wire);
    try std.testing.expectEqualSlices(u8, wire[33..65], env.sender); // signer carried through
    // Tampered signature: refused with the verifyEnvelope failure, before any ledger entry.
    var bad = wire;
    bad[bad.len - 1] ^= 0xff;
    try std.testing.expectError(sync.SyncError.BadEnvelope, sync.adoptVerify(&bad));
    // Non-envelope bytes: refused at parse, same BadEnvelope.
    try std.testing.expectError(sync.SyncError.BadEnvelope, sync.adoptVerify(wire[0..64]));
    // Scope note: BE-SYNC-05's role/membership/parent clauses key off the sender
    // cert; SPEC declares no cert carriage for historical senders in SyncResponse,
    // so they ride on the live path (see src/sync.zig header).
}
