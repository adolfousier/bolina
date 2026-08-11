// relay_test.zig
//
// Unit tests for the relay surface (SPEC §5.2a, BE-MESH-02, D-044).
// Tests assert parsing correctness, table bounds, timestamp skew, and
// the no-key-material forwarding guarantee.

const std = @import("std");
const relay = @import("relay.zig");
const parser = @import("parser.zig");

fn decodeHex(comptime hex: []const u8) [hex.len / 2]u8 {
    var b: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&b, hex) catch unreachable;
    return b;
}

// Type 5 relay route header (20 bytes):
// type=5, reserved=000, sender_index=1, recipient_index=2, timestamp=1000
const ROUTE_HEX = "05000000000000010000000200000000000003e8";
const ROUTE_BYTES = decodeHex(ROUTE_HEX);

// Type 6 relay registration (124 bytes):
// type=6, reserved=000, relay_index=10, client_index=20, timestamp=1000,
// overlay_addr=fd0102030405060708090a0b0c0d0e0f, expiry=2000,
// sig=64 zeros (invalid sig, but parsing doesn't verify), padding=16 zeros
const REG_HEX =
    "060000000000000a0000001400000000000003e8" ++
    "fd0102030405060708090a0b0c0d0e0f" ++
    "00000000000007d0" ++
    "0000000000000000000000000000000000000000000000000000000000000000" ++
    "0000000000000000000000000000000000000000000000000000000000000000" ++
    "00000000000000000000000000000000";
const REG_BYTES = decodeHex(REG_HEX);

test "BE_MESH_02 parseRelayRoute happy path" {
    const route = try relay.parseRelayRoute(&ROUTE_BYTES);
    try std.testing.expectEqual(@as(u32, 1), route.sender_index);
    try std.testing.expectEqual(@as(u32, 2), route.recipient_index);
    try std.testing.expectEqual(@as(u64, 1000), route.timestamp);
}

test "BE_MESH_02 parseRelayRoute rejects wrong type" {
    var buf = ROUTE_BYTES;
    buf[0] = 0x04; // wrong type
    const result = relay.parseRelayRoute(&buf);
    try std.testing.expectError(parser.ParseError.Malformed, result);
}

test "BE_MESH_02 parseRelayRoute rejects non-zero reserved" {
    var buf = ROUTE_BYTES;
    buf[1] = 0x01; // non-zero reserved
    const result = relay.parseRelayRoute(&buf);
    try std.testing.expectError(parser.ParseError.Malformed, result);
}

test "BE_MESH_02 parseRelayRoute rejects trailing bytes" {
    var buf: [21]u8 = undefined;
    @memcpy(buf[0..20], &ROUTE_BYTES);
    buf[20] = 0xff;
    const result = relay.parseRelayRoute(&buf);
    try std.testing.expectError(parser.ParseError.TrailingBytes, result);
}

test "BE_MESH_02 parseRelayRoute rejects truncated input" {
    const result = relay.parseRelayRoute(ROUTE_BYTES[0..19]);
    try std.testing.expectError(parser.ParseError.Truncated, result);
}

test "BE_MESH_02 parseRelayRegistration happy path" {
    const reg = try relay.parseRelayRegistration(&REG_BYTES);
    try std.testing.expectEqual(@as(u32, 10), reg.relay_index);
    try std.testing.expectEqual(@as(u32, 20), reg.client_index);
    try std.testing.expectEqual(@as(u64, 1000), reg.timestamp);
    try std.testing.expectEqual(@as(u64, 2000), reg.expiry);
    try std.testing.expectEqual(@as(usize, 16), reg.overlay_addr.len);
    try std.testing.expectEqual(@as(usize, 64), reg.sig.len);
}

test "BE_MESH_02 parseRelayRegistration rejects wrong type" {
    var buf = REG_BYTES;
    buf[0] = 0x05; // wrong type
    const result = relay.parseRelayRegistration(&buf);
    try std.testing.expectError(parser.ParseError.Malformed, result);
}

test "BE_MESH_02 parseRelayRegistration rejects non-zero reserved" {
    var buf = REG_BYTES;
    buf[2] = 0x01; // non-zero reserved
    const result = relay.parseRelayRegistration(&buf);
    try std.testing.expectError(parser.ParseError.Malformed, result);
}

test "BE_MESH_02 parseRelayRegistration rejects trailing bytes" {
    var buf: [125]u8 = undefined;
    @memcpy(buf[0..124], &REG_BYTES);
    buf[124] = 0xff;
    const result = relay.parseRelayRegistration(&buf);
    try std.testing.expectError(parser.ParseError.TrailingBytes, result);
}

test "BE_MESH_02 parseRelayRegistration rejects truncated input" {
    const result = relay.parseRelayRegistration(REG_BYTES[0..123]);
    try std.testing.expectError(parser.ParseError.Truncated, result);
}

test "BE_MESH_02 RelayTable insert and lookup" {
    var table = relay.RelayTable.init();
    const addr = decodeHex("fd0102030405060708090a0b0c0d0e0f");
    const entry = relay.RelayEntry{
        .overlay_addr = addr,
        .relay_index = 10,
        .client_index = 20,
        .expiry = 2000,
    };
    try std.testing.expect(table.insert(entry));
    const found = table.lookup(&addr);
    try std.testing.expect(found != null);
    try std.testing.expectEqual(@as(u32, 20), found.?.client_index);
}

test "BE_MESH_02 RelayTable rejects insert when full" {
    var table = relay.RelayTable.init();
    var addr: [16]u8 = undefined;
    // Literal 4096: the SPEC §5.2a bound (D-044), not relay.MAX_RELAY_TABLE.
    // A mutant on the constant must not scale the test with it (D-027).
    for (0..4096) |i| {
        @memset(&addr, 0);
        addr[0] = @intCast(i & 0xff);
        addr[1] = @intCast((i >> 8) & 0xff);
        const entry = relay.RelayEntry{
            .overlay_addr = addr,
            .relay_index = 1,
            .client_index = @intCast(i),
            .expiry = 9999,
        };
        try std.testing.expect(table.insert(entry));
    }
    // Table is now full; next insert should fail.
    const entry = relay.RelayEntry{
        .overlay_addr = addr,
        .relay_index = 1,
        .client_index = 99999,
        .expiry = 9999,
    };
    try std.testing.expect(!table.insert(entry));
}

test "BE_MESH_02 RelayTable prunes expired entries" {
    var table = relay.RelayTable.init();
    const addr1 = decodeHex("fd0102030405060708090a0b0c0d0e0f");
    const addr2 = decodeHex("fd1112131415161718191a1b1c1d1e1f");
    _ = table.insert(.{ .overlay_addr = addr1, .relay_index = 1, .client_index = 1, .expiry = 100 });
    _ = table.insert(.{ .overlay_addr = addr2, .relay_index = 2, .client_index = 2, .expiry = 200 });
    table.prune(150); // prunes addr1 (expiry 100 <= 150)
    try std.testing.expectEqual(@as(usize, 1), table.count);
    try std.testing.expect(table.lookup(&addr1) == null);
    try std.testing.expect(table.lookup(&addr2) != null);
}

test "BE_MESH_02 forwardPacket returns packet unchanged" {
    var table = relay.RelayTable.init();
    const addr = decodeHex("fd0102030405060708090a0b0c0d0e0f");
    _ = table.insert(.{ .overlay_addr = addr, .relay_index = 1, .client_index = 2, .expiry = 9999 });
    const route = relay.RelayRoute{ .sender_index = 1, .recipient_index = 2, .timestamp = 1000 };
    const packet = decodeHex("04000000000000010000000000000001aabbccdd");
    const result = try relay.forwardPacket(&table, route, &packet, 1000);
    try std.testing.expect(result != null);
    // The forwarded packet is the same slice, unchanged.
    try std.testing.expectEqualSlices(u8, &packet, result.?);
}

test "BE_MESH_02 forwardPacket rejects stale route" {
    var table = relay.RelayTable.init();
    const addr = decodeHex("fd0102030405060708090a0b0c0d0e0f");
    _ = table.insert(.{ .overlay_addr = addr, .relay_index = 1, .client_index = 2, .expiry = 9999 });
    const route = relay.RelayRoute{ .sender_index = 1, .recipient_index = 2, .timestamp = 100 };
    const packet = decodeHex("04000000000000010000000000000001aabbccdd");
    const result = relay.forwardPacket(&table, route, &packet, 1000);
    try std.testing.expectError(relay.ForwardError.StaleRoute, result);
}

test "BE_MESH_02 forwardPacket rejects unknown recipient" {
    var table = relay.RelayTable.init();
    const route = relay.RelayRoute{ .sender_index = 1, .recipient_index = 999, .timestamp = 1000 };
    const packet = decodeHex("04000000000000010000000000000001aabbccdd");
    const result = relay.forwardPacket(&table, route, &packet, 1000);
    try std.testing.expectError(relay.ForwardError.UnknownRecipient, result);
}

test "BE_MESH_02 forwardPacket accepts route at exactly the 300s skew bound" {
    // Literal 300: SPEC §5.2a bounds |now - timestamp| at 300 (D-044), not
    // relay.TIMESTAMP_SKEW - a mutant on the constant must not scale the
    // boundary with it (D-027). Both edges of the window are legal.
    var table = relay.RelayTable.init();
    const addr = decodeHex("fd0102030405060708090a0b0c0d0e0f");
    _ = table.insert(.{ .overlay_addr = addr, .relay_index = 1, .client_index = 2, .expiry = 9999 });
    const packet = decodeHex("04000000000000010000000000000001aabbccdd");
    var route = relay.RelayRoute{ .sender_index = 1, .recipient_index = 2, .timestamp = 700 }; // 1000 - 300
    const older = try relay.forwardPacket(&table, route, &packet, 1000);
    try std.testing.expect(older != null);
    route.timestamp = 1300; // 1000 + 300
    const newer = try relay.forwardPacket(&table, route, &packet, 1000);
    try std.testing.expect(newer != null);
}

test "BE_MESH_02 forwardPacket drops route one second past the skew bound" {
    // Literal 301: one second outside the SPEC §5.2a bound on both sides.
    var table = relay.RelayTable.init();
    const addr = decodeHex("fd0102030405060708090a0b0c0d0e0f");
    _ = table.insert(.{ .overlay_addr = addr, .relay_index = 1, .client_index = 2, .expiry = 9999 });
    const packet = decodeHex("04000000000000010000000000000001aabbccdd");
    var route = relay.RelayRoute{ .sender_index = 1, .recipient_index = 2, .timestamp = 699 }; // 1000 - 301
    try std.testing.expectError(relay.ForwardError.StaleRoute, relay.forwardPacket(&table, route, &packet, 1000));
    route.timestamp = 1301; // 1000 + 301
    try std.testing.expectError(relay.ForwardError.StaleRoute, relay.forwardPacket(&table, route, &packet, 1000));
}

test "BE_MESH_02 registration tbs is exactly the 44 bytes before sig" {
    // Literal 44 and literal bytes: the signature covers type..expiry, the
    // 124-byte message minus the 64-byte sig and 16-byte padding (SPEC
    // §5.2a). The verification hook is deferred (D-043), so the boundary
    // itself is what the tests pin.
    const reg = try relay.parseRelayRegistration(&REG_BYTES);
    try std.testing.expectEqual(@as(usize, 44), reg.tbs.len);
    try std.testing.expectEqualSlices(u8, REG_BYTES[0..44], reg.tbs);
}

test "BE_MESH_02 registration domain tag pinned to 0x07" {
    // BE-SIG-01 row 0x07 (RelayRegistration). The verification path that
    // consumes this tag is deferred (D-043 scope: forwarding only); the pin
    // keeps the wire commitment from drifting silently. Same shape as
    // vectors_test's domain_tag checks: constant against an independent
    // literal, so a mutant on the constant cannot scale both sides (D-027).
    try std.testing.expectEqual(@as(u8, 0x07), relay.DOMAIN_RELAY_REGISTRATION);
}

test "BE_MESH_02 relay holds no key material (no session state in RelayTable)" {
    // The RelayTable stores only overlay_addr, indices, and expiry.
    // It does not store any key material, session keys, or decryption state.
    // This is a structural assertion: RelayEntry has no key fields.
    const entry_size = @sizeOf(relay.RelayEntry);
    // RelayEntry = 16 (overlay_addr) + 4 (relay_index) + 4 (client_index) + 8 (expiry) = 32 bytes
    try std.testing.expectEqual(@as(usize, 32), entry_size);
}

// ---------------------------------------------------------------------------
// Store-and-forward wiring (BE-MESH-03, D-058).
// ---------------------------------------------------------------------------

const relay_store = @import("relay_store.zig");

// Literal registration identity from REG_HEX (D-027).
const ADDR_WIRE: [relay.LEN_OVERLAY_ADDR]u8 = decodeHex("fd0102030405060708090a0b0c0d0e0f");
const BODY_DEFERRED = "opaque-deferred-ciphertext-body";

var wire_store: relay_store.Store = undefined;
var wire_table: relay.RelayTable = undefined;

test "BE_MESH_03 storeDeferred resolves through the table; unknown and stale get no service" {
    wire_store.reset();
    wire_table = relay.RelayTable.init();
    _ = wire_table.insert(.{
        .overlay_addr = ADDR_WIRE,
        .relay_index = 10,
        .client_index = 20, // REG_HEX literal
        .expiry = 2000,
    });
    // known recipient stores, keyed by overlay_addr
    try relay.storeDeferred(&wire_table, &wire_store, .{ .sender_index = 1, .recipient_index = 20, .timestamp = 1000 }, BODY_DEFERRED, 1000_000);
    try std.testing.expectEqual(@as(usize, 1), wire_store.count);
    try std.testing.expectEqual(ADDR_WIRE, wire_store.packets[0].recipient_addr);
    // unknown index: no service, storage included (BE-MESH-04 extended)
    try std.testing.expectError(error.UnknownRecipient, relay.storeDeferred(&wire_table, &wire_store, .{ .sender_index = 1, .recipient_index = 999, .timestamp = 1000 }, BODY_DEFERRED, 1000_000));
    try std.testing.expectEqual(@as(usize, 1), wire_store.count);
    // stale route: refused exactly as on the live path (300s skew)
    try std.testing.expectError(error.StaleRoute, relay.storeDeferred(&wire_table, &wire_store, .{ .sender_index = 1, .recipient_index = 20, .timestamp = 500 }, BODY_DEFERRED, 1000_000));
    try std.testing.expectEqual(@as(usize, 1), wire_store.count);
}

test "BE_MESH_03 drainFor rewrites recipient_index; body stays byte-for-byte; header round-trips" {
    wire_store.reset();
    wire_table = relay.RelayTable.init();
    _ = wire_table.insert(.{ .overlay_addr = ADDR_WIRE, .relay_index = 10, .client_index = 20, .expiry = 2000 });
    try relay.storeDeferred(&wire_table, &wire_store, .{ .sender_index = 7, .recipient_index = 20, .timestamp = 1000 }, BODY_DEFERRED, 1000_000);
    // recipient re-registers with a fresh client_index; drain rewrites to it
    var out: [4]relay.DrainedForward = undefined;
    const n = relay.drainFor(&wire_store, ADDR_WIRE, 42, 1001_000, &out);
    try std.testing.expectEqual(@as(usize, 1), n);
    // rewritten header round-trips through the real parser
    const route = try relay.parseRelayRoute(&out[0].header);
    try std.testing.expectEqual(@as(u32, 7), route.sender_index); // sender preserved
    try std.testing.expectEqual(@as(u32, 42), route.recipient_index); // rewritten
    try std.testing.expectEqual(@as(u64, 1001), route.timestamp); // fresh stamp
    // ciphertext body untouched (BE-MESH-02 opacity)
    try std.testing.expectEqualStrings(BODY_DEFERRED, out[0].body);
    // queue is empty; a second drain yields nothing
    try std.testing.expectEqual(@as(usize, 0), relay.drainFor(&wire_store, ADDR_WIRE, 42, 1002_000, &out));
    try std.testing.expectEqual(@as(usize, 0), wire_store.count);
}

test "BE_MESH_03 writeRelayRoute mirrors parseRelayRoute and refuses small buffers" {
    var buf: [relay.LEN_RELAY_ROUTE]u8 = undefined;
    try relay.writeRelayRoute(&buf, .{ .sender_index = 5, .recipient_index = 9, .timestamp = 1234567 });
    const route = try relay.parseRelayRoute(&buf);
    try std.testing.expectEqual(@as(u32, 5), route.sender_index);
    try std.testing.expectEqual(@as(u32, 9), route.recipient_index);
    try std.testing.expectEqual(@as(u64, 1234567), route.timestamp);
    var small: [relay.LEN_RELAY_ROUTE - 1]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, relay.writeRelayRoute(&small, .{ .sender_index = 5, .recipient_index = 9, .timestamp = 1 }));
}
