// relay.zig
//
// Relay surface: pre-authentication parsing and forwarding for Bolina's
// relay role (SPEC.md §5.2a, BE-MESH-02, D-043/D-044). Two fixed-size
// packet types are parsed before authentication; both are role-gated to
// the relay role. The relay holds no key material, cannot decrypt, and
// forwards Noise transport packets unchanged.
//
// Budget: relay sub-unit ≤ 510 lines (BE-SURF-03 subdivision, D-043).
// Tripwire: if this file reaches 510 lines before BE-MESH-02 is done,
// work stops and the relay defers to M2.

const std = @import("std");
const parser = @import("parser.zig");
const coverage = @import("coverage.zig");
const verify = @import("verify.zig");
const relay_store = @import("relay_store.zig");

// ---------------------------------------------------------------------------
// Constants (SPEC §5.2a, BE-SIG-01).
// ---------------------------------------------------------------------------

pub const MSG_RELAY_ROUTE: u8 = 5;
pub const MSG_RELAY_REGISTRATION: u8 = 6;
pub const DOMAIN_RELAY_REGISTRATION: u8 = 0x07;

pub const LEN_RELAY_ROUTE: usize = 20; // type + reserved + sender_index + recipient_index + timestamp
pub const LEN_RELAY_REGISTRATION: usize = 124; // type + reserved + relay_index + client_index + timestamp + overlay_addr + expiry + sig + padding
pub const LEN_RESERVED: usize = 3;
pub const LEN_OVERLAY_ADDR: usize = 16; // BE-ID-01
pub const LEN_SIG: usize = 64; // Ed25519
pub const LEN_PADDING: usize = 16;

pub const MAX_RELAY_TABLE: usize = 4096; // bounded registration table (D-044)
pub const TIMESTAMP_SKEW: u64 = 300; // seconds, relay-local (D-044)
pub const MAX_EXPIRY: u64 = 86400; // 24 hours, client-chosen cap (D-044)

// ---------------------------------------------------------------------------
// Type 5 - Relay route header (20 bytes).
// ---------------------------------------------------------------------------

pub const RelayRoute = struct {
    sender_index: u32,
    recipient_index: u32,
    timestamp: u64,
};

pub fn parseRelayRoute(buf: []const u8) parser.ParseError!RelayRoute {
    var c = parser.Cursor{ .buf = buf };
    const msg_type = try c.u8r();
    if (msg_type != MSG_RELAY_ROUTE) return coverage.reject(.relay_route_type);
    const reserved = try c.take(LEN_RESERVED);
    if ((reserved[0] | reserved[1] | reserved[2]) != 0) return coverage.reject(.relay_route_reserved);
    const sender_index = try c.u32be();
    const recipient_index = try c.u32be();
    const timestamp = try c.u64be();
    if (c.pos != buf.len) return coverage.reject(.relay_route_trailing);
    coverage.accept(.relay_route_accepted);
    return .{ .sender_index = sender_index, .recipient_index = recipient_index, .timestamp = timestamp };
}

// ---------------------------------------------------------------------------
// Type 6 - Relay registration (124 bytes).
// ---------------------------------------------------------------------------

pub const RelayRegistration = struct {
    relay_index: u32,
    client_index: u32,
    timestamp: u64,
    overlay_addr: []const u8, // aliases caller buffer, LEN_OVERLAY_ADDR
    expiry: u64,
    sig: []const u8, // aliases caller buffer, LEN_SIG
    tbs: []const u8, // all bytes before sig, for verification
};

pub fn parseRelayRegistration(buf: []const u8) parser.ParseError!RelayRegistration {
    var c = parser.Cursor{ .buf = buf };
    const msg_type = try c.u8r();
    if (msg_type != MSG_RELAY_REGISTRATION) return coverage.reject(.relay_reg_type);
    const reserved = try c.take(LEN_RESERVED);
    if (reserved[0] != 0 or reserved[1] != 0 or reserved[2] != 0)
        return coverage.reject(.relay_reg_reserved);
    const relay_index = try c.u32be();
    const client_index = try c.u32be();
    const timestamp = try c.u64be();
    const overlay_addr = try c.take(LEN_OVERLAY_ADDR);
    const expiry = try c.u64be();
    const sig = try c.take(LEN_SIG);
    const padding = try c.take(LEN_PADDING);
    _ = padding; // reserved, ignored on recv
    if (c.pos != buf.len) return coverage.reject(.relay_reg_trailing);
    const tbs = buf[0..(LEN_RELAY_REGISTRATION - LEN_SIG - LEN_PADDING)];
    coverage.accept(.relay_reg_accepted);
    return .{
        .relay_index = relay_index,
        .client_index = client_index,
        .timestamp = timestamp,
        .overlay_addr = overlay_addr,
        .expiry = expiry,
        .sig = sig,
        .tbs = tbs,
    };
}

// ---------------------------------------------------------------------------
// Bounded routing table (D-044 decision 2).
// ---------------------------------------------------------------------------

pub const RelayEntry = struct {
    overlay_addr: [LEN_OVERLAY_ADDR]u8,
    relay_index: u32,
    client_index: u32,
    expiry: u64,
};

pub const RelayTable = struct {
    entries: [MAX_RELAY_TABLE]RelayEntry,
    count: usize = 0,

    pub fn init() RelayTable {
        return .{ .entries = undefined };
    }

    // Insert: same overlay_addr re-registers as an in-place refresh (MD5):
    // newest wins, a stale route never shadows a live one, no clone floods;
    // false only for a NEW address at a full table.
    pub fn insert(self: *RelayTable, entry: RelayEntry) bool {
        for (self.entries[0..self.count]) |*e| {
            if (std.mem.eql(u8, &e.overlay_addr, &entry.overlay_addr)) {
                e.* = entry;
                return true;
            }
        }
        if (self.count >= MAX_RELAY_TABLE) return false;
        self.entries[self.count] = entry;
        self.count += 1;
        return true;
    }

    // Look up an entry by overlay_addr. Returns null if not found.
    pub fn lookup(self: *const RelayTable, overlay_addr: []const u8) ?RelayEntry {
        for (self.entries[0..self.count]) |e| {
            if (std.mem.eql(u8, &e.overlay_addr, overlay_addr)) return e;
        }
        return null;
    }

    // Prune expired entries (BE-MESH-05).
    pub fn prune(self: *RelayTable, now: u64) void {
        var i: usize = 0;
        while (i < self.count) {
            if (self.entries[i].expiry <= now) {
                // Swap with last entry and shrink.
                self.count -= 1;
                self.entries[i] = self.entries[self.count];
            } else {
                i += 1;
            }
        }
    }
};

// ---------------------------------------------------------------------------
// Forwarding (BE-MESH-02): forward opaque Noise transport packet unchanged.
// The relay holds no key material and does not decrypt.
// ---------------------------------------------------------------------------

pub fn forwardPacket(table: *const RelayTable, route: RelayRoute, packet: []const u8, now: u64) ForwardError!?[]const u8 {
    // Check timestamp skew (D-044 decision 1).
    if (route.timestamp > now + TIMESTAMP_SKEW or route.timestamp + TIMESTAMP_SKEW < now)
        return ForwardError.StaleRoute;

    // Look up the recipient by client_index.
    for (table.entries[0..table.count]) |e| {
        if (e.client_index == route.recipient_index) {
            // Forward the packet unchanged. The caller sends it to the
            // recipient's UDP endpoint (obtained from the session table).
            return packet;
        }
    }
    return ForwardError.UnknownRecipient;
}

pub const ForwardError = error{
    StaleRoute,
    UnknownRecipient,
};

// ---------------------------------------------------------------------------
// Store-and-forward wiring (BE-MESH-03, D-058, SPEC v0.3.4-draft clause).
// Storage keys by overlay_addr because client indexes die with the session
// and registration is one-shot per session. Drain rewrites the relay-layer
// recipient_index at registration time; the ciphertext body passes through
// byte-for-byte (BE-MESH-02 opacity). The rewrite touches relay routing
// metadata only: D-058 and the SPEC clause are the written warrant.
// ---------------------------------------------------------------------------

pub const StoreDeferredError = relay_store.StoreError || error{ StaleRoute, UnknownRecipient };

// storeDeferred (BE-MESH-03, D-058): store a forward whose live delivery
// is not possible. The recipient MUST resolve through the registration
// table: unknown indexes receive no service, storage included (D-058
// extends BE-MESH-04 to storage). Timestamp skew is enforced exactly as on
// the live path: stale routes are never stored.
pub fn storeDeferred(table: *const RelayTable, store: *relay_store.Store, route: RelayRoute, body: []const u8, now_ms: u64) StoreDeferredError!void {
    const now_s = now_ms / 1000;
    if (route.timestamp > now_s + TIMESTAMP_SKEW or route.timestamp + TIMESTAMP_SKEW < now_s)
        return StoreDeferredError.StaleRoute;
    for (table.entries[0..table.count]) |e| {
        if (e.client_index == route.recipient_index) {
            try store.store(e.overlay_addr, route.sender_index, body, now_ms);
            return;
        }
    }
    return StoreDeferredError.UnknownRecipient;
}

pub const WriteRouteError = error{BufferTooSmall};

// writeRelayRoute (D-058): serialize a type-5 route header, byte-for-byte
// mirror of parseRelayRoute. The drain path uses it to rewrite the
// relay-layer recipient_index; the ciphertext body is never touched here.
pub fn writeRelayRoute(buf: []u8, route: RelayRoute) WriteRouteError!void {
    if (buf.len < LEN_RELAY_ROUTE) return WriteRouteError.BufferTooSmall;
    buf[0] = MSG_RELAY_ROUTE;
    buf[1] = 0;
    buf[2] = 0;
    buf[3] = 0;
    std.mem.writeInt(u32, buf[4..8], route.sender_index, .big);
    std.mem.writeInt(u32, buf[8..12], route.recipient_index, .big);
    std.mem.writeInt(u64, buf[12..20], route.timestamp, .big);
}

pub const DrainedForward = struct {
    header: [LEN_RELAY_ROUTE]u8, // rewritten route header, ready to send
    body: []const u8, // borrows engine slot storage until the next store()
};

// drainFor (BE-MESH-03, D-058): drain stored packets for a freshly
// registered recipient in storage order, rewriting each relay-layer
// recipient_index to the fresh client_index and stamping a fresh
// timestamp. Returns the number of drained packets written into `out`;
// the caller bounds the batch and forwards each packet before the next
// store() call.
pub fn drainFor(store: *relay_store.Store, overlay_addr: [LEN_OVERLAY_ADDR]u8, new_client_index: u32, now_ms: u64, out: []DrainedForward) usize {
    var n: usize = 0;
    while (n < out.len) {
        const d = store.drainNext(overlay_addr, now_ms) orelse break;
        var header: [LEN_RELAY_ROUTE]u8 = undefined;
        writeRelayRoute(&header, .{
            .sender_index = d.sender_index,
            .recipient_index = new_client_index,
            .timestamp = now_ms / 1000,
        }) catch unreachable; // fixed 20-byte buffer, provably large enough
        out[n] = .{ .header = header, .body = d.body };
        n += 1;
    }
    return n;
}
