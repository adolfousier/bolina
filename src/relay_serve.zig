// relay_serve.zig
//
// Phase C serve-loop glue (SPEC §0.4 BE-EXEC-04, §5.2a decision table,
// D-060). Non-surface per the BE-SURF-03 placement (D-060): daemon wiring
// over parsed values, not reached by attacker bytes directly. The
// fixed-size pre-auth parsing stays in relay.zig (relay sub-unit); this
// module classifies, gates, and routes. It holds no key material
// (BE-MESH-02): ciphertext bodies pass byte-for-byte.
//
// D-060 ruling 2: the serve-loop owns the index-to-endpoint map.
// session.zig carries indexes and keys but no endpoint, and the listener
// sub-unit (246/250, frozen cap) discards the source address on recv and
// has no room for a capturing variant. Flat libc externs follow the
// handshake.zig precedent (Zig 0.16 moved std networking behind std.Io).

const std = @import("std");
const relay = @import("relay.zig");
const relay_store = @import("relay_store.zig");
const handshake = @import("handshake.zig");
const binding = @import("binding.zig");
const verify = @import("verify.zig");

extern "c" fn recvfrom(fd: c_int, buf: [*]u8, len: usize, flags: c_int, src_addr: ?*anyopaque, addrlen: ?*c_uint) isize;
extern "c" fn sendto(fd: c_int, buf: [*]const u8, len: usize, flags: c_int, dest_addr: [*]const u8, addrlen: c_uint) isize;

pub const MAX_SA_LEN: c_uint = 28;
pub const MAX_ENDPOINTS: usize = 128;
// D-060 ruling 3: the drain batch IS the quota. Registrations are one-shot
// per session, so the accepted registration is the only event that can
// trigger the drain; the per-recipient packet quota bounds the batch.
pub const MAX_DRAIN_BATCH: usize = relay_store.MAX_PER_RECIPIENT;

pub const Endpoint = struct {
    index: u32 = 0,
    sa: [MAX_SA_LEN]u8 = undefined,
    sa_len: c_uint = 0,
};

// Index-to-endpoint map (D-060 ruling 2). Populated at exactly two points:
// session commit during handshake, and accepted type-6 registration. A
// re-mapping replaces the endpoint in place (a fresh session re-points the
// delivery address for its index).
pub const EndpointMap = struct {
    entries: [MAX_ENDPOINTS]Endpoint = [_]Endpoint{.{}} ** MAX_ENDPOINTS,
    count: usize = 0,

    pub fn put(self: *EndpointMap, index: u32, sa: [*]const u8, sa_len: c_uint) bool {
        for (self.entries[0..self.count]) |*e| {
            if (e.index == index) {
                @memcpy(e.sa[0..sa_len], sa[0..sa_len]);
                e.sa_len = sa_len;
                return true;
            }
        }
        if (self.count >= MAX_ENDPOINTS) return false;
        const e = &self.entries[self.count];
        e.index = index;
        @memcpy(e.sa[0..sa_len], sa[0..sa_len]);
        e.sa_len = sa_len;
        self.count += 1;
        return true;
    }

    pub fn get(self: *const EndpointMap, index: u32) ?Endpoint {
        for (self.entries[0..self.count]) |e| {
            if (e.index == index) return e;
        }
        return null;
    }

    // Session release drops the delivery endpoint; the registration entry
    // survives until expiry, so later forwards store instead of delivering.
    pub fn remove(self: *EndpointMap, index: u32) void {
        var i: usize = 0;
        while (i < self.count) {
            if (self.entries[i].index == index) {
                self.count -= 1;
                self.entries[i] = self.entries[self.count];
                return;
            }
            i += 1;
        }
    }
};

pub const ServeResult = enum {
    to_handshake, // types 1-3 handed to the handshake machinery
    forwarded, // type 5 live delivery
    stored, // type 5 deferred: registration known, endpoint unknown
    registered, // type 6 accepted, nothing stored to drain
    drained, // type 6 accepted and the stored queue drained
    dropped, // no service: unknown type, parse failure, failed gate
};

pub const RecvError = error{RecvFailed};

pub const RelayServe = struct {
    fd: c_int,
    sessions: *handshake.HandshakeServer,
    table: *relay.RelayTable,
    store: *relay_store.Store,
    endpoints: EndpointMap = .{},
    forwarded: u64 = 0,
    stored_count: u64 = 0,
    drained: u64 = 0,
    dropped: u64 = 0,
    // Identity seam (D-059 shape): the daemon supplies the client sig_pubkey
    // for a committed session slot; the handshake table holds X25519 statics
    // only. Returning null refuses the registration.
    sig_pubkey_for_slot: *const fn (slot: usize) ?[32]u8,

    // One serve step: recv a datagram capturing the source address, then
    // serve it. The caller owns the buffer and the clock (house pattern).
    pub fn serveOne(self: *RelayServe, buf: []u8, now_ms: u64) RecvError!ServeResult {
        var src_sa: [MAX_SA_LEN]u8 = undefined;
        var src_len: c_uint = MAX_SA_LEN;
        const n = recvfrom(self.fd, buf.ptr, buf.len, 0, &src_sa, &src_len);
        if (n < 0) return error.RecvFailed;
        return self.serveDatagram(buf[0..@intCast(n)], &src_sa, src_len, now_ms);
    }

    // Classifier (BE-EXEC-04): the leading type byte routes the datagram;
    // any other value is dropped with no service.
    pub fn serveDatagram(self: *RelayServe, dgram: []const u8, src_sa: [*]const u8, src_sa_len: c_uint, now_ms: u64) ServeResult {
        if (dgram.len == 0) return self.drop();
        return switch (dgram[0]) {
            1, 2, 3 => self.serveHandshake(dgram, src_sa, src_sa_len, now_ms),
            relay.MSG_RELAY_ROUTE => self.serveRoute(dgram, now_ms),
            relay.MSG_RELAY_REGISTRATION => self.serveRegistration(dgram, src_sa, src_sa_len, now_ms),
            else => self.drop(),
        };
    }

    fn serveHandshake(self: *RelayServe, dgram: []const u8, src_sa: [*]const u8, src_sa_len: c_uint, now_ms: u64) ServeResult {
        const slot = self.sessions.processDatagram(dgram, src_sa, src_sa_len, now_ms) catch return self.drop();
        // D-060 ruling 2: the datagram that commits the session names the
        // peer's delivery endpoint for the session slot.
        _ = self.endpoints.put(@intCast(slot), src_sa, src_sa_len);
        return .to_handshake;
    }

    // Type 5 (BE-EXEC-04, §5.2a decision table): parse on the raw datagram,
    // gate on the sender session, then split on endpoint knowledge.
    fn serveRoute(self: *RelayServe, dgram: []const u8, now_ms: u64) ServeResult {
        if (dgram.len < relay.LEN_RELAY_ROUTE) return self.drop();
        const route = relay.parseRelayRoute(dgram[0..relay.LEN_RELAY_ROUTE]) catch return self.drop();
        // §5.2a, D-060 ruling 1: the forwarding node MUST hold an
        // established session at the relay. B2 slots are contiguous from
        // zero, so the session count is the gate (revisit when phase D adds
        // session release).
        if (route.sender_index >= self.sessions.session_count) return self.drop();
        // The engine is the tested authority for skew and recipient
        // existence: StaleRoute and UnknownRecipient both get no service
        // (BE-MESH-04 extended to storage by D-058).
        _ = relay.forwardPacket(self.table, route, dgram, now_ms / 1000) catch return self.drop();
        if (self.endpoints.get(route.recipient_index)) |ep| {
            const want: isize = @intCast(dgram.len);
            if (sendto(self.fd, dgram.ptr, dgram.len, 0, &ep.sa, ep.sa_len) != want) return self.drop();
            self.forwarded += 1;
            return .forwarded;
        }
        // Registration known, endpoint unknown: deferred storage. The body
        // is the opaque ciphertext past the fixed header (BE-MESH-02).
        relay.storeDeferred(self.table, self.store, route, dgram[relay.LEN_RELAY_ROUTE..], now_ms) catch return self.drop();
        self.stored_count += 1;
        return .stored;
    }

    // Type 6 (BE-EXEC-04): signature and identity gates, prune-before-insert
    // (BE-MESH-05), bounded table (BE-MESH-04), then the quota-bounded drain
    // (D-060 ruling 3).
    fn serveRegistration(self: *RelayServe, dgram: []const u8, src_sa: [*]const u8, src_sa_len: c_uint, now_ms: u64) ServeResult {
        if (dgram.len != relay.LEN_RELAY_REGISTRATION) return self.drop();
        const reg = relay.parseRelayRegistration(dgram) catch return self.drop();
        const now_s = now_ms / 1000;
        if (reg.relay_index >= self.sessions.session_count) return self.drop();
        if (reg.timestamp > now_s + relay.TIMESTAMP_SKEW or reg.timestamp + relay.TIMESTAMP_SKEW < now_s) return self.drop();
        if (reg.expiry > now_s + relay.MAX_EXPIRY) return self.drop();
        const sig_pub = self.sig_pubkey_for_slot(reg.relay_index) orelse return self.drop();
        // BE-ID-01: the overlay address is the commitment to the client's
        // own key; an asserted address that does not match is refused.
        const derived = binding.deriveOverlayAddr(&sig_pub);
        if (!std.mem.eql(u8, reg.overlay_addr, &derived)) return self.drop();
        // BE-SIG-01, domain tag 0x07.
        verify.verifySigned(relay.DOMAIN_RELAY_REGISTRATION, reg.tbs, reg.sig, &sig_pub) catch return self.drop();
        self.table.prune(now_s);
        if (!self.table.insert(.{
            .overlay_addr = derived,
            .relay_index = reg.relay_index,
            .client_index = reg.client_index,
            .expiry = reg.expiry,
        })) return self.drop();
        // D-060 ruling 2: the registration's source address is the client's
        // delivery endpoint. Without it the drain cannot deliver, and a
        // one-shot registration will not come again: leave the queue stored.
        if (!self.endpoints.put(reg.client_index, src_sa, src_sa_len)) return .registered;
        var out: [MAX_DRAIN_BATCH]relay.DrainedForward = undefined;
        const n = relay.drainFor(self.store, derived, reg.client_index, now_ms, &out);
        if (n == 0) return .registered;
        const ep = self.endpoints.get(reg.client_index) orelse return .registered;
        var pkt: [relay.LEN_RELAY_ROUTE + relay_store.MAX_BODY]u8 = undefined;
        for (out[0..n]) |d| {
            const total = relay.LEN_RELAY_ROUTE + d.body.len;
            @memcpy(pkt[0..relay.LEN_RELAY_ROUTE], &d.header);
            @memcpy(pkt[relay.LEN_RELAY_ROUTE..total], d.body);
            _ = sendto(self.fd, &pkt, total, 0, &ep.sa, ep.sa_len);
        }
        self.drained += n;
        return .drained;
    }

    fn drop(self: *RelayServe) ServeResult {
        self.dropped += 1;
        return .dropped;
    }
};
