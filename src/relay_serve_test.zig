// relay_serve_test.zig
//
// Phase C binding tests (SPEC.md §0.4 BE-EXEC-04): relay serving on live
// traffic. Literal values throughout (D-027); the forward and drain paths
// run over real loopback UDP through the bound listener with real Noise_IK
// sessions committed by the bound handshake machinery, so the socket layer
// is part of what is falsified. Fixture keys: X25519 statics from literal
// seeds, sig keys from the cert_test_helpers seed family.

const std = @import("std");
const testing = std.testing;
const noise = @import("noise.zig");
const mac = @import("mac.zig");
const listener_mod = @import("listener.zig");
const handshake_mod = @import("handshake.zig");
const relay = @import("relay.zig");
const relay_store = @import("relay_store.zig");
const relay_serve = @import("relay_serve.zig");
const binding = @import("binding.zig");
const cth = @import("cert_test_helpers.zig");

// Flat libc socket layer for the client side (tests are outside the surface
// budget; same pattern as listener.zig and handshake_test.zig).
extern "c" fn socket(domain: c_uint, sock_type: c_uint, protocol: c_uint) c_int;
extern "c" fn bind(fd: c_int, addr: [*]const u8, addrlen: c_uint) c_int;
extern "c" fn sendto(fd: c_int, buf: [*]const u8, len: usize, flags: c_int, dest_addr: [*]const u8, addrlen: c_uint) isize;
extern "c" fn recvfrom(fd: c_int, buf: [*]u8, len: usize, flags: c_int, src_addr: ?*anyopaque, addrlen: ?*c_uint) isize;
extern "c" fn close(fd: c_int) c_int;

const AF_INET: c_uint = 2;
const SOCK_DGRAM: c_uint = 2;
const LOOPBACK_V4 = [4]u8{ 127, 0, 0, 1 };

const RESP_STATIC_SEED = [_]u8{0x33} ** 32;
const INIT_A_SEED = [_]u8{0x11} ** 32;
const INIT_B_SEED = [_]u8{0x22} ** 32;
const RELAY_SIG_PREFIX: u8 = 0xD2;
const A_SIG_PREFIX: u8 = 0xE1;
const B_SIG_PREFIX: u8 = 0xE2;
const NOW_MS: u64 = 1_700_000_000_000;
const NOW_S: u64 = NOW_MS / 1000;
const CLIENT_A_INDEX: u32 = 7;
const CLIENT_B_INDEX: u32 = 77;
const BODY_LIVE = [_]u8{0xAB} ** 32; // opaque ciphertext stand-in (BE-MESH-02)

// Identity seam hook (D-059 shape): test-level slot-to-sig-pubkey map.
var hook_slots: [2][32]u8 = undefined;
var hook_count: usize = 0;
fn testSigPubkey(slot: usize) ?[32]u8 {
    if (slot >= hook_count) return null;
    return hook_slots[slot];
}

fn v4Sockaddr(addr: [4]u8, port: u16, out: *[16]u8) void {
    out.* = .{0} ** 16;
    out[0] = 16; // macOS sa_len
    out[1] = 2; // AF_INET
    out[2] = @intCast(port >> 8);
    out[3] = @intCast(port & 0xff);
    out[4] = addr[0];
    out[5] = addr[1];
    out[6] = addr[2];
    out[7] = addr[3];
}

fn openClient(port: u16) c_int {
    const fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) unreachable;
    var sa: [16]u8 = undefined;
    v4Sockaddr(LOOPBACK_V4, port, &sa);
    if (bind(fd, &sa, 16) != 0) unreachable;
    return fd;
}

// Real Noise_IK handshake with the relay over live UDP: the client sends a
// type-1 initiation, the relay's serve-loop routes it to the handshake
// machinery, the response comes back, and the client finalizes. Returns the
// committed relay-side session slot (count before this handshake).
fn liveHandshake(serve: *relay_serve.RelayServe, client_fd: c_int, relay_port: u16, init_static: noise.X25519KeyPair) !usize {
    const slot_before = serve.sessions.session_count;
    var initiator = noise.Initiator.init(testing.io, init_static, serve.sessions.responder_static.public);
    var msg1: [noise.MSG1_SIZE]u8 = undefined;
    const no_cookie = [_]u8{0} ** mac.MAC_BYTES;
    try initiator.writeInitiation(&msg1, CLIENT_A_INDEX, NOW_MS, cth.pubkeyOf(RELAY_SIG_PREFIX), no_cookie);
    var relay_sa: [16]u8 = undefined;
    v4Sockaddr(LOOPBACK_V4, relay_port, &relay_sa);
    const want: isize = @intCast(msg1.len);
    try testing.expectEqual(want, sendto(client_fd, &msg1, msg1.len, 0, &relay_sa, 16));

    var in: [512]u8 = undefined;
    const r = serve.serveOne(&in, NOW_MS);
    try testing.expectEqual(relay_serve.ServeResult.to_handshake, try r);

    var msg2: [512]u8 = undefined;
    const got = recvfrom(client_fd, &msg2, msg2.len, 0, null, null);
    try testing.expectEqual(@as(isize, noise.MSG2_SIZE), got);
    try initiator.readResponse(msg2[0..noise.MSG2_SIZE], cth.pubkeyOf(RELAY_SIG_PREFIX));
    _ = initiator.finalize();
    try testing.expectEqual(slot_before + 1, serve.sessions.session_count);
    // D-060 ruling 2: the commit recorded the client's delivery endpoint.
    try testing.expect(serve.endpoints.get(@intCast(slot_before)) != null);
    return slot_before;
}

fn buildRegistration(out: *[relay.LEN_RELAY_REGISTRATION]u8, relay_index: u32, client_index: u32, timestamp: u64, overlay_addr: [16]u8, expiry: u64, kp: cth.Ed.KeyPair) void {
    out[0] = relay.MSG_RELAY_REGISTRATION;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    std.mem.writeInt(u32, out[4..8], relay_index, .big);
    std.mem.writeInt(u32, out[8..12], client_index, .big);
    std.mem.writeInt(u64, out[12..20], timestamp, .big);
    @memcpy(out[20..36], &overlay_addr);
    std.mem.writeInt(u64, out[36..44], expiry, .big);
    var msg: [1 + 44]u8 = undefined;
    msg[0] = relay.DOMAIN_RELAY_REGISTRATION; // BE-SIG-01 domain tag 0x07
    @memcpy(msg[1..45], out[0..44]);
    const sig = cth.Ed.KeyPair.sign(kp, &msg, null) catch unreachable;
    @memcpy(out[44..108], &cth.Ed.Signature.toBytes(sig));
    @memset(out[108..124], 0); // padding: zero on send
}

fn buildRoute(out: *[relay.LEN_RELAY_ROUTE]u8, sender_index: u32, recipient_index: u32, timestamp: u64) void {
    relay.writeRelayRoute(out, .{
        .sender_index = sender_index,
        .recipient_index = recipient_index,
        .timestamp = timestamp,
    }) catch unreachable;
}

fn serveFromFd(serve: *relay_serve.RelayServe, fd: c_int, payload: []const u8, port: u16) !void {
    var sa: [16]u8 = undefined;
    v4Sockaddr(LOOPBACK_V4, port, &sa);
    const want: isize = @intCast(payload.len);
    try testing.expectEqual(want, sendto(fd, payload.ptr, payload.len, 0, &sa, 16));
    var in: [4096]u8 = undefined;
    _ = try serve.serveOne(&in, NOW_MS);
}

test "BE_EXEC_04 classifier routes handshake types and drops everything else" {
    const resp_static = try noise.keypairFromSecret(RESP_STATIC_SEED);
    var reg = listener_mod.EndpointRegistry{};
    var l = try listener_mod.Listener.open(.ipv4);
    defer l.close();
    try l.bind(&reg, &LOOPBACK_V4, 45691);
    var hs = handshake_mod.HandshakeServer{
        .fd = l.fd,
        .responder_static = resp_static,
        .responder_sig_pubkey = cth.pubkeyOf(RELAY_SIG_PREFIX),
        .io = testing.io,
    };
    var table = relay.RelayTable.init();
    var store = relay_store.Store{};
    store.reset();
    hook_slots[0] = cth.pubkeyOf(A_SIG_PREFIX);
    hook_count = 1;
    var serve = relay_serve.RelayServe{
        .fd = l.fd,
        .sessions = &hs,
        .table = &table,
        .store = &store,
        .sig_pubkey_for_slot = testSigPubkey,
    };

    const client = openClient(45692);
    defer _ = close(client);

    // Unknown type: no service, no state change.
    const junk = [_]u8{0x99} ** 64;
    try serveFromFd(&serve, client, &junk, 45691);
    try testing.expectEqual(@as(usize, 0), hs.session_count);

    // Transport type (4) is not relay traffic: dropped.
    const transport = [_]u8{4} ++ [_]u8{0} ** 31;
    try serveFromFd(&serve, client, &transport, 45691);
    try testing.expectEqual(@as(u64, 2), serve.dropped);

    // Type 1 reaches the handshake machinery and commits.
    const init_static = try noise.keypairFromSecret(INIT_A_SEED);
    _ = try liveHandshake(&serve, client, 45691, init_static);
    try testing.expectEqual(@as(usize, 1), hs.session_count);
}

test "BE_EXEC_04 T1 forward live: registered recipient gets the body byte-for-byte" {
    const resp_static = try noise.keypairFromSecret(RESP_STATIC_SEED);
    var reg = listener_mod.EndpointRegistry{};
    var l = try listener_mod.Listener.open(.ipv4);
    defer l.close();
    try l.bind(&reg, &LOOPBACK_V4, 45694);
    var hs = handshake_mod.HandshakeServer{
        .fd = l.fd,
        .responder_static = resp_static,
        .responder_sig_pubkey = cth.pubkeyOf(RELAY_SIG_PREFIX),
        .io = testing.io,
    };
    var table = relay.RelayTable.init();
    var store = relay_store.Store{};
    store.reset();
    hook_slots[0] = cth.pubkeyOf(A_SIG_PREFIX);
    hook_slots[1] = cth.pubkeyOf(B_SIG_PREFIX);
    hook_count = 2;
    var serve = relay_serve.RelayServe{
        .fd = l.fd,
        .sessions = &hs,
        .table = &table,
        .store = &store,
        .sig_pubkey_for_slot = testSigPubkey,
    };

    // A and B establish real Noise sessions with the relay: slots 0 and 1.
    const a_fd = openClient(45695);
    defer _ = close(a_fd);
    const b_fd = openClient(45696);
    defer _ = close(b_fd);
    const slot_a = try liveHandshake(&serve, a_fd, 45694, try noise.keypairFromSecret(INIT_A_SEED));
    const slot_b = try liveHandshake(&serve, b_fd, 45694, try noise.keypairFromSecret(INIT_B_SEED));

    // B registers: signed type 6, overlay derived from B's own key.
    var reg_pkt: [relay.LEN_RELAY_REGISTRATION]u8 = undefined;
    buildRegistration(&reg_pkt, @intCast(slot_b), CLIENT_B_INDEX, NOW_S, binding.deriveOverlayAddr(&cth.pubkeyOf(B_SIG_PREFIX)), NOW_S + 3600, cth.keypair(B_SIG_PREFIX));
    try serveFromFd(&serve, b_fd, &reg_pkt, 45694);
    try testing.expectEqual(@as(usize, 1), table.count);

    // A forwards to B: live delivery, body unchanged.
    var pkt: [relay.LEN_RELAY_ROUTE + BODY_LIVE.len]u8 = undefined;
    buildRoute(pkt[0..relay.LEN_RELAY_ROUTE], @intCast(slot_a), CLIENT_B_INDEX, NOW_S);
    @memcpy(pkt[relay.LEN_RELAY_ROUTE..], &BODY_LIVE);
    try serveFromFd(&serve, a_fd, &pkt, 45694);
    try testing.expectEqual(@as(u64, 1), serve.forwarded);

    var got: [512]u8 = undefined;
    const n = recvfrom(b_fd, &got, got.len, 0, null, null);
    try testing.expectEqual(@as(isize, pkt.len), n);
    try testing.expectEqualSlices(u8, pkt[0..], got[0..pkt.len]); // byte-for-byte
}

test "BE_EXEC_04 sender gate: no established session, no service" {
    const resp_static = try noise.keypairFromSecret(RESP_STATIC_SEED);
    var reg = listener_mod.EndpointRegistry{};
    var l = try listener_mod.Listener.open(.ipv4);
    defer l.close();
    try l.bind(&reg, &LOOPBACK_V4, 45697);
    var hs = handshake_mod.HandshakeServer{
        .fd = l.fd,
        .responder_static = resp_static,
        .responder_sig_pubkey = cth.pubkeyOf(RELAY_SIG_PREFIX),
        .io = testing.io,
    };
    var table = relay.RelayTable.init();
    _ = table.insert(.{ .overlay_addr = binding.deriveOverlayAddr(&cth.pubkeyOf(B_SIG_PREFIX)), .relay_index = 0, .client_index = CLIENT_B_INDEX, .expiry = NOW_S + 3600 });
    var store = relay_store.Store{};
    store.reset();
    hook_count = 0;
    var serve = relay_serve.RelayServe{
        .fd = l.fd,
        .sessions = &hs,
        .table = &table,
        .store = &store,
        .sig_pubkey_for_slot = testSigPubkey,
    };

    // Zero sessions: every sender_index fails the gate.
    const a_fd = openClient(45698);
    defer _ = close(a_fd);
    var pkt: [relay.LEN_RELAY_ROUTE + 8]u8 = undefined;
    buildRoute(pkt[0..relay.LEN_RELAY_ROUTE], 0, CLIENT_B_INDEX, NOW_S);
    @memcpy(pkt[relay.LEN_RELAY_ROUTE..], &[_]u8{0xCD} ** 8);
    try serveFromFd(&serve, a_fd, &pkt, 45697);
    try testing.expectEqual(@as(u64, 1), serve.dropped);
    try testing.expectEqual(@as(u64, 0), serve.forwarded);

    // Unknown recipient with a session held: no service, nothing stored.
    _ = try liveHandshake(&serve, a_fd, 45697, try noise.keypairFromSecret(INIT_A_SEED));
    buildRoute(pkt[0..relay.LEN_RELAY_ROUTE], 0, 12345, NOW_S);
    try serveFromFd(&serve, a_fd, &pkt, 45697);
    try testing.expectEqual(@as(usize, 0), store.count);
    try testing.expectEqual(@as(u64, 0), serve.stored_count);

    // Stale route (past the 300s skew): dropped by the engine.
    buildRoute(pkt[0..relay.LEN_RELAY_ROUTE], 0, CLIENT_B_INDEX, NOW_S - 301);
    try serveFromFd(&serve, a_fd, &pkt, 45697);
    try testing.expectEqual(@as(u64, 0), serve.forwarded);
}

test "BE_EXEC_04 T2 store then drain: late registration drains in order with rewritten index" {
    const resp_static = try noise.keypairFromSecret(RESP_STATIC_SEED);
    var reg = listener_mod.EndpointRegistry{};
    var l = try listener_mod.Listener.open(.ipv4);
    defer l.close();
    try l.bind(&reg, &LOOPBACK_V4, 45700);
    var hs = handshake_mod.HandshakeServer{
        .fd = l.fd,
        .responder_static = resp_static,
        .responder_sig_pubkey = cth.pubkeyOf(RELAY_SIG_PREFIX),
        .io = testing.io,
    };
    var table = relay.RelayTable.init();
    var store = relay_store.Store{};
    store.reset();
    hook_slots[0] = cth.pubkeyOf(A_SIG_PREFIX);
    hook_slots[1] = cth.pubkeyOf(B_SIG_PREFIX);
    hook_count = 2;
    var serve = relay_serve.RelayServe{
        .fd = l.fd,
        .sessions = &hs,
        .table = &table,
        .store = &store,
        .sig_pubkey_for_slot = testSigPubkey,
    };

    const a_fd = openClient(45701);
    defer _ = close(a_fd);
    const b_fd = openClient(45702);
    defer _ = close(b_fd);
    const slot_a = try liveHandshake(&serve, a_fd, 45700, try noise.keypairFromSecret(INIT_A_SEED));
    const slot_b = try liveHandshake(&serve, b_fd, 45700, try noise.keypairFromSecret(INIT_B_SEED));

    // B registers, then goes offline: the endpoint dies, the entry survives.
    var reg_pkt: [relay.LEN_RELAY_REGISTRATION]u8 = undefined;
    buildRegistration(&reg_pkt, @intCast(slot_b), CLIENT_B_INDEX, NOW_S, binding.deriveOverlayAddr(&cth.pubkeyOf(B_SIG_PREFIX)), NOW_S + 3600, cth.keypair(B_SIG_PREFIX));
    try serveFromFd(&serve, b_fd, &reg_pkt, 45700);
    serve.endpoints.remove(CLIENT_B_INDEX);

    // Two forwards while B is offline: both stored, in order.
    const BODY_ONE = [_]u8{0x11} ** 24;
    const BODY_TWO = [_]u8{0x22} ** 24;
    var pkt: [relay.LEN_RELAY_ROUTE + 24]u8 = undefined;
    buildRoute(pkt[0..relay.LEN_RELAY_ROUTE], @intCast(slot_a), CLIENT_B_INDEX, NOW_S);
    @memcpy(pkt[relay.LEN_RELAY_ROUTE..], &BODY_ONE);
    try serveFromFd(&serve, a_fd, &pkt, 45700);
    buildRoute(pkt[0..relay.LEN_RELAY_ROUTE], @intCast(slot_a), CLIENT_B_INDEX, NOW_S + 1);
    @memcpy(pkt[relay.LEN_RELAY_ROUTE..], &BODY_TWO);
    try serveFromFd(&serve, a_fd, &pkt, 45700);
    try testing.expectEqual(@as(u64, 2), serve.stored_count);
    try testing.expectEqual(@as(usize, 2), store.count);

    // B re-registers (fresh session semantics: fresh client_index): the
    // queue drains to the new endpoint with the relay-layer index rewritten.
    const CLIENT_B_FRESH: u32 = 88;
    buildRegistration(&reg_pkt, @intCast(slot_b), CLIENT_B_FRESH, NOW_S + 2, binding.deriveOverlayAddr(&cth.pubkeyOf(B_SIG_PREFIX)), NOW_S + 3600, cth.keypair(B_SIG_PREFIX));
    try serveFromFd(&serve, b_fd, &reg_pkt, 45700);
    try testing.expectEqual(@as(u64, 2), serve.drained);
    try testing.expectEqual(@as(usize, 0), store.count);

    var got: [512]u8 = undefined;
    var n = recvfrom(b_fd, &got, got.len, 0, null, null);
    try testing.expectEqual(@as(isize, relay.LEN_RELAY_ROUTE + 24), n);
    try testing.expectEqual(@as(u8, 5), got[0]);
    try testing.expectEqual(CLIENT_B_FRESH, std.mem.readInt(u32, got[8..12], .big)); // rewritten
    try testing.expectEqualSlices(u8, &BODY_ONE, got[relay.LEN_RELAY_ROUTE .. relay.LEN_RELAY_ROUTE + 24]); // body unchanged
    n = recvfrom(b_fd, &got, got.len, 0, null, null);
    try testing.expectEqual(@as(isize, relay.LEN_RELAY_ROUTE + 24), n);
    try testing.expectEqual(CLIENT_B_FRESH, std.mem.readInt(u32, got[8..12], .big));
    try testing.expectEqualSlices(u8, &BODY_TWO, got[relay.LEN_RELAY_ROUTE .. relay.LEN_RELAY_ROUTE + 24]); // store order
}

test "BE_EXEC_04 T3 bounds: quota drop at 65, expiry pruned at registration" {
    const resp_static = try noise.keypairFromSecret(RESP_STATIC_SEED);
    var reg = listener_mod.EndpointRegistry{};
    var l = try listener_mod.Listener.open(.ipv4);
    defer l.close();
    try l.bind(&reg, &LOOPBACK_V4, 45703);
    var hs = handshake_mod.HandshakeServer{
        .fd = l.fd,
        .responder_static = resp_static,
        .responder_sig_pubkey = cth.pubkeyOf(RELAY_SIG_PREFIX),
        .io = testing.io,
    };
    var table = relay.RelayTable.init();
    var store = relay_store.Store{};
    store.reset();
    hook_slots[0] = cth.pubkeyOf(A_SIG_PREFIX);
    hook_slots[1] = cth.pubkeyOf(B_SIG_PREFIX);
    hook_count = 2;
    var serve = relay_serve.RelayServe{
        .fd = l.fd,
        .sessions = &hs,
        .table = &table,
        .store = &store,
        .sig_pubkey_for_slot = testSigPubkey,
    };

    const a_fd = openClient(45704);
    defer _ = close(a_fd);
    const b_fd = openClient(45705);
    defer _ = close(b_fd);
    const slot_a = try liveHandshake(&serve, a_fd, 45703, try noise.keypairFromSecret(INIT_A_SEED));
    const slot_b = try liveHandshake(&serve, b_fd, 45703, try noise.keypairFromSecret(INIT_B_SEED));

    var reg_pkt: [relay.LEN_RELAY_REGISTRATION]u8 = undefined;
    buildRegistration(&reg_pkt, @intCast(slot_b), CLIENT_B_INDEX, NOW_S, binding.deriveOverlayAddr(&cth.pubkeyOf(B_SIG_PREFIX)), NOW_S + 3600, cth.keypair(B_SIG_PREFIX));
    try serveFromFd(&serve, b_fd, &reg_pkt, 45703);
    serve.endpoints.remove(CLIENT_B_INDEX);

    // 64 stores fill the quota; the 65th is refused and counted.
    var pkt: [relay.LEN_RELAY_ROUTE + 16]u8 = undefined;
    @memcpy(pkt[relay.LEN_RELAY_ROUTE..], &[_]u8{0xEE} ** 16);
    var i: usize = 0;
    while (i < relay_store.MAX_PER_RECIPIENT) : (i += 1) {
        buildRoute(pkt[0..relay.LEN_RELAY_ROUTE], @intCast(slot_a), CLIENT_B_INDEX, NOW_S);
        try serveFromFd(&serve, a_fd, &pkt, 45703);
    }
    try testing.expectEqual(@as(u64, 64), serve.stored_count);
    buildRoute(pkt[0..relay.LEN_RELAY_ROUTE], @intCast(slot_a), CLIENT_B_INDEX, NOW_S);
    try serveFromFd(&serve, a_fd, &pkt, 45703);
    try testing.expectEqual(@as(usize, 64), store.count);
    try testing.expectEqual(@as(u64, 1), store.refused_quota);
    try testing.expectEqual(@as(u64, 1), serve.dropped);
}

test "BE_EXEC_04 registration gates: signature, overlay, relay_index, skew, table bound" {
    const resp_static = try noise.keypairFromSecret(RESP_STATIC_SEED);
    var reg = listener_mod.EndpointRegistry{};
    var l = try listener_mod.Listener.open(.ipv4);
    defer l.close();
    try l.bind(&reg, &LOOPBACK_V4, 45706);
    var hs = handshake_mod.HandshakeServer{
        .fd = l.fd,
        .responder_static = resp_static,
        .responder_sig_pubkey = cth.pubkeyOf(RELAY_SIG_PREFIX),
        .io = testing.io,
    };
    var table = relay.RelayTable.init();
    var store = relay_store.Store{};
    store.reset();
    hook_slots[0] = cth.pubkeyOf(B_SIG_PREFIX);
    hook_count = 1;
    var serve = relay_serve.RelayServe{
        .fd = l.fd,
        .sessions = &hs,
        .table = &table,
        .store = &store,
        .sig_pubkey_for_slot = testSigPubkey,
    };
    const b_fd = openClient(45707);
    defer _ = close(b_fd);
    const slot_b = try liveHandshake(&serve, b_fd, 45706, try noise.keypairFromSecret(INIT_B_SEED));
    const overlay_b = binding.deriveOverlayAddr(&cth.pubkeyOf(B_SIG_PREFIX));

    var reg_pkt: [relay.LEN_RELAY_REGISTRATION]u8 = undefined;

    // Corrupted signature: refused.
    buildRegistration(&reg_pkt, @intCast(slot_b), CLIENT_B_INDEX, NOW_S, overlay_b, NOW_S + 3600, cth.keypair(B_SIG_PREFIX));
    reg_pkt[44] ^= 0xFF;
    try serveFromFd(&serve, b_fd, &reg_pkt, 45706);
    try testing.expectEqual(@as(usize, 0), table.count);

    // Overlay asserted for a different key: refused (BE-ID-01).
    buildRegistration(&reg_pkt, @intCast(slot_b), CLIENT_B_INDEX, NOW_S, binding.deriveOverlayAddr(&cth.pubkeyOf(A_SIG_PREFIX)), NOW_S + 3600, cth.keypair(B_SIG_PREFIX));
    try serveFromFd(&serve, b_fd, &reg_pkt, 45706);
    try testing.expectEqual(@as(usize, 0), table.count);

    // Unknown relay_index: refused.
    buildRegistration(&reg_pkt, 99, CLIENT_B_INDEX, NOW_S, overlay_b, NOW_S + 3600, cth.keypair(B_SIG_PREFIX));
    try serveFromFd(&serve, b_fd, &reg_pkt, 45706);
    try testing.expectEqual(@as(usize, 0), table.count);

    // Timestamp past the skew bound: refused.
    buildRegistration(&reg_pkt, @intCast(slot_b), CLIENT_B_INDEX, NOW_S - 301, overlay_b, NOW_S + 3600, cth.keypair(B_SIG_PREFIX));
    try serveFromFd(&serve, b_fd, &reg_pkt, 45706);
    try testing.expectEqual(@as(usize, 0), table.count);

    // Expiry beyond the 24h client cap: refused.
    buildRegistration(&reg_pkt, @intCast(slot_b), CLIENT_B_INDEX, NOW_S, overlay_b, NOW_S + relay.MAX_EXPIRY + 1, cth.keypair(B_SIG_PREFIX));
    try serveFromFd(&serve, b_fd, &reg_pkt, 45706);
    try testing.expectEqual(@as(usize, 0), table.count);

    // Table bound: a full table refuses new registrations (BE-MESH-04).
    while (table.count < relay.MAX_RELAY_TABLE) {
        _ = table.insert(.{ .overlay_addr = overlay_b, .relay_index = 0, .client_index = @intCast(table.count), .expiry = NOW_S + 3600 });
    }
    buildRegistration(&reg_pkt, @intCast(slot_b), CLIENT_B_INDEX, NOW_S, overlay_b, NOW_S + 3600, cth.keypair(B_SIG_PREFIX));
    try serveFromFd(&serve, b_fd, &reg_pkt, 45706);
    try testing.expectEqual(relay.MAX_RELAY_TABLE, table.count);

    // Expired entries are pruned before a new registration (BE-MESH-05).
    table.count = 0;
    _ = table.insert(.{ .overlay_addr = overlay_b, .relay_index = 0, .client_index = 5, .expiry = NOW_S - 1 }); // expired
    buildRegistration(&reg_pkt, @intCast(slot_b), CLIENT_B_INDEX, NOW_S, overlay_b, NOW_S + 3600, cth.keypair(B_SIG_PREFIX));
    try serveFromFd(&serve, b_fd, &reg_pkt, 45706);
    try testing.expectEqual(@as(usize, 1), table.count);
    try testing.expectEqual(CLIENT_B_INDEX, table.entries[0].client_index); // the expired entry was pruned, the fresh one inserted
}
