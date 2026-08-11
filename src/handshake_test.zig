// handshake_test.zig
//
// Phase B2 binding tests (SPEC.md section 0.4): BE-SESS-02, a failed or
// refused handshake leaves zero half-session. Literal values throughout
// (D-027); the success path runs over real loopback UDP through the bound
// listener, so the socket layer is part of what is falsified. Fixture keys:
// X25519 statics from literal seeds via the bound keypairFromSecret, sig
// keys from the cert_test_helpers seed family.

const std = @import("std");
const testing = std.testing;
const noise = @import("noise.zig");
const mac = @import("mac.zig");
const listener_mod = @import("listener.zig");
const handshake_mod = @import("handshake.zig");
const cth = @import("cert_test_helpers.zig");

// Flat libc socket layer for the client side and the reply sockaddr
// (tests are outside the surface budget; same pattern as listener.zig).
extern "c" fn socket(domain: c_uint, sock_type: c_uint, protocol: c_uint) c_int;
extern "c" fn bind(fd: c_int, addr: [*]const u8, addrlen: c_uint) c_int;
extern "c" fn sendto(fd: c_int, buf: [*]const u8, len: usize, flags: c_int, dest_addr: [*]const u8, addrlen: c_uint) isize;
extern "c" fn recvfrom(fd: c_int, buf: [*]u8, len: usize, flags: c_int, src_addr: ?*anyopaque, addrlen: ?*c_uint) isize;
extern "c" fn close(fd: c_int) c_int;

const AF_INET: c_uint = 2;
const SOCK_DGRAM: c_uint = 2;
const LOOPBACK_V4 = [4]u8{ 127, 0, 0, 1 };
const PORT_SERVER: u16 = 45681;
const PORT_CLIENT: u16 = 45682;

const INIT_STATIC_SEED = [_]u8{0x11} ** 32;
const RESP_STATIC_SEED = [_]u8{0x22} ** 32;
const SIG_KEY_PREFIX: u8 = 0xD1;
const TIMESTAMP_MS: u64 = 1_700_000_000_000;

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

fn openClient() c_int {
    const fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) unreachable;
    var sa: [16]u8 = undefined;
    v4Sockaddr(LOOPBACK_V4, PORT_CLIENT, &sa);
    if (bind(fd, &sa, 16) != 0) unreachable; // fixed port: server replies here
    return fd;
}

test "BE_SESS_02 handshake success over the listener commits exactly one session" {
    const resp_static = try noise.keypairFromSecret(RESP_STATIC_SEED);
    const init_static = try noise.keypairFromSecret(INIT_STATIC_SEED);
    const sig_pub = cth.pubkeyOf(SIG_KEY_PREFIX);

    // Server: bound listener + handshake server on its socket.
    var reg = listener_mod.EndpointRegistry{};
    var server_listener = try listener_mod.Listener.open(.ipv4);
    defer server_listener.close();
    try server_listener.bind(&reg, &LOOPBACK_V4, PORT_SERVER);
    var server = handshake_mod.HandshakeServer{
        .fd = server_listener.fd,
        .responder_static = resp_static,
        .responder_sig_pubkey = sig_pub,
        .io = testing.io,
    };

    // Client: initiator builds msg1, sends it to the server endpoint.
    var initiator = noise.Initiator.init(testing.io, init_static, resp_static.public);
    var msg1: [noise.MSG1_SIZE]u8 = undefined;
    const no_cookie = [_]u8{0} ** mac.MAC_BYTES;
    try initiator.writeInitiation(&msg1, 7, TIMESTAMP_MS, sig_pub, no_cookie);
    const client = openClient();
    defer _ = close(client);
    var server_sa: [16]u8 = undefined;
    v4Sockaddr(LOOPBACK_V4, PORT_SERVER, &server_sa);
    _ = sendto(client, &msg1, msg1.len, 0, &server_sa, 16);

    // Server: recv through the bound listener, process, reply.
    var in: [512]u8 = undefined;
    const n = try server_listener.recv(&in);
    var client_sa: [16]u8 = undefined;
    v4Sockaddr(LOOPBACK_V4, PORT_CLIENT, &client_sa);
    const slot = try server.processDatagram(in[0..n], &client_sa, 16, TIMESTAMP_MS);
    try std.testing.expectEqual(@as(usize, 0), slot);

    // Client: the response arrives on the bound client port; keys must match.
    var msg2: [512]u8 = undefined;
    const got = recvfrom(client, &msg2, msg2.len, 0, null, null);
    try std.testing.expectEqual(@as(isize, noise.MSG2_SIZE), got);
    try initiator.readResponse(msg2[0..noise.MSG2_SIZE], sig_pub);
    const ir = initiator.finalize();

    try std.testing.expectEqual(@as(usize, 1), server.session_count);
    const s = server.sessions[slot];
    try std.testing.expectEqualSlices(u8, &ir.send_key, &s.recv_key);
    try std.testing.expectEqualSlices(u8, &ir.recv_key, &s.send_key);
    try std.testing.expectEqualSlices(u8, &ir.handshake_hash, &s.handshake_hash);
    try std.testing.expectEqualSlices(u8, &init_static.public, &s.peer_static);
}

test "BE_SESS_02 refused mac1 leaves zero half-session" {
    const resp_static = try noise.keypairFromSecret(RESP_STATIC_SEED);
    const init_static = try noise.keypairFromSecret(INIT_STATIC_SEED);
    const sig_pub = cth.pubkeyOf(SIG_KEY_PREFIX);
    var server = handshake_mod.HandshakeServer{
        .fd = -1, // refused before any reply is sent
        .responder_static = resp_static,
        .responder_sig_pubkey = sig_pub,
        .io = testing.io,
    };
    var initiator = noise.Initiator.init(testing.io, init_static, resp_static.public);
    var msg1: [noise.MSG1_SIZE]u8 = undefined;
    const no_cookie = [_]u8{0} ** mac.MAC_BYTES;
    try initiator.writeInitiation(&msg1, 7, TIMESTAMP_MS, sig_pub, no_cookie);
    msg1[noise.OFF1_MAC1] ^= 0xFF; // tamper mac1: refused before any DH
    var sa: [16]u8 = undefined;
    v4Sockaddr(LOOPBACK_V4, PORT_CLIENT, &sa);
    try std.testing.expectError(handshake_mod.HandshakeError.Refused, server.processDatagram(&msg1, &sa, 16, TIMESTAMP_MS));
    try std.testing.expectEqual(@as(usize, 0), server.session_count); // zero half-session
}

test "BE_SESS_02 truncated and wrong-type datagrams leave zero half-session" {
    const resp_static = try noise.keypairFromSecret(RESP_STATIC_SEED);
    const sig_pub = cth.pubkeyOf(SIG_KEY_PREFIX);
    var server = handshake_mod.HandshakeServer{
        .fd = -1,
        .responder_static = resp_static,
        .responder_sig_pubkey = sig_pub,
        .io = testing.io,
    };
    var sa: [16]u8 = undefined;
    v4Sockaddr(LOOPBACK_V4, PORT_CLIENT, &sa);
    const truncated = [_]u8{0xAB} ** 10;
    try std.testing.expectError(handshake_mod.HandshakeError.NotInitiation, server.processDatagram(&truncated, &sa, 16, TIMESTAMP_MS));
    var wrong_type = [_]u8{0xCD} ** noise.MSG1_SIZE;
    wrong_type[0] = 3; // transport packet type, not an initiation
    try std.testing.expectError(handshake_mod.HandshakeError.NotInitiation, server.processDatagram(&wrong_type, &sa, 16, TIMESTAMP_MS));
    try std.testing.expectEqual(@as(usize, 0), server.session_count); // zero half-session
}
