// pilot_test.zig
//
// D-089 section 5: the conformance pilot. Two nodes over a real UDP loopback
// (no mocked transport), a test CA minted in-process, and node certs carrying
// each side's REAL key material (the shared test helper hardcodes its kex, so
// this file builds its own certs - F1 compares cert kex against the Noise
// static, which is exactly what must be real here).
//
// The happy path is exercised end to end: handshake (Noise_IK over the wire)
// -> binding frames BOTH directions inside the encrypted session (BE-TR-01)
// -> Intent admitted by the resolver -> Grant signed by an approver on its
// own session -> verifyGrantThen with the durable ledger commit -> effect
// fired through the daemon's hook seam -> restart -> the refused-effect grant
// comes back as exactly one orphan (BE-GRANT-01a at-least-once).
//
// Negatives ride the same wire: a cert whose kex does not match the handshake
// static never binds (F1) and its envelopes stay gated; a replayed Intent
// packet dies in the session replay window. Every drop is counted, none is
// reflected.

const std = @import("std");
const testing = std.testing;
const listener = @import("listener.zig");
const handshake = @import("handshake.zig");
const noise = @import("noise.zig");
const session = @import("session.zig");
const parser = @import("parser.zig");
const channel = @import("parser/channel.zig");
const cert_parser = @import("parser/session.zig");
const resolver_mod = @import("resolver.zig");
const binding = @import("binding.zig");
const dispatch_mod = @import("dispatch.zig");
const keys_mod = @import("keys.zig");
const grant_ledger_mod = @import("grant_ledger.zig");
const daemon_mod = @import("daemon.zig");
const cth = @import("cert_test_helpers.zig");

const Ed = std.crypto.sign.Ed25519;
const Blake2s256 = std.crypto.hash.blake2.Blake2s256;

extern "c" fn sendto(fd: c_int, buf: [*]const u8, len: usize, flags: c_int, dest_addr: [*]const u8, addrlen: c_uint) isize;

const LOOPBACK = [4]u8{ 127, 0, 0, 1 };
const PORT_NODE_B: u16 = 47881;
const PORT_CLIENT: u16 = 47882;
const NOW_MS: u64 = 1000;
const MAX_DGRAM: usize = 2048;

const IID_A = [16]u8{ 'p', 'i', 'l', 'o', 't', 'I', 'n', 't', 'A', '0', '0', '0', '1', 0, 0, 0 };
const IID_B = [16]u8{ 'p', 'i', 'l', 'o', 't', 'I', 'n', 't', 'A', '0', '0', '0', '2', 0, 0, 0 };
const GID_A = [16]u8{ 'p', 'i', 'l', 'o', 't', 'G', 'r', 'n', 'A', '0', '0', '0', '1', 0, 0, 0 };
const GID_B = [16]u8{ 'p', 'i', 'l', 'o', 't', 'G', 'r', 'n', 'A', '0', '0', '0', '2', 0, 0, 0 };

const chan_id: [channel.LEN_CHANNEL_ID]u8 = blk: {
    var c: [channel.LEN_CHANNEL_ID]u8 = .{0} ** channel.LEN_CHANNEL_ID;
    const tag = "bolina-pilot";
    @memcpy(c[0..tag.len], tag);
    break :blk c;
};

var recorder_fired: usize = 0;
fn recordingEffect(g: channel.Grant) @import("verify.zig").EffectOutcome {
    _ = g;
    recorder_fired += 1;
    return .fired;
}

// ---------------------------------------------------------------------------
// Identity minting: one Ed25519 (signing identity) + one X25519 (Noise
// static) per party, and a cert that carries both for real.
// ---------------------------------------------------------------------------

const Identity = struct {
    ed_kp: Ed.KeyPair,
    x_kp: noise.X25519KeyPair,
    cert_buf: [keys_mod.MAX_CERT]u8,
    cert_len: usize,
};

// buildNodeCert: cth.buildCertInto's layout with the caller's REAL kex pubkey
// (the helper hardcodes seedFrom(0x4b); F1 makes that byte region load-bearing).
// CAs are sorted strictly ascending by pubkey (parseCert rejects otherwise);
// the approver rides two CAs for BE-ID-04 quorum.
fn buildNodeCert(wire: []u8, sig_pub: [32]u8, kex_pub: [32]u8, role_bits: u8, cas: []const Ed.KeyPair) usize {
    var kps: [4]Ed.KeyPair = undefined;
    var pubs: [4][32]u8 = undefined;
    for (cas, 0..) |ca, i| {
        kps[i] = ca;
        pubs[i] = Ed.PublicKey.toBytes(ca.public_key);
    }
    var a: usize = 0;
    while (a < cas.len) : (a += 1) {
        var b_i: usize = a + 1;
        while (b_i < cas.len) : (b_i += 1) {
            if (std.mem.order(u8, &pubs[b_i], &pubs[a]) == .lt) {
                const tk = kps[a];
                kps[a] = kps[b_i];
                kps[b_i] = tk;
                const tp = pubs[a];
                pubs[a] = pubs[b_i];
                pubs[b_i] = tp;
            }
        }
    }
    var n: usize = 0;
    wire[n] = 2; // version (SPEC 2.2)
    n += 1;
    wire[n] = role_bits;
    n += 1;
    @memcpy(wire[n..][0..32], &sig_pub);
    n += 32;
    @memcpy(wire[n..][0..32], &kex_pub);
    n += 32;
    std.mem.writeInt(u64, wire[n..][0..8], NOW_MS - 5, .big); // not_before
    n += 8;
    std.mem.writeInt(u64, wire[n..][0..8], NOW_MS + 1_296_000_000, .big); // not_after: 15d, half the BE-REV-01 30d cap
    n += 8;
    wire[n] = 0;
    wire[n + 1] = 0; // name_len 0
    n += 2;
    wire[n] = 0; // scope_count 0
    n += 1;
    const tbs_len = n;
    wire[n] = @intCast(cas.len);
    n += 1;
    var msg: [1 + keys_mod.MAX_CERT]u8 = undefined;
    msg[0] = binding.DOMAIN_CERT;
    @memcpy(msg[1..][0..tbs_len], wire[0..tbs_len]);
    for (0..cas.len) |i| {
        @memcpy(wire[n..][0..32], &pubs[i]);
        n += 32;
        const sig = Ed.KeyPair.sign(kps[i], msg[0 .. 1 + tbs_len], null) catch unreachable;
        @memcpy(wire[n..][0..64], &Ed.Signature.toBytes(sig));
        n += 64;
    }
    return n;
}

fn mintIdentity(ed_prefix: u8, x_prefix: u8, role_bits: u8, cas: []const Ed.KeyPair) Identity {
    var id: Identity = undefined;
    id.ed_kp = cth.keypair(ed_prefix);
    id.x_kp = noise.keypairFromSecret(cth.seedFrom(x_prefix)) catch unreachable;
    const sig_pub = Ed.PublicKey.toBytes(id.ed_kp.public_key);
    id.cert_len = buildNodeCert(&id.cert_buf, sig_pub, id.x_kp.public, role_bits, cas);
    _ = cert_parser.parseCert(id.cert_buf[0..id.cert_len]) catch unreachable;
    return id;
}

fn pubOf(id: *const Identity) [32]u8 {
    return Ed.PublicKey.toBytes(id.ed_kp.public_key);
}

// ---------------------------------------------------------------------------
// Wire builders (envelope SPEC 6.x, grant SPEC 8.1 - house big-endian rule).
// ---------------------------------------------------------------------------

fn sealEnvelope(out: []u8, id: *const Identity, seq: u64, ts: u64, body_type: u8, body: []const u8) usize {
    var n: usize = 0;
    out[n] = 2; // version
    n += 1;
    @memcpy(out[n..][0..32], &chan_id);
    n += 32;
    const sender = pubOf(id);
    @memcpy(out[n..][0..32], &sender);
    n += 32;
    std.mem.writeInt(u64, out[n..][0..8], seq, .big);
    n += 8;
    out[n] = 0; // parent_count
    n += 1;
    std.mem.writeInt(u64, out[n..][0..8], ts, .big);
    n += 8;
    out[n] = body_type;
    n += 1;
    std.mem.writeInt(u32, out[n..][0..4], @intCast(body.len), .big);
    n += 4;
    @memcpy(out[n..][0..body.len], body);
    n += body.len;
    var msg: [1 + 1024]u8 = undefined;
    msg[0] = channel.DOMAIN_ENVELOPE;
    @memcpy(msg[1..][0..n], out[0..n]);
    const sig = Ed.KeyPair.sign(id.ed_kp, msg[0 .. 1 + n], null) catch unreachable;
    @memcpy(out[n..][0..64], &Ed.Signature.toBytes(sig));
    n += 64;
    return n;
}

fn buildGrantBody(out: []u8, grant_id: [16]u8, intent_id: [16]u8, approver: *const Identity, subject: [32]u8, executor: [32]u8, resource: []const u8, action: []const u8, not_after: u64) usize {
    var digest: [32]u8 = undefined;
    Blake2s256.hash(action, &digest, .{}); // BE-GRANT-02 check 9
    var n: usize = 0;
    out[n] = 2; // version
    n += 1;
    @memcpy(out[n..][0..16], &grant_id);
    n += 16;
    @memcpy(out[n..][0..16], &intent_id);
    n += 16;
    const approver_pub = pubOf(approver);
    @memcpy(out[n..][0..32], &approver_pub);
    n += 32;
    @memcpy(out[n..][0..32], &subject);
    n += 32;
    @memcpy(out[n..][0..32], &executor);
    n += 32;
    std.mem.writeInt(u16, out[n..][0..2], @intCast(resource.len), .big);
    n += 2;
    @memcpy(out[n..][0..resource.len], resource);
    n += resource.len;
    @memcpy(out[n..][0..32], &digest);
    n += 32;
    std.mem.writeInt(u64, out[n..][0..8], not_after, .big);
    n += 8;
    var msg: [1 + 512]u8 = undefined;
    msg[0] = channel.DOMAIN_GRANT;
    @memcpy(msg[1..][0..n], out[0..n]);
    const sig = Ed.KeyPair.sign(approver.ed_kp, msg[0 .. 1 + n], null) catch unreachable;
    @memcpy(out[n..][0..64], &Ed.Signature.toBytes(sig));
    n += 64;
    return n;
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

// ---------------------------------------------------------------------------
// Loopback drivers: the client sends from its own bound socket; node B is fed
// one datagram per driveB() call straight into the daemon.
// ---------------------------------------------------------------------------

fn driveB(d: *daemon_mod.Daemon, lis_b: *listener.Listener, now: u64) daemon_mod.HandleResult {
    var buf: [MAX_DGRAM]u8 = undefined;
    var sa: [28]u8 = undefined;
    var slen: c_uint = 28;
    const n = lis_b.recvFrom(&buf, &sa, &slen) catch return .dropped;
    return d.handleDatagram(buf[0..n], &sa, slen, now);
}

fn clientSend(lis_c: *listener.Listener, packet: []const u8, sa_b: *const [16]u8) !void {
    const want: isize = @intCast(packet.len);
    try testing.expectEqual(want, sendto(lis_c.fd, packet.ptr, packet.len, 0, sa_b, 16));
}

// clientHandshake: flight 1 out, response + B's binding push back, client
// binding frame out. Returns the client-side session slot. `bind_cert` lets
// the F1 negative present a mismatched-kex cert while keeping the handshake
// itself honest.
fn clientHandshake(
    io: std.Io,
    lis_c: *listener.Listener,
    d: *daemon_mod.Daemon,
    lis_b: *listener.Listener,
    sa_b: *const [16]u8,
    table: *session.SessionTable,
    ident: *const Identity,
    b_x_pub: [32]u8,
    b_sig_pub: [32]u8,
    ca_pub: [32]u8,
    announced_index: u32,
    bind_cert_buf: ?[]const u8,
    now: u64,
) !usize {
    var initiator = noise.Initiator.init(io, ident.x_kp, b_x_pub);
    var msg1: [noise.MSG1_SIZE]u8 = undefined;
    const no_cookie = [_]u8{0} ** 16;
    try initiator.writeInitiation(&msg1, announced_index, now, b_sig_pub, no_cookie);
    try clientSend(lis_c, &msg1, sa_b);

    const r = driveB(d, lis_b, now);
    try testing.expect(r == .handshake_committed);

    var csa: [28]u8 = undefined;
    var csalen: c_uint = 28;
    var buf: [MAX_DGRAM]u8 = undefined;
    var got: usize = 0;
    while (true) {
        got = try lis_c.recvFrom(&buf, &csa, &csalen);
        if (buf[0] == 2) break; // MSG2 before the binding push
    }
    try testing.expectEqual(@as(usize, noise.MSG2_SIZE), got);
    try initiator.readResponse(buf[0..noise.MSG2_SIZE], b_sig_pub);
    const result = initiator.finalize();
    const peer_index = std.mem.readInt(u32, buf[noise.OFF2_SENDER_INDEX..][0..4], .big);
    // SPEC 4.1a pin: receiver_index echoes the initiator's announced index.
    // The G2 live interop run found this field swapped with sender_index on
    // the wire; this assert pins the conformant layout against regression.
    const echo = std.mem.readInt(u32, buf[noise.OFF2_RECEIVER_INDEX..][0..4], .big);
    try testing.expectEqual(announced_index, echo);
    const slot = try table.admit(peer_index, result, now);

    // B's binding push arrives next (BE-TR-01: responder pushes first).
    got = try lis_c.recvFrom(&buf, &csa, &csalen);
    try testing.expectEqual(@as(u8, parser.MSG_TRANSPORT_DATA), buf[0]);
    const sess = table.lookup(slot).?;
    const hdr = try parser.parseDataPacketHeader(buf[0..got]);
    var pt: [MAX_DGRAM]u8 = undefined;
    const pt_n = try sess.open(buf[0..got], hdr, &pt);
    const bm = try cert_parser.parseBindingMessage(pt[0..pt_n]);
    const pc = try cert_parser.parseCert(bm.cert);
    const cas = [_][]const u8{&ca_pub};
    try binding.bindSession(pc, bm.sig, &sess.handshake_hash, &b_x_pub, &cas, now);

    // Client's own binding frame: real cert unless the caller overrides.
    const cert_wire: []const u8 = bind_cert_buf orelse ident.cert_buf[0..ident.cert_len];
    var frame: [2 + keys_mod.MAX_CERT + 64]u8 = undefined;
    std.mem.writeInt(u16, frame[0..2], @intCast(cert_wire.len), .big);
    @memcpy(frame[2..][0..cert_wire.len], cert_wire);
    var bmsg: [33]u8 = undefined;
    bmsg[0] = binding.DOMAIN_BINDING;
    @memcpy(bmsg[1..], &sess.handshake_hash);
    const bsig = try Ed.KeyPair.sign(ident.ed_kp, &bmsg, null);
    @memcpy(frame[2 + cert_wire.len ..][0..64], &Ed.Signature.toBytes(bsig));
    var pkt: [MAX_DGRAM]u8 = undefined;
    const total = try sess.seal(&pkt, frame[0 .. 2 + cert_wire.len + 64]);
    try clientSend(lis_c, pkt[0..total], sa_b);
    return slot;
}

test "D-089 pilot: handshake, binding both ways, intent, grant, effect, ledger, restart orphan, F1 and replay negatives" {
    recorder_fired = 0;

    // Ledger seam: fresh durable file under /tmp, threaded io kept alive for
    // the whole test body (dispatch_test's SeamLedger shape).
    var threaded = std.Io.Threaded.init_single_threaded;
    const io = threaded.io();
    const ledger_path = "/tmp/bolina_pilot_d089.log";
    const cwd = std.Io.Dir.cwd();
    cwd.deleteFile(io, ledger_path) catch {};

    // Test CAs + identities. The approver rides TWO CAs (BE-ID-04 quorum).
    const ca_kp = cth.keypair(0xA7);
    const ca2_kp = cth.keypair(0xA8);
    const ca_pub = Ed.PublicKey.toBytes(ca_kp.public_key);
    const ca2_pub = Ed.PublicKey.toBytes(ca2_kp.public_key);
    const cas_one = [_]Ed.KeyPair{ca_kp};
    const cas_two = [_]Ed.KeyPair{ ca_kp, ca2_kp };
    var agent = mintIdentity(0xB1, 0xC1, binding.ROLE_AGENT, &cas_one);
    var appr = mintIdentity(0xB2, 0xC2, binding.ROLE_APPROVER, &cas_two);
    var evil = mintIdentity(0xB3, 0xC3, binding.ROLE_AGENT, &cas_one);
    // The evil cert presents a kex pubkey that is NOT the handshake static.
    var evil_cert: [keys_mod.MAX_CERT]u8 = undefined;
    const evil_cert_len = buildNodeCert(&evil_cert, pubOf(&evil), cth.pubkeyOf(0x99), binding.ROLE_AGENT, &cas_one);

    // Node B: real key material (D-018), executor cert, CA trust set.
    var b_ed = cth.keypair(0xB0);
    const bx_secret = cth.seedFrom(0xC0);
    const bx = noise.keypairFromSecret(bx_secret) catch unreachable;
    var bkeys: keys_mod.Keys = undefined;
    bkeys.kex_secret = bx_secret;
    bkeys.kex_public = bx.public;
    bkeys.sig_seed = cth.seedFrom(0xB0);
    bkeys.sig_public = Ed.PublicKey.toBytes(b_ed.public_key);
    bkeys.trusted_ca_keys[0] = ca_pub;
    bkeys.trusted_ca_keys[1] = ca2_pub;
    bkeys.trusted_ca_count = 2;
    bkeys.own_cert_len = buildNodeCert(&bkeys.own_cert, bkeys.sig_public, bx.public, binding.ROLE_EXECUTOR, &cas_one);
    _ = &b_ed;

    // Sockets: node B and the client, both on loopback.
    var reg_b = listener.EndpointRegistry{};
    var reg_c = listener.EndpointRegistry{};
    var lis_b = try listener.Listener.open(.ipv4);
    defer lis_b.close();
    try lis_b.bind(&reg_b, &LOOPBACK, PORT_NODE_B);
    var lis_c = try listener.Listener.open(.ipv4);
    defer lis_c.close();
    try lis_c.bind(&reg_c, &LOOPBACK, PORT_CLIENT);
    var sa_b: [16]u8 = undefined;
    v4Sockaddr(LOOPBACK, PORT_NODE_B, &sa_b);

    var hs = handshake.HandshakeServer{
        .fd = lis_b.fd,
        .responder_static = bx,
        .responder_sig_pubkey = bkeys.sig_public,
        .io = io,
    };
    const d = try daemon_mod.Daemon.init(io, &lis_b, &bkeys, &hs, null);

    // The executor declares its one resource (BE-RES-06 canonical form).
    var fp: [resolver_mod.FP_HEX_LEN]u8 = undefined;
    resolver_mod.executorFp(&bkeys.sig_public, &fp);
    var canon: [resolver_mod.ID_MAX]u8 = undefined;
    var cn: usize = 0;
    @memcpy(canon[cn..][0..4], "bol:");
    cn += 4;
    @memcpy(canon[cn..][0..resolver_mod.FP_HEX_LEN], &fp);
    cn += resolver_mod.FP_HEX_LEN;
    const tail = "/logs/deploy.log";
    @memcpy(canon[cn..][0..tail.len], tail);
    cn += tail.len;
    try d.dispatcher.resolver.add(canon[0..cn]);
    const resource = canon[0..cn];
    // Second resource: the resource lock (ResourceHeld) is per canonical
    // entry, so the orphan-path grant must hold a DIFFERENT one while the
    // first stays held by the executed grant.
    var canon2: [resolver_mod.ID_MAX]u8 = undefined;
    var c2n: usize = 0;
    @memcpy(canon2[c2n..][0..4], "bol:");
    c2n += 4;
    @memcpy(canon2[c2n..][0..resolver_mod.FP_HEX_LEN], &fp);
    c2n += resolver_mod.FP_HEX_LEN;
    const tail2 = "/logs/restart.log";
    @memcpy(canon2[c2n..][0..tail2.len], tail2);
    c2n += tail2.len;
    try d.dispatcher.resolver.add(canon2[0..c2n]);
    const resource2 = canon2[0..c2n];

    // Boot ledger AFTER the daemon exists (dispatch's module seam attaches).
    var orphan_buf: [16]grant_ledger_mod.OrphanGrant = undefined;
    try testing.expectEqual(@as(usize, 0), try dispatch_mod.initDurableLedger(io, ledger_path, &orphan_buf));

    var table = session.SessionTable.init();

    // --- Handshake + binding, agent session (slot 0) ---
    const slot_a = try clientHandshake(io, &lis_c, d, &lis_b, &sa_b, &table, &agent, bx.public, bkeys.sig_public, ca_pub, 0xA70F1E, null, NOW_MS);
    try testing.expect(driveB(d, &lis_b, NOW_MS) == .bound);
    try testing.expectEqual(@as(u32, 0), slot_a);
    try testing.expectEqual(@as(u64, 1), d.handshakes_committed);
    try testing.expectEqual(@as(u64, 1), d.bindings_accepted);
    try testing.expect(d.certForSender(&pubOf(&agent)) != null);

    // --- Handshake + binding, approver session (slot 1) ---
    const slot_p = try clientHandshake(io, &lis_c, d, &lis_b, &sa_b, &table, &appr, bx.public, bkeys.sig_public, ca_pub, 1, null, NOW_MS);
    try testing.expect(driveB(d, &lis_b, NOW_MS) == .bound);
    try testing.expectEqual(@as(u32, 1), slot_p);
    try testing.expect(d.certForSender(&pubOf(&appr)) != null);

    const sess_a = table.lookup(0).?;
    const sess_p = table.lookup(1).?;

    // --- Intent A over the wire ---
    const action_a = "deploy-bolina-v5";
    var ibody: [256]u8 = undefined;
    const ilen = @import("dispatch_test.zig").buildIntentBodyId(&ibody, &IID_A, resource, action_a);
    var env_pkt: [MAX_DGRAM]u8 = undefined;
    const env_n = sealEnvelope(&env_pkt, &agent, 1, NOW_MS, channel.BODY_INTENT, ibody[0..ilen]);
    var wire: [MAX_DGRAM]u8 = undefined;
    const wire_n = try sess_a.seal(&wire, env_pkt[0..env_n]);
    var intent_packet: [MAX_DGRAM]u8 = undefined;
    const intent_packet_len = wire_n;
    @memcpy(intent_packet[0..wire_n], wire[0..wire_n]);
    try clientSend(&lis_c, wire[0..wire_n], &sa_b);
    const ri = driveB(d, &lis_b, NOW_MS);
    try testing.expect(ri == .dispatched);
    try testing.expectEqual(dispatch_mod.Outcome.intent_admitted, ri.dispatched);

    // --- Grant A (approver signs on its own session), effect FIRED ---
    daemon_mod.pilot_effect_hook = &recordingEffect;
    defer daemon_mod.pilot_effect_hook = null;
    var gbody_a: [512]u8 = undefined;
    const glen_a = buildGrantBody(&gbody_a, GID_A, IID_A, &appr, pubOf(&agent), bkeys.sig_public, resource, action_a, NOW_MS + 60_000);
    const genv_n = sealEnvelope(&env_pkt, &appr, 1, NOW_MS, channel.BODY_GRANT, gbody_a[0..glen_a]);
    const gwire_n = try sess_p.seal(&wire, env_pkt[0..genv_n]);
    try clientSend(&lis_c, wire[0..gwire_n], &sa_b);
    const rg = driveB(d, &lis_b, NOW_MS);
    try testing.expect(rg == .dispatched);
    try testing.expectEqual(dispatch_mod.Outcome.grant_executed, rg.dispatched);
    try testing.expectEqual(@as(usize, 1), recorder_fired);

    // --- Intent B + Grant B with the SHIPPED fail-closed effect hook:
    // checks pass, commit stands, effect refuses -> unpublished orphan. ---
    const action_b = "deploy-bolina-v6";
    const ilen_b = @import("dispatch_test.zig").buildIntentBodyId(&ibody, &IID_B, resource2, action_b);
    const env_b = sealEnvelope(&env_pkt, &agent, 2, NOW_MS, channel.BODY_INTENT, ibody[0..ilen_b]);
    const wire_b = try sess_a.seal(&wire, env_pkt[0..env_b]);
    try clientSend(&lis_c, wire[0..wire_b], &sa_b);
    const rib = driveB(d, &lis_b, NOW_MS);
    try testing.expect(rib == .dispatched);
    try testing.expectEqual(dispatch_mod.Outcome.intent_admitted, rib.dispatched);

    daemon_mod.pilot_effect_hook = null;
    var gbody_b: [512]u8 = undefined;
    const glen_b = buildGrantBody(&gbody_b, GID_B, IID_B, &appr, pubOf(&agent), bkeys.sig_public, resource2, action_b, NOW_MS + 60_000);
    const genv_b = sealEnvelope(&env_pkt, &appr, 2, NOW_MS, channel.BODY_GRANT, gbody_b[0..glen_b]);
    const gwire_b = try sess_p.seal(&wire, env_pkt[0..genv_b]);
    try clientSend(&lis_c, wire[0..gwire_b], &sa_b);
    const rgb = driveB(d, &lis_b, NOW_MS);
    try testing.expect(rgb == .dispatched);
    try testing.expectEqual(dispatch_mod.Outcome.effect_refused, rgb.dispatched);
    try testing.expectEqual(@as(usize, 1), recorder_fired); // unchanged

    // --- Restart: close, reopen, recover exactly ONE orphan (GID_B).
    // Grant A was published (fired), so it must NOT come back. ---
    dispatch_mod.closeDurableLedger();
    var orphans: [16]grant_ledger_mod.OrphanGrant = undefined;
    const n_orphans = try daemon_mod.openLedger(io, ledger_path, &orphans);
    try testing.expectEqual(@as(usize, 1), n_orphans);
    try testing.expectEqualSlices(u8, &GID_B, &orphans[0].grant_id);

    // --- Negative F1: evil handshake binds nothing when the cert kex does
    // not match its Noise static. Session commits, gate stays shut. ---
    const slot_e = try clientHandshake(io, &lis_c, d, &lis_b, &sa_b, &table, &evil, bx.public, bkeys.sig_public, ca_pub, 2, evil_cert[0..evil_cert_len], NOW_MS);
    try testing.expect(driveB(d, &lis_b, NOW_MS) == .dropped);
    try testing.expectEqual(@as(u32, 2), slot_e);
    try testing.expectEqual(@as(u64, 3), d.handshakes_committed);
    try testing.expectEqual(@as(u64, 2), d.bindings_accepted);
    try testing.expect(!table.lookup(2).?.bound);

    // An envelope from the unbound session drops unread (BE-TR-01 gate).
    const env_e = sealEnvelope(&env_pkt, &evil, 1, NOW_MS, channel.BODY_UTTERANCE, "let me in");
    const wire_e = try table.lookup(2).?.seal(&wire, env_pkt[0..env_e]);
    try clientSend(&lis_c, wire[0..wire_e], &sa_b);
    const re = driveB(d, &lis_b, NOW_MS);
    try testing.expect(re == .dropped);

    // --- Negative replay: the exact Intent A packet bytes again. The
    // session replay window eats it before any parse. ---
    try clientSend(&lis_c, intent_packet[0..intent_packet_len], &sa_b);
    const rr = driveB(d, &lis_b, NOW_MS);
    try testing.expect(rr == .dropped);

    // --- Counters close the loop: 3 handshakes, 2 bindings, 4 dispatched
    // envelopes, at least 2 counted drops, zero reflections. ---
    try testing.expectEqual(@as(u64, 4), d.envelopes_dispatched);
    try testing.expect(d.datagrams_dropped >= 2);

    dispatch_mod.closeDurableLedger();
    cwd.deleteFile(io, ledger_path) catch {};
}
