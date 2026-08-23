// daemon.zig
//
// D-089: the node core. One struct owns the wire path end to end: the
// handshake server (types 1-3), the transport session table (type 4), the
// optional relay serve (types 5/6), and the dispatch machines behind them.
// main.zig is deliberately thin: env parse, keys, ledger, bind, loop; every
// decision about bytes lives here where the pilot can drive it.
//
// BE-TR-01 wiring (D-089 section 4, settled against SPEC line 504): there is
// no pre-binding envelope allowlist. The first plaintext a session carries is
// the binding message (u16be cert_len | cert | 64-byte Ed25519 over
// (0x05 || h)), in both directions, inside the encrypted session. Until the
// peer's frame verifies against the handshake transcript and its cert passes
// BE-ID-01..03 with kex == the Noise static (F1), every type-4 payload from
// that session drops, never parsed as an envelope. The responder pushes its
// own binding frame immediately after the handshake commit; it does not wait
// to see the peer's first.
//
// Fail-closed posture: unknown types drop, unparseable frames drop, failed
// bindings drop, the default effect hook refuses. The relay seam is optional
// by construction: certs carry no relay role (ROLE_AGENT/EXECUTOR/APPROVER
// are the whole vocabulary), so a node relays only when the process was
// wired with a RelayServe; otherwise types 5/6 are counted and dropped. No
// env knob exists to flip that (D-089 section 2: no other knobs).
//
// Hook seam (M10 shape, same ruling as dispatch.zig's module ledger): the
// dispatch hooks are bare function pointers, so the one-daemon-per-process
// invariant lives in a module-level pointer installed at init over fixed
// process-static storage (zero heap, stable addresses for the process life).
// The shipped effect hook is fail-closed by design: it executes nothing and
// returns refused until an effect backend exists; the pilot injects a
// recorder instead.

const std = @import("std");
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
const relay_serve = @import("relay_serve.zig");
const verify = @import("verify.zig");
const grant_ledger = @import("grant_ledger.zig");

const MAX_DGRAM: usize = 2048;
const SA_LEN: usize = 28;

// Bound-identity registry bound: sig_pubkey -> cert wire bytes, filled only
// by a verified binding frame. cert_for_sender walks it; dispatch never sees
// an identity the session layer did not authenticate. Full table refuses new
// identities (refuse-new keep-existing, every other fixed bound's shape).
const MAX_IDENTITIES: usize = 64;
pub const MAX_ORPHANS_BOOT: usize = 16;

pub const BootError = error{
    KeyMaterial, // keys layer failed (D-049 detail stays at that layer)
    LedgerUnreadable, // open/recover failed: a corrupt log is fatal, loud
    OrphanOverflow, // recovered orphans exceed the boot buffer
    OwnCertInvalid, // cert.bin present but unparseable
};

const IdentityRecord = struct {
    sig_pub: [32]u8,
    cert: [keys_mod.MAX_CERT]u8,
    cert_len: usize,
    in_use: bool,
};

pub const HandleResult = union(enum) {
    dropped,
    handshake_committed: u32, // the new session's local_index
    bound, // inbound binding frame verified, session bound
    dispatched: dispatch_mod.Outcome,
    relayed: relay_serve.ServeResult,
};

pub const Daemon = struct {
    io: std.Io,
    lis: *listener.Listener,
    keys: *const keys_mod.Keys,
    hs: *handshake.HandshakeServer,
    sessions: session.SessionTable,
    // Peer X25519 statics by local_index: the F1 binding input. The transport
    // Session struct carries none, and the handshake slot number is not the
    // session table slot, so the daemon keeps the pairing itself.
    peer_kex: [session.MAX_SESSIONS][32]u8,
    // Peer sockaddr captured at handshake commit: the reply path for our own
    // binding push, indexed by local_index like everything else here.
    peer_sa: [session.MAX_SESSIONS][SA_LEN]u8,
    peer_sa_len: [session.MAX_SESSIONS]c_uint,
    dispatcher: dispatch_mod.Dispatch,
    identities: [MAX_IDENTITIES]IdentityRecord,
    identity_count: usize,
    // Absent = types 5/6 count and drop (fail-closed, D-089 section 2).
    relay: ?*relay_serve.RelayServe,
    // Slices over keys.trusted_ca_keys: bindSession and Dispatch want
    // []const []const u8, the keys store keeps a flat [8][32].
    ca_slices: [keys_mod.MAX_CAS][]const u8,
    // Surfaced counters (SPEC clause: count, never block).
    handshakes_committed: u64 = 0,
    bindings_accepted: u64 = 0,
    datagrams_dropped: u64 = 0,
    envelopes_dispatched: u64 = 0,

    // init: build the dispatcher from key material and install the module
    // hook seam. The handshake server is the caller's (it needs the listener
    // fd first); everything else the daemon owns. An unparseable cert.bin is
    // fatal here: a node that cannot state its own identity must not run.
    pub fn init(io: std.Io, lis: *listener.Listener, keys: *const keys_mod.Keys, hs: *handshake.HandshakeServer, relay: ?*relay_serve.RelayServe) BootError!*Daemon {
        var ca_slices: [keys_mod.MAX_CAS][]const u8 = undefined;
        for (0..keys.trusted_ca_count) |i| ca_slices[i] = &keys.trusted_ca_keys[i];
        var own_cert: cert_parser.Cert = std.mem.zeroes(cert_parser.Cert);
        if (keys.own_cert_len > 0) {
            own_cert = cert_parser.parseCert(keys.own_cert[0..keys.own_cert_len]) catch return BootError.OwnCertInvalid;
        }
        daemon_storage = .{
            .io = io,
            .lis = lis,
            .keys = keys,
            .hs = hs,
            .sessions = session.SessionTable.init(),
            .peer_kex = std.mem.zeroes([session.MAX_SESSIONS][32]u8),
            .peer_sa = std.mem.zeroes([session.MAX_SESSIONS][SA_LEN]u8),
            .peer_sa_len = std.mem.zeroes([session.MAX_SESSIONS]c_uint),
            .dispatcher = dispatch_mod.Dispatch.init(
                resolver_mod.Resolver.init(&keys.sig_public),
                &keys.sig_public,
                own_cert,
                ca_slices[0..keys.trusted_ca_count],
            ),
            .identities = std.mem.zeroes([MAX_IDENTITIES]IdentityRecord),
            .identity_count = 0,
            .relay = relay,
            .ca_slices = ca_slices,
        };
        hook_daemon = &daemon_storage;
        return &daemon_storage;
    }

    // handleDatagram: one inbound datagram, classified by its leading type
    // byte (SPEC 4.1a). Every failure path drops and counts; nothing here
    // ever replies with an error datagram (reflection is a service).
    pub fn handleDatagram(self: *Daemon, dgram: []const u8, sa: [*]const u8, sa_len: c_uint, now_ms: u64) HandleResult {
        if (dgram.len == 0) return self.drop();
        return switch (dgram[0]) {
            1 => self.handleHandshake(dgram, sa, sa_len, now_ms),
            parser.MSG_TRANSPORT_DATA => self.handleTransport(dgram, now_ms),
            5, 6 => self.handleRelay(dgram, sa, sa_len, now_ms),
            else => self.drop(),
        };
    }

    // Type 1: the handshake server answers (it sends the type-2 response
    // itself); on commit the session joins the transport table under the
    // initiator's announced index and our binding frame is pushed while the
    // peer still holds its handshake slot open. BE-SESS-02 holds: the table
    // admit runs last, after the server's own commit succeeded.
    fn handleHandshake(self: *Daemon, dgram: []const u8, sa: [*]const u8, sa_len: c_uint, now_ms: u64) HandleResult {
        if (dgram.len < noise.MSG1_SIZE) return self.drop();
        const slot = self.hs.processDatagram(dgram, sa, sa_len, now_ms) catch return self.drop();
        const sender_index = std.mem.readInt(u32, dgram[noise.OFF1_SENDER_INDEX..][0..4], .big);
        const hsess = &self.hs.sessions[slot];
        const result = noise.HandshakeResult{
            .send_key = hsess.send_key,
            .recv_key = hsess.recv_key,
            .handshake_hash = hsess.handshake_hash,
        };
        const local = self.sessions.admit(sender_index, result, now_ms) catch return self.drop();
        self.peer_kex[local] = hsess.peer_static;
        if (sa_len <= SA_LEN) {
            @memcpy(self.peer_sa[local][0..sa_len], sa[0..sa_len]);
            self.peer_sa_len[local] = sa_len;
        }
        self.handshakes_committed += 1;
        // BE-TR-01 both directions: our frame goes out first. A failed push
        // does not undo the session; the peer's frame still binds it inbound.
        if (self.keys.own_cert_len > 0) self.sendBindingFrame(local) catch {};
        return .{ .handshake_committed = local };
    }

    // Type 4: decrypt, then the BE-TR-01 gate. Unbound sessions carry
    // exactly one message shape: the binding message. Bound sessions carry
    // envelopes for the dispatch machines. Anything else drops.
    fn handleTransport(self: *Daemon, dgram: []const u8, now_ms: u64) HandleResult {
        const hdr = parser.parseDataPacketHeader(dgram) catch return self.drop();
        const sess = self.sessions.lookup(hdr.receiver_index) orelse return self.drop();
        var pt: [MAX_DGRAM]u8 = undefined;
        const n = sess.open(dgram, hdr, &pt) catch return self.drop();
        if (!sess.bound) {
            const bm = cert_parser.parseBindingMessage(pt[0..n]) catch return self.drop();
            const cert = cert_parser.parseCert(bm.cert) catch return self.drop();
            binding.bindSession(
                cert,
                bm.sig,
                &sess.handshake_hash,
                &self.peer_kex[sess.local_index],
                self.ca_slices[0..self.keys.trusted_ca_count],
                now_ms,
            ) catch return self.drop();
            sess.bound = true;
            self.recordIdentity(cert, bm.cert);
            self.bindings_accepted += 1;
            return .bound;
        }
        const env = channel.parseEnvelope(pt[0..n]) catch return self.drop();
        const outcome = self.dispatcher.dispatch(env, .{
            .execute_effect = hookEffect,
            .cert_for_sender = hookCertForSender,
            .on_rejected = hookRejected,
        }, now_ms) catch return self.drop();
        self.envelopes_dispatched += 1;
        return .{ .dispatched = outcome };
    }

    // Types 5/6: relay work. Served only when the process was wired with a
    // RelayServe; a plain node drops and counts. There is no cert role for
    // relaying, so wiring is a deployment decision, not a credential one.
    fn handleRelay(self: *Daemon, dgram: []const u8, sa: [*]const u8, sa_len: c_uint, now_ms: u64) HandleResult {
        if (self.relay) |rs| {
            const r = rs.serveDatagram(dgram, sa, sa_len, now_ms);
            if (r == .dropped) _ = self.drop();
            return .{ .relayed = r };
        }
        return self.drop();
    }

    // sendBindingFrame: u16be cert_len | cert | 64-byte Ed25519 over
    // (0x05 || h), sealed as a type-4 packet on the session. The message is
    // the transcript hash, so the frame is replay-proof across handshakes by
    // construction: a fresh h mints a fresh signature requirement.
    fn sendBindingFrame(self: *Daemon, local_index: u32) session.Error!void {
        const sess = self.sessions.lookup(local_index) orelse return;
        const kp = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(self.keys.sig_seed) catch return;
        var msg: [33]u8 = undefined;
        msg[0] = binding.DOMAIN_BINDING;
        @memcpy(msg[1..], &sess.handshake_hash);
        const sig = std.crypto.sign.Ed25519.KeyPair.sign(kp, &msg, null) catch return;
        const sig_bytes = std.crypto.sign.Ed25519.Signature.toBytes(sig);
        var frame: [2 + keys_mod.MAX_CERT + 64]u8 = undefined;
        std.mem.writeInt(u16, frame[0..2], @intCast(self.keys.own_cert_len), .big);
        @memcpy(frame[2..][0..self.keys.own_cert_len], self.keys.own_cert[0..self.keys.own_cert_len]);
        @memcpy(frame[2 + self.keys.own_cert_len ..][0..64], &sig_bytes);
        var out: [MAX_DGRAM]u8 = undefined;
        const total = try sess.seal(&out, frame[0 .. 2 + self.keys.own_cert_len + 64]);
        _ = sendto(self.lis.fd, &out, total, 0, &self.peer_sa[local_index], self.peer_sa_len[local_index]);
    }

    // recordIdentity: the verified cert joins the registry cert_for_sender
    // serves from. Duplicate sig_pubkey collapses in place (one identity, one
    // record); a full table refuses the record, never evicts a live one.
    fn recordIdentity(self: *Daemon, cert: cert_parser.Cert, cert_wire: []const u8) void {
        if (cert.sig_pubkey.len != 32 or cert_wire.len > keys_mod.MAX_CERT) return;
        for (self.identities[0..self.identity_count]) |*rec| {
            if (std.mem.eql(u8, &rec.sig_pub, cert.sig_pubkey)) return; // already known
        }
        if (self.identity_count >= MAX_IDENTITIES) return;
        const rec = &self.identities[self.identity_count];
        @memcpy(&rec.sig_pub, cert.sig_pubkey);
        @memcpy(rec.cert[0..cert_wire.len], cert_wire);
        rec.cert_len = cert_wire.len;
        rec.in_use = true;
        self.identity_count += 1;
    }

    // certForSender: the dispatch hook's lookup. Returns a Cert aliasing the
    // process-static registry; dispatch consumes it inside its own call
    // frame, so the borrow never outlives the registry entry.
    pub fn certForSender(self: *Daemon, sender: []const u8) ?cert_parser.Cert {
        if (sender.len != 32) return null;
        for (self.identities[0..self.identity_count]) |*rec| {
            if (!rec.in_use) continue;
            if (std.mem.eql(u8, &rec.sig_pub, sender)) {
                return cert_parser.parseCert(rec.cert[0..rec.cert_len]) catch null;
            }
        }
        return null;
    }

    fn drop(self: *Daemon) HandleResult {
        self.datagrams_dropped += 1;
        return .dropped;
    }
};

// Process-static storage: fixed bounds, zero heap, and the stable address
// the M10 bare-fn hooks require. One daemon per process is the deployment
// shape (single UDP listener, MD3 single-writer ledger).
var daemon_storage: Daemon = undefined;
var hook_daemon: ?*Daemon = null;

// Reply path, same flat pattern as handshake.zig (Zig 0.16 keeps high-level
// networking behind std.Io; the wire path stays libc-flat).
extern "c" fn sendto(fd: c_int, buf: [*]const u8, len: usize, flags: c_int, dest_addr: [*]const u8, addrlen: c_uint) isize;

// ---------------------------------------------------------------------------
// Dispatch hooks (M10 bare fn pointers). Resolved through hook_daemon; every
// miss fails closed.
// ---------------------------------------------------------------------------

// Pilot effect seam (D-089 section 5): the conformance pilot installs a
// recorder here to drive the fired path over the real wire. Null (shipped
// state) keeps the fail-closed refusal byte-for-byte; no env knob gates it.
pub var pilot_effect_hook: ?*const fn (channel.Grant) verify.EffectOutcome = null;

// Fail-closed default effect (D-089 section 2): the shipped binary executes
// nothing. The grant verifies, the ledger commits, the effect refuses and
// the refusal surfaces upward. An effect backend replaces this hook in code;
// no env knob gates it.
fn hookEffect(g: channel.Grant) verify.EffectOutcome {
    if (pilot_effect_hook) |hook| return hook(g);
    return .refused;
}

fn hookCertForSender(sender: []const u8) ?cert_parser.Cert {
    const d = hook_daemon orelse return null;
    return d.certForSender(sender);
}

fn hookRejected(intent_id: []const u8) void {
    _ = intent_id; // surfaced through dispatch outcomes; no log channel yet
}

// ---------------------------------------------------------------------------
// Boot seam shared with main.zig: the ledger open lives here so the pilot
// exercises the exact boot path the shipped binary runs.
// ---------------------------------------------------------------------------

// openLedger: D-089 section 3 step 4. A corrupt log is fatal at boot, loud,
// with the failure surfaced; it is never truncated in place. Recovered
// orphans return for the caller to publish and tombstone (BE-GRANT-01a);
// the boot buffer ceiling is the honest fixed bound.
pub fn openLedger(io: std.Io, path: []const u8, orphan_out: []grant_ledger.OrphanGrant) BootError!usize {
    return dispatch_mod.initDurableLedger(io, path, orphan_out) catch |e| switch (e) {
        error.ResourceExhausted => BootError.OrphanOverflow,
        else => BootError.LedgerUnreadable,
    };
}
