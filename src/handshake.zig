// handshake.zig
//
// Phase B2: live Noise_IK handshake over the listener (SPEC 4.1,
// BE-SESS-02). Pre-authentication surface: initiation datagrams are
// attacker bytes; budgeted in the BE-SURF-03 Listener sub-unit.
//
// BE-SESS-02 by construction: the session table is mutated in exactly one
// place (the commit at the end of processDatagram), reached only after
// mac1 verification, Noise decryption, and the outgoing response all
// succeed. Every failure returns before it, and the Responder is
// stack-local, so a failed handshake leaves zero half-session state.
//
// Scope notes: mac2 cookie exchange is DoS hardening declared for phase C
// (the cookie machinery is bound in mac.zig, BE-TR-04a); B2 answers with a
// zero cookie. Timestamp replay policy is session-layer work (SPEC 2.2).

const std = @import("std");
const noise = @import("noise.zig");
const mac = @import("mac.zig");

// Reply path: flat libc sendto, same pattern as listener.zig (Zig 0.16
// moved high-level networking behind std.Io; B2 stays flat).
extern "c" fn sendto(fd: c_int, buf: [*]const u8, len: usize, flags: c_int, dest_addr: [*]const u8, addrlen: c_uint) isize;

pub const MAX_SESSIONS: usize = 16;

pub const Session = struct {
    send_key: [noise.KEYLEN]u8 = undefined,
    recv_key: [noise.KEYLEN]u8 = undefined,
    handshake_hash: [noise.HASHLEN]u8 = undefined,
    peer_static: [noise.DHLEN]u8 = undefined, // initiator static, from IK
};

pub const HandshakeError = error{ NotInitiation, TableFull, Refused, SendFailed };

pub const HandshakeServer = struct {
    fd: c_int, // the listener socket; replies leave from the bound endpoint
    responder_static: noise.X25519KeyPair,
    responder_sig_pubkey: mac.ResponderSigPubkey,
    sessions: [MAX_SESSIONS]Session = undefined,
    session_count: usize = 0,
    io: std.Io,

    // processDatagram: one inbound datagram. Type-1 initiations only (B2).
    // Returns the committed session slot. The commit is the sole session
    // table mutation and runs last; every failure returns before it
    // (BE-SESS-02).
    pub fn processDatagram(self: *HandshakeServer, datagram: []const u8, reply_sa: [*]const u8, reply_sa_len: c_uint, now_ms: u64) HandshakeError!usize {
        _ = now_ms;
        if (datagram.len < noise.MSG1_SIZE or datagram[0] != 1) return error.NotInitiation;
        if (self.session_count >= MAX_SESSIONS) return error.TableFull;
        var responder = noise.Responder.init(self.io, self.responder_static);
        responder.readInitiation(datagram[0..noise.MSG1_SIZE], self.responder_sig_pubkey) catch return error.Refused;
        const sender_index = std.mem.readInt(u32, datagram[noise.OFF1_SENDER_INDEX..][0..4], .big);
        var msg2: [noise.MSG2_SIZE]u8 = undefined;
        const no_cookie = [_]u8{0} ** mac.MAC_BYTES;
        // SPEC 4.1a: sender_index carries OUR newly chosen index; receiver_
        // index echoes the initiator's. The G2 live interop run found these
        // two arguments swapped (echo at 4, our slot at 8), which a
        // spec-conformant initiator rejects whenever the two differ.
        responder.writeResponse(&msg2, @intCast(self.session_count), sender_index, self.responder_sig_pubkey, no_cookie) catch return error.Refused;
        const want: isize = @intCast(msg2.len);
        if (sendto(self.fd, &msg2, msg2.len, 0, reply_sa, reply_sa_len) != want) return error.SendFailed;
        const result = responder.finalize();
        const slot = self.session_count;
        self.sessions[slot] = .{
            .send_key = result.send_key,
            .recv_key = result.recv_key,
            .handshake_hash = result.handshake_hash,
            .peer_static = responder.remote_static_pub,
        };
        self.session_count += 1;
        return slot;
    }
};
