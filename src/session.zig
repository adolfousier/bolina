// session.zig
//
// Established transport sessions (SPEC 4.2, 4.3; BE-TR-02, BE-TR-03, BE-TR-05).
// A session is the post-handshake state for one peer pair: two CipherStates
// (send and recv), the receiver's sliding-window anti-replay filter, and the
// rekey bookkeeping. Sessions live in a fixed 512-slot table; the node-level
// ceiling is enforced by refusing new sessions, never by degrading existing
// ones, and the refusal is surfaced as an error, not absorbed (BE-TR-05).
//
// Two crypto-critical decisions, stated because a round-trip test cannot tell
// the wrong choice from the right one:
//   (1) The transport AEAD's associated data is the 16-byte wire header
//       (type, reserved, receiver_index, counter). The construction is
//       WireGuard's, adopted; SPEC's "decrypt in place" clause is exactly the
//       header-as-AD shape (header stays clear, is authenticated, payload is
//       the ciphertext suffix).
//   (2) A counter is recorded in the replay window only AFTER its AEAD tag
//       verifies. Recording before authentication would let a forger poison
//       window slots for counters it cannot produce valid ciphertext for.
//       The price, one decryption per replayed packet, is accepted here; the
//       cheap-flood defenses live at the handshake layer (BE-TR-04).
//
// The nonce is noise.transportNonce: [0x00 x4] || big-endian u64 counter, one
// construction for handshake and transport (SPEC 2.2, D-019). Zero-heap,
// caller-owned buffers (BE-WIRE-01); parser.zig validates the wire header and
// this module consumes the validated structure plus the original bytes (D-018).

const std = @import("std");
const noise = @import("noise.zig");
const replay = @import("replay.zig");
const parser = @import("parser.zig");
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

// BE-TR-05 table row "Concurrent sessions, per node: 512 (default)". The
// reassembly module declares the same value for its node-level accounting; a
// test asserts the two never drift apart.
pub const MAX_SESSIONS: usize = 512;

// BE-TR-02: replace a session key at the earlier of 120 seconds or 2^48
// messages, zeroing the old key. The message bound keeps the big-endian u64
// counter nonce fresh well inside its range; the time bound bounds key age.
pub const REKEY_AFTER_MS: u64 = 120_000;
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 48;

// Transport data packet: 16-byte header, then ciphertext plus 16-byte tag.
pub const HEADER_SIZE: usize = 16;
pub const MSG_TYPE_TRANSPORT: u8 = 4;

pub const Error = error{
    // The node session ceiling (BE-TR-05): refuse the new, keep the existing.
    NodeCapacity,
    // The send side hit the 2^48 message bound; rotate the key first.
    RekeyRequired,
    // AEAD tag mismatch under the receiving key.
    DecryptFailed,
    // Counter replayed or below the window floor (BE-TR-03).
    Replay,
};

// One direction of a session: a key and its counter.
pub const CipherState = struct {
    key: [noise.KEYLEN]u8,
    counter: u64,

    // Encrypt plaintext under this state's key with ad as associated data,
    // writing ciphertext plus tag to out. Refuses at the 2^48 bound.
    pub fn seal(cs: *CipherState, out: []u8, plaintext: []const u8, ad: []const u8) Error!void {
        if (cs.counter >= REKEY_AFTER_MESSAGES) return Error.RekeyRequired;
        var tag: [noise.TAGLEN]u8 = undefined;
        ChaCha20Poly1305.encrypt(out[0..plaintext.len], &tag, plaintext, ad, noise.transportNonce(cs.counter), cs.key);
        @memcpy(out[plaintext.len..][0..noise.TAGLEN], &tag);
        cs.counter += 1;
    }

    // BE-TR-02: zero the key on replacement.
    pub fn zero(cs: *CipherState) void {
        @memset(&cs.key, 0);
        cs.counter = 0;
    }
};

// The receiving direction: a key and the anti-replay window (BE-TR-03).
pub const RecvState = struct {
    key: [noise.KEYLEN]u8,
    window: replay.ReplayWindow,

    // Decrypt ct (ciphertext plus tag) under this state's key with ad as
    // associated data; record the counter only after the tag verifies
    // (decision 2 above). Returns the plaintext length.
    pub fn open(rs: *RecvState, out: []u8, ad: []const u8, ct: []const u8, counter: u64) Error!usize {
        const pt_len = ct.len - noise.TAGLEN;
        const tag: [noise.TAGLEN]u8 = ct[pt_len..][0..noise.TAGLEN].*;
        ChaCha20Poly1305.decrypt(out[0..pt_len], ct[0..pt_len], tag, ad, noise.transportNonce(counter), rs.key) catch return Error.DecryptFailed;
        if (!rs.window.check(counter)) return Error.Replay;
        return pt_len;
    }

    pub fn zero(rs: *RecvState) void {
        @memset(&rs.key, 0);
        rs.window = replay.ReplayWindow.init();
    }
};

pub const Session = struct {
    local_index: u32, // this node's index; the peer puts it in receiver_index
    peer_index: u32, // the peer's index; this node puts it in outgoing headers
    send: CipherState,
    recv: RecvState,
    // The Noise transcript hash of the key's handshake: the value the BE-TR-01
    // binding signature is over. binding.zig owns the binding policy.
    handshake_hash: [noise.HASHLEN]u8,
    // Millisecond timestamp when the current key epoch started (BE-TR-02).
    key_epoch_ms: u64,
    bound: bool, // BE-TR-01: no application data upward until bound
    in_use: bool,

    // BE-TR-02: rekey is due at the earlier of the time bound and the message
    // bound. The caller starts a fresh handshake and then calls rotate().
    pub fn dueForRekey(s: *const Session, now_ms: u64) bool {
        return s.send.counter >= REKEY_AFTER_MESSAGES or
            now_ms >= s.key_epoch_ms + REKEY_AFTER_MS;
    }

    // Seal one transport data packet: build the 16-byte header (type 4, zero
    // reserved, peer index, send counter, all big-endian per SPEC 2.2), then
    // AEAD the payload behind it with the header as associated data. Returns
    // the packet length. An empty plaintext is a legal keepalive.
    pub fn seal(s: *Session, out: []u8, plaintext: []const u8) Error!usize {
        const total = HEADER_SIZE + plaintext.len + noise.TAGLEN;
        std.debug.assert(out.len >= total);
        out[0] = MSG_TYPE_TRANSPORT;
        @memset(out[1..4], 0);
        std.mem.writeInt(u32, out[4..8], s.peer_index, .big);
        std.mem.writeInt(u64, out[8..16], s.send.counter, .big);
        try s.send.seal(out[HEADER_SIZE..total], plaintext, out[0..HEADER_SIZE]);
        return total;
    }

    // Open one validated transport data packet: the header bytes are the
    // associated data, the parsed payload the ciphertext. Replay consumption
    // happens inside recv.open, after the tag verifies.
    pub fn open(s: *Session, packet: []const u8, hdr: parser.DataPacketHeader, out: []u8) Error!usize {
        std.debug.assert(packet.len >= HEADER_SIZE);
        return s.recv.open(out, packet[0..HEADER_SIZE], hdr.encrypted_payload, hdr.counter);
    }

    // BE-TR-02 rotation: zero both old keys, install the fresh handshake's
    // keys and transcript hash, reset both counters, swap in a fresh replay
    // window (counters do not carry across keys), and restart the clock. The
    // bound flag survives rotation: identity was established for the peer,
    // and Noise_IK re-authenticates the same static keys on every handshake;
    // binding.zig owns that policy.
    pub fn rotate(s: *Session, result: noise.HandshakeResult, now_ms: u64) void {
        s.send.zero();
        s.recv.zero();
        s.send.key = result.send_key;
        s.recv.key = result.recv_key;
        s.handshake_hash = result.handshake_hash;
        s.key_epoch_ms = now_ms;
    }
};

// The node's session store: a fixed array of MAX_SESSIONS slots, indexed by
// local_index. Zero-heap: the caller owns the table; lookup is bounds-checked
// and slot-checked, so a forged or stale receiver_index is just null.
pub const SessionTable = struct {
    slots: [MAX_SESSIONS]Session,
    count: usize,

    pub fn init() SessionTable {
        return .{
            .slots = std.mem.zeroes([MAX_SESSIONS]Session),
            .count = 0,
        };
    }

    // The receiving path: resolve a packet's receiver_index to a live session.
    pub fn lookup(t: *SessionTable, local_index: u32) ?*Session {
        if (local_index >= MAX_SESSIONS) return null;
        if (!t.slots[local_index].in_use) return null;
        return &t.slots[local_index];
    }

    // Install a session for a completed handshake. The peer_index is the
    // counterpart's announced index; the send/recv keys come from the Noise
    // split as seen from this side. Returns this node's local_index, which is
    // the slot position by construction. Refuses at the ceiling (BE-TR-05):
    // a new session is refused, existing sessions are untouched.
    pub fn admit(
        t: *SessionTable,
        peer_index: u32,
        result: noise.HandshakeResult,
        now_ms: u64,
    ) Error!u32 {
        if (t.count >= MAX_SESSIONS) return Error.NodeCapacity;
        for (&t.slots, 0..) |*slot, i| {
            if (slot.in_use) continue;
            slot.* = .{
                .local_index = @intCast(i),
                .peer_index = peer_index,
                .send = .{ .key = result.send_key, .counter = 0 },
                .recv = .{ .key = result.recv_key, .window = replay.ReplayWindow.init() },
                .handshake_hash = result.handshake_hash,
                .key_epoch_ms = now_ms,
                .bound = false,
                .in_use = true,
            };
            t.count += 1;
            return @intCast(i);
        }
        // Unreachable: count said a slot exists. Kept because the compiler
        // cannot see the invariant and the table must never admit past the cap.
        return Error.NodeCapacity;
    }

    // Remove a session, zeroing the whole slot: keys, window, transcript hash.
    pub fn release(t: *SessionTable, local_index: u32) void {
        if (local_index >= MAX_SESSIONS) return;
        if (!t.slots[local_index].in_use) return;
        t.slots[local_index] = std.mem.zeroes(Session);
        t.count -= 1;
    }
};
