// noise.zig
//
// Noise_IK_25519_ChaChaPoly_BLAKE2s (SPEC 4.1, BE-TR-04): the symmetric state
// and the initiator/responder handshake machine. The pattern, the mac1/mac2
// DoS design, the field set and order are adopted unchanged; only the byte
// serialization obeys SPEC 2.2.
//
// HKDF core is HMAC-BLAKE2s (Hmac(Blake2s256), unkeyed under ipad/opad), not
// BLAKE2's built-in keyed mode: "adopt the construction" means adopt HMAC.
//
// mac1-first (BE-TR-04): the responder verifies mac1 BEFORE any X25519 and
// drops on failure, so a flood costs one BLAKE2s-MAC, not a curve op. mac1/mac2
// live in mac.zig; this file owns the ordering and the cookie hook. Both read
// paths call mac.verifyMac1 and return Mac1Failed before the first DH.
//
// Two crypto-critical decisions, both forced by SPEC (a round-trip test cannot
// tell the wrong choice from the right one):
//   (1) AEAD nonce: [0x00 x4] || big-endian u64 counter (SPEC 2.2 "big-endian
//       everywhere"; wire-layout decision). This is what makes a Bolina
//       handshake non-byte-compatible with WireGuard. Stated, not accidental.
//   (2) Prologue: SPEC declares none, so it is empty, matching the construction.
//
// Zero-heap, caller-owned (BE-WIRE-01). Parser (parser.zig) validates wire
// structures; this file consumes a validated buffer and does the crypto (D-018:
// transport is outside the M5 line budget).

const std = @import("std");
const crypto = std.crypto;

const Blake2s256 = crypto.hash.blake2.Blake2s256;
const Hmac = crypto.auth.hmac.Hmac;
const X25519 = crypto.dh.X25519;
const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;
const mac = @import("mac.zig");

// HMAC-BLAKE2s-256: the Noise HKDF core. Hmac(Blake2s256) uses Blake2s256
// unkeyed (init(.{})) under the standard ipad/opad construction, not BLAKE2's
// built-in keyed mode.
const HmacBlake2s256 = Hmac(Blake2s256);

// Noise framework constants for the 25519_ChaChaPoly_BLAKE2s variant.
pub const DHLEN: usize = 32; // X25519 public/secret/shared length (SPEC 2.1)
pub const HASHLEN: usize = 32; // BLAKE2s-256 output (SPEC 2.1)
pub const KEYLEN: usize = 32; // ChaCha20-Poly1305 key (SPEC 2.1)
pub const TAGLEN: usize = 16; // Poly1305 tag (SPEC 2.1)
pub const NONCELEN: usize = 12; // ChaCha20-Poly1305 nonce (SPEC 2.1)

// SPEC 4.1: the Noise_IK protocol name. 33 bytes, longer than HASHLEN, so the
// initial chaining hash is BLAKE2s-256(name) rather than a zero-padded name.
pub const PROTOCOL_NAME: []const u8 = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

// SPEC 4.1a message sizes and the offset of the first mac1 byte (the count of
// bytes mac1 covers). Bolina's own framing; the field set and order are
// WireGuard's.
pub const MSG1_SIZE: usize = 144; // handshake initiation
pub const MSG2_SIZE: usize = 92; // handshake response
pub const MSG1_BEFORE_MAC1: usize = 112; // type..encrypted_timestamp
pub const MSG2_BEFORE_MAC1: usize = 60; // type..encrypted_nothing

// Initiation field offsets (SPEC 4.1a, type 1).
pub const OFF1_SENDER_INDEX: usize = 4;
pub const OFF1_EPHEMERAL: usize = 8;
pub const OFF1_ENC_STATIC: usize = 40; // 48 bytes (32 + 16 tag)
pub const OFF1_ENC_TIMESTAMP: usize = 88; // 24 bytes (8 + 16 tag)
pub const OFF1_MAC1: usize = 112;
pub const OFF1_MAC2: usize = 128;

// Response field offsets (SPEC 4.1a, type 2).
pub const OFF2_SENDER_INDEX: usize = 4;
pub const OFF2_RECEIVER_INDEX: usize = 8;
pub const OFF2_EPHEMERAL: usize = 12;
pub const OFF2_ENC_NOTHING: usize = 44; // 16 bytes (0 + 16 tag)
pub const OFF2_MAC1: usize = 60;
pub const OFF2_MAC2: usize = 76;

// Errors a handshake can surface. mac1 failure is reported before any curve
// operation (BE-TR-04); a tampered ciphertext is DecryptFailed; a degenerate
// (low-order) peer public key is IdentityPoint and the handshake aborts.
pub const Error = error{ Mac1Failed, DecryptFailed, IdentityPoint };

// The two transport keys and the final transcript hash a completed handshake
// yields. send_key encrypts this side's outgoing transport; recv_key decrypts
// the peer's; handshake_hash is the value the post-handshake certificate
// signature binds (BE-TR-01). Split convention: output 1 is the initiator's
// sending key, output 2 the responder's, so the initiator and responder swap
// send/recv from the same (c1, c2) pair.
pub const HandshakeResult = struct {
    send_key: [KEYLEN]u8,
    recv_key: [KEYLEN]u8,
    handshake_hash: [HASHLEN]u8,
};

// A 32-byte field of a validated message buffer, copied out so it can be passed
// by value to the curve and AEAD APIs without holding the message alive.
fn field(comptime N: usize, buf: []const u8, off: usize) [N]u8 {
    var out: [N]u8 = undefined;
    @memcpy(&out, buf[off .. off + N]);
    return out;
}

// The ChaCha20-Poly1305 nonce for any session key counter: four zero bytes then
// the big-endian u64 counter (SPEC 2.2 "big-endian everywhere"; wire-layout
// decision pins the transport nonce). Shared by the handshake symmetric state
// (nonce counter) and the post-handshake transport AEAD (the packet counter).
pub fn transportNonce(counter: u64) [NONCELEN]u8 {
    var nb = [_]u8{0} ** NONCELEN;
    std.mem.writeInt(u64, nb[4..], counter, .big);
    return nb;
}

// ---------------------------------------------------------------------------
// HKDF (Noise). Two and three outputs over HMAC-BLAKE2s.
//
// temp_key = HMAC(ck, ikm); out1 = HMAC(temp_key, 0x01); out2 = HMAC(temp_key,
// out1 || 0x02); out3 = HMAC(temp_key, out2 || 0x03). The counter byte is the
// only domain separation, which is the Noise definition.

fn hkdf2(ck: [HASHLEN]u8, ikm: []const u8) struct { o1: [HASHLEN]u8, o2: [HASHLEN]u8 } {
    var temp_key: [HASHLEN]u8 = undefined;
    HmacBlake2s256.create(&temp_key, ikm, &ck);
    var o1: [HASHLEN]u8 = undefined;
    HmacBlake2s256.create(&o1, &[_]u8{1}, &temp_key);
    var buf: [HASHLEN + 1]u8 = undefined;
    @memcpy(buf[0..HASHLEN], &o1);
    buf[HASHLEN] = 2;
    var o2: [HASHLEN]u8 = undefined;
    HmacBlake2s256.create(&o2, buf[0..], &temp_key);
    return .{ .o1 = o1, .o2 = o2 };
}

fn hkdf3(ck: [HASHLEN]u8, ikm: []const u8) struct { o1: [HASHLEN]u8, o2: [HASHLEN]u8, o3: [HASHLEN]u8 } {
    var temp_key: [HASHLEN]u8 = undefined;
    HmacBlake2s256.create(&temp_key, ikm, &ck);
    var o1: [HASHLEN]u8 = undefined;
    HmacBlake2s256.create(&o1, &[_]u8{1}, &temp_key);
    var chain: [HASHLEN + 1]u8 = undefined;
    @memcpy(chain[0..HASHLEN], &o1);
    chain[HASHLEN] = 2;
    var o2: [HASHLEN]u8 = undefined;
    HmacBlake2s256.create(&o2, chain[0..], &temp_key);
    @memcpy(chain[0..HASHLEN], &o2);
    chain[HASHLEN] = 3;
    var o3: [HASHLEN]u8 = undefined;
    HmacBlake2s256.create(&o3, chain[0..], &temp_key);
    return .{ .o1 = o1, .o2 = o2, .o3 = o3 };
}

// ---------------------------------------------------------------------------
// The Noise symmetric state.

pub const SymmetricState = struct {
    h: [HASHLEN]u8,
    ck: [HASHLEN]u8,
    k: [KEYLEN]u8,
    n: u64,
    has_key: bool,

    // Initialize from the protocol name (longer than HASHLEN, so hash it) with
    // ck = h and no key. The prologue is empty (SPEC declares none).
    pub fn init() SymmetricState {
        var s: SymmetricState = undefined;
        Blake2s256.hash(PROTOCOL_NAME, &s.h, .{});
        s.ck = s.h;
        s.k = std.mem.zeroes([KEYLEN]u8);
        s.n = 0;
        s.has_key = false;
        return s;
    }

    // h = BLAKE2s(h || data).
    pub fn mixHash(self: *SymmetricState, data: []const u8) void {
        var hasher = Blake2s256.init(.{});
        hasher.update(&self.h);
        hasher.update(data);
        hasher.final(&self.h);
    }

    // ck, k = HKDF(ck, ikm, 2); reset the nonce, key now present.
    pub fn mixKey(self: *SymmetricState, ikm: [DHLEN]u8) void {
        const out = hkdf2(self.ck, &ikm);
        self.ck = out.o1;
        self.k = out.o2;
        self.n = 0;
        self.has_key = true;
    }

    // ck, h, k = HKDF(ck, ikm, 3); ck=o1, MixHash(o2), k=o3. Used by PSK
    // patterns; IK does not call it, but the symmetric state exposes the full
    // Noise API and it is unit-tested.
    pub fn mixKeyAndHash(self: *SymmetricState, ikm: []const u8) void {
        const out = hkdf3(self.ck, ikm);
        self.ck = out.o1;
        self.mixHash(&out.o2);
        self.k = out.o3;
        self.n = 0;
        self.has_key = true;
    }

    // The ChaChaPoly nonce: four zero bytes then the counter, big-endian u64
    // (SPEC 2.2 / wire-layout decision).
    fn nonce(n: u64) [NONCELEN]u8 {
        return transportNonce(n);
    }

    // EncryptAndHash: AEAD-encrypt plaintext under k with ad = h, append the tag,
    // advance the nonce, and MixHash the ciphertext-with-tag. With no key (the
    // pre-DH state), the plaintext passes through unchanged and is only hashed.
    // In Noise_IK every encrypted field comes after the first mixKey, so a key is
    // always present; the no-key branch is implemented for correctness.
    pub fn encryptAndHash(self: *SymmetricState, out: []u8, plaintext: []const u8) void {
        if (self.has_key) {
            const tag_off = plaintext.len;
            var tag: [TAGLEN]u8 = undefined;
            ChaCha20Poly1305.encrypt(out[0..plaintext.len], &tag, plaintext, &self.h, nonce(self.n), self.k);
            @memcpy(out[tag_off..][0..TAGLEN], &tag);
            self.n += 1;
            self.mixHash(out[0 .. plaintext.len + TAGLEN]);
        } else {
            @memcpy(out[0..plaintext.len], plaintext);
            self.mixHash(out[0..plaintext.len]);
        }
    }

    // DecryptAndHash: the inverse. A tag mismatch is DecryptFailed; the nonce
    // advances and the ciphertext-with-tag is mixed exactly as on encrypt, so a
    // matching transcript is a matching transcript both ways.
    pub fn decryptAndHash(self: *SymmetricState, out: []u8, ct: []const u8) Error!void {
        if (self.has_key) {
            const ct_len = ct.len - TAGLEN;
            const tag: [TAGLEN]u8 = ct[ct_len..][0..TAGLEN].*;
            ChaCha20Poly1305.decrypt(out[0..ct_len], ct[0..ct_len], tag, &self.h, nonce(self.n), self.k) catch return Error.DecryptFailed;
            self.n += 1;
            self.mixHash(ct);
        } else {
            @memcpy(out[0..ct.len], ct);
            self.mixHash(ct);
        }
    }

    // Split: two transport keys from HKDF(ck, "", 2). o1 is the initiator's
    // sending key, o2 the responder's.
    pub fn split(self: *SymmetricState) struct { c1: [KEYLEN]u8, c2: [KEYLEN]u8 } {
        const out = hkdf2(self.ck, &[_]u8{});
        return .{ .c1 = out.o1, .c2 = out.o2 };
    }
};

// ---------------------------------------------------------------------------
// X25519 helpers.

pub const X25519KeyPair = struct {
    secret: [DHLEN]u8,
    public: [DHLEN]u8,
};

// Derive an X25519 keypair from a caller-supplied secret. The secret source is
// the caller's (RNG in production, fixed bytes in a test); this module never
// generates long-term static material itself.
pub fn keypairFromSecret(secret: [DHLEN]u8) Error!X25519KeyPair {
    const public = X25519.recoverPublicKey(secret) catch return Error.IdentityPoint;
    return .{ .secret = secret, .public = public };
}

// Scalar multiplication of a local secret against a peer public key. The shared
// output is zero on a low-order point, which X25519 reports and we surface.
fn dh(local: X25519KeyPair, remote_pub: [DHLEN]u8) Error![DHLEN]u8 {
    return X25519.scalarmult(local.secret, remote_pub) catch Error.IdentityPoint;
}

// ---------------------------------------------------------------------------
// Noise_IK initiator.

pub const Initiator = struct {
    sym: SymmetricState,
    static_kp: X25519KeyPair,
    eph_kp: X25519KeyPair,
    responder_static_pub: [DHLEN]u8,
    // The responder's response ephemeral, captured while reading message 2.
    re: [DHLEN]u8,
    // Entropy for the per-handshake ephemeral key (std.Io, Zig 0.16: the
    // daemon threads init.io through; tests pass std.testing.io).
    io: std.Io,

    // The initiator knows the responder's static X25519 key (from its
    // certificate, SPEC 5.1a). The empty prologue leaves h at the protocol-name
    // hash; the responder static is the IK pre-message, mixed in once.
    pub fn init(io: std.Io, static_kp: X25519KeyPair, responder_static_pub: [DHLEN]u8) Initiator {
        var s = SymmetricState.init();
        s.mixHash(&responder_static_pub);
        return .{
            .sym = s,
            .static_kp = static_kp,
            .eph_kp = undefined,
            .responder_static_pub = responder_static_pub,
            .re = undefined,
            .io = io,
        };
    }

    // Write the 144-byte initiation (message 1). Tokens: e, es, s, ss, then the
    // encrypted timestamp. mac1 covers bytes 0..112; mac2 is the caller's cookie
    // (zeros when none is held).
    pub fn writeInitiation(
        self: *Initiator,
        out: []u8,
        sender_index: u32,
        timestamp_ms: u64,
        responder_sig_pubkey: mac.ResponderSigPubkey,
        mac2_cookie: [mac.MAC_BYTES]u8,
    ) Error!void {
        std.debug.assert(out.len >= MSG1_SIZE);

        // e: fresh ephemeral, written and hashed. std generates the seed and
        // retries identity-element draws, so no IdentityPoint path here.
        const eph = X25519.KeyPair.generate(self.io);
        self.eph_kp = .{ .secret = eph.secret_key, .public = eph.public_key };
        @memcpy(out[OFF1_EPHEMERAL..][0..DHLEN], &self.eph_kp.public);
        self.sym.mixHash(&self.eph_kp.public);

        // es: DH(e_i, s_R).
        self.sym.mixKey(try dh(self.eph_kp, self.responder_static_pub));

        // s: initiator static, encrypted and hashed.
        self.sym.encryptAndHash(out[OFF1_ENC_STATIC..][0 .. DHLEN + TAGLEN], &self.static_kp.public);

        // ss: DH(s_i, s_R).
        self.sym.mixKey(try dh(self.static_kp, self.responder_static_pub));

        // Bolina's encrypted timestamp (SPEC 2.2, u64 ms), encrypted and hashed.
        var ts_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &ts_bytes, timestamp_ms, .big);
        self.sym.encryptAndHash(out[OFF1_ENC_TIMESTAMP..][0 .. 8 + TAGLEN], &ts_bytes);

        // Framing and the DoS proofs (the framing is not part of the Noise
        // transcript; mac1 covers framing plus the crypto body).
        out[0] = 1;
        @memset(out[1..OFF1_SENDER_INDEX], 0);
        std.mem.writeInt(u32, out[OFF1_SENDER_INDEX..][0..4], sender_index, .big);
        const m1 = mac.computeMac1(responder_sig_pubkey, out[0..MSG1_BEFORE_MAC1]);
        @memcpy(out[OFF1_MAC1..][0..mac.MAC_BYTES], &m1);
        @memcpy(out[OFF1_MAC2..][0..mac.MAC_BYTES], &mac2_cookie);
    }

    // Read the 92-byte response (message 2), verifying mac1 first. Tokens:
    // e, ee, se, then the empty encrypted payload. On success the handshake is
    // complete and finalize() yields the transport keys.
    pub fn readResponse(
        self: *Initiator,
        msg2: []const u8,
        responder_sig_pubkey: mac.ResponderSigPubkey,
    ) Error!void {
        std.debug.assert(msg2.len >= MSG2_SIZE);

        // BE-TR-04: mac1 before any X25519.
        const m1_in: [mac.MAC_BYTES]u8 = field(mac.MAC_BYTES, msg2, OFF2_MAC1);
        if (!mac.verifyMac1(responder_sig_pubkey, msg2[0..MSG2_BEFORE_MAC1], m1_in)) return Error.Mac1Failed;

        // e: responder ephemeral, hashed; captured for ee/se.
        const eph_r = field(DHLEN, msg2, OFF2_EPHEMERAL);
        self.re = eph_r;
        self.sym.mixHash(&eph_r);

        // ee: DH(e_i, e_R).
        self.sym.mixKey(try dh(self.eph_kp, self.re));

        // se: DH(s_i, e_R).
        self.sym.mixKey(try dh(self.static_kp, self.re));

        // Empty encrypted payload: tag-only, verified and hashed.
        var nothing: [0]u8 = undefined;
        try self.sym.decryptAndHash(&nothing, msg2[OFF2_ENC_NOTHING..][0..TAGLEN]);
    }

    // After reading the response, split into transport keys. The initiator
    // sends under c1 and receives under c2.
    pub fn finalize(self: *Initiator) HandshakeResult {
        const sp = self.sym.split();
        return .{ .send_key = sp.c1, .recv_key = sp.c2, .handshake_hash = self.sym.h };
    }
};

// ---------------------------------------------------------------------------
// Noise_IK responder.

pub const Responder = struct {
    sym: SymmetricState,
    static_kp: X25519KeyPair,
    eph_kp: X25519KeyPair,
    responder_static_pub: [DHLEN]u8,
    // Peer (initiator) ephemeral and static, captured while reading message 1.
    re: [DHLEN]u8,
    remote_static_pub: [DHLEN]u8,
    // Entropy for the per-handshake ephemeral key (see Initiator.io).
    io: std.Io,

    pub fn init(io: std.Io, static_kp: X25519KeyPair) Responder {
        var s = SymmetricState.init();
        s.mixHash(&static_kp.public);
        return .{
            .sym = s,
            .static_kp = static_kp,
            .eph_kp = undefined,
            .responder_static_pub = static_kp.public,
            .re = undefined,
            .remote_static_pub = undefined,
            .io = io,
        };
    }

    // Read the 144-byte initiation (message 1), verifying mac1 before any DH.
    // Tokens: e, es, s, ss, then the encrypted timestamp.
    pub fn readInitiation(
        self: *Responder,
        msg1: []const u8,
        responder_sig_pubkey: mac.ResponderSigPubkey,
    ) Error!void {
        std.debug.assert(msg1.len >= MSG1_SIZE);

        // BE-TR-04: mac1 before any X25519.
        const m1_in: [mac.MAC_BYTES]u8 = field(mac.MAC_BYTES, msg1, OFF1_MAC1);
        if (!mac.verifyMac1(responder_sig_pubkey, msg1[0..MSG1_BEFORE_MAC1], m1_in)) return Error.Mac1Failed;

        // e: initiator ephemeral, hashed; captured for es/ee.
        const eph_i = field(DHLEN, msg1, OFF1_EPHEMERAL);
        self.re = eph_i;
        self.sym.mixHash(&eph_i);

        // es: DH(s_R, e_I).
        self.sym.mixKey(try dh(self.static_kp, self.re));

        // s: initiator static, decrypted and hashed; captured for ss/se.
        var static_i: [DHLEN]u8 = undefined;
        try self.sym.decryptAndHash(&static_i, msg1[OFF1_ENC_STATIC..][0 .. DHLEN + TAGLEN]);
        self.remote_static_pub = static_i;

        // ss: DH(s_R, s_I).
        self.sym.mixKey(try dh(self.static_kp, self.remote_static_pub));

        // Encrypted timestamp: verified and hashed. The anti-replay policy lives
        // in the session layer; here it is decrypted into the transcript.
        var ts: [8]u8 = undefined;
        try self.sym.decryptAndHash(&ts, msg1[OFF1_ENC_TIMESTAMP..][0 .. 8 + TAGLEN]);
    }

    // Write the 92-byte response (message 2). Tokens: e, ee, se, then the empty
    // encrypted payload.
    pub fn writeResponse(
        self: *Responder,
        out: []u8,
        sender_index: u32,
        receiver_index: u32,
        responder_sig_pubkey: mac.ResponderSigPubkey,
        mac2_cookie: [mac.MAC_BYTES]u8,
    ) Error!void {
        std.debug.assert(out.len >= MSG2_SIZE);

        // e: fresh ephemeral, written and hashed. std generates the seed and
        // retries identity-element draws, so no IdentityPoint path here.
        const eph = X25519.KeyPair.generate(self.io);
        self.eph_kp = .{ .secret = eph.secret_key, .public = eph.public_key };
        out[0] = 2;
        @memset(out[1..OFF2_SENDER_INDEX], 0);
        std.mem.writeInt(u32, out[OFF2_SENDER_INDEX..][0..4], sender_index, .big);
        std.mem.writeInt(u32, out[OFF2_RECEIVER_INDEX..][0..4], receiver_index, .big);
        @memcpy(out[OFF2_EPHEMERAL..][0..DHLEN], &self.eph_kp.public);
        self.sym.mixHash(&self.eph_kp.public);

        // ee: DH(e_R, e_I).
        self.sym.mixKey(try dh(self.eph_kp, self.re));

        // se: DH(e_R, s_I).
        self.sym.mixKey(try dh(self.eph_kp, self.remote_static_pub));

        // Empty encrypted payload.
        self.sym.encryptAndHash(out[OFF2_ENC_NOTHING..][0 .. 0 + TAGLEN], &[_]u8{});

        // DoS proofs.
        const m1 = mac.computeMac1(responder_sig_pubkey, out[0..MSG2_BEFORE_MAC1]);
        @memcpy(out[OFF2_MAC1..][0..mac.MAC_BYTES], &m1);
        @memcpy(out[OFF2_MAC2..][0..mac.MAC_BYTES], &mac2_cookie);
    }

    // After writing the response, split into transport keys. The responder
    // sends under c2 and receives under c1 (the swap of the initiator's pair).
    pub fn finalize(self: *Responder) HandshakeResult {
        const sp = self.sym.split();
        return .{ .send_key = sp.c2, .recv_key = sp.c1, .handshake_hash = self.sym.h };
    }
};
