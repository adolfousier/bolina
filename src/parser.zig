// parser.zig
//
// Zero-heap, total wire-format parsers for Bolina's PRE-AUTHENTICATION
// transport surface (SPEC.md section 4.1a), and the root of the parser
// module: the whole wire grammar, split along BE-SURF-01's authentication
// line (D-030/D-032, BE-SURF-03):
//
//   parser.zig          pre-authentication: handshake initiation/response,
//                       cookie reply, data-packet header. Everything an
//                       unauthenticated peer's bytes can reach.
//   parser/channel.zig  post-authentication channel surface: Envelope,
//                       Intent, Grant, Span, Effect, Claim.
//   parser/session.zig  post-authentication session surface: fragment
//                       header, lighthouse lookups, certificate.
//
// The shared reader (Cursor), ParseError, and the transport-wide limits live
// here; the two submodules are re-exported below, so one import still
// reaches the whole wire grammar, and qualified names (parser.channel.X,
// parser.session.X) make every caller say which side of the line it reads.
//
// Same discipline across the whole module: every multi-byte integer is
// big-endian (SPEC 2.2), the parser never allocates (every returned slice
// aliases the caller-supplied buffer), and version fields are parsed but
// not rejected here. SPEC section 2.2 makes version the sole negotiation
// surface ("negotiation is by the version field only"), so the wire layer
// records it and leaves version policy to the caller. Grant.version IS
// refused (BE-GRANT-03 step 0) by the verifier, not by the parser.
//
// Every error exit routes through the reject wrapper and every accepted
// return through the accept wrapper, both in coverage.zig: no file of the
// parser module carries a raw error return, zero exceptions. Gate M9
// (tools/prumo-verify) counts those wrapper call sites across the whole
// module as the coverage denominator and fails on any unmarked way out, so
// the denominator is the source, not a hand-kept list (CONTRIBUTING.md
// section 2).

const std = @import("std");
const coverage = @import("coverage.zig");

// The two post-authentication submodules, re-exported so one import reaches
// the whole wire grammar (D-032 decision 2).
pub const channel = @import("parser/channel.zig");
pub const session = @import("parser/session.zig");

// ---------------------------------------------------------------------------
// Transport-wide declared limits (SPEC BE-TR-05). MAX_MESSAGE is the
// reassembled-message ceiling shared by both sides of the authentication
// line (parser/channel.zig derives MAX_BODY from it); LEN_PUBKEY is shared
// the same way (envelope senders on the channel side, certificate keys on
// the session side). Every attacker-influenced size is bounded before it
// drives a slice.
// ---------------------------------------------------------------------------

pub const MAX_MESSAGE: usize = 1 << 20; // 1 MiB, reassembled message ceiling
pub const LEN_PUBKEY: usize = 32;

pub const LEN_RESERVED: usize = 3; // reserved bytes after the type byte (SPEC 2.2, 4.1a)
pub const LEN_EPHEMERAL: usize = 32; // X25519 unencrypted ephemeral public key (SPEC 4.1a)
pub const LEN_AEAD_TAG: usize = 16; // ChaCha20-Poly1305 authentication tag (SPEC 2.1)
pub const LEN_NONCE: usize = 12; // ChaCha20-Poly1305 96-bit nonce (SPEC 4.1a)
pub const LEN_MAC: usize = 16; // mac1 / mac2 keyed-BLAKE2s-128 (SPEC 4.4)
pub const LEN_ENCRYPTED_STATIC: usize = 48; // 32 static key + 16 tag (SPEC 4.1a)
pub const LEN_ENCRYPTED_TIMESTAMP: usize = 24; // 8 u64-ms timestamp + 16 tag (SPEC 4.1a)
pub const LEN_ENCRYPTED_NOTHING: usize = 16; // 0 plaintext + 16 tag (SPEC 4.1a)
pub const LEN_ENCRYPTED_COOKIE: usize = 32; // 16 cookie + 16 tag (SPEC 4.1a)
pub const LEN_TRANSPORT_HEADER: usize = 16; // type + reserved + receiver_index + counter (SPEC 4.1a)
pub const MAX_PACKET: usize = 1400; // transport packet ceiling (SPEC BE-TR-05)

// Transport message_type discriminants (SPEC section 4.1a). The parser
// validates byte 0 against the expected constant for the function called; it
// never dispatches on it, so these name the wire values, not control flow.
pub const MSG_HANDSHAKE_INITIATION: u8 = 1;
pub const MSG_HANDSHAKE_RESPONSE: u8 = 2;
pub const MSG_COOKIE_REPLY: u8 = 3;
pub const MSG_TRANSPORT_DATA: u8 = 4;

// Domain-separation tag for Ed25519 handshake signing (SPEC BE-SIG-01). The
// verifier prefixes tag || tbs before checking sig. The remaining tags are
// declared by the surface that carries them: parser/channel.zig
// (DOMAIN_ENVELOPE/SPAN/GRANT/REFUSAL) and parser/session.zig (DOMAIN_CERT).
pub const DOMAIN_HANDSHAKE: u8 = 0x05;

// ---------------------------------------------------------------------------
// Errors. Distinct kinds so tests assert the failure class, not a bag of
// "invalid". Every error is total: a rejection, never a read past the buffer.
// ---------------------------------------------------------------------------

pub const ParseError = error{
    Truncated, // input ended before a fixed/declared field completed
    Oversize, // a count or length exceeded its declared bound (BE-TR-05)
    TrailingBytes, // input carried bytes after the single structure (BE-WIRE-02)
    Malformed, // structural violation: wrong type byte or non-zero reserved (SPEC 4.1a, 2.2)
};

// ---------------------------------------------------------------------------
// Cursor: a position-tracking, bounds-checked reader over a caller slice,
// shared by the whole parser module (parser/channel.zig and
// parser/session.zig read through the same reader, so the truncation exit
// point stays one site). Centralising the bounds check here is what makes
// BE-WIRE-02 an invariant of the parser rather than a hope: every read
// routes through need(), so no path indexes past the end of the buffer.
// ---------------------------------------------------------------------------

pub const Cursor = struct {
    buf: []const u8,
    pos: usize = 0,

    fn remaining(self: *const Cursor) usize {
        return self.buf.len - self.pos;
    }

    fn need(self: *Cursor, n: usize) ParseError!void {
        if (self.remaining() < n) return coverage.reject(.cursor_truncated);
    }

    pub fn u8r(self: *Cursor) ParseError!u8 {
        try self.need(1);
        const v = self.buf[self.pos];
        self.pos += 1;
        return v;
    }

    pub fn u16be(self: *Cursor) ParseError!u16 {
        try self.need(2);
        const v = std.mem.readInt(u16, self.buf[self.pos..][0..2], .big);
        self.pos += 2;
        return v;
    }

    pub fn u32be(self: *Cursor) ParseError!u32 {
        try self.need(4);
        const v = std.mem.readInt(u32, self.buf[self.pos..][0..4], .big);
        self.pos += 4;
        return v;
    }

    pub fn u64be(self: *Cursor) ParseError!u64 {
        try self.need(8);
        const v = std.mem.readInt(u64, self.buf[self.pos..][0..8], .big);
        self.pos += 8;
        return v;
    }

    // A slice of n bytes aliased into the caller buffer. No allocation.
    pub fn take(self: *Cursor, n: usize) ParseError![]const u8 {
        try self.need(n);
        const out = self.buf[self.pos .. self.pos + n];
        self.pos += n;
        return out;
    }

    // u16-length-prefixed field with a declared maximum.
    pub fn field16(self: *Cursor, max: usize) ParseError![]const u8 {
        const len = try self.u16be();
        if (len > max) return coverage.reject(.field16_oversize);
        return try self.take(@intCast(len));
    }

    // u32-length-prefixed field with a declared maximum.
    pub fn field32(self: *Cursor, max: u32) ParseError![]const u8 {
        const len = try self.u32be();
        if (len > max) return coverage.reject(.field32_oversize);
        return try self.take(@intCast(len));
    }
};

// ---------------------------------------------------------------------------
// Transport messages (SPEC 4.1a)
//
// Four byte-level layouts, pinned in SPEC section 4.1a. Bolina's transport is
// NOT byte-compatible with WireGuard: big-endian integers (SPEC 2.2), u64-ms
// timestamps (SPEC 2.2), and a ChaCha20-Poly1305 cookie (SPEC 2.1) diverge
// from WireGuard's little-endian / Tai64n / XChaCha20-Poly1305 (D-019).
//
// These parsers are STRUCTURAL ONLY (D-018: bytes-to-fields lives in the
// parser module). They validate the type discriminator, enforce zero reserved
// bytes (SPEC 2.2), check exact lengths for the fixed messages, and slice the
// authenticated ciphertexts out without decrypting or authenticating them.
// mac1/mac2 verification, cookie decryption, and Noise handshake state are
// transport-module concerns (tasks 8-10), not parser concerns.
//
// Every error exit routes through coverage.reject(); every accepted return
// through coverage.accept(). The Malformed error covers the two structural
// violations SPEC 2.2 / 4.1a make a parse failure: a wrong type byte and a
// non-zero reserved field.
// ---------------------------------------------------------------------------

// Handshake initiation (SPEC 4.1a). Fixed 144 bytes:
//   u8 type(=1) | [3] reserved(=0) | u32 sender_index
//   [32] ephemeral | [48] encrypted_static | [24] encrypted_timestamp
//   [16] mac1 | [16] mac2
pub const HandshakeInitiation = struct {
    sender_index: u32,
    ephemeral: []const u8,
    encrypted_static: []const u8,
    encrypted_timestamp: []const u8,
    mac1: []const u8,
    mac2: []const u8,
};

pub fn parseHandshakeInitiation(buf: []const u8) ParseError!HandshakeInitiation {
    var c = Cursor{ .buf = buf };
    const msg_type = try c.u8r();
    if (msg_type != MSG_HANDSHAKE_INITIATION) return coverage.reject(.hs_init_type);
    const reserved = try c.take(LEN_RESERVED);
    if (reserved[0] != 0 or reserved[1] != 0 or reserved[2] != 0)
        return coverage.reject(.hs_init_reserved);
    const sender_index = try c.u32be();
    const ephemeral = try c.take(LEN_EPHEMERAL);
    const encrypted_static = try c.take(LEN_ENCRYPTED_STATIC);
    const encrypted_timestamp = try c.take(LEN_ENCRYPTED_TIMESTAMP);
    const mac1 = try c.take(LEN_MAC);
    const mac2 = try c.take(LEN_MAC);
    if (c.pos != buf.len) return coverage.reject(.hs_init_trailing);
    coverage.accept(.hs_init_accepted);
    return .{
        .sender_index = sender_index,
        .ephemeral = ephemeral,
        .encrypted_static = encrypted_static,
        .encrypted_timestamp = encrypted_timestamp,
        .mac1 = mac1,
        .mac2 = mac2,
    };
}

// Handshake response (SPEC 4.1a). Fixed 92 bytes:
//   u8 type(=2) | [3] reserved(=0) | u32 sender_index | u32 receiver_index
//   [32] ephemeral | [16] encrypted_nothing | [16] mac1 | [16] mac2
pub const HandshakeResponse = struct {
    sender_index: u32,
    receiver_index: u32,
    ephemeral: []const u8,
    encrypted_nothing: []const u8,
    mac1: []const u8,
    mac2: []const u8,
};

pub fn parseHandshakeResponse(buf: []const u8) ParseError!HandshakeResponse {
    var c = Cursor{ .buf = buf };
    const msg_type = try c.u8r();
    if (msg_type != MSG_HANDSHAKE_RESPONSE) return coverage.reject(.hs_resp_type);
    const reserved = try c.take(LEN_RESERVED);
    if (reserved[0] != 0 or reserved[1] != 0 or reserved[2] != 0)
        return coverage.reject(.hs_resp_reserved);
    const sender_index = try c.u32be();
    const receiver_index = try c.u32be();
    const ephemeral = try c.take(LEN_EPHEMERAL);
    const encrypted_nothing = try c.take(LEN_ENCRYPTED_NOTHING);
    const mac1 = try c.take(LEN_MAC);
    const mac2 = try c.take(LEN_MAC);
    if (c.pos != buf.len) return coverage.reject(.hs_resp_trailing);
    coverage.accept(.hs_resp_accepted);
    return .{
        .sender_index = sender_index,
        .receiver_index = receiver_index,
        .ephemeral = ephemeral,
        .encrypted_nothing = encrypted_nothing,
        .mac1 = mac1,
        .mac2 = mac2,
    };
}

// Cookie reply (SPEC 4.1a). Fixed 52 bytes:
//   u8 type(=3) | [3] reserved(=0) | u32 receiver_index
//   [12] nonce | [32] encrypted_cookie
pub const CookieReply = struct {
    receiver_index: u32,
    nonce: []const u8,
    encrypted_cookie: []const u8,
};

pub fn parseCookieReply(buf: []const u8) ParseError!CookieReply {
    var c = Cursor{ .buf = buf };
    const msg_type = try c.u8r();
    if (msg_type != MSG_COOKIE_REPLY) return coverage.reject(.cookie_type);
    const reserved = try c.take(LEN_RESERVED);
    if (reserved[0] != 0 or reserved[1] != 0 or reserved[2] != 0)
        return coverage.reject(.cookie_reserved);
    const receiver_index = try c.u32be();
    const nonce = try c.take(LEN_NONCE);
    const encrypted_cookie = try c.take(LEN_ENCRYPTED_COOKIE);
    if (c.pos != buf.len) return coverage.reject(.cookie_trailing);
    coverage.accept(.cookie_accepted);
    return .{
        .receiver_index = receiver_index,
        .nonce = nonce,
        .encrypted_cookie = encrypted_cookie,
    };
}

// Transport data packet header (SPEC 4.1a). 16-byte header + variable payload:
//   u8 type(=4) | [3] reserved(=0) | u32 receiver_index | u64 counter
//   [n] encrypted_payload   (n >= 16 for the AEAD tag, n <= 1384 under BE-TR-05)
//
// The payload is every byte after the 16-byte header: a fragment of a
// reassembled message (tasks 9-10) carrying its own ChaCha20-Poly1305 tag.
// This parser exposes the payload as an aliased slice and bounds it; it does
// not decrypt, reorder, or reassemble. There is no totality trailing check:
// the payload is the variable-length suffix by definition, so BE-WIRE-02
// totality holds because the header is fixed and the remainder is the payload.
// The fragment header inside the decrypted payload is post-authentication
// (SPEC 4.5, D-032) and lives in parser/session.zig.
pub const DataPacketHeader = struct {
    receiver_index: u32,
    counter: u64,
    encrypted_payload: []const u8,
};

pub fn parseDataPacketHeader(buf: []const u8) ParseError!DataPacketHeader {
    var c = Cursor{ .buf = buf };
    const msg_type = try c.u8r();
    if (msg_type != MSG_TRANSPORT_DATA) return coverage.reject(.data_type);
    const reserved = try c.take(LEN_RESERVED);
    if (reserved[0] != 0 or reserved[1] != 0 or reserved[2] != 0)
        return coverage.reject(.data_reserved);
    const receiver_index = try c.u32be();
    const counter = try c.u64be();
    const encrypted_payload = buf[c.pos..];
    if (encrypted_payload.len < LEN_AEAD_TAG) return coverage.reject(.data_payload_short);
    if (encrypted_payload.len > MAX_PACKET - LEN_TRANSPORT_HEADER)
        return coverage.reject(.data_payload_oversize);
    coverage.accept(.data_accepted);
    return .{
        .receiver_index = receiver_index,
        .counter = counter,
        .encrypted_payload = encrypted_payload,
    };
}
