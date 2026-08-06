// parser.zig
//
// Zero-heap, total wire-format parsers for Bolina (SPEC.md section 2.2, 6.2, 6.3).
//
// This is the LANGUAGE.md section 4 implementation slice, item 1: the Envelope
// parser under BE-WIRE-01 (no heap allocation; offsets/lengths into a caller
// slice) and BE-WIRE-02 (totality: every input either yields exactly one valid
// structure or a rejection, and the parser never reads outside the input).
//
// All multi-byte integers are big-endian (SPEC section 2.2). The parser never
// allocates: every returned slice aliases the caller-supplied buffer.
//
// Version is parsed but not rejected here. SPEC section 2.2 makes version the
// sole negotiation surface ("negotiation is by the version field only"), so the
// wire layer records it and leaves version policy to the caller. Grant.version
// IS refused (BE-GRANT-03 step 0) by the verifier, not by this parser.
//
// Every error exit routes through the reject wrapper and every accepted
// return through the accept wrapper, both in coverage.zig: this file carries
// no raw error returns, zero exceptions. Gate M9 (tools/prumo-verify) counts
// those wrapper call sites as the coverage denominator and fails on any
// unmarked way out, so the denominator is this file, not a hand-kept list
// (CONTRIBUTING.md section 2).

const std = @import("std");
const coverage = @import("coverage.zig");

// ---------------------------------------------------------------------------
// Declared limits (SPEC BE-TR-05). These are the only attacker-influenced
// sizes on the wire; every one is bounded before it drives a slice.
// ---------------------------------------------------------------------------

pub const MAX_MESSAGE: usize = 1 << 20; // 1 MiB, reassembled message ceiling
pub const MAX_HEADER: usize = 512; // envelope overhead (version..sig, slack)
pub const MAX_BODY: u32 = @intCast(MAX_MESSAGE - MAX_HEADER); // body_len bound
pub const MAX_PARENTS: u8 = 4; // parent_count bound (SPEC 6.2)
pub const MAX_RESOURCE: usize = 256; // Intent.resource_id (SPEC 6.3)
pub const MAX_ACTION: u32 = 256 * 1024; // Intent.action, opaque (SPEC 6.3)
pub const MAX_RATIONALE: usize = 4 * 1024; // Intent.rationale (SPEC 6.3)

// Fixed field widths, named so every magic number in the parser is traceable
// to the SPEC grammar.
pub const LEN_CHANNEL_ID: usize = 32;
pub const LEN_PUBKEY: usize = 32;
pub const LEN_PARENT: usize = 32;
pub const LEN_SIG: usize = 64;
pub const LEN_INTENT_ID: usize = 16;
pub const LEN_GRANT_ID: usize = 16;
pub const LEN_ACTION_DIGEST: usize = 32; // BLAKE2s-256 of Intent.action (BE-GRANT-02)

// Fixed widths for the attestation structures (SPEC section 7).
pub const LEN_SPAN_ID: usize = 16; // Span.span_id (SPEC 7.1)
pub const LEN_TRACE_ID: usize = 16; // Span.trace_id (SPEC 7.1)
pub const LEN_ORIGIN: usize = 32; // Span.origin: BLAKE2s of the publishing Effect envelope (SPEC 7.1)
pub const LEN_DIGEST: usize = 32; // Span.digest / Effect.output_digest: BLAKE2s of observed output
pub const LEN_SPAN_REF: usize = 16; // Claim.span_ids element (SPEC 7.2)
pub const MAX_CLAIM_TEXT: usize = 1024; // Claim.text (SPEC 7.2)
pub const MAX_SUBJECT: usize = 256; // Claim.subject (SPEC 7.2)

// Fixed widths for the transport messages (SPEC section 4.1a). These pin the
// four Noise-handshake / data-packet layouts byte for byte; every magic number
// in the transport parsers below traces to one of them.
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

// Mesh / fragment field widths (SPEC section 4.5, 5.1a). The fragment header
// is the flat msg_id/index/total prefix on every fragmented packet body; the
// lighthouse lookup fields name the grammar in section 5.1a.
pub const LEN_FRAGMENT_HEADER: usize = 12; // msg_id u64 + index u16 + total u16 (SPEC 4.5)
pub const LEN_OVERLAY_ADDR: usize = 16; // overlay address, the mesh node id (SPEC 5.1)
pub const LEN_ENDPOINT: usize = 19; // lighthouse endpoint tuple: family u8 + [16] addr + u16 port (SPEC 5.1a)

// Certificate field widths (SPEC section 3.1). The certificate is the
// identity structure: a version byte, a role bitmask, the holder Ed25519
// signing key and X25519 key-exchange key, a validity window, a UTF-8
// label, group identifiers, and one to four CA countersignatures. name is
// a convenience label only (SPEC 3.1: no authorization decision may depend
// on name); group_ids are 8-byte BLAKE2s-256 prefixes parsed as opaque
// bytes. sig_pubkey reuses LEN_PUBKEY (Ed25519, 32 bytes).
pub const LEN_KEX_PUBKEY: usize = 32; // X25519 key-exchange public key (SPEC 3.1)
pub const LEN_GROUP_ID: usize = 8; // group_id = BLAKE2s-256(group_name)[0..8] (SPEC 3.1)
pub const MAX_NAME: usize = 64; // Cert.name length bound (SPEC 3.1)
pub const MAX_GROUPS: u8 = 16; // Cert.group_count bound (SPEC 3.1)
pub const MAX_CA_SIGS: u8 = 4; // Cert.ca_sig_count upper bound (SPEC 3.1)
pub const LEN_CA_KEY: usize = 32; // CA Ed25519 public key (SPEC 3.1)
pub const LEN_CA_SIG: usize = 64; // CA Ed25519 signature (SPEC 3.1)

// Transport message_type discriminants (SPEC section 4.1a). The parser
// validates byte 0 against the expected constant for the function called; it
// never dispatches on it, so these name the wire values, not control flow.
pub const MSG_HANDSHAKE_INITIATION: u8 = 1;
pub const MSG_HANDSHAKE_RESPONSE: u8 = 2;
pub const MSG_COOKIE_REPLY: u8 = 3;
pub const MSG_TRANSPORT_DATA: u8 = 4;

// Domain-separation tags for Ed25519 signing (SPEC BE-SIG-01). The verifier
// (LANGUAGE.md section 4 item 2) prefixes tag || tbs before checking sig.
pub const DOMAIN_CERT: u8 = 0x01;
pub const DOMAIN_ENVELOPE: u8 = 0x02;
pub const DOMAIN_SPAN: u8 = 0x03;
pub const DOMAIN_GRANT: u8 = 0x04;
pub const DOMAIN_HANDSHAKE: u8 = 0x05;
pub const DOMAIN_REFUSAL: u8 = 0x06;

// Envelope body_type discriminant (SPEC 6.3).
pub const BODY_UTTERANCE: u8 = 1;
pub const BODY_INTENT: u8 = 2;
pub const BODY_GRANT: u8 = 3;
pub const BODY_EFFECT: u8 = 4;
pub const BODY_CONTROL: u8 = 5;
pub const BODY_REFUSAL: u8 = 6;

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
// Cursor: a position-tracking, bounds-checked reader over a caller slice.
// Centralising the bounds check here is what makes BE-WIRE-02 an invariant of
// the parser rather than a hope: every read routes through need(), so no path
// indexes past the end of the buffer.
// ---------------------------------------------------------------------------

const Cursor = struct {
    buf: []const u8,
    pos: usize = 0,

    fn remaining(self: *const Cursor) usize {
        return self.buf.len - self.pos;
    }

    fn need(self: *Cursor, n: usize) ParseError!void {
        if (self.remaining() < n) return coverage.reject(.cursor_truncated);
    }

    fn u8r(self: *Cursor) ParseError!u8 {
        try self.need(1);
        const v = self.buf[self.pos];
        self.pos += 1;
        return v;
    }

    fn u16be(self: *Cursor) ParseError!u16 {
        try self.need(2);
        const v = std.mem.readInt(u16, self.buf[self.pos..][0..2], .big);
        self.pos += 2;
        return v;
    }

    fn u32be(self: *Cursor) ParseError!u32 {
        try self.need(4);
        const v = std.mem.readInt(u32, self.buf[self.pos..][0..4], .big);
        self.pos += 4;
        return v;
    }

    fn u64be(self: *Cursor) ParseError!u64 {
        try self.need(8);
        const v = std.mem.readInt(u64, self.buf[self.pos..][0..8], .big);
        self.pos += 8;
        return v;
    }

    // A slice of n bytes aliased into the caller buffer. No allocation.
    fn take(self: *Cursor, n: usize) ParseError![]const u8 {
        try self.need(n);
        const out = self.buf[self.pos .. self.pos + n];
        self.pos += n;
        return out;
    }

    // u16-length-prefixed field with a declared maximum.
    fn field16(self: *Cursor, max: usize) ParseError![]const u8 {
        const len = try self.u16be();
        if (len > max) return coverage.reject(.field16_oversize);
        return try self.take(@intCast(len));
    }

    // u32-length-prefixed field with a declared maximum.
    fn field32(self: *Cursor, max: u32) ParseError![]const u8 {
        const len = try self.u32be();
        if (len > max) return coverage.reject(.field32_oversize);
        return try self.take(@intCast(len));
    }
};

// ---------------------------------------------------------------------------
// Envelope (SPEC 6.2)
//
//   u8 version(=2) | [32] channel_id | [32] sender | u64 seq
//   u8 parent_count(0..4) | [32]* parents | u64 ts | u8 body_type
//   u32 body_len | body | [64] sig
//
// tbs is every byte before sig; sig is Ed25519 over (DOMAIN_ENVELOPE || tbs).
// ---------------------------------------------------------------------------

pub const Envelope = struct {
    version: u8,
    channel_id: []const u8,
    sender: []const u8,
    seq: u64,
    parent_count: u8,
    parents: []const u8,
    ts: u64,
    body_type: u8,
    body: []const u8,
    tbs: []const u8,
    sig: []const u8,
};

pub fn parseEnvelope(buf: []const u8) ParseError!Envelope {
    var c = Cursor{ .buf = buf };
    const version = try c.u8r();
    const channel_id = try c.take(LEN_CHANNEL_ID);
    const sender = try c.take(LEN_PUBKEY);
    const seq = try c.u64be();
    const parent_count = try c.u8r();
    if (parent_count > MAX_PARENTS) return coverage.reject(.env_parent_oversize);
    const parents = try c.take(@as(usize, parent_count) * LEN_PARENT);
    const ts = try c.u64be();
    const body_type = try c.u8r();
    const body_len = try c.u32be();
    if (body_len > MAX_BODY) return coverage.reject(.env_body_oversize);
    const body = try c.take(@intCast(body_len));
    const tbs = buf[0..c.pos];
    const sig = try c.take(LEN_SIG);
    // BE-WIRE-02 totality: the buffer holds exactly one envelope, nothing more.
    if (c.pos != buf.len) return coverage.reject(.env_trailing);
    coverage.accept(.env_accepted);
    return .{
        .version = version,
        .channel_id = channel_id,
        .sender = sender,
        .seq = seq,
        .parent_count = parent_count,
        .parents = parents,
        .ts = ts,
        .body_type = body_type,
        .body = body,
        .tbs = tbs,
        .sig = sig,
    };
}

// ---------------------------------------------------------------------------
// Intent body (SPEC 6.3)
//
//   [16] intent_id | u16 resource_len, resource_id(<=256)
//   u32 action_len, action(<=256KiB, OPAQUE) | u16 rationale_len, rationale(<=4KiB)
//
// The daemon treats action as opaque bytes (BE-BODY-01); it never parses them.
// This parser only slices action out so a verifier can hash it for BE-GRANT-02.
// ---------------------------------------------------------------------------

pub const Intent = struct {
    intent_id: []const u8,
    resource_id: []const u8,
    action: []const u8,
    rationale: []const u8,
};

pub fn parseIntent(buf: []const u8) ParseError!Intent {
    var c = Cursor{ .buf = buf };
    const intent_id = try c.take(LEN_INTENT_ID);
    const resource_id = try c.field16(MAX_RESOURCE);
    const action = try c.field32(MAX_ACTION);
    const rationale = try c.field16(MAX_RATIONALE);
    if (c.pos != buf.len) return coverage.reject(.intent_trailing);
    coverage.accept(.intent_accepted);
    return .{
        .intent_id = intent_id,
        .resource_id = resource_id,
        .action = action,
        .rationale = rationale,
    };
}

// ---------------------------------------------------------------------------
// Grant (SPEC 8.1)
//
//   u8 version(=2) | [16] grant_id | [16] intent_id | [32] approver
//   [32] subject | [32] executor | u16 resource_len, resource_id
//   [32] action_digest | u64 not_after | [64] sig
//
// tbs is every byte before sig; sig is Ed25519 over (DOMAIN_GRANT || tbs).
// Like the Envelope, version is parsed here but refused by the verifier
// (BE-GRANT-03 step 0), keeping parsing total and policy out of the parser.
//
// wire is the full input buffer this Grant was parsed from (tbs || sig). The
// verifier borrows it to seal the capability by content (BE-GRANT-03c): a
// keyed digest over wire is frozen at verification time and recomputed over the
// same live bytes at every access, so a caller write to the buffer between
// verification and consumption is detected, not silently honored.
// ---------------------------------------------------------------------------

pub const Grant = struct {
    version: u8,
    grant_id: []const u8,
    intent_id: []const u8,
    approver: []const u8,
    subject: []const u8,
    executor: []const u8,
    resource_id: []const u8,
    action_digest: []const u8,
    not_after: u64,
    tbs: []const u8,
    sig: []const u8,
    wire: []const u8,
};

pub fn parseGrant(buf: []const u8) ParseError!Grant {
    var c = Cursor{ .buf = buf };
    const version = try c.u8r();
    const grant_id = try c.take(LEN_GRANT_ID);
    const intent_id = try c.take(LEN_INTENT_ID);
    const approver = try c.take(LEN_PUBKEY);
    const subject = try c.take(LEN_PUBKEY);
    const executor = try c.take(LEN_PUBKEY);
    const resource_id = try c.field16(MAX_RESOURCE);
    const action_digest = try c.take(LEN_ACTION_DIGEST);
    const not_after = try c.u64be();
    const tbs = buf[0..c.pos];
    const sig = try c.take(LEN_SIG);
    // BE-WIRE-02 totality: exactly one grant, nothing after it.
    if (c.pos != buf.len) return coverage.reject(.grant_trailing);
    coverage.accept(.grant_accepted);
    return .{
        .version = version,
        .grant_id = grant_id,
        .intent_id = intent_id,
        .approver = approver,
        .subject = subject,
        .executor = executor,
        .resource_id = resource_id,
        .action_digest = action_digest,
        .not_after = not_after,
        .tbs = tbs,
        .sig = sig,
        .wire = buf,
    };
}

// ---------------------------------------------------------------------------
// Span (SPEC 7.1)
//
//   u8 version(=2) | [16] span_id | [16] trace_id | u16 resource_len, resource_id(<=256)
//   u8 method_id | u8 volatility | [32] origin | u64 observed_at
//   [32] digest | [32] executor | [64] sig
//
// sig is Ed25519 over all preceding bytes, domain tag 0x03 (BE-SIG-01). The
// evidence class is DERIVED from method_id by the receiver (BE-EVID-15), never
// carried on the wire, so the parser records method_id and decides nothing
// about class here. volatility is the executor's declaration; BE-EVID-06 makes
// an unrecognized value the receiver's floor, also a verifier concern. Version
// is parsed but not refused, same as Envelope and Grant: policy stays out of
// the parser, BE-WIRE-02 totality stays in.
//
// readSpan advances a SHARED cursor over one Span with no trailing check: the
// byte that ends one span is the first byte of the next (inline spans inside
// an Effect, SPEC 6.3) or of a following field. The trailing check belongs to
// the parser that owns the buffer, not to the reader. Every exit routes through
// the shared Cursor rejection, so readSpan adds no exit point of its own (M9).
// ---------------------------------------------------------------------------

pub const Span = struct {
    version: u8,
    span_id: []const u8,
    trace_id: []const u8,
    resource_id: []const u8,
    method_id: u8,
    volatility: u8,
    origin: []const u8,
    observed_at: u64,
    digest: []const u8,
    executor: []const u8,
    tbs: []const u8,
    sig: []const u8,
};

fn readSpan(c: *Cursor) ParseError!Span {
    const start = c.pos;
    const version = try c.u8r();
    const span_id = try c.take(LEN_SPAN_ID);
    const trace_id = try c.take(LEN_TRACE_ID);
    const resource_id = try c.field16(MAX_RESOURCE);
    const method_id = try c.u8r();
    const volatility = try c.u8r();
    const origin = try c.take(LEN_ORIGIN);
    const observed_at = try c.u64be();
    const digest = try c.take(LEN_DIGEST);
    const executor = try c.take(LEN_PUBKEY);
    const tbs = c.buf[start..c.pos];
    const sig = try c.take(LEN_SIG);
    return .{
        .version = version,
        .span_id = span_id,
        .trace_id = trace_id,
        .resource_id = resource_id,
        .method_id = method_id,
        .volatility = volatility,
        .origin = origin,
        .observed_at = observed_at,
        .digest = digest,
        .executor = executor,
        .tbs = tbs,
        .sig = sig,
    };
}

pub fn parseSpan(buf: []const u8) ParseError!Span {
    var c = Cursor{ .buf = buf };
    const s = try readSpan(&c);
    // BE-WIRE-02 totality: exactly one span, nothing after it.
    if (c.pos != buf.len) return coverage.reject(.span_trailing);
    coverage.accept(.span_accepted);
    return s;
}

// ---------------------------------------------------------------------------
// Effect body (SPEC 6.3)
//
//   [16] intent_id | [16] grant_id | u8 ok | i32 exit_code
//   u8 span_count | Span[] | [32] output_digest
//
// The Effect is a body (body_type 4) inside a signed Envelope (SPEC 6.2); it
// authenticates nothing itself, so parseEffect takes the body slice. Inline
// spans are full Span wires (tbs || sig, SPEC 7.1) walked here for totality:
// readSpan consumes every byte of the span region before output_digest is read,
// so a truncated or overlong span is rejected, not silently mis-sliced.
// exit_code is i32 on the wire; read as u32 and bit-cast (identical 4 bytes,
// no pointer mint: @bitCast to a non-pointer is outside the M8 forbidden set).
// ok, exit_code and span_count are parsed, not policy-checked: BE-EFF-01 and the
// Utterance-level span bound (BE-EVID-10) are verifier concerns. No per-Effect
// span cap is declared in BE-TR-05, so none is invented here; body_len bounds
// the whole input and a span_count past the buffer truncates via readSpan.
// ---------------------------------------------------------------------------

pub const Effect = struct {
    intent_id: []const u8,
    grant_id: []const u8,
    ok: u8,
    exit_code: i32,
    span_count: u8,
    spans: []const u8, // raw span region: span_count full Span wires, caller re-parses
    output_digest: []const u8,
};

pub fn parseEffect(buf: []const u8) ParseError!Effect {
    var c = Cursor{ .buf = buf };
    const intent_id = try c.take(LEN_INTENT_ID);
    const grant_id = try c.take(LEN_GRANT_ID);
    const ok = try c.u8r();
    const exit_code = @as(i32, @bitCast(try c.u32be()));
    const span_count = try c.u8r();
    const span_start = c.pos;
    var i: usize = 0;
    while (i < span_count) : (i += 1) {
        _ = try readSpan(&c);
    }
    const spans = buf[span_start..c.pos];
    const output_digest = try c.take(LEN_DIGEST);
    if (c.pos != buf.len) return coverage.reject(.effect_trailing);
    coverage.accept(.effect_accepted);
    return .{
        .intent_id = intent_id,
        .grant_id = grant_id,
        .ok = ok,
        .exit_code = exit_code,
        .span_count = span_count,
        .spans = spans,
        .output_digest = output_digest,
    };
}

// ---------------------------------------------------------------------------
// Claim body (SPEC 7.2)
//
//   u16 text_len, text(<=1KiB) | u16 subject_len, subject(<=256)
//   u8 confidence_q8 | u8 span_count | [16]* span_ids
//
// A Claim carries no signature of its own: it is authenticated only inside a
// signed Utterance envelope (BE-EVID-08). The Utterance grammar is deferred to
// RED-TEAM-09 F1, so this parser fixes the Claim body layout against the
// vector in test/vectors.json. confidence_q8 is the sender's upper-bound
// request (BE-EVID-02); the receiver recomputes, so the parser records the
// byte and enforces nothing about it. span_ids are 16 bytes each; span_count is
// bounded by the enclosing body_len, not by a per-claim cap (BE-TR-05 declares
// none; the 64-span bound is on the Utterance, BE-EVID-10).
// ---------------------------------------------------------------------------

pub const Claim = struct {
    text: []const u8,
    subject: []const u8,
    confidence_q8: u8,
    span_count: u8,
    span_ids: []const u8, // span_count * 16 bytes, aliased into the body
};

pub fn parseClaim(buf: []const u8) ParseError!Claim {
    var c = Cursor{ .buf = buf };
    const text = try c.field16(MAX_CLAIM_TEXT);
    const subject = try c.field16(MAX_SUBJECT);
    const confidence_q8 = try c.u8r();
    const span_count = try c.u8r();
    const span_ids = try c.take(@as(usize, span_count) * LEN_SPAN_REF);
    if (c.pos != buf.len) return coverage.reject(.claim_trailing);
    coverage.accept(.claim_accepted);
    return .{
        .text = text,
        .subject = subject,
        .confidence_q8 = confidence_q8,
        .span_count = span_count,
        .span_ids = span_ids,
    };
}

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

// ---------------------------------------------------------------------------
// Fragment header (SPEC section 4.5) and lighthouse lookups (SPEC section 5.1a).
//
// These are session-AEAD plaintext bodies: a fragment header prefixes every
// fragmented packet body, and LookupRequest / LookupResponse are the lighthouse
// discovery messages. None carries its own Ed25519 signature; each is
// authenticated by the transport session it rides in (D-020).
//
// Derived max for the fragment `total` field: a reassembled message is bounded
// by MAX_MESSAGE (1 MiB, BE-TR-05). The smallest fragment payload is one byte,
// so the theoretical fragment ceiling is MAX_MESSAGE itself (1,048,576), which
// is wider than the u16 `total` range. Every u16-representable `total` is
// therefore consistent with MAX_MESSAGE (65535 one-byte fragments reassemble to
// 64 KiB, under the 1 MiB ceiling), and reading `total` as a u16 is itself the
// derived-max clamp. MAX_FRAGMENTS is not a row in the BE-TR-05 table, so no
// tighter limit is declared here; inventing one would add an undeclared bound.
// Fragment indices are zero-based: a valid index is in [0, total). (SPEC 4.5)
//
// BE-MESH-07: LookupRequest and LookupResponse MUST travel inside an
// established session with a lighthouse and MUST NOT be parsed from
// unauthenticated input. This parser performs structural validation only; the
// caller is responsible for having authenticated the session. The served
// certificate is returned as an opaque byte slice here and verified under
// BE-ID-01..04 by the caller (BE-MESH-04); its internal structure is walked by
// the certificate parser in a later task. (SPEC 5.1a)
// ---------------------------------------------------------------------------

pub const FragmentHeader = struct {
    msg_id: u64,
    index: u16,
    total: u16,
    payload: []const u8,
};

pub const LookupRequest = struct {
    version: u8,
    overlay_addr: []const u8,
};

pub const LookupResponse = struct {
    version: u8,
    overlay_addr: []const u8,
    endpoint_count: u8,
    endpoints: []const u8, // endpoint_count * LEN_ENDPOINT bytes flat (family u8 | [16] addr | u16 port), aliases the caller buffer
    cert: []const u8, // opaque certificate bytes; caller runs BE-ID-01..04 over them (BE-MESH-04)
};

// parseFragmentHeader reads the flat msg_id/index/total prefix (SPEC 4.5) and
// exposes the remaining bytes as the fragment payload. The payload floor and
// BE-TR-05 ceiling are enforced upstream by parseDataPacketHeader on the
// enclosing transport packet; this function sees only the AEAD plaintext body,
// so it applies no payload bound of its own (the variable-payload pattern from
// parseDataPacketHeader).
pub fn parseFragmentHeader(buf: []const u8) ParseError!FragmentHeader {
    var c = Cursor{ .buf = buf };
    const msg_id = try c.u64be();
    const index = try c.u16be();
    const total = try c.u16be();
    if (total == 0) return coverage.reject(.frag_total_zero);
    if (index >= total) return coverage.reject(.frag_index_range);
    const payload = buf[c.pos..];
    coverage.accept(.frag_accepted);
    return .{
        .msg_id = msg_id,
        .index = index,
        .total = total,
        .payload = payload,
    };
}

// parseLookupRequest reads the fixed 17-byte lighthouse request (SPEC 5.1a): a
// version byte and the overlay address being looked up. The grammar is
// fixed-width, so any trailing byte is a parse failure (SPEC 2.2).
pub fn parseLookupRequest(buf: []const u8) ParseError!LookupRequest {
    var c = Cursor{ .buf = buf };
    const version = try c.u8r();
    const overlay_addr = try c.take(LEN_OVERLAY_ADDR);
    if (c.pos != buf.len) return coverage.reject(.lookup_req_trailing);
    coverage.accept(.lookup_req_accepted);
    return .{
        .version = version,
        .overlay_addr = overlay_addr,
    };
}

// parseLookupResponse reads the lighthouse response (SPEC 5.1a): version, the
// overlay address echoed back, a u8 endpoint_count followed by that many
// (family, addr, port) tuples read as one flat slice (the envelope-parent
// convention: a count plus a single take of count * stride, no allocation),
// then a u16 cert_len and the served certificate. Each field read runs through
// the cursor, so a short buffer fails with the shared truncation exit point
// rather than a bespoke one. The cert closes the message, so any byte after it
// is trailing and a parse failure (SPEC 2.2).
pub fn parseLookupResponse(buf: []const u8) ParseError!LookupResponse {
    var c = Cursor{ .buf = buf };
    const version = try c.u8r();
    const overlay_addr = try c.take(LEN_OVERLAY_ADDR);
    const endpoint_count = try c.u8r();
    const endpoints = try c.take(@as(usize, endpoint_count) * LEN_ENDPOINT);
    const cert_len = try c.u16be();
    const cert = try c.take(@as(usize, cert_len));
    if (c.pos != buf.len) return coverage.reject(.lookup_resp_trailing);
    coverage.accept(.lookup_resp_accepted);
    return .{
        .version = version,
        .overlay_addr = overlay_addr,
        .endpoint_count = endpoint_count,
        .endpoints = endpoints,
        .cert = cert,
    };
}

// ---------------------------------------------------------------------------
// Certificate (SPEC section 3.1)
//
//   u8 version(=2) | u8 role_bits | [32] sig_pubkey | [32] kex_pubkey
//   u64 not_before | u64 not_after | u16 name_len, name(<=64)
//   u8 group_count(<=16) | [8]* group_ids | u8 ca_sig_count(1..4)
//   ([32] ca_key + [64] ca_sig) x ca_sig_count
//
// version is parsed and carried, never rejected here (SPEC section 2.2: version
// is the sole negotiation surface; section 3.1 pins no version-refusal step,
// unlike section 8.1 for Grant). The caller applies version policy under
// BE-ID-01..04. name is a convenience label (SPEC 3.1: no authorization
// decision may depend on it); group_ids are 8-byte BLAKE2s-256 prefixes read
// as opaque bytes. ca_sigs is the flat region of ca_sig_count (ca_key || ca_sig)
// pairs the caller re-walks. tbs is every byte preceding ca_sig_count, the
// input to each CA Ed25519 signature (BE-SIG-01, domain tag 0x01).
//
// The CA-key ordering check is the one structural invariant section 3.1 makes
// "a parse failure rather than a policy check": keys must be strictly ascending
// and pairwise distinct, so duplicate-key quorum forgery cannot encode.
// ---------------------------------------------------------------------------

pub const Cert = struct {
    version: u8,
    role_bits: u8,
    sig_pubkey: []const u8,
    kex_pubkey: []const u8,
    not_before: u64,
    not_after: u64,
    name: []const u8,
    group_count: u8,
    group_ids: []const u8, // group_count * LEN_GROUP_ID bytes, aliases the caller buffer
    ca_sig_count: u8,
    ca_sigs: []const u8, // ca_sig_count * (LEN_CA_KEY + LEN_CA_SIG) bytes, key+sig pairs flat
    tbs: []const u8, // all bytes preceding ca_sig_count (BE-SIG-01 signature input)
};

pub fn parseCert(buf: []const u8) ParseError!Cert {
    var c = Cursor{ .buf = buf };
    const version = try c.u8r();
    const role_bits = try c.u8r();
    const sig_pubkey = try c.take(LEN_PUBKEY);
    const kex_pubkey = try c.take(LEN_KEX_PUBKEY);
    const not_before = try c.u64be();
    const not_after = try c.u64be();
    const name = try c.field16(MAX_NAME);
    const group_count = try c.u8r();
    if (group_count > MAX_GROUPS) return coverage.reject(.cert_group_oversize);
    const group_ids = try c.take(@as(usize, group_count) * LEN_GROUP_ID);
    // tbs is every byte preceding ca_sig_count (SPEC 3.1): each CA signature
    // covers version..group_ids, so freeze the offset before reading the count.
    const tbs = buf[0..c.pos];
    const ca_sig_count = try c.u8r();
    if (ca_sig_count == 0) return coverage.reject(.cert_ca_count_zero);
    if (ca_sig_count > MAX_CA_SIGS) return coverage.reject(.cert_ca_count_oversize);
    const ca_start = c.pos;
    // CA keys strictly ascending and pairwise distinct: a parse failure, not a
    // policy check (SPEC 3.1). Each pair is [32] ca_key + [64] ca_sig; a key
    // must be strictly greater than its predecessor for a canonical encoding.
    var prev_key: []const u8 = &[_]u8{};
    var i: usize = 0;
    while (i < ca_sig_count) : (i += 1) {
        const ca_key = try c.take(LEN_CA_KEY);
        if (i > 0) {
            if (std.mem.order(u8, ca_key, prev_key) != .gt)
                return coverage.reject(.cert_ca_order);
        }
        prev_key = ca_key;
        _ = try c.take(LEN_CA_SIG);
    }
    const ca_sigs = buf[ca_start..c.pos];
    if (c.pos != buf.len) return coverage.reject(.cert_trailing);
    coverage.accept(.cert_accepted);
    return .{
        .version = version,
        .role_bits = role_bits,
        .sig_pubkey = sig_pubkey,
        .kex_pubkey = kex_pubkey,
        .not_before = not_before,
        .not_after = not_after,
        .name = name,
        .group_count = group_count,
        .group_ids = group_ids,
        .ca_sig_count = ca_sig_count,
        .ca_sigs = ca_sigs,
        .tbs = tbs,
    };
}
