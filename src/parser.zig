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
        if (self.remaining() < n) {
            coverage.hit(.cursor_truncated);
            return error.Truncated;
        }
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
        if (len > max) {
            coverage.hit(.field16_oversize);
            return error.Oversize;
        }
        return try self.take(@intCast(len));
    }

    // u32-length-prefixed field with a declared maximum.
    fn field32(self: *Cursor, max: u32) ParseError![]const u8 {
        const len = try self.u32be();
        if (len > max) {
            coverage.hit(.field32_oversize);
            return error.Oversize;
        }
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
    if (parent_count > MAX_PARENTS) {
        coverage.hit(.env_parent_oversize);
        return error.Oversize;
    }
    const parents = try c.take(@as(usize, parent_count) * LEN_PARENT);
    const ts = try c.u64be();
    const body_type = try c.u8r();
    const body_len = try c.u32be();
    if (body_len > MAX_BODY) {
        coverage.hit(.env_body_oversize);
        return error.Oversize;
    }
    const body = try c.take(@intCast(body_len));
    const tbs = buf[0..c.pos];
    const sig = try c.take(LEN_SIG);
    // BE-WIRE-02 totality: the buffer holds exactly one envelope, nothing more.
    if (c.pos != buf.len) {
        coverage.hit(.env_trailing);
        return error.TrailingBytes;
    }
    coverage.hit(.env_accepted);
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
    if (c.pos != buf.len) {
        coverage.hit(.intent_trailing);
        return error.TrailingBytes;
    }
    coverage.hit(.intent_accepted);
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
    if (c.pos != buf.len) {
        coverage.hit(.grant_trailing);
        return error.TrailingBytes;
    }
    coverage.hit(.grant_accepted);
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
    };
}
