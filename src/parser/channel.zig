// parser/channel.zig
//
// Zero-heap, total wire-format parsers for the POST-AUTHENTICATION channel
// surface (SPEC 2.2, 6.1b/c, 6.2, 6.3, 7, 8.1): Envelope, ControlGenesis,
// Control, Intent, Grant, Span, Effect, Claim. This is the channel half of
// the BE-SURF-03 post-authentication unit (D-030/D-032): everything a hostile
// authenticated peer's channel bytes can reach. Shared Cursor/ParseError and
// the transport limits live in src/parser.zig (the pre-authentication half).
// Big-endian, never allocates (slices alias the caller buffer), version parsed
// not rejected (SPEC 2.2). Every exit routes through coverage.reject/accept,
// counted one for one by gate M9 (CONTRIBUTING.md M9).

const coverage = @import("../coverage.zig");
const parser = @import("../parser.zig");

const Cursor = parser.Cursor;
const ParseError = parser.ParseError;
const LEN_PUBKEY = parser.LEN_PUBKEY;
const MAX_MESSAGE = parser.MAX_MESSAGE;

// Declared limits (SPEC BE-TR-05): every attacker-influenced size on the
// channel wire, bounded before it drives a slice. MAX_MESSAGE (the reassembly
// ceiling) lives in the parent module; MAX_BODY derives from it here.

pub const MAX_HEADER: usize = 512; // envelope overhead (version..sig, slack)
pub const MAX_BODY: u32 = @intCast(MAX_MESSAGE - MAX_HEADER); // body_len bound
pub const MAX_PARENTS: u8 = 4; // parent_count bound (SPEC 6.2)
pub const MAX_RESOURCE: usize = 256; // Intent.resource_id (SPEC 6.3)
pub const MAX_ACTION: u32 = 256 * 1024; // Intent.action, opaque (SPEC 6.3)
pub const MAX_RATIONALE: usize = 4 * 1024; // Intent.rationale (SPEC 6.3)

// Fixed field widths, traceable to the SPEC grammar.
pub const LEN_CHANNEL_ID: usize = 32;
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

// Domain-separation tags for Ed25519 signing (SPEC BE-SIG-01). The verifier
// (LANGUAGE.md section 4 item 2) prefixes tag || tbs before checking sig.
pub const DOMAIN_ENVELOPE: u8 = 0x02;
pub const DOMAIN_SPAN: u8 = 0x03;
pub const DOMAIN_GRANT: u8 = 0x04;
pub const DOMAIN_REFUSAL: u8 = 0x06;

// Envelope body_type discriminant (SPEC 6.3).
pub const BODY_UTTERANCE: u8 = 1;
pub const BODY_INTENT: u8 = 2;
pub const BODY_GRANT: u8 = 3;
pub const BODY_EFFECT: u8 = 4;
pub const BODY_CONTROL: u8 = 5;
pub const BODY_REFUSAL: u8 = 6;

// Envelope (SPEC 6.2)
//
//   u8 version(=2) | [32] channel_id | [32] sender | u64 seq
//   u8 parent_count(0..4) | [32]* parents | u64 ts | u8 body_type
//   u32 body_len | body | [64] sig
//
// tbs is every byte before sig; sig is Ed25519 over (DOMAIN_ENVELOPE || tbs).

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
    return .{ .version = version, .channel_id = channel_id, .sender = sender, .seq = seq, .parent_count = parent_count, .parents = parents, .ts = ts, .body_type = body_type, .body = body, .tbs = tbs, .sig = sig };
}

// Intent body (SPEC 6.3)
//
//   [16] intent_id | u16 resource_len, resource_id(<=256)
//   u32 action_len, action(<=256KiB, OPAQUE) | u16 rationale_len, rationale(<=4KiB)
//
// The daemon treats action as opaque bytes (BE-BODY-01); it never parses them.
// This parser only slices action out so a verifier can hash it for BE-GRANT-02.

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
    return .{ .intent_id = intent_id, .resource_id = resource_id, .action = action, .rationale = rationale };
}

// Grant (SPEC 8.1)
//
//   u8 version(=2) | [16] grant_id | [16] intent_id | [32] approver
//   [32] subject | [32] executor | u16 resource_len, resource_id
//   [32] action_digest | u64 not_after | [64] sig
//
// tbs is every byte before sig; sig is Ed25519 over (DOMAIN_GRANT || tbs).
// version parsed, refused by verifier (BE-GRANT-03 step 0).
//
// wire is the full input buffer (tbs || sig). The verifier seals the capability
// by content (BE-GRANT-03c): a keyed digest over wire frozen at verification
// and recomputed over the live bytes at every access, so a caller write between
// verification and consumption is detected, not honored.

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
    return .{ .version = version, .grant_id = grant_id, .intent_id = intent_id, .approver = approver, .subject = subject, .executor = executor, .resource_id = resource_id, .action_digest = action_digest, .not_after = not_after, .tbs = tbs, .sig = sig, .wire = buf };
}

// Span (SPEC 7.1)
//
//   u8 version(=2) | [16] span_id | [16] trace_id | u16 resource_len, resource_id(<=256)
//   u8 method_id | u8 volatility | [32] origin | u64 observed_at
//   [32] digest | [32] executor | [64] sig
//
// sig is Ed25519 over all preceding bytes, domain tag 0x03 (BE-SIG-01). The
// evidence class is DERIVED from method_id by the receiver (BE-EVID-15), never
// on the wire; volatility is the executor's declaration (BE-EVID-06 floor),
// also a verifier concern. readSpan advances a SHARED cursor with no trailing
// check: the byte ending one span is the first of the next (inline spans in an
// Effect). readSpan adds no exit point of its own; every exit routes through
// the shared Cursor rejection (M9).

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
    return .{ .version = version, .span_id = span_id, .trace_id = trace_id, .resource_id = resource_id, .method_id = method_id, .volatility = volatility, .origin = origin, .observed_at = observed_at, .digest = digest, .executor = executor, .tbs = tbs, .sig = sig };
}

pub fn parseSpan(buf: []const u8) ParseError!Span {
    var c = Cursor{ .buf = buf };
    const s = try readSpan(&c);
    // BE-WIRE-02 totality: exactly one span, nothing after it.
    if (c.pos != buf.len) return coverage.reject(.span_trailing);
    coverage.accept(.span_accepted);
    return s;
}

// Effect body (SPEC 6.3)
//
//   [16] intent_id | [16] grant_id | u8 ok | i32 exit_code
//   u8 span_count | Span[] | [32] output_digest
//
// The Effect is a body (body_type 4) inside a signed Envelope (SPEC 6.2); it
// authenticates nothing itself. Inline spans are full Span wires walked here for
// totality: readSpan consumes every byte of the span region before
// output_digest is read, so a truncated or overlong span is rejected, not
// mis-sliced. exit_code is i32 on the wire, read as u32 and @bitCast (no pointer
// mint: bit-cast to a non-pointer is outside the M8 forbidden set). ok,
// exit_code and span_count are parsed not policy-checked (BE-EFF-01, BE-EVID-10
// are verifier concerns). No per-Effect span cap in BE-TR-05; body_len bounds
// the whole input and a span_count past the buffer truncates via readSpan.

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
    return .{ .intent_id = intent_id, .grant_id = grant_id, .ok = ok, .exit_code = exit_code, .span_count = span_count, .spans = spans, .output_digest = output_digest };
}

// Claim body (SPEC 7.2)
//
//   u16 text_len, text(<=1KiB) | u16 subject_len, subject(<=256)
//   u8 confidence_q8 | u8 span_count | [16]* span_ids
//
// A Claim carries no signature of its own: authenticated only inside a signed
// Utterance envelope (BE-EVID-08). The Utterance grammar is deferred to
// RED-TEAM-09 F1, so this parser fixes the Claim body layout against the vector
// in test/vectors.json. confidence_q8 is the sender's upper-bound request
// (BE-EVID-02); the receiver recomputes, so the byte is recorded not enforced.
// span_count is bounded by the enclosing body_len, not a per-claim cap (the
// 64-span bound is on the Utterance, BE-EVID-10).

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
    return .{ .text = text, .subject = subject, .confidence_q8 = confidence_q8, .span_count = span_count, .span_ids = span_ids };
}

// Channel control structures (SPEC 6.1b, 6.1c). ControlGenesis is the
// immutable body of the genesis envelope (parent_count 0, body_type 5);
// Control is every later control envelope's body. Both flat. version and
// match_rule are parsed not rejected (SPEC 2.2); ca_keys ascending order is a
// verify-time concern (BE-GEN-03 derives channel_id from ca_key_0).

pub const LEN_MEMBER_GROUP: usize = 8; // SPEC 6.1b member_group / admin_group
pub const LEN_ADMIN_GROUP: usize = 8;
pub const LEN_CA_KEY: usize = 32; // SPEC 6.1b ca_keys element
pub const MAX_GENESIS_NAME: usize = 64; // SPEC 6.1b name_len bound
pub const MAX_CA_COUNT: u8 = 16; // BE-TR-05: bound ca_count before the slice
pub const MAX_CONTROL_BODY: usize = 1024; // BE-TR-05: Control body bound

// ControlGenesis (SPEC 6.1b): u8 version | u16 name_len,name(<=64) | [8]
// member_group | [8] admin_group | u8 ca_count,[32]* ca_keys | u8 match_rule.
pub const ControlGenesis = struct {
    version: u8,
    name: []const u8,
    member_group: []const u8,
    admin_group: []const u8,
    ca_count: u8,
    ca_keys: []const u8,
    match_rule: u8,
};

pub fn parseControlGenesis(buf: []const u8) ParseError!ControlGenesis {
    var c = Cursor{ .buf = buf };
    const version = try c.u8r();
    const name = try c.field16(MAX_GENESIS_NAME);
    const member_group = try c.take(LEN_MEMBER_GROUP);
    const admin_group = try c.take(LEN_ADMIN_GROUP);
    const ca_count = try c.u8r();
    if (ca_count == 0) return coverage.reject(.genesis_ca_count_zero);
    if (ca_count > MAX_CA_COUNT) return coverage.reject(.genesis_ca_count_oversize);
    const ca_keys = try c.take(@as(usize, ca_count) * LEN_CA_KEY);
    const match_rule = try c.u8r();
    if (c.pos != buf.len) return coverage.reject(.genesis_trailing);
    coverage.accept(.genesis_accepted);
    return .{ .version = version, .name = name, .member_group = member_group, .admin_group = admin_group, .ca_count = ca_count, .ca_keys = ca_keys, .match_rule = match_rule };
}

// Control (SPEC 6.1c): u8 version | u8 action_type(1=Genesis,2=Revoke) | [32]
// subject(zero for Genesis) | u16 body_len,body. action_type parsed not rejected.
pub const Control = struct { action_type: u8, subject: []const u8, body: []const u8 };

pub fn parseControl(buf: []const u8) ParseError!Control {
    var c = Cursor{ .buf = buf };
    _ = try c.u8r(); // version; refused by verifier (SPEC 2.2)
    const action_type = try c.u8r();
    const subject = try c.take(LEN_PUBKEY);
    const body = try c.field16(MAX_CONTROL_BODY);
    if (c.pos != buf.len) return coverage.reject(.control_trailing);
    coverage.accept(.control_accepted);
    return .{ .action_type = action_type, .subject = subject, .body = body };
}
