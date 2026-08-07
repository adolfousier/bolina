// parser/session.zig
//
// Zero-heap, total wire-format parsers for Bolina's POST-AUTHENTICATION
// session surface (SPEC.md sections 3.1, 4.5, 5.1a): the fragment header,
// the lighthouse lookups, and the certificate. Carved out of parser.zig by
// D-030/D-032: BE-SURF-03 budgets the two sides of BE-SURF-01's
// authentication line separately, and this file is the session half of the
// post-authentication unit, everything a hostile authenticated peer's
// session bytes can reach. The shared reader (Cursor), ParseError, and the
// transport-wide limits live in the parent module (src/parser.zig), which
// parses the pre-authentication bytes.
//
// Same discipline as the parent: every multi-byte integer is big-endian
// (SPEC 2.2), the parser never allocates (every returned slice aliases the
// caller buffer), and version fields are parsed but not rejected here
// (SPEC 2.2: version is the sole negotiation surface; the caller applies
// version policy under BE-ID-01..04). Every error exit routes through
// coverage.reject and every accepted return through coverage.accept; gate
// M9 counts those wrapper call sites across the whole parser module
// (CONTRIBUTING.md M9).

const std = @import("std");
const coverage = @import("../coverage.zig");
const parser = @import("../parser.zig");

const Cursor = parser.Cursor;
const ParseError = parser.ParseError;
const LEN_PUBKEY = parser.LEN_PUBKEY;

// ---------------------------------------------------------------------------
// Declared widths (SPEC BE-TR-05, sections 3.1, 4.5, 5.1a) for the session
// surface. Every one is bounded before it drives a slice.
// ---------------------------------------------------------------------------

pub const LEN_FRAGMENT_HEADER: usize = 12; // msg_id u64 + index u16 + total u16 (SPEC 4.5)
pub const LEN_OVERLAY_ADDR: usize = 16; // overlay address, the mesh node id (SPEC 5.1)
pub const LEN_ENDPOINT: usize = 19; // lighthouse endpoint tuple: family u8 + [16] addr + u16 port (SPEC 5.1a)

pub const LEN_KEX_PUBKEY: usize = 32; // X25519 key-exchange public key (SPEC 3.1)
pub const LEN_GROUP_ID: usize = 8; // group_id = BLAKE2s-256(group_name)[0..8] (SPEC 3.1)
pub const MAX_NAME: usize = 64; // Cert.name length bound (SPEC 3.1)
pub const MAX_GROUPS: u8 = 16; // Cert.group_count bound (SPEC 3.1)
pub const MAX_CA_SIGS: u8 = 4; // Cert.ca_sig_count upper bound (SPEC 3.1)
pub const LEN_CA_KEY: usize = 32; // CA Ed25519 public key (SPEC 3.1)
pub const LEN_CA_SIG: usize = 64; // CA Ed25519 signature (SPEC 3.1)

// Domain-separation tag for Ed25519 certificate signing (SPEC BE-SIG-01).
pub const DOMAIN_CERT: u8 = 0x01;

// ---------------------------------------------------------------------------
// Fragment header (SPEC section 4.5).
//
// Fragments are session-AEAD plaintext bodies: a fragment header prefixes
// every fragmented packet body, readable only after decryption inside a
// bound session (D-032; SPEC 4.5 "there is no unauthenticated
// fragmentation"). It carries no Ed25519 signature of its own; it is
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
// ---------------------------------------------------------------------------

pub const FragmentHeader = struct {
    msg_id: u64,
    index: u16,
    total: u16,
    payload: []const u8,
};

// parseFragmentHeader reads the flat msg_id/index/total prefix (SPEC 4.5) and
// exposes the remaining bytes as the fragment payload. The payload floor and
// BE-TR-05 ceiling are enforced upstream by parser.parseDataPacketHeader on
// the enclosing transport packet; this function sees only the AEAD plaintext
// body, so it applies no payload bound of its own (the variable-payload
// pattern from parser.parseDataPacketHeader).
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

// ---------------------------------------------------------------------------
// Lighthouse lookups (SPEC section 5.1a).
//
// BE-MESH-07: LookupRequest and LookupResponse MUST travel inside an
// established session with a lighthouse and MUST NOT be parsed from
// unauthenticated input. This parser performs structural validation only; the
// caller is responsible for having authenticated the session. The served
// certificate is returned as an opaque byte slice here and verified under
// BE-ID-01..04 by the caller (BE-MESH-04); its internal structure is walked
// by parseCert below. (SPEC 5.1a)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Binding message (SPEC section 4.1, BE-TR-01).
//
// The binding message is the first AEAD plaintext exchanged after the Noise
// handshake: a length-prefixed certificate followed by a 64-byte Ed25519
// signature by sig_pubkey over the Noise handshake hash h (domain 0x05). It
// rides inside an established session, so like the fragment header it has no
// type byte of its own (BE-TR-07 forbids certificates in the handshake). The
// certificate is returned as an opaque slice here; the caller runs parseCert
// and the BE-ID-01..04 checks (binding.zig), the same opaque-cert convention
// as the lighthouse LookupResponse (BE-MESH-04).
// ---------------------------------------------------------------------------

pub const LEN_BINDING_SIG: usize = 64; // Ed25519 over (0x05 || Noise h), BE-TR-01

pub const BindingMessage = struct {
    cert: []const u8, // cert_len bytes; caller runs parseCert + BE-ID-01..04 (binding.zig)
    sig: []const u8, // 64-byte Ed25519 signature over (0x05 || h), aliases the caller buffer
};

// parseBindingMessage frames a cert+sig pair (SPEC 4.1 BE-TR-01). A u16
// cert_len bounds the certificate before it drives a slice; the signature is a
// fixed 64 bytes that close the message, so any byte after it is trailing and
// a parse failure (SPEC 2.2). The certificate's internal structure is walked
// by parseCert when the caller runs the BE-ID checks, not here.
pub fn parseBindingMessage(buf: []const u8) ParseError!BindingMessage {
    var c = Cursor{ .buf = buf };
    const cert_len = try c.u16be();
    if (cert_len == 0) return coverage.reject(.bind_cert_len_zero);
    const cert = try c.take(@as(usize, cert_len));
    const sig = try c.take(LEN_BINDING_SIG);
    if (c.pos != buf.len) return coverage.reject(.bind_trailing);
    coverage.accept(.bind_accepted);
    return .{ .cert = cert, .sig = sig };
}
