// coverage.zig
//
// Hand-instrumented exit-point coverage for the parser (LANGUAGE.md O2,
// SPEC.md section 11.6). The Zig toolchain's -ffuzz coverage is consumed only
// by a WebSocket UI and emits no script-readable report (see the decision note
// in research/coverage-mechanism-decision.md), so coverage here is measured
// directly.
//
// Every rejection in parser.zig returns through reject() and every accepted
// return goes through accept(); parser.zig contains no raw `return error.` at
// all, zero exceptions (gate M9 in tools/prumo-verify). The wrappers are also
// the denominator source: M9 counts the reject/accept call sites in
// parser.zig at run time and fails unless the Branch enum below matches them
// one for one. The denominator is the code, not this file: a new exit point
// fails the gate until the enum grows, and a dead enum member fails it the
// other way (CONTRIBUTING.md section 2, gate-design law).
//
// Measurement unit, stated precisely: EXIT POINTS, not branches. One counter
// marks one exit site; a site shared by several readers (cursor_truncated is
// reached through u8r, u16be, u32be, u64be and take) reports reached when ANY
// path into it was taken. "N of M reached" therefore never claims more than
// exit-point reach (LANGUAGE.md section 4.1).
//
// Compile-time gated. ENABLED is true only in the `zig build coverage` run;
// in the test and shipped builds it is comptime false, so the counter logic
// inside reject()/accept() is dead-code eliminated and the wrappers compile
// to nothing. No unconditional increment on the 7.3B-input fuzz path.

const opts = @import("build_options");
const parser = @import("parser.zig");

pub const ENABLED: bool = opts.coverage_enabled;

// One member per exit point in the parser module: the shared truncation rejection,
// every other rejection site, and every accepted return. Reach is "hit at
// least once".
pub const Branch = enum {
    cursor_truncated, // Cursor.need: a field read ran past the buffer end
    env_parent_oversize, // parseEnvelope: parent_count > MAX_PARENTS
    env_body_oversize, // parseEnvelope: body_len > MAX_BODY
    env_trailing, // parseEnvelope: bytes after the single envelope
    env_accepted, // parseEnvelope: returned a valid Envelope
    field16_oversize, // Cursor.field16: u16 length > declared max
    field32_oversize, // Cursor.field32: u32 length > declared max
    intent_trailing, // parseIntent: bytes after the single intent
    intent_accepted, // parseIntent: returned a valid Intent
    grant_trailing, // parseGrant: bytes after the single grant
    grant_accepted, // parseGrant: returned a valid Grant
    span_trailing, // parseSpan: bytes after the single span
    span_accepted, // parseSpan: returned a valid Span
    effect_trailing, // parseEffect: bytes after the single effect body
    effect_accepted, // parseEffect: returned a valid Effect
    claim_trailing, // parseClaim: bytes after the single claim body
    claim_accepted, // parseClaim: returned a valid Claim
    // Transport parsers (SPEC 4.1a). Malformed covers the two structural
    // violations SPEC 2.2 / 4.1a make a parse failure: a wrong type byte and a
    // non-zero reserved field. Each fixed message has its own trailing check;
    // the variable data packet has a payload floor and a BE-TR-05 ceiling instead.
    hs_init_type, // parseHandshakeInitiation: message_type != 1
    hs_init_reserved, // parseHandshakeInitiation: reserved bytes non-zero
    hs_init_trailing, // parseHandshakeInitiation: bytes after the 144-byte message
    hs_init_accepted, // parseHandshakeInitiation: returned a valid message
    hs_resp_type, // parseHandshakeResponse: message_type != 2
    hs_resp_reserved, // parseHandshakeResponse: reserved bytes non-zero
    hs_resp_trailing, // parseHandshakeResponse: bytes after the 92-byte message
    hs_resp_accepted, // parseHandshakeResponse: returned a valid message
    cookie_type, // parseCookieReply: message_type != 3
    cookie_reserved, // parseCookieReply: reserved bytes non-zero
    cookie_trailing, // parseCookieReply: bytes after the 52-byte message
    cookie_accepted, // parseCookieReply: returned a valid message
    data_type, // parseDataPacketHeader: message_type != 4
    data_reserved, // parseDataPacketHeader: reserved bytes non-zero
    data_payload_short, // parseDataPacketHeader: payload shorter than the AEAD tag
    data_payload_oversize, // parseDataPacketHeader: payload above the BE-TR-05 bound
    data_accepted, // parseDataPacketHeader: returned a valid header
    // Mesh / fragment parsers (SPEC 4.5, 5.1a). These are session-AEAD plaintext
    // bodies with no type byte of their own; Malformed covers the two structural
    // impossibilities a fragment header can assert (a zero total and an
    // out-of-range index). Each lighthouse message has its own trailing check;
    // the fragment header exposes its remaining bytes as payload like the
    // variable data packet, so it has none.
    frag_total_zero, // parseFragmentHeader: total == 0 (zero-fragment message)
    frag_index_range, // parseFragmentHeader: index >= total (impossible position)
    frag_accepted, // parseFragmentHeader: returned a valid header
    lookup_req_trailing, // parseLookupRequest: bytes after the 17-byte request
    lookup_req_accepted, // parseLookupRequest: returned a valid request
    lookup_resp_trailing, // parseLookupResponse: bytes after the served cert
    lookup_resp_accepted, // parseLookupResponse: returned a valid response
    // Certificate parser (SPEC 3.1). name_len > MAX_NAME reuses the shared
    // field16_oversize exit point (every u16-length field with a declared max
    // routes there); version is parsed, not rejected, so it adds no exit point
    // (SPEC 2.2, D-022). The CA-key ordering check is the one structural
    // invariant section 3.1 makes a parse failure rather than a policy check.
    cert_group_oversize, // parseCert: group_count > MAX_GROUPS
    cert_ca_count_zero, // parseCert: ca_sig_count == 0 (grammar floor 1)
    cert_ca_count_oversize, // parseCert: ca_sig_count > MAX_CA_SIGS
    cert_ca_order, // parseCert: CA keys not strictly ascending / not distinct (SPEC 3.1)
    cert_trailing, // parseCert: bytes after the last CA signature
    cert_accepted, // parseCert: returned a valid Cert
    // Binding message parser (SPEC 4.1 BE-TR-01). The binding message is the
    // first AEAD plaintext after the handshake: a length-prefixed certificate
    // followed by a 64-byte Ed25519 signature over the Noise handshake hash h.
    // It rides inside an established session (BE-TR-07), so like the fragment
    // header it has no type byte; its only structural exit points are a zero
    // cert_len, a trailing check, and the accepted return.
    bind_cert_len_zero, // parseBindingMessage: cert_len == 0 (grammar floor 1)
    bind_trailing, // parseBindingMessage: bytes after the 64-byte binding sig
    bind_accepted, // parseBindingMessage: returned a valid cert+sig pair
    // Channel control parsers (SPEC 6.1b, 6.1c). ca_count is bounded before it
    // drives the ca_keys slice (BE-TR-05); a zero trust set is a grammar floor.
    // match_rule and version are parsed not rejected (policy stays out).
    genesis_ca_count_zero, // parseControlGenesis: ca_count == 0 (grammar floor 1)
    genesis_ca_count_oversize, // parseControlGenesis: ca_count > MAX_CA_COUNT
    genesis_trailing, // parseControlGenesis: bytes after the genesis body
    genesis_accepted, // parseControlGenesis: returned a valid ControlGenesis
    control_trailing, // parseControl: bytes after the control body
    control_accepted, // parseControl: returned a valid Control
};

pub const COUNT: usize = @typeInfo(Branch).@"enum".fields.len;
pub var hit_count: [COUNT]u64 = [_]u64{0} ** COUNT;

fn hit(b: Branch) void {
    if (!ENABLED) return;
    hit_count[@intFromEnum(b)] += 1;
}

// reject: the ONLY path by which parser.zig returns an error. The tag names
// the exit point (the coverage unit); the switch maps it to the error value
// and is total over the enum, so a tag added without a mapping is a compile
// error. The accepted tags map to @compileError: the tag is comptime-known at
// every call site, so the other arms are pruned and this fires only on
// genuine misuse, at compile time.
pub inline fn reject(comptime tag: Branch) parser.ParseError {
    hit(tag);
    return switch (tag) {
        .cursor_truncated, .data_payload_short => error.Truncated,
        .env_parent_oversize, .env_body_oversize, .field16_oversize, .field32_oversize, .data_payload_oversize, .cert_group_oversize, .cert_ca_count_oversize, .genesis_ca_count_oversize => error.Oversize,
        .env_trailing, .intent_trailing, .grant_trailing, .span_trailing, .effect_trailing, .claim_trailing, .hs_init_trailing, .hs_resp_trailing, .cookie_trailing, .lookup_req_trailing, .lookup_resp_trailing, .cert_trailing, .bind_trailing, .genesis_trailing, .control_trailing => error.TrailingBytes,
        .hs_init_type, .hs_init_reserved, .hs_resp_type, .hs_resp_reserved, .cookie_type, .cookie_reserved, .data_type, .data_reserved, .frag_total_zero, .frag_index_range, .cert_ca_count_zero, .cert_ca_order, .bind_cert_len_zero, .genesis_ca_count_zero => error.Malformed,
        .env_accepted, .intent_accepted, .grant_accepted, .span_accepted, .effect_accepted, .claim_accepted, .hs_init_accepted, .hs_resp_accepted, .cookie_accepted, .data_accepted, .frag_accepted, .lookup_req_accepted, .lookup_resp_accepted, .cert_accepted, .bind_accepted, .genesis_accepted, .control_accepted => @compileError("accepted exit points do not reject; use accept()"),
    };
}

// accept: marks an accepted return. Void on purpose: the parser returns its
// struct literal itself, so no parsed value type leaks into coverage.zig.
pub inline fn accept(comptime tag: Branch) void {
    hit(tag);
}
