// wire_test.zig
//
// Grounded in the canonical cross-implementation vector (test/vectors.json,
// structure envelope_intent). The wire bytes here are the exact bytes two
// independent implementations (the Zig generator and the Python cryptography
// verifier) agreed on under M3. If this parser disagrees, the parser is wrong.
//
// Naming follows the build.zig M1 registry convention: test "BE_<CLASS>_<NN>".

const std = @import("std");
const parser = @import("parser.zig");

// The canonical genesis envelope carrying an Intent body (parent_count = 0),
// signed by the agent. 280 bytes: TBS(216) + sig(64).
const ENVELOPE_HEX =
    "026d14f9d827a8ec4ad1c5b7a34076f5f0ff41eaffce1cf37959e63df6cceb59ce" ++
    "020bd427446b723424d80d2cad352ba3df3649d0ef8faae0ca7eb25443941b29" ++
    "0000000000000001" ++
    "00" ++
    "0000018bcfe58f10" ++
    "02" ++
    "00000081" ++
    "0102030405060708090a0b0c0d0e0f10" ++
    "0024" ++
    "626f6c3a633365666436343162666130353832662f6c6f67732f6465706c6f792e6c6f67" ++
    "0000001a" ++
    "6170742d67657420696e7374616c6c202d792073716c69746533" ++
    "002b" ++
    "496e7374616c6c2073716c69746520666f72206c6f63616c20736368656d6120696e7370656374696f6e2e" ++
    "3d96e79606b694f286bac4ae1836c351a9ba817bae9a26d14a9844593293bec16d07c18cb44f19e4a77c75c9bc4cbe8eeb6f9c9376da85a74b3abf38e6e0ec02";

const CHANNEL_ID_HEX = "6d14f9d827a8ec4ad1c5b7a34076f5f0ff41eaffce1cf37959e63df6cceb59ce";
const SENDER_HEX = "020bd427446b723424d80d2cad352ba3df3649d0ef8faae0ca7eb25443941b29";
const INTENT_ID_HEX = "0102030405060708090a0b0c0d0e0f10";

fn decodeHex(comptime hex: []const u8) [hex.len / 2]u8 {
    var b: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&b, hex) catch unreachable;
    return b;
}

const ENVELOPE_BYTES = decodeHex(ENVELOPE_HEX);

test "BE_WIRE_01 envelope round-trips the canonical vector, zero heap" {
    const env = try parser.channel.parseEnvelope(&ENVELOPE_BYTES);

    try std.testing.expectEqual(@as(u8, 2), env.version);
    try std.testing.expectEqual(@as(u64, 1), env.seq);
    try std.testing.expectEqual(@as(u8, 0), env.parent_count);
    try std.testing.expectEqual(@as(u64, 1700000010000), env.ts);
    try std.testing.expectEqual(parser.channel.BODY_INTENT, env.body_type);

    try std.testing.expectEqual(@as(usize, 0), env.parents.len);
    try std.testing.expectEqual(@as(usize, 129), env.body.len);
    try std.testing.expectEqual(@as(usize, 216), env.tbs.len);
    try std.testing.expectEqual(@as(usize, 64), env.sig.len);

    // Slices alias the input buffer: tbs is the prefix, sig the trailer.
    try std.testing.expectEqualSlices(u8, ENVELOPE_BYTES[0..216], env.tbs);
    try std.testing.expectEqualSlices(u8, ENVELOPE_BYTES[216..280], env.sig);
    try std.testing.expectEqualSlices(u8, &decodeHex(CHANNEL_ID_HEX), env.channel_id);
    try std.testing.expectEqualSlices(u8, &decodeHex(SENDER_HEX), env.sender);
}

test "BE_BODY_01 intent body slices the opaque action without parsing it" {
    const env = try parser.channel.parseEnvelope(&ENVELOPE_BYTES);
    const intent = try parser.channel.parseIntent(env.body);

    try std.testing.expectEqualSlices(u8, &decodeHex(INTENT_ID_HEX), intent.intent_id);
    try std.testing.expectEqualStrings("bol:c3efd641bfa0582f/logs/deploy.log", intent.resource_id);
    // action is opaque to the daemon (BE-BODY-01); parsed by length, not content.
    try std.testing.expectEqualStrings("apt-get install -y sqlite3", intent.action);
    try std.testing.expectEqualStrings("Install sqlite for local schema inspection.", intent.rationale);
}

test "BE_WIRE_02 truncated signature is rejected" {
    var buf: [279]u8 = undefined;
    @memcpy(buf[0..279], ENVELOPE_BYTES[0..279]);
    try std.testing.expectError(error.Truncated, parser.channel.parseEnvelope(&buf));
}

test "BE_WIRE_02 trailing byte is rejected" {
    var buf: [281]u8 = undefined;
    @memcpy(buf[0..280], &ENVELOPE_BYTES);
    buf[280] = 0x00;
    try std.testing.expectError(error.TrailingBytes, parser.channel.parseEnvelope(&buf));
}

test "BE_WIRE_02 oversize body_len is rejected before any large read" {
    var buf: [280]u8 = ENVELOPE_BYTES;
    // body_len lives at byte 83 (version + channel_id + sender + seq +
    // parent_count + ts + body_type = 1+32+32+8+1+8+1).
    buf[83] = 0xff;
    buf[84] = 0xff;
    buf[85] = 0xff;
    buf[86] = 0xff;
    try std.testing.expectError(error.Oversize, parser.channel.parseEnvelope(&buf));
}

test "BE_WIRE_02 parent_count above the bound is rejected" {
    var buf: [280]u8 = ENVELOPE_BYTES;
    // parent_count lives at byte 73 (version + channel_id + sender + seq).
    buf[73] = 5;
    try std.testing.expectError(error.Oversize, parser.channel.parseEnvelope(&buf));
}

test "BE_WIRE_02 empty input is rejected" {
    try std.testing.expectError(error.Truncated, parser.channel.parseEnvelope(&[_]u8{}));
}

test "BE_WIRE_02 intent with a trailing byte is rejected" {
    const env = try parser.channel.parseEnvelope(&ENVELOPE_BYTES);
    var buf: [130]u8 = undefined;
    @memcpy(buf[0..129], env.body);
    buf[129] = 0x00;
    try std.testing.expectError(error.TrailingBytes, parser.channel.parseIntent(&buf));
}

// ---------------------------------------------------------------------------
// Transport wire fixtures (SPEC 4.1a). Synthetic, structurally valid bytes:
// there is no canonical transport vector (D-020 deferred them: transport
// messages carry no Ed25519 signature, so verify-vectors.py cannot cross-check
// them). These pin the byte layout against the SPEC 4.1a tables. Each field
// carries a distinct fill so a round-trip asserts the slice landed at the
// right offset, not just the right length.
// ---------------------------------------------------------------------------

const EPHEMERAL_FILL = "e1" ** 32; // 32 bytes, X25519 ephemeral key
const ENC_STATIC_FILL = "e2" ** 48; // 48 bytes, encrypted static key + tag
const ENC_TS_FILL = "e3" ** 24; // 24 bytes, encrypted timestamp + tag
const ENC_NOTHING_FILL = "e4" ** 16; // 16 bytes, empty plaintext + tag
const MAC1_FILL = "e5" ** 16; // 16 bytes, mac1
const MAC2_FILL = "e6" ** 16; // 16 bytes, mac2
const NONCE_FILL = "e7" ** 12; // 12 bytes, cookie nonce
const ENC_COOKIE_FILL = "e8" ** 32; // 32 bytes, encrypted cookie + tag
const PAYLOAD_FILL = "e9" ** 32; // 32 bytes, opaque encrypted payload + tag

// Handshake initiation: 1 + 3 + 4 + 32 + 48 + 24 + 16 + 16 = 144 bytes.
const HS_INITIATION_HEX =
    "01" ++ // type = 1
    "000000" ++ // reserved = 0
    "00000007" ++ // sender_index = 7 (u32 BE)
    EPHEMERAL_FILL ++
    ENC_STATIC_FILL ++
    ENC_TS_FILL ++
    MAC1_FILL ++
    MAC2_FILL;

test "BE_WIRE_01 handshake initiation round-trips the pinned layout, zero heap" {
    const bytes = decodeHex(HS_INITIATION_HEX);
    try std.testing.expectEqual(@as(usize, 144), bytes.len);
    const msg = try parser.parseHandshakeInitiation(&bytes);
    try std.testing.expectEqual(@as(u32, 7), msg.sender_index);
    try std.testing.expectEqual(@as(usize, 32), msg.ephemeral.len);
    try std.testing.expectEqual(@as(usize, 48), msg.encrypted_static.len);
    try std.testing.expectEqual(@as(usize, 24), msg.encrypted_timestamp.len);
    try std.testing.expectEqual(@as(usize, 16), msg.mac1.len);
    try std.testing.expectEqual(@as(usize, 16), msg.mac2.len);
    // Slices alias the input buffer at the SPEC 4.1a offsets.
    try std.testing.expectEqualSlices(u8, &decodeHex(EPHEMERAL_FILL), msg.ephemeral);
    try std.testing.expectEqualSlices(u8, &decodeHex(ENC_STATIC_FILL), msg.encrypted_static);
    try std.testing.expectEqualSlices(u8, &decodeHex(ENC_TS_FILL), msg.encrypted_timestamp);
    try std.testing.expectEqualSlices(u8, &decodeHex(MAC1_FILL), msg.mac1);
    try std.testing.expectEqualSlices(u8, &decodeHex(MAC2_FILL), msg.mac2);
}

test "BE_WIRE_02 initiation with a wrong type byte is rejected as Malformed" {
    var bytes = decodeHex(HS_INITIATION_HEX);
    bytes[0] = 0x02;
    try std.testing.expectError(error.Malformed, parser.parseHandshakeInitiation(&bytes));
}

test "BE_WIRE_02 initiation with a non-zero reserved byte is rejected as Malformed" {
    var bytes = decodeHex(HS_INITIATION_HEX);
    bytes[2] = 0x01;
    try std.testing.expectError(error.Malformed, parser.parseHandshakeInitiation(&bytes));
}

test "BE_WIRE_02 initiation with a trailing byte is rejected" {
    const bytes = decodeHex(HS_INITIATION_HEX);
    var buf: [145]u8 = undefined;
    @memcpy(buf[0..144], &bytes);
    buf[144] = 0x00;
    try std.testing.expectError(error.TrailingBytes, parser.parseHandshakeInitiation(&buf));
}

test "BE_WIRE_02 truncated initiation is rejected" {
    const bytes = decodeHex(HS_INITIATION_HEX);
    try std.testing.expectError(error.Truncated, parser.parseHandshakeInitiation(bytes[0..100]));
}

// Handshake response: 1 + 3 + 4 + 4 + 32 + 16 + 16 + 16 = 92 bytes.
const HS_RESPONSE_HEX =
    "02" ++ // type = 2
    "000000" ++ // reserved = 0
    "00000009" ++ // sender_index = 9 (u32 BE)
    "0000000b" ++ // receiver_index = 11 (u32 BE)
    EPHEMERAL_FILL ++
    ENC_NOTHING_FILL ++
    MAC1_FILL ++
    MAC2_FILL;

test "BE_WIRE_01 handshake response round-trips the pinned layout, zero heap" {
    const bytes = decodeHex(HS_RESPONSE_HEX);
    try std.testing.expectEqual(@as(usize, 92), bytes.len);
    const msg = try parser.parseHandshakeResponse(&bytes);
    try std.testing.expectEqual(@as(u32, 9), msg.sender_index);
    try std.testing.expectEqual(@as(u32, 11), msg.receiver_index);
    try std.testing.expectEqualSlices(u8, &decodeHex(EPHEMERAL_FILL), msg.ephemeral);
    try std.testing.expectEqualSlices(u8, &decodeHex(ENC_NOTHING_FILL), msg.encrypted_nothing);
    try std.testing.expectEqualSlices(u8, &decodeHex(MAC1_FILL), msg.mac1);
    try std.testing.expectEqualSlices(u8, &decodeHex(MAC2_FILL), msg.mac2);
}

test "BE_WIRE_02 response with a wrong type byte is rejected as Malformed" {
    var bytes = decodeHex(HS_RESPONSE_HEX);
    bytes[0] = 0x04;
    try std.testing.expectError(error.Malformed, parser.parseHandshakeResponse(&bytes));
}

test "BE_WIRE_02 response with a non-zero reserved byte is rejected as Malformed" {
    var bytes = decodeHex(HS_RESPONSE_HEX);
    bytes[3] = 0xff;
    try std.testing.expectError(error.Malformed, parser.parseHandshakeResponse(&bytes));
}

test "BE_WIRE_02 response with a trailing byte is rejected" {
    const bytes = decodeHex(HS_RESPONSE_HEX);
    var buf: [93]u8 = undefined;
    @memcpy(buf[0..92], &bytes);
    buf[92] = 0x00;
    try std.testing.expectError(error.TrailingBytes, parser.parseHandshakeResponse(&buf));
}

test "BE_WIRE_02 truncated response is rejected" {
    const bytes = decodeHex(HS_RESPONSE_HEX);
    try std.testing.expectError(error.Truncated, parser.parseHandshakeResponse(bytes[0..60]));
}

// Cookie reply: 1 + 3 + 4 + 12 + 32 = 52 bytes.
const COOKIE_REPLY_HEX =
    "03" ++ // type = 3
    "000000" ++ // reserved = 0
    "0000000d" ++ // receiver_index = 13 (u32 BE)
    NONCE_FILL ++
    ENC_COOKIE_FILL;

test "BE_WIRE_01 cookie reply round-trips the pinned layout, zero heap" {
    const bytes = decodeHex(COOKIE_REPLY_HEX);
    try std.testing.expectEqual(@as(usize, 52), bytes.len);
    const msg = try parser.parseCookieReply(&bytes);
    try std.testing.expectEqual(@as(u32, 13), msg.receiver_index);
    try std.testing.expectEqualSlices(u8, &decodeHex(NONCE_FILL), msg.nonce);
    try std.testing.expectEqualSlices(u8, &decodeHex(ENC_COOKIE_FILL), msg.encrypted_cookie);
}

test "BE_WIRE_02 cookie reply with a wrong type byte is rejected as Malformed" {
    var bytes = decodeHex(COOKIE_REPLY_HEX);
    bytes[0] = 0x01;
    try std.testing.expectError(error.Malformed, parser.parseCookieReply(&bytes));
}

test "BE_WIRE_02 cookie reply with a non-zero reserved byte is rejected as Malformed" {
    var bytes = decodeHex(COOKIE_REPLY_HEX);
    bytes[1] = 0x80;
    try std.testing.expectError(error.Malformed, parser.parseCookieReply(&bytes));
}

test "BE_WIRE_02 cookie reply with a trailing byte is rejected" {
    const bytes = decodeHex(COOKIE_REPLY_HEX);
    var buf: [53]u8 = undefined;
    @memcpy(buf[0..52], &bytes);
    buf[52] = 0x00;
    try std.testing.expectError(error.TrailingBytes, parser.parseCookieReply(&buf));
}

test "BE_WIRE_02 truncated cookie reply is rejected" {
    const bytes = decodeHex(COOKIE_REPLY_HEX);
    try std.testing.expectError(error.Truncated, parser.parseCookieReply(bytes[0..30]));
}

// Transport data packet: 16-byte header + variable payload (32 here) = 48 bytes.
const DATA_PACKET_HEX =
    "04" ++ // type = 4
    "000000" ++ // reserved = 0
    "0000000f" ++ // receiver_index = 15 (u32 BE)
    "0000000000000011" ++ // counter = 17 (u64 BE)
    PAYLOAD_FILL; // 32 bytes

test "BE_WIRE_01 transport data header round-trips the pinned layout, zero heap" {
    const bytes = decodeHex(DATA_PACKET_HEX);
    try std.testing.expectEqual(@as(usize, 48), bytes.len);
    const msg = try parser.parseDataPacketHeader(&bytes);
    try std.testing.expectEqual(@as(u32, 15), msg.receiver_index);
    try std.testing.expectEqual(@as(u64, 17), msg.counter);
    // Payload aliases the suffix; no totality trailing check (variable by design).
    try std.testing.expectEqualSlices(u8, &decodeHex(PAYLOAD_FILL), msg.encrypted_payload);
}

test "BE_WIRE_02 transport data with a wrong type byte is rejected as Malformed" {
    var bytes = decodeHex(DATA_PACKET_HEX);
    bytes[0] = 0x03;
    try std.testing.expectError(error.Malformed, parser.parseDataPacketHeader(&bytes));
}

test "BE_WIRE_02 transport data with a non-zero reserved byte is rejected as Malformed" {
    var bytes = decodeHex(DATA_PACKET_HEX);
    bytes[2] = 0x01;
    try std.testing.expectError(error.Malformed, parser.parseDataPacketHeader(&bytes));
}

test "BE_WIRE_02 transport data with no AEAD tag in the payload is rejected" {
    var buf: [20]u8 = undefined;
    @memset(&buf, 0x00);
    buf[0] = 0x04;
    // 20 bytes = 16-byte header + 4-byte payload: shorter than the 16-byte tag,
    // so it cannot be a valid ciphertext.
    try std.testing.expectError(error.Truncated, parser.parseDataPacketHeader(&buf));
}

test "BE_WIRE_02 transport data above the BE-TR-05 packet ceiling is rejected" {
    var buf: [1401]u8 = undefined;
    @memset(&buf, 0x00);
    buf[0] = 0x04;
    // 1401 bytes = 16-byte header + 1385-byte payload: one byte over the
    // 1384-byte (1400 - 16) BE-TR-05 payload bound.
    try std.testing.expectError(error.Oversize, parser.parseDataPacketHeader(&buf));
}

// ---------------------------------------------------------------------------
// Fragment header + lighthouse lookup fixtures (SPEC 4.5, 5.1a). Synthetic,
// structurally valid bytes: like the four transport messages above there is no
// canonical vector for these (D-020), so each field carries a distinct fill so
// a round-trip asserts the slice landed at the right offset, not just the right
// length. Round-trip tests are BE_WIRE_01 (zero heap), rejections BE_WIRE_02
// (totality); both markers are already declared in SPEC section 11.1, so no new
// BE-* binding and no M1 high-water bump.
// ---------------------------------------------------------------------------

// Fragment header (SPEC 4.5): msg_id u64 + index u16 + total u16 + payload.
// 12-byte header + 4-byte payload = 16 bytes.
const FRAG_HEADER_HEX =
    "0102030405060708" ++ // msg_id = 0x0102030405060708 (u64 BE)
    "0002" ++ // index = 2 (u16 BE)
    "0005" ++ // total = 5 (u16 BE)
    "deadbeef"; // 4-byte fragment payload

test "BE_WIRE_01 fragment header round-trips the pinned layout, zero heap" {
    const bytes = decodeHex(FRAG_HEADER_HEX);
    try std.testing.expectEqual(@as(usize, 16), bytes.len);
    const frag = try parser.session.parseFragmentHeader(&bytes);
    try std.testing.expectEqual(@as(u64, 0x0102030405060708), frag.msg_id);
    try std.testing.expectEqual(@as(u16, 2), frag.index);
    try std.testing.expectEqual(@as(u16, 5), frag.total);
    // Payload aliases the suffix; variable like the data packet, no trailing check.
    try std.testing.expectEqualSlices(u8, bytes[12..16], frag.payload);
}

test "BE_WIRE_01 fragment header with an empty payload is accepted (no spec floor)" {
    // 12-byte header, index 0 of 1, no payload bytes: structurally valid. SPEC 4.5
    // declares no per-fragment payload floor (MAX_FRAGMENTS is not a BE-TR-05 row),
    // so the parser does not invent one.
    const bytes = decodeHex("0102030405060708" ++ "0000" ++ "0001");
    try std.testing.expectEqual(@as(usize, 12), bytes.len);
    const frag = try parser.session.parseFragmentHeader(&bytes);
    try std.testing.expectEqual(@as(u16, 0), frag.index);
    try std.testing.expectEqual(@as(u16, 1), frag.total);
    try std.testing.expectEqual(@as(usize, 0), frag.payload.len);
}

test "BE_WIRE_02 fragment header with total == 0 is rejected as Malformed" {
    var bytes = decodeHex(FRAG_HEADER_HEX);
    // total field at bytes 10..11; set to 0.
    bytes[10] = 0x00;
    bytes[11] = 0x00;
    try std.testing.expectError(error.Malformed, parser.session.parseFragmentHeader(&bytes));
}

test "BE_WIRE_02 fragment header with index >= total is rejected as Malformed" {
    var bytes = decodeHex(FRAG_HEADER_HEX);
    // index 2, total 5 in the fixture; raise index to 5 so index == total.
    bytes[8] = 0x00;
    bytes[9] = 0x05;
    try std.testing.expectError(error.Malformed, parser.session.parseFragmentHeader(&bytes));
}

test "BE_WIRE_02 truncated fragment header is rejected" {
    const bytes = decodeHex(FRAG_HEADER_HEX);
    // 11 bytes: one short of the 12-byte header.
    try std.testing.expectError(error.Truncated, parser.session.parseFragmentHeader(bytes[0..11]));
}

// LookupRequest (SPEC 5.1a): u8 version + [16] overlay_addr = 17 bytes fixed.
const OVERLAY_ADDR_FILL = "0a" ** 16; // 16 bytes, the overlay address being looked up
const LOOKUP_REQ_HEX =
    "01" ++ // version = 1
    OVERLAY_ADDR_FILL;

test "BE_WIRE_01 lookup request round-trips the pinned layout, zero heap" {
    const bytes = decodeHex(LOOKUP_REQ_HEX);
    try std.testing.expectEqual(@as(usize, 17), bytes.len);
    const req = try parser.session.parseLookupRequest(&bytes);
    try std.testing.expectEqual(@as(u8, 1), req.version);
    try std.testing.expectEqualSlices(u8, bytes[1..17], req.overlay_addr);
}

test "BE_WIRE_02 lookup request with a trailing byte is rejected" {
    const bytes = decodeHex(LOOKUP_REQ_HEX);
    var buf: [18]u8 = undefined;
    @memcpy(buf[0..17], &bytes);
    buf[17] = 0x00;
    try std.testing.expectError(error.TrailingBytes, parser.session.parseLookupRequest(&buf));
}

test "BE_WIRE_02 truncated lookup request is rejected" {
    const bytes = decodeHex(LOOKUP_REQ_HEX);
    // 16 bytes: one short of the 17-byte fixed message.
    try std.testing.expectError(error.Truncated, parser.session.parseLookupRequest(bytes[0..16]));
}

// LookupResponse (SPEC 5.1a): u8 version + [16] overlay_addr + u8 endpoint_count +
// endpoint_count*(u8 family + [16] addr + u16 port) + u16 cert_len + cert.
// 2 endpoints, 4-byte cert: 1 + 16 + 1 + 2*19 + 2 + 4 = 62 bytes.
const EP_ADDR_A_FILL = "b1" ** 16; // endpoint A address
const EP_ADDR_B_FILL = "b2" ** 16; // endpoint B address
const CERT_FILL = "c1" ** 4; // 4-byte opaque certificate slice
const LOOKUP_RESP_HEX =
    "01" ++ // version = 1
    OVERLAY_ADDR_FILL ++ // [16] overlay_addr echoed back
    "02" ++ // endpoint_count = 2 (u8)
    "02" ++ EP_ADDR_A_FILL ++ "01f5" ++ // endpoint A: family=2, [16] addr, port=501 (u16 BE)
    "0a" ++ EP_ADDR_B_FILL ++ "1f90" ++ // endpoint B: family=10, [16] addr, port=8080 (u16 BE)
    "0004" ++ // cert_len = 4 (u16 BE)
    CERT_FILL; // 4-byte cert

test "BE_WIRE_01 lookup response round-trips the pinned layout, zero heap" {
    const bytes = decodeHex(LOOKUP_RESP_HEX);
    try std.testing.expectEqual(@as(usize, 62), bytes.len);
    const resp = try parser.session.parseLookupResponse(&bytes);
    try std.testing.expectEqual(@as(u8, 1), resp.version);
    try std.testing.expectEqualSlices(u8, bytes[1..17], resp.overlay_addr);
    try std.testing.expectEqual(@as(u8, 2), resp.endpoint_count);
    // Endpoints flat slice = 2 tuples * 19 bytes = 38 bytes, aliasing buffer[18..56].
    try std.testing.expectEqual(@as(usize, 38), resp.endpoints.len);
    try std.testing.expectEqualSlices(u8, bytes[18..56], resp.endpoints);
    // Cert opaque slice aliases buffer[58..62]; caller runs BE-ID-01..04 (BE-MESH-04).
    try std.testing.expectEqualSlices(u8, bytes[58..62], resp.cert);
}

test "BE_WIRE_02 lookup response with a trailing byte is rejected" {
    const bytes = decodeHex(LOOKUP_RESP_HEX);
    var buf: [63]u8 = undefined;
    @memcpy(buf[0..62], &bytes);
    buf[62] = 0x00;
    try std.testing.expectError(error.TrailingBytes, parser.session.parseLookupResponse(&buf));
}

test "BE_WIRE_02 lookup response with fewer endpoint bytes than declared is rejected" {
    const bytes = decodeHex(LOOKUP_RESP_HEX);
    // endpoint_count = 2 (38 bytes needed) but truncate after one endpoint:
    // version(1) + overlay(16) + count(1) + one endpoint(19) = 37 bytes.
    try std.testing.expectError(error.Truncated, parser.session.parseLookupResponse(bytes[0..37]));
}

test "BE_WIRE_02 lookup response whose cert is shorter than cert_len is rejected" {
    var bytes = decodeHex(LOOKUP_RESP_HEX);
    // cert_len at bytes 56..57 (= 1+16+1+19+19); claim 5 bytes, only 4 follow.
    bytes[56] = 0x00;
    bytes[57] = 0x05;
    try std.testing.expectError(error.Truncated, parser.session.parseLookupResponse(&bytes));
}

test "BE_WIRE_01 lookup response with no endpoints is accepted" {
    // A lighthouse may have no observed endpoint for an overlay (BE-MESH-01: a
    // lighthouse can refuse to answer). endpoint_count = 0, cert still served.
    const hex = "01" ++ OVERLAY_ADDR_FILL ++ "00" ++ "0004" ++ CERT_FILL;
    const bytes = decodeHex(hex);
    try std.testing.expectEqual(@as(usize, 24), bytes.len); // 1+16+1+0+2+4
    const resp = try parser.session.parseLookupResponse(&bytes);
    try std.testing.expectEqual(@as(u8, 0), resp.endpoint_count);
    try std.testing.expectEqual(@as(usize, 0), resp.endpoints.len);
    try std.testing.expectEqualSlices(u8, bytes[20..24], resp.cert);
}

// Certificate (SPEC section 3.1). The canonical agent-1 cert from
// test/vectors.json (structure /structures/cert): 293 bytes, version 2,
// role_bits 0x03 (participant + agent), two strictly-ascending CA
// countersignatures, zero trailing. M3 (vectors_test.zig) verifies both CA
// signatures over these exact bytes, so this round-trip is anchored to real
// cross-implementation bytes, not synthetic fill. Crypto verification
// (BE-ID-01..04) stays out of the parser; parseCert enforces only the section
// 3.1 structural invariants and the CA-key ordering.
const CERT_WIRE_HEX =
    "0203020bd427446b723424d80d2cad352ba3df3649d0ef8faae0ca7eb2544394" ++
    "1b29b16e7150a191f75488a3e9a9b4b3f8e334f096b87d7bea974c8f6afd0d26" ++
    "254c0000018bcfe56800000001a3185c500000076167656e742d310121c9a4aa" ++
    "d663d1ed0279b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e391" ++
    "0bad0496645bd00e38771c2fd093b5085d4be27ef0b2b8d07e6ce6c7841a410e" ++
    "b866adeb7aaa54bca17bce130428d73437cb858e59801f275461c15a468b7a72" ++
    "c3948f250ae7f162a10bec559afea195e4dce84b69568d5d2cb0963eb446c068" ++
    "5e2b17f2f05a91d5910dea0f09fe0ec00b16123f6e87117ce5b17548093487c0" ++
    "2388f9b159acdf932380528d32ae911d3dcc4a9cf6868e94c206ec7490618dbc" ++
    "a1d6099d0f";

test "BE_WIRE_01 certificate round-trips the canonical vector, zero heap" {
    const bytes = decodeHex(CERT_WIRE_HEX);
    try std.testing.expectEqual(@as(usize, 293), bytes.len);
    const cert = try parser.session.parseCert(&bytes);
    try std.testing.expectEqual(@as(u8, 2), cert.version);
    try std.testing.expectEqual(@as(u8, 0x03), cert.role_bits);
    // sig_pubkey is the agent Ed25519 key (same as SENDER_HEX); aliases the buffer.
    try std.testing.expectEqualSlices(u8, bytes[2..34], cert.sig_pubkey);
    try std.testing.expectEqualSlices(u8, bytes[34..66], cert.kex_pubkey);
    try std.testing.expectEqual(@as(u64, 1700000000000), cert.not_before);
    try std.testing.expectEqual(@as(u64, 1800000000000), cert.not_after);
    try std.testing.expectEqualStrings("agent-1", cert.name);
    try std.testing.expectEqual(@as(u8, 1), cert.group_count);
    try std.testing.expectEqualSlices(u8, bytes[92..100], cert.group_ids);
    // tbs is every byte preceding ca_sig_count (offset 100): version..group_ids.
    try std.testing.expectEqual(@as(usize, 100), cert.tbs.len);
    try std.testing.expectEqualSlices(u8, bytes[0..100], cert.tbs);
    try std.testing.expectEqual(@as(u8, 2), cert.ca_sig_count);
    // ca_sigs flat region = 2 pairs * (32 key + 64 sig) = 192 bytes, offset 101.
    try std.testing.expectEqual(@as(usize, 192), cert.ca_sigs.len);
    try std.testing.expectEqualSlices(u8, bytes[101..293], cert.ca_sigs);
}

test "BE_WIRE_01 certificate with version != 2 is parsed, policy deferred (SPEC 2.2)" {
    // Version is the sole negotiation surface (SPEC 2.2); parseCert carries it
    // without rejecting, matching parseEnvelope/parseGrant/parseSpan. A v3 cert
    // parses and the caller applies version policy under BE-ID-01..04.
    var bytes = decodeHex(CERT_WIRE_HEX);
    bytes[0] = 0x03;
    const cert = try parser.session.parseCert(&bytes);
    try std.testing.expectEqual(@as(u8, 3), cert.version);
}

test "BE_WIRE_01 certificate with a single CA signature and empty name is accepted" {
    // Synthetic but structurally valid: one CA countersignature (trivial ordering),
    // empty name, no groups. Proves the ca_sig_count == 1 path and the zero-length
    // name/group paths. Sigs are not verified by the parser (BE-ID-01..04, caller).
    const hex = "02" ++ "01" ++ "aa" ** 32 ++ "bb" ** 32 ++
        "0000000000000001" ++ "0000000000000002" ++
        "0000" ++ "00" ++ "01" ++ "cc" ** 32 ++ "dd" ** 64;
    const bytes = decodeHex(hex);
    try std.testing.expectEqual(@as(usize, 182), bytes.len);
    const cert = try parser.session.parseCert(&bytes);
    try std.testing.expectEqual(@as(u8, 1), cert.role_bits);
    try std.testing.expectEqual(@as(usize, 0), cert.name.len);
    try std.testing.expectEqual(@as(u8, 0), cert.group_count);
    try std.testing.expectEqual(@as(u8, 1), cert.ca_sig_count);
    try std.testing.expectEqual(@as(usize, 96), cert.ca_sigs.len);
    try std.testing.expectEqual(@as(usize, 85), cert.tbs.len);
}

test "BE_WIRE_02 certificate with name_len above 64 is rejected as Oversize" {
    var bytes = decodeHex(CERT_WIRE_HEX);
    // name_len at bytes 82..83; set to 65 (big-endian). field16 rejects > MAX_NAME.
    bytes[82] = 0x00;
    bytes[83] = 0x41;
    try std.testing.expectError(error.Oversize, parser.session.parseCert(&bytes));
}

test "BE_WIRE_02 certificate with group_count above 16 is rejected as Oversize" {
    var bytes = decodeHex(CERT_WIRE_HEX);
    bytes[91] = 17; // group_count
    try std.testing.expectError(error.Oversize, parser.session.parseCert(&bytes));
}

test "BE_WIRE_02 certificate with ca_sig_count == 0 is rejected as Malformed" {
    var bytes = decodeHex(CERT_WIRE_HEX);
    bytes[100] = 0x00; // ca_sig_count: a cert needs at least one countersignature
    try std.testing.expectError(error.Malformed, parser.session.parseCert(&bytes));
}

test "BE_WIRE_02 certificate with ca_sig_count above 4 is rejected as Oversize" {
    var bytes = decodeHex(CERT_WIRE_HEX);
    bytes[100] = 0x05; // ca_sig_count > MAX_CA_SIGS; checked before the read loop
    try std.testing.expectError(error.Oversize, parser.session.parseCert(&bytes));
}

test "BE_WIRE_02 certificate with non-ascending (equal) CA keys is rejected as Malformed" {
    var bytes = decodeHex(CERT_WIRE_HEX);
    // Copy ca_key[0] (bytes 101..133) over ca_key[1] (bytes 197..229): equal keys
    // violate the strict-ascending / pairwise-distinct rule (SPEC 3.1).
    @memcpy(bytes[197..229], bytes[101..133]);
    try std.testing.expectError(error.Malformed, parser.session.parseCert(&bytes));
}

test "BE_WIRE_02 certificate with a trailing byte is rejected" {
    const bytes = decodeHex(CERT_WIRE_HEX);
    var buf: [294]u8 = undefined;
    @memcpy(buf[0..293], &bytes);
    buf[293] = 0x00;
    try std.testing.expectError(error.TrailingBytes, parser.session.parseCert(&buf));
}

test "BE_WIRE_02 truncated certificate is rejected" {
    const bytes = decodeHex(CERT_WIRE_HEX);
    // 200 bytes: cuts into the first CA signature region.
    try std.testing.expectError(error.Truncated, parser.session.parseCert(bytes[0..200]));
}

// ---------------------------------------------------------------------------
// Channel control structures (SPEC 6.1b, 6.1c). Hand-built flat bodies, not a
// cross-implementation vector: ControlGenesis and Control are unsigned inner
// bodies authenticated by the enclosing envelope signature, so the parser is
// tested against the SPEC layout directly. GENESIS: version | name |
// member_group | admin_group | ca_count,ca_keys | match_rule. CONTROL:
// version | action_type | subject | body.

const GENESIS_HEX =
    "01" ++ // version
    "0004" ++ "74657374" ++ // name_len, "test"
    "aaaaaaaaaaaaaaaa" ++ // member_group (8 bytes)
    "bbbbbbbbbbbbbbbb" ++ // admin_group (8 bytes)
    "01" ++ "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" ++ // ca_count=1, one 32-byte key
    "01"; // match_rule (byte equality, BE-GEN-04)

const CONTROL_HEX =
    "01" ++ // version (parsed, not enforced)
    "01" ++ // action_type (1 = Genesis)
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" ++ // subject (32 bytes)
    "0003" ++ "666f6f"; // body_len, "foo"

test "BE_WIRE_01 control genesis round-trips the SPEC layout, zero heap" {
    const bytes = decodeHex(GENESIS_HEX);
    const g = try parser.channel.parseControlGenesis(&bytes);

    try std.testing.expectEqual(@as(u8, 1), g.version);
    try std.testing.expectEqualSlices(u8, "test", g.name);
    try std.testing.expectEqual(@as(usize, 8), g.member_group.len);
    try std.testing.expectEqual(@as(usize, 8), g.admin_group.len);
    try std.testing.expectEqual(@as(u8, 1), g.ca_count);
    try std.testing.expectEqual(@as(usize, 32), g.ca_keys.len);
    try std.testing.expectEqual(@as(u8, 1), g.match_rule);

    // Slices alias the input buffer.
    try std.testing.expectEqualSlices(u8, bytes[7..15], g.member_group);
    try std.testing.expectEqualSlices(u8, bytes[15..23], g.admin_group);
    try std.testing.expectEqualSlices(u8, bytes[24..56], g.ca_keys);
}

test "BE_WIRE_02 control genesis ca_count == 0 is rejected as Malformed" {
    var bytes = decodeHex(GENESIS_HEX);
    bytes[23] = 0x00; // grammar floor 1: a trust set needs at least one key
    try std.testing.expectError(error.Malformed, parser.channel.parseControlGenesis(&bytes));
}

test "BE_WIRE_02 control genesis ca_count above 16 is rejected as Oversize" {
    var bytes = decodeHex(GENESIS_HEX);
    bytes[23] = 17; // BE-TR-05: ca_count bounded before it drives the slice
    try std.testing.expectError(error.Oversize, parser.channel.parseControlGenesis(&bytes));
}

test "BE_WIRE_02 control genesis with a trailing byte is rejected" {
    const bytes = decodeHex(GENESIS_HEX);
    var buf: [58]u8 = undefined;
    @memcpy(buf[0..57], &bytes);
    buf[57] = 0x00;
    try std.testing.expectError(error.TrailingBytes, parser.channel.parseControlGenesis(&buf));
}

test "BE_WIRE_02 truncated control genesis is rejected" {
    const bytes = decodeHex(GENESIS_HEX);
    // 40 bytes: cuts into the ca_keys slice read at offset 24.
    try std.testing.expectError(error.Truncated, parser.channel.parseControlGenesis(bytes[0..40]));
}

test "BE_WIRE_01 control message round-trips the SPEC layout, zero heap" {
    const bytes = decodeHex(CONTROL_HEX);
    const c = try parser.channel.parseControl(&bytes);

    try std.testing.expectEqual(@as(u8, 1), c.action_type);
    try std.testing.expectEqual(@as(usize, 32), c.subject.len);
    try std.testing.expectEqualSlices(u8, "foo", c.body);

    // Slices alias the input buffer; the version byte is consumed and discarded.
    try std.testing.expectEqualSlices(u8, bytes[2..34], c.subject);
    try std.testing.expectEqualSlices(u8, bytes[36..39], c.body);
}

test "BE_WIRE_02 control message with a trailing byte is rejected" {
    const bytes = decodeHex(CONTROL_HEX);
    var buf: [40]u8 = undefined;
    @memcpy(buf[0..39], &bytes);
    buf[39] = 0x00;
    try std.testing.expectError(error.TrailingBytes, parser.channel.parseControl(&buf));
}

// ---------------------------------------------------------------------------
// BE-EFF-01 (wire half). ok=false means the mechanism did not run; a subprocess
// that ran and returned a non-zero exit code is ok=true with exit_code inline.
// "Did the mechanism work" and "what did it report" stay separate all the way
// up the wire. The executor-side reporting obligation is out of slice; this
// binds the parser half: ok and exit_code are distinct fields that round-trip.
// Effect body: [16]intent_id | [16]grant_id | u8 ok | i32 exit_code |
//              u8 span_count | Span[] | [32]output_digest   (SPEC 6.3)
// ---------------------------------------------------------------------------

test "BE_EFF_01 ok and exit_code are distinct fields on the wire" {
    // A subprocess that ran and reported failure (exit 1) is ok=true with
    // exit_code=1, NOT collapsed into ok=false.
    var ran: [70]u8 = [_]u8{0} ** 70;
    ran[32] = 1; // ok = true (mechanism ran)
    ran[33] = 0;
    ran[34] = 0;
    ran[35] = 0;
    ran[36] = 1; // exit_code = 1 (big-endian i32, non-zero)
    ran[37] = 0; // span_count = 0
    // output_digest occupies [38..70], already zero.

    const eff_ran = try parser.channel.parseEffect(&ran);
    try std.testing.expectEqual(@as(u8, 1), eff_ran.ok);
    try std.testing.expectEqual(@as(i32, 1), eff_ran.exit_code);

    // A mechanism that did not run is ok=false with exit_code=0.
    var norun: [70]u8 = [_]u8{0} ** 70;
    norun[32] = 0; // ok = false
    norun[37] = 0; // span_count = 0

    const eff_norun = try parser.channel.parseEffect(&norun);
    try std.testing.expectEqual(@as(u8, 0), eff_norun.ok);
    try std.testing.expectEqual(@as(i32, 0), eff_norun.exit_code);
}

// ---------------------------------------------------------------------------
// BE-TR-07 (no handshake payloads). Handshake messages MUST carry no
// application payload. In Noise_IK, message-1's payload is encrypted under
// es+ss only: replayable and not forward-secret, so no payload (and no cert)
// may ride the handshake. Bound structurally: neither handshake message type
// has a payload field, and the response carries encrypted_nothing (a
// zero-length encrypted body). Adding a payload field fails this test.
// ---------------------------------------------------------------------------

test "BE_TR_07 handshake messages carry no payload field" {
    try std.testing.expect(!@hasField(parser.HandshakeInitiation, "payload"));
    try std.testing.expect(!@hasField(parser.HandshakeResponse, "payload"));
    // The response's body is literally encrypted_nothing: zero payload.
    try std.testing.expect(@hasField(parser.HandshakeResponse, "encrypted_nothing"));
}

// ---------------------------------------------------------------------------
// BE-EVID-12 (intent carries no observation method). An Intent MUST NOT name,
// hint at, or constrain the observation method. The Intent body is action +
// rationale only; no method selector may ride it, so an agent cannot pin or
// bias how its action is observed. Bound structurally: the Intent type has no
// method field. Adding one fails this test.
// ---------------------------------------------------------------------------

test "BE_EVID_12 intent carries no observation-method selector" {
    try std.testing.expect(!@hasField(parser.channel.Intent, "method"));
    try std.testing.expect(!@hasField(parser.channel.Intent, "method_id"));
}

// ---------------------------------------------------------------------------
// BE-BODY-02 (action digest recomputed, never transmitted). An action digest
// is always recomputed and never transmitted: no wire structure carries a
// digest of its own action, and no party accepts a digest supplied by the
// party whose action it describes. The agent's own structure carries raw
// action bytes (opaque, never parsed); the daemon recomputes BLAKE2s(action)
// at verify time and compares it against the approver-supplied grant digest.
// The grant (an approver structure) may carry action_digest as its binding;
// the Intent (the agent's own structure) MUST NOT. Bound structurally: the
// Intent type has no action_digest field. Adding one fails this test.
// ---------------------------------------------------------------------------

test "BE_BODY_02 intent carries no transmitted action digest" {
    // The agent's own structure carries the raw action, not a digest of it.
    try std.testing.expect(!@hasField(parser.channel.Intent, "action_digest"));
    // The raw action bytes are present (opaque); the daemon digests them.
    try std.testing.expect(@hasField(parser.channel.Intent, "action"));
}
