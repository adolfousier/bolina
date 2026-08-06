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
    const env = try parser.parseEnvelope(&ENVELOPE_BYTES);

    try std.testing.expectEqual(@as(u8, 2), env.version);
    try std.testing.expectEqual(@as(u64, 1), env.seq);
    try std.testing.expectEqual(@as(u8, 0), env.parent_count);
    try std.testing.expectEqual(@as(u64, 1700000010000), env.ts);
    try std.testing.expectEqual(parser.BODY_INTENT, env.body_type);

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
    const env = try parser.parseEnvelope(&ENVELOPE_BYTES);
    const intent = try parser.parseIntent(env.body);

    try std.testing.expectEqualSlices(u8, &decodeHex(INTENT_ID_HEX), intent.intent_id);
    try std.testing.expectEqualStrings("bol:c3efd641bfa0582f/logs/deploy.log", intent.resource_id);
    // action is opaque to the daemon (BE-BODY-01); parsed by length, not content.
    try std.testing.expectEqualStrings("apt-get install -y sqlite3", intent.action);
    try std.testing.expectEqualStrings("Install sqlite for local schema inspection.", intent.rationale);
}

test "BE_WIRE_02 truncated signature is rejected" {
    var buf: [279]u8 = undefined;
    @memcpy(buf[0..279], ENVELOPE_BYTES[0..279]);
    try std.testing.expectError(error.Truncated, parser.parseEnvelope(&buf));
}

test "BE_WIRE_02 trailing byte is rejected" {
    var buf: [281]u8 = undefined;
    @memcpy(buf[0..280], &ENVELOPE_BYTES);
    buf[280] = 0x00;
    try std.testing.expectError(error.TrailingBytes, parser.parseEnvelope(&buf));
}

test "BE_WIRE_02 oversize body_len is rejected before any large read" {
    var buf: [280]u8 = ENVELOPE_BYTES;
    // body_len lives at byte 83 (version + channel_id + sender + seq +
    // parent_count + ts + body_type = 1+32+32+8+1+8+1).
    buf[83] = 0xff;
    buf[84] = 0xff;
    buf[85] = 0xff;
    buf[86] = 0xff;
    try std.testing.expectError(error.Oversize, parser.parseEnvelope(&buf));
}

test "BE_WIRE_02 parent_count above the bound is rejected" {
    var buf: [280]u8 = ENVELOPE_BYTES;
    // parent_count lives at byte 73 (version + channel_id + sender + seq).
    buf[73] = 5;
    try std.testing.expectError(error.Oversize, parser.parseEnvelope(&buf));
}

test "BE_WIRE_02 empty input is rejected" {
    try std.testing.expectError(error.Truncated, parser.parseEnvelope(&[_]u8{}));
}

test "BE_WIRE_02 intent with a trailing byte is rejected" {
    const env = try parser.parseEnvelope(&ENVELOPE_BYTES);
    var buf: [130]u8 = undefined;
    @memcpy(buf[0..129], env.body);
    buf[129] = 0x00;
    try std.testing.expectError(error.TrailingBytes, parser.parseIntent(&buf));
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
