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
