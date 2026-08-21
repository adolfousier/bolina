// noise_test.zig
//
// Tests for the Noise symmetric state and Noise_IK handshake (src/noise.zig,
// SPEC section 4.1 / BE-TR-04). The symmetric state is unit-tested directly;
// the handshake is proven by an initiator/responder round trip that ends with
// matching transport keys, plus the two negative paths mac1-first and a tampered
// ciphertext force.

const std = @import("std");
const testing = std.testing;
const noise = @import("noise.zig");
const mac = @import("mac.zig");

test "BE_TR_04 nonce is four zero bytes then a big-endian counter" {
    // counter 1: four zero bytes, then seven zero bytes and a 0x01.
    const n1 = noise.transportNonce(1);
    try testing.expectEqual(@as(u8, 0), n1[0]);
    try testing.expectEqual(@as(u8, 0), n1[3]);
    try testing.expectEqual(@as(u8, 0), n1[10]);
    try testing.expectEqual(@as(u8, 1), n1[11]);

    // A large counter lands big-endian: 0x0102030405060708.
    const nb = noise.transportNonce(0x0102030405060708);
    try testing.expectEqual(@as(u8, 0), nb[0]);
    try testing.expectEqual(@as(u8, 0), nb[3]);
    try testing.expectEqual(@as(u8, 0x01), nb[4]);
    try testing.expectEqual(@as(u8, 0x08), nb[11]);
}

test "BE_TR_04 symmetric state seeds from the protocol name, no key" {
    var s = noise.SymmetricState.init();
    // h = BLAKE2s("Noise_IK_25519_ChaChaPoly_BLAKE2s"), ck == h, no key.
    // Literal KAT from an independent Python hashlib run: D-027, the test must
    // not hash the module's own PROTOCOL_NAME or a mutant on the name hashes
    // its own mutation and survives.
    const want = [32]u8{ 0xbb, 0xea, 0x02, 0x2b, 0x94, 0x8c, 0xf3, 0xbc, 0x58, 0x57, 0xd7, 0x08, 0x04, 0x22, 0x91, 0x79, 0xe1, 0x11, 0x6b, 0xc4, 0x0c, 0xb8, 0xcc, 0x07, 0x48, 0x35, 0x34, 0x9c, 0x46, 0x4b, 0xca, 0x36 };
    try testing.expectEqualSlices(u8, &want, &s.h);
    try testing.expectEqualSlices(u8, &want, &s.ck);
    try testing.expect(!s.has_key);
}

test "BE_TR_04 mixHash and mixKey are deterministic and key the state" {
    var a = noise.SymmetricState.init();
    var b = noise.SymmetricState.init();
    const blob = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    a.mixHash(&blob);
    b.mixHash(&blob);
    try testing.expectEqualSlices(u8, &a.h, &b.h);

    // mixKey consumes a 32-byte DH output, sets has_key, and is reproducible.
    const ikm = [_]u8{0x55} ** 32;
    a.mixKey(ikm);
    b.mixKey(ikm);
    try testing.expect(a.has_key);
    try testing.expectEqualSlices(u8, &a.ck, &b.ck);
    try testing.expectEqualSlices(u8, &a.k, &b.k);

    // Literal KATs from an independent Python HMAC-BLAKE2s run (Noise HKDF,
    // counter bytes 0x01/0x02): the a/b cross-check scales with any HKDF
    // mutant, only fixed bytes kill it. D-027.
    const want_ck = [32]u8{ 0xac, 0x82, 0xdc, 0x08, 0xb0, 0x53, 0x30, 0x33, 0x7a, 0x44, 0xd3, 0x43, 0xf0, 0x87, 0x8a, 0xe5, 0xa6, 0x78, 0x1c, 0x5a, 0x75, 0xbe, 0x87, 0x06, 0xd2, 0xe2, 0x8a, 0xbc, 0x33, 0xa8, 0x4b, 0x5e };
    const want_k = [32]u8{ 0x65, 0xe4, 0x46, 0xab, 0xf5, 0xca, 0x10, 0x61, 0x0a, 0x94, 0x96, 0x4f, 0x31, 0x25, 0xe8, 0xe2, 0x04, 0xb7, 0x72, 0xd2, 0x04, 0xd0, 0xda, 0x80, 0x57, 0x62, 0xe3, 0xa1, 0xad, 0xd7, 0xd5, 0x4e };
    try testing.expectEqualSlices(u8, &want_ck, &a.ck);
    try testing.expectEqualSlices(u8, &want_k, &a.k);
}

test "BE_TR_04 split yields a fixed pair from a fixed chaining key" {
    var a = noise.SymmetricState.init();
    var b = noise.SymmetricState.init();
    const ikm = [_]u8{0x33} ** 32;
    a.mixKey(ikm);
    b.mixKey(ikm);
    const sa = a.split();
    const sb = b.split();
    try testing.expectEqualSlices(u8, &sa.c1, &sb.c1);
    try testing.expectEqualSlices(u8, &sa.c2, &sb.c2);
    // The two split halves of a non-degenerate state differ.
    try testing.expect(!std.mem.eql(u8, &sa.c1, &sa.c2));

    // Literal KATs from the independent Python run (hkdf2 over empty ikm).
    // A c1/c2 swap mutant is invisible to the symmetric round trip because
    // both sides split the same way; only fixed bytes kill it. D-027.
    const want_c1 = [32]u8{ 0x0c, 0xea, 0xe9, 0xb4, 0x13, 0x3d, 0xd8, 0x9a, 0xc6, 0xf4, 0x73, 0xad, 0x26, 0x5f, 0x86, 0xa1, 0x6d, 0xc2, 0xfc, 0xc0, 0x5a, 0x20, 0x89, 0xdf, 0x5a, 0xbe, 0x01, 0x49, 0x59, 0x60, 0xff, 0x4a };
    const want_c2 = [32]u8{ 0x4b, 0x57, 0x8d, 0xe5, 0x0b, 0x39, 0xce, 0xbe, 0x26, 0x63, 0x56, 0x5d, 0xbf, 0x32, 0xb8, 0xa5, 0x10, 0xe0, 0x31, 0xd8, 0xdd, 0x85, 0x33, 0x00, 0xa8, 0x20, 0x4b, 0x84, 0x0e, 0xc3, 0xfe, 0xb6 };
    try testing.expectEqualSlices(u8, &want_c1, &sa.c1);
    try testing.expectEqualSlices(u8, &want_c2, &sa.c2);
}

test "BE_TR_04 EncryptAndHash and DecryptAndHash are inverses" {
    var enc = noise.SymmetricState.init();
    const ikm = [_]u8{0x11} ** 32;
    enc.mixKey(ikm); // key the state before encrypting
    var dec = enc; // responder starts from the same state

    const plaintext = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    var ciphertext: [plaintext.len + noise.TAGLEN]u8 = undefined;
    enc.encryptAndHash(&ciphertext, &plaintext);

    var recovered: [plaintext.len]u8 = undefined;
    try dec.decryptAndHash(&recovered, &ciphertext);
    try testing.expectEqualSlices(u8, &plaintext, &recovered);
    // Both transcript hashes advance identically over the ciphertext.
    try testing.expectEqualSlices(u8, &enc.h, &dec.h);
}

test "BE_TR_04 a tampered ciphertext fails decryption" {
    var enc = noise.SymmetricState.init();
    const ikm = [_]u8{0x22} ** 32;
    enc.mixKey(ikm);
    var dec = enc;

    const plaintext = [_]u8{ 9, 9, 9, 9 };
    var ciphertext: [plaintext.len + noise.TAGLEN]u8 = undefined;
    enc.encryptAndHash(&ciphertext, &plaintext);

    ciphertext[0] ^= 0xFF; // flip a plaintext byte
    var recovered: [plaintext.len]u8 = undefined;
    try testing.expectError(noise.Error.DecryptFailed, dec.decryptAndHash(&recovered, &ciphertext));
}

// A full Noise_IK round trip. Static keypairs are random; the ephemeral keys are
// generated inside the handshake. The assertion is key agreement, not a fixed
// transcript, so it proves the construction composes without pinning bytes.
fn runHandshake(seed_init: [32]u8, seed_resp: [32]u8, responder_sig_pubkey: mac.ResponderSigPubkey) !struct {
    ir: noise.HandshakeResult,
    rr: noise.HandshakeResult,
} {
    const init_static = try noise.keypairFromSecret(seed_init);
    const resp_static = try noise.keypairFromSecret(seed_resp);

    var initiator = noise.Initiator.init(testing.io, init_static, resp_static.public);
    var responder = noise.Responder.init(testing.io, resp_static);

    var msg1: [noise.MSG1_SIZE]u8 = undefined;
    var msg2: [noise.MSG2_SIZE]u8 = undefined;
    const no_cookie = [_]u8{0} ** mac.MAC_BYTES;

    try initiator.writeInitiation(&msg1, 1, 1_700_000_000_000, responder_sig_pubkey, no_cookie);
    try responder.readInitiation(&msg1, responder_sig_pubkey);
    try responder.writeResponse(&msg2, 2, 1, responder_sig_pubkey, no_cookie);
    try initiator.readResponse(&msg2, responder_sig_pubkey);

    return .{ .ir = initiator.finalize(), .rr = responder.finalize() };
}

test "BE_TR_01 Noise_IK round trip derives matching transport keys" {
    var seed_init: [32]u8 = undefined;
    var seed_resp: [32]u8 = undefined;
    var sig_pub: mac.ResponderSigPubkey = undefined;
    testing.io.random(&seed_init);
    testing.io.random(&seed_resp);
    testing.io.random(&sig_pub);

    const r = try runHandshake(seed_init, seed_resp, sig_pub);

    // The initiator sends under c1 and the responder receives under c1, and the
    // reverse for c2. Mismatch here is a silently broken, non-interoperable
    // session, so it is the load-bearing assertion.
    try testing.expectEqualSlices(u8, &r.ir.send_key, &r.rr.recv_key);
    try testing.expectEqualSlices(u8, &r.ir.recv_key, &r.rr.send_key);
    try testing.expectEqualSlices(u8, &r.ir.handshake_hash, &r.rr.handshake_hash);
    try testing.expect(!std.mem.eql(u8, &r.ir.send_key, &r.ir.recv_key));
}

test "BE_TR_04 responder rejects a tampered mac1 before any X25519" {
    var seed_init: [32]u8 = undefined;
    var seed_resp: [32]u8 = undefined;
    var sig_pub: mac.ResponderSigPubkey = undefined;
    testing.io.random(&seed_init);
    testing.io.random(&seed_resp);
    testing.io.random(&sig_pub);

    const resp_static = try noise.keypairFromSecret(seed_resp);
    var initiator = noise.Initiator.init(testing.io, try noise.keypairFromSecret(seed_init), resp_static.public);
    var responder = noise.Responder.init(testing.io, resp_static);

    var msg1: [noise.MSG1_SIZE]u8 = undefined;
    const no_cookie = [_]u8{0} ** mac.MAC_BYTES;
    try initiator.writeInitiation(&msg1, 1, 1_700_000_000_000, sig_pub, no_cookie);

    // Flip one byte inside the mac1 proof. The responder MUST fail here, and the
    // failure precedes every curve operation in readInitiation.
    msg1[noise.OFF1_MAC1] ^= 0x01;
    try testing.expectError(noise.Error.Mac1Failed, responder.readInitiation(&msg1, sig_pub));
}

test "BE_TR_04 initiator rejects a tampered response mac1 before any X25519" {
    var seed_init: [32]u8 = undefined;
    var seed_resp: [32]u8 = undefined;
    var sig_pub: mac.ResponderSigPubkey = undefined;
    testing.io.random(&seed_init);
    testing.io.random(&seed_resp);
    testing.io.random(&sig_pub);

    const resp_static = try noise.keypairFromSecret(seed_resp);
    var initiator = noise.Initiator.init(testing.io, try noise.keypairFromSecret(seed_init), resp_static.public);
    var responder = noise.Responder.init(testing.io, resp_static);

    var msg1: [noise.MSG1_SIZE]u8 = undefined;
    var msg2: [noise.MSG2_SIZE]u8 = undefined;
    const no_cookie = [_]u8{0} ** mac.MAC_BYTES;
    try initiator.writeInitiation(&msg1, 1, 1_700_000_000_000, sig_pub, no_cookie);
    try responder.readInitiation(&msg1, sig_pub);
    try responder.writeResponse(&msg2, 2, 1, sig_pub, no_cookie);

    msg2[noise.OFF2_MAC1] ^= 0x01;
    try testing.expectError(noise.Error.Mac1Failed, initiator.readResponse(&msg2, sig_pub));
}

test "BE_TR_04 mac1 failure precedes the first X25519 even on a degenerate ephemeral" {
    // The ordering witness: an identity-point ephemeral makes the first DH
    // error with IdentityPoint. If the responder ran the curve before the
    // mac1 check, that error would surface instead of Mac1Failed. The two
    // tampered-mac1 tests above only prove the refusal exists, not that it
    // precedes every curve operation, because a delayed check still returns
    // Mac1Failed on a healthy ephemeral.
    var seed_init: [32]u8 = undefined;
    var seed_resp: [32]u8 = undefined;
    var sig_pub: mac.ResponderSigPubkey = undefined;
    testing.io.random(&seed_init);
    testing.io.random(&seed_resp);
    testing.io.random(&sig_pub);

    const resp_static = try noise.keypairFromSecret(seed_resp);
    var initiator = noise.Initiator.init(testing.io, try noise.keypairFromSecret(seed_init), resp_static.public);
    var responder = noise.Responder.init(testing.io, resp_static);

    var msg1: [noise.MSG1_SIZE]u8 = undefined;
    const no_cookie = [_]u8{0} ** mac.MAC_BYTES;
    try initiator.writeInitiation(&msg1, 1, 1_700_000_000_000, sig_pub, no_cookie);

    @memset(msg1[noise.OFF1_EPHEMERAL..][0..noise.DHLEN], 0); // identity point
    msg1[noise.OFF1_MAC1] ^= 0x01; // and an invalid mac1
    try testing.expectError(noise.Error.Mac1Failed, responder.readInitiation(&msg1, sig_pub));
}
