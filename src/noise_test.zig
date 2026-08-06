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
    var want: [noise.HASHLEN]u8 = undefined;
    std.crypto.hash.blake2.Blake2s256.hash(noise.PROTOCOL_NAME, &want, .{});
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
}

test "BE_TR_04 mixKeyAndHash runs the three-output HKDF and stays keyed" {
    var a = noise.SymmetricState.init();
    var b = noise.SymmetricState.init();
    const ikm = [_]u8{0x77} ** 32;
    a.mixKeyAndHash(&ikm);
    b.mixKeyAndHash(&ikm);
    try testing.expect(a.has_key);
    try testing.expectEqualSlices(u8, &a.h, &b.h);
    try testing.expectEqualSlices(u8, &a.ck, &b.ck);
    try testing.expectEqualSlices(u8, &a.k, &b.k);
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
