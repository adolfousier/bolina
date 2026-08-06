// mac.zig
//
// LANGUAGE.md section 4 implementation slice, transport item: the mac1/mac2
// denial-of-service gate (SPEC.md section 4.4, BE-TR-04 and BE-TR-04a). This is
// WireGuard's cookie-bricks design, adopted unchanged, ported to Bolina's
// four-primitive set. Only BLAKE2s is needed here: no asymmetric operation is
// performed before mac1 is checked, which is the whole point.
//
// Two proofs, layered:
//
//   * mac1 (BE-TR-04), proof of knowing who you are calling. Every handshake
//     message carries, in its unencrypted header, mac1 = BLAKE2s-MAC(key =
//     BLAKE2s("bolina-mac1-v2" || responder_sig_pubkey), message_bytes_preceding_mac1).
//     A responder verifies mac1 BEFORE any X25519 operation and silently drops
//     on failure. The sender must already know the responder's public key to
//     produce a valid mac1, so an unsolicited flood is rejected at the cost of
//     one BLAKE2s MAC, orders of magnitude cheaper than a curve operation.
//
//   * mac2 / cookie (BE-TR-04a), proof of controlling your source address. A
//     responder under load replies with a cookie, a BLAKE2s-MAC over the
//     initiator's observed source address under a server secret rotated at
//     least every 120 s, and requires the next attempt to carry it as mac2.
//     A message with a valid mac1 but absent or stale mac2 gets a cookie reply
//     and no curve operation.
//
//   mac1 stops attackers who do not know the target; mac2 stops attackers who
//   spoof their source. Neither alone suffices.
//
// Zero-heap and caller-owned (BE-WIRE-01). mac1 is computed from slices the
// caller already holds; the cookie secret is a fixed-size struct the caller
// declares on its own frame. No allocation, anywhere. The mac1 key is derived
// fresh per call (BLAKE2s-256 of the label and the responder key); the secret
// material for cookie rotation is supplied by the caller, so the module stays
// pure and deterministic under test. Comparison on verify is constant-time:
// the byte-wise XOR is OR-folded into one accumulator and only the accumulator
// is tested, so a wrong tag never leaks timing and the loop always runs to
// completion.
//
// This module is the pure crypto primitive. The ordering guarantee (verify mac1
// before any X25519, drop on failure, issue a cookie under load) is enforced by
// the handshake state machine that calls it, per D-018: state over parsed values
// lives in transport, and this file is transport, not parser (M5 budget N/A).

const std = @import("std");

const Blake2s128 = std.crypto.hash.blake2.Blake2s128;
const Blake2s256 = std.crypto.hash.blake2.Blake2s256;

// SPEC 4.4 BE-TR-04: the mac1 derivation label.
pub const MAC1_LABEL: []const u8 = "bolina-mac1-v2";

// SPEC 4.4 BE-TR-04a: the cookie secret is rotated at least every 120 seconds.
pub const COOKIE_ROTATE_MS: u64 = 120_000;

// BLAKE2s-128 output: the size of every mac1, mac2, and cookie.
pub const MAC_BYTES: usize = 16;

// BLAKE2s-256 output: the derived mac1 key and the cookie secret width
// (BLAKE2s key_length_max is 32, the recommended key length).
pub const KEY_BYTES: usize = 32;

// An Ed25519 signature public key is 32 bytes (SPEC 3.1). Fixed-width so a
// caller cannot pass a truncated or extended responder key by accident.
pub const RESPONDER_SIG_PUBKEY_BYTES: usize = 32;
pub const ResponderSigPubkey = [RESPONDER_SIG_PUBKEY_BYTES]u8;

// ---------------------------------------------------------------------------
// Constant-time comparison. OR-folds the byte-wise XOR into one accumulator
// and tests only the accumulator, so the loop runs to completion on a mismatch
// and the branch outcome does not depend on how many bytes agreed. No early
// exit, no data-dependent control flow.
fn constantTimeEql(comptime N: usize, a: [N]u8, b: [N]u8) bool {
    var diff: u8 = 0;
    for (a, b) |x, y| diff |= x ^ y;
    return diff == 0;
}

// ---------------------------------------------------------------------------
// mac1 (BE-TR-04).
//
// The key is BLAKE2s-256 of the label concatenated with the responder's
// signature public key (an unkeyed 256-bit digest over two chunks). The MAC is
// BLAKE2s-128 keyed with that derived key over the message bytes that precede
// mac1 in the on-wire header. Both stages use BLAKE2s's built-in keyed mode,
// the standard construction for a BLAKE2s-MAC (RFC 7693).

fn mac1Key(responder_sig_pubkey: ResponderSigPubkey) [KEY_BYTES]u8 {
    var key: [KEY_BYTES]u8 = undefined;
    var h = Blake2s256.init(.{});
    h.update(MAC1_LABEL);
    h.update(&responder_sig_pubkey);
    h.final(&key);
    return key;
}

// Compute mac1 over the message bytes that precede it in the on-wire header.
pub fn computeMac1(
    responder_sig_pubkey: ResponderSigPubkey,
    msg_preceding_mac1: []const u8,
) [MAC_BYTES]u8 {
    const key = mac1Key(responder_sig_pubkey);
    var out: [MAC_BYTES]u8 = undefined;
    Blake2s128.hash(msg_preceding_mac1, &out, .{ .key = &key });
    return out;
}

// Verify a received mac1 in constant time. Returns true only on an exact match.
// The caller MUST call this before any X25519 operation and silently drop on
// false (BE-TR-04).
pub fn verifyMac1(
    responder_sig_pubkey: ResponderSigPubkey,
    msg_preceding_mac1: []const u8,
    received_mac1: [MAC_BYTES]u8,
) bool {
    return constantTimeEql(
        MAC_BYTES,
        computeMac1(responder_sig_pubkey, msg_preceding_mac1),
        received_mac1,
    );
}

// ---------------------------------------------------------------------------
// Cookie secret and mac2 (BE-TR-04a).
//
// The cookie is BLAKE2s-128 keyed with the server secret over the initiator's
// observed source address. The secret is rotated at least every COOKIE_ROTATE_MS;
// needsRotate reports when that interval has elapsed so the caller can supply
// fresh material, and rotate applies it. Splitting the "when" (needsRotate, a
// pure time comparison) from the "what" (rotate, caller-supplied bytes) keeps
// the module free of an RNG dependency: the responder sources new secret bytes
// the same way it sources any key material, and the rotation decision is a pure
// comparison that is trivial to test across the boundary.

pub const CookieSecret = struct {
    secret: [KEY_BYTES]u8,
    created_ms: u64,

    // Construct from caller-supplied initial material stamped at now_ms.
    pub fn init(initial_secret: [KEY_BYTES]u8, now_ms: u64) CookieSecret {
        return .{ .secret = initial_secret, .created_ms = now_ms };
    }

    // True once the secret is COOKIE_ROTATE_MS old. Wrapping subtract handles a
    // clock that moved backwards without a false "needs rotate" storm.
    pub fn needsRotate(self: CookieSecret, now_ms: u64) bool {
        return (now_ms -% self.created_ms) >= COOKIE_ROTATE_MS;
    }

    // Replace the secret with caller-supplied material and stamp it now. The
    // caller decides the source of the bytes (RNG, KDF, test vector) and when
    // to call this, driven by needsRotate.
    pub fn rotate(self: *CookieSecret, new_secret: [KEY_BYTES]u8, now_ms: u64) void {
        self.secret = new_secret;
        self.created_ms = now_ms;
    }

    // Issue a cookie over the initiator's observed source address. This is the
    // mac2 a responder sends under load and later expects echoed back.
    pub fn issueCookie(self: CookieSecret, source_addr: []const u8) [MAC_BYTES]u8 {
        var out: [MAC_BYTES]u8 = undefined;
        Blake2s128.hash(source_addr, &out, .{ .key = &self.secret });
        return out;
    }

    // Verify a received cookie/mac2 in constant time.
    pub fn verifyCookie(
        self: CookieSecret,
        source_addr: []const u8,
        received: [MAC_BYTES]u8,
    ) bool {
        return constantTimeEql(MAC_BYTES, self.issueCookie(source_addr), received);
    }
};
