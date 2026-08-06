// mac_test.zig
//
// Tests for the mac1/mac2 DoS gate (src/mac.zig, SPEC.md section 4.4).
//
// Two tests bind spec items by name (the M1 bijection, SPEC 11.1):
//   * BE_TR_04  covers mac1 (proof of knowing who you are calling)
//   * BE_TR_04a covers the cookie / mac2 (proof of controlling your source address)
// Both are declared in SPEC.md section 4.4, so binding them here is the grow-only
// ratchet doing what it is meant to: a declared item gains a test. The
// known-answer constants are computed independently in Python (hashlib.blake2s,
// RFC 7693) so the Zig implementation is checked against a second BLAKE2s, not
// against itself. Every other test uses a descriptive name so it cannot become
// an orphan that names an undeclared BE item.

const std = @import("std");
const mac = @import("mac.zig");

const testing = std.testing;

// The Python reference used responder = bytes(range(32)), secret = bytes(range(32,64)),
// secret2 = bytes(range(64,95+1)). Rebuild the same ramps here.
fn ramp(comptime start: u8) [32]u8 {
    var a: [32]u8 = undefined;
    for (&a, 0..) |*b, i| b.* = start +% @as(u8, @intCast(i));
    return a;
}

const responder = ramp(0);
const secret = ramp(32);
const secret2 = ramp(64);

const msg = "bolina-handshake-init-preceding-mac1";
const addr = "198.51.100.7:51820";

// Independently derived from Python hashlib.blake2s (RFC 7693).
const expected_mac1: [16]u8 = .{
    0xb0, 0x1d, 0x8e, 0xbc, 0x37, 0x49, 0x47, 0x5d,
    0x9c, 0xb9, 0x61, 0xea, 0x43, 0xd6, 0xe4, 0xa6,
};
const expected_cookie: [16]u8 = .{
    0x65, 0x35, 0x6b, 0x01, 0xbd, 0xba, 0x64, 0xe4,
    0xa7, 0x85, 0x05, 0xae, 0xd1, 0x24, 0x5b, 0x43,
};
const expected_cookie2: [16]u8 = .{
    0x25, 0xc5, 0xf5, 0xd1, 0x6e, 0x8d, 0xa8, 0x83,
    0xbb, 0xa5, 0x1f, 0x50, 0xc9, 0xd7, 0x67, 0xfe,
};

// --- BE-TR-04: mac1 --------------------------------------------------------

test "BE_TR_04 mac1 known-answer matches the independent Python vector" {
    const got = mac.computeMac1(responder, msg);
    try testing.expectEqualSlices(u8, &expected_mac1, &got);
}

test "BE_TR_04 mac1 verify accepts a freshly computed tag" {
    const tag = mac.computeMac1(responder, msg);
    try testing.expect(mac.verifyMac1(responder, msg, tag));
}

test "BE_TR_04 mac1 verify rejects a single-bit flip in the tag" {
    var flipped = mac.computeMac1(responder, msg);
    flipped[0] ^= 0x01;
    try testing.expect(!mac.verifyMac1(responder, msg, flipped));
}

test "mac1 changes when the responder signature key changes" {
    const a = mac.computeMac1(responder, msg);
    var other = responder;
    other[0] ^= 0x01;
    const b = mac.computeMac1(other, msg);
    // A responder who does not know the real key cannot forge this; a different
    // key must yield a different tag, so mac1 is genuinely keyed on the identity.
    try testing.expect(!std.mem.eql(u8, &a, &b));
}

test "mac1 changes when any message byte changes" {
    const a = mac.computeMac1(responder, msg);
    const b = mac.computeMac1(responder, msg[0 .. msg.len - 1]);
    try testing.expect(!std.mem.eql(u8, &a, &b));
}

// --- BE-TR-04a: cookie / mac2 ----------------------------------------------

test "BE_TR_04a cookie known-answer matches the independent Python vector" {
    var cs = mac.CookieSecret.init(secret, 0);
    const got = cs.issueCookie(addr);
    try testing.expectEqualSlices(u8, &expected_cookie, &got);
}

test "BE_TR_04a cookie verify accepts a freshly issued cookie" {
    var cs = mac.CookieSecret.init(secret, 0);
    const cookie = cs.issueCookie(addr);
    try testing.expect(cs.verifyCookie(addr, cookie));
}

test "BE_TR_04a cookie verify rejects a cookie issued under a rotated secret" {
    var cs = mac.CookieSecret.init(secret, 0);
    const old_cookie = cs.issueCookie(addr);
    try testing.expect(cs.verifyCookie(addr, old_cookie));
    // Rotate past the 120s window with fresh material. The old cookie, which
    // was valid a moment ago, must now fail: a captured mac2 does not outlive
    // the secret that minted it.
    cs.rotate(secret2, 130_000);
    try testing.expect(!cs.verifyCookie(addr, old_cookie));
    // The new cookie under the rotated secret matches the second KAT.
    try testing.expectEqualSlices(u8, &expected_cookie2, &cs.issueCookie(addr));
    try testing.expect(cs.verifyCookie(addr, cs.issueCookie(addr)));
}

test "BE_TR_04a cookie verify rejects a single-bit flip in the cookie" {
    var cs = mac.CookieSecret.init(secret, 0);
    var flipped = cs.issueCookie(addr);
    flipped[0] ^= 0x01;
    try testing.expect(!cs.verifyCookie(addr, flipped));
}

test "cookie issue is deterministic across calls" {
    var cs = mac.CookieSecret.init(secret, 0);
    const a = cs.issueCookie(addr);
    const b = cs.issueCookie(addr);
    try testing.expectEqualSlices(u8, &a, &b);
}

test "cookie needsRotate is false inside the window and true at the boundary" {
    var cs = mac.CookieSecret.init(secret, 1_000);
    try testing.expect(!cs.needsRotate(1_000));
    try testing.expect(!cs.needsRotate(120_999)); // one ms before the boundary
    try testing.expect(cs.needsRotate(121_000)); // exactly 120s elapsed
}

test "cookie rotate stamps a new created_ms and replaces the secret" {
    var cs = mac.CookieSecret.init(secret, 100);
    try testing.expectEqual(100, cs.created_ms);
    cs.rotate(secret2, 9_999);
    try testing.expectEqual(9_999, cs.created_ms);
    // New secret -> cookie now matches the second KAT, not the first.
    try testing.expectEqualSlices(u8, &expected_cookie2, &cs.issueCookie(addr));
}
