// cert_test_helpers.zig
//
// Shared certificate fixtures for the identity-chain tests (binding_test.zig)
// and the grant verifier (verify_test.zig). One home for the deterministic
// Ed25519 cert builder, per CODE.md: shared test helpers live in one place,
// never copy-pasted. This module has no test blocks of its own; it compiles
// transitively because binding_test.zig imports it.
//
// Every keypair here derives from a fixed seed (seedFrom(prefix): byte i =
// prefix +% i), the same scheme the vector generator uses, so a CA signature
// is the only way a cert can fail to verify. CAs are Ed25519 keypairs from the
// same seed family; the cert's identity sig_pubkey is supplied by the caller
// (the grant vectors use the canonical approver/subject pubkeys; the binding
// tests use keypairs whose secret key is known so the binding signature can be
// minted).
//
// Zig 0.16 note: module-level `var` initializers are evaluated at comptime,
// and Ed25519 (SHA-512) exceeds the comptime branch quota, so the canonical
// fixtures are built lazily at runtime into module-level `undefined` buffers
// the first time an accessor runs. build.zig pins the test module to
// single_threaded, so the init flag races nothing.

const std = @import("std");
const parser = @import("parser.zig");
const binding = @import("binding.zig");

pub const Ed = std.crypto.sign.Ed25519;

const DOMAIN_CERT: u8 = parser.session.DOMAIN_CERT; // 0x01, CA signatures over cert.tbs

// Deterministic seed: byte i = prefix +% i (matches tools/gen-vectors.zig).
pub fn seedFrom(prefix: u8) [32]u8 {
    var s: [32]u8 = undefined;
    for (&s, 0..) |*b, i| b.* = prefix +% @as(u8, @intCast(i));
    return s;
}

// An Ed25519 keypair from a fixed seed. Used for both CA keys and identity
// keys; the name reflects only that the bytes are deterministic.
pub fn keypair(prefix: u8) Ed.KeyPair {
    return Ed.KeyPair.generateDeterministic(seedFrom(prefix)) catch unreachable;
}

pub fn pubkeyOf(prefix: u8) [32]u8 {
    return Ed.PublicKey.toBytes(keypair(prefix).public_key);
}

// ---------------------------------------------------------------------------
// Canonical grant identities (test/vectors.json structures grant). The
// approver/subject pubkeys are the exact bytes the canonical grant carries, so
// a cert built with them binds the same identity the grant names.
// ---------------------------------------------------------------------------

pub const APPROVER_PUB = decodeHex("adc14011f82d1c56d956aa4f9d73d8858361a606048525e0d08c638dc75dd8c7");
pub const SUBJECT_PUB = decodeHex("020bd427446b723424d80d2cad352ba3df3649d0ef8faae0ca7eb25443941b29");
pub const INTENT_ID = decodeHex("0102030405060708090a0b0c0d0e0f10");
pub const RESOURCE_ID = "bol:c3efd641bfa0582f/logs/deploy.log";

// Validity window wide enough to contain every grant clock the verify tests
// swing (now_ms ranges across the expiry boundary tests from ~1.699e12 to
// ~1.7001e12). Far apart so the window is never the failure under test unless a
// cert test deliberately sets it.
pub const CERT_NOT_BEFORE: u64 = 1_000_000_000_000;
pub const CERT_NOT_AFTER: u64 = 2_000_000_000_000;

// Trusted CA seed prefixes (their pubkeys populate the local trust set).
pub const TRUSTED_CA_PREFIXES = [_]u8{ 0xc0, 0xc1, 0xc2 };

fn decodeHex(comptime hex: []const u8) [hex.len / 2]u8 {
    var b: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&b, hex) catch unreachable;
    return b;
}

// ---------------------------------------------------------------------------
// buildCertInto: lay a certificate down in `wire` and return its parsed view.
//
// The wire layout is SPEC 3.1: version, role_bits, [32] sig_pubkey, [32]
// kex_pubkey, u64 not_before, u64 not_after, u16 name_len + name, u8
// group_count + group_ids, then u8 ca_sig_count and that many (ca_key + ca_sig)
// pairs. tbs is every byte preceding ca_sig_count, the input each CA Ed25519
// signature covers under domain 0x01. CA keys are sorted strictly ascending
// before emission because parseCert enforces that ordering as a parse failure.
//
// The returned Cert's slices alias `wire`, which the caller owns, so the cert
// stays valid as long as the caller's buffer does (zero-heap, parser style).
// ---------------------------------------------------------------------------

pub fn buildCertInto(
    wire: []u8,
    sig_pubkey: [32]u8,
    role_bits: u8,
    ca_prefixes: []const u8,
    not_before: u64,
    not_after: u64,
) parser.session.Cert {
    const ca_count: u8 = @intCast(ca_prefixes.len);

    // Generate the CA keypairs and sort their pubkeys strictly ascending
    // (parseCert rejects a non-canonical CA-key ordering as a parse failure).
    var kps: [4]Ed.KeyPair = undefined;
    var pubs: [4][32]u8 = undefined;
    for (0..ca_count) |i| {
        kps[i] = keypair(ca_prefixes[i]);
        pubs[i] = Ed.PublicKey.toBytes(kps[i].public_key);
    }
    var a: usize = 0;
    while (a < ca_count) : (a += 1) {
        var b_idx: usize = a + 1;
        while (b_idx < ca_count) : (b_idx += 1) {
            if (std.mem.order(u8, &pubs[b_idx], &pubs[a]) == .lt) {
                const tk = kps[a];
                kps[a] = kps[b_idx];
                kps[b_idx] = tk;
                const tp = pubs[a];
                pubs[a] = pubs[b_idx];
                pubs[b_idx] = tp;
            }
        }
    }

    var n: usize = 0;
    wire[n] = 2; // version = 2 (parsed, not rejected here; SPEC 2.2)
    n += 1;
    wire[n] = role_bits;
    n += 1;
    @memcpy(wire[n..][0..32], &sig_pubkey);
    n += 32;
    @memcpy(wire[n..][0..32], &seedFrom(0x4b)); // kex_pubkey (unused by validateCert)
    n += 32;
    var bb: [8]u8 = undefined;
    std.mem.writeInt(u64, &bb, not_before, .big);
    @memcpy(wire[n..][0..8], &bb);
    n += 8;
    std.mem.writeInt(u64, &bb, not_after, .big);
    @memcpy(wire[n..][0..8], &bb);
    n += 8;
    wire[n] = 0; // name_len high byte
    wire[n + 1] = 0; // name_len low byte (empty name)
    n += 2;
    wire[n] = 0; // group_count = 0
    n += 1;
    const tbs_len = n;
    const tbs = wire[0..tbs_len];

    wire[n] = ca_count;
    n += 1;
    var k: usize = 0;
    while (k < ca_count) : (k += 1) {
        @memcpy(wire[n..][0..32], &pubs[k]);
        n += 32;
        // CA Ed25519 over (DOMAIN_CERT || tbs), matching the streaming verifier
        // in binding.zig (BE-SIG-01 domain separation).
        var msg: [1 + 512]u8 = undefined;
        msg[0] = DOMAIN_CERT;
        @memcpy(msg[1..][0..tbs_len], tbs);
        const sig = Ed.KeyPair.sign(kps[k], msg[0 .. 1 + tbs_len], null) catch unreachable;
        @memcpy(wire[n..][0..64], &(Ed.Signature.toBytes(sig)));
        n += 64;
    }

    return parser.session.parseCert(wire[0..n]) catch unreachable;
}

// ---------------------------------------------------------------------------
// Canonical fixtures: the approver cert (ROLE_APPROVER, quorum-2), the subject
// cert (ROLE_AGENT), and the trusted-CA set. Built lazily into module-level
// buffers the first time an accessor runs (see the Zig 0.16 note above).
// ---------------------------------------------------------------------------

var approver_wire: [512]u8 = undefined;
var approver_cert: parser.session.Cert = undefined;
var subject_wire: [512]u8 = undefined;
var subject_cert: parser.session.Cert = undefined;
var trusted_pubs: [3][32]u8 = undefined;
var trusted_keys: [3][]const u8 = undefined;
var inited: bool = false;

fn ensureInited() void {
    if (inited) return;
    approver_cert = buildCertInto(
        &approver_wire,
        APPROVER_PUB,
        binding.ROLE_APPROVER,
        &[_]u8{ 0xc0, 0xc1 },
        CERT_NOT_BEFORE,
        CERT_NOT_AFTER,
    );
    subject_cert = buildCertInto(
        &subject_wire,
        SUBJECT_PUB,
        binding.ROLE_AGENT,
        &[_]u8{0xc2},
        CERT_NOT_BEFORE,
        CERT_NOT_AFTER,
    );
    for (TRUSTED_CA_PREFIXES, 0..) |p, i| trusted_pubs[i] = pubkeyOf(p);
    trusted_keys = .{ &trusted_pubs[0], &trusted_pubs[1], &trusted_pubs[2] };
    inited = true;
}

pub fn approverCert() parser.session.Cert {
    ensureInited();
    return approver_cert;
}

pub fn subjectCert() parser.session.Cert {
    ensureInited();
    return subject_cert;
}

pub fn trustedSet() []const []const u8 {
    ensureInited();
    return &trusted_keys;
}
