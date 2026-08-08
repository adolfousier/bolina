// binding_test.zig
//
// Tests for the certificate identity chain (SPEC section 3.2, BE-ID-01..04)
// and the post-handshake session binding (SPEC section 4.1, BE-TR-01). The
// certificate fixtures come from cert_test_helpers.zig: deterministic Ed25519
// CA keypairs sign cert.tbs under domain 0x01, and the binding signature is
// minted with an identity key whose secret the test holds. A tampered
// signature is the only way a cert or binding fails to verify, which is what
// the BE-ID/BE-TR sig paths need to exercise.
//
// Naming follows the build.zig M1 registry convention: test "BE_<CLASS>_<NN>".

const std = @import("std");
const parser = @import("parser.zig");
const binding = @import("binding.zig");
const cth = @import("cert_test_helpers.zig");

const Ed = std.crypto.sign.Ed25519;
const B2s = std.crypto.hash.blake2.Blake2s256;

// ---------------------------------------------------------------------------
// BE-ID-01: overlay address derivation. overlay_addr = 0xfd ||
// BLAKE2s-256(sig_pubkey)[0..15], a 16-byte fd00::/8 ULA. The address is a
// commitment to the key: no resolution step to poison, and no party may assert
// another's address.
// ---------------------------------------------------------------------------

test "BE_ID_01 overlay addr is fd prefix over blake2s of sig_pubkey" {
    const pk = cth.pubkeyOf(0xa1);
    const addr = binding.deriveOverlayAddr(&pk);

    var full: [32]u8 = undefined;
    B2s.hash(&pk, &full, .{});

    try std.testing.expectEqual(@as(u8, 0xfd), addr[0]);
    // [0..15] is exclusive-end (first 15 bytes), giving 16 total with the prefix.
    try std.testing.expectEqualSlices(u8, full[0..15], addr[1..16]);
}

// ---------------------------------------------------------------------------
// BE-ID-03: forbidden role pairings. BE-ROLE-01 forbids agent+approver,
// BE-ROLE-02 agent+executor, BE-ROLE-04 approver+executor. Checked at receipt
// so a compromised CA cannot mint a self-approving identity a peer accepts.
// ---------------------------------------------------------------------------

test "BE_ID_03 forbidden role pairings refused" {
    try std.testing.expectError(error.RoleAgentApprover, binding.checkRoleConstraints(binding.ROLE_AGENT | binding.ROLE_APPROVER));
    try std.testing.expectError(error.RoleAgentExecutor, binding.checkRoleConstraints(binding.ROLE_AGENT | binding.ROLE_EXECUTOR));
    try std.testing.expectError(error.RoleApproverExecutor, binding.checkRoleConstraints(binding.ROLE_APPROVER | binding.ROLE_EXECUTOR));
}

test "BE_ID_03 single roles and benign combinations accepted" {
    try binding.checkRoleConstraints(binding.ROLE_AGENT);
    try binding.checkRoleConstraints(binding.ROLE_APPROVER);
    try binding.checkRoleConstraints(binding.ROLE_EXECUTOR);
    // participant (bit 0) pairs with anything; only the three pairings above
    // are forbidden.
    try binding.checkRoleConstraints(1 | binding.ROLE_APPROVER);
}

// ---------------------------------------------------------------------------
// BE-ROLE-01/02/04: the three forbidden role pairings, bound by their own
// names. BE-ID-03 is the receipt-side rejection that re-checks all three; each
// constraint here is the definition that makes the rejection normative. The
// slice has no CA issuance function, so the issuance-refusal half of each
// marker is out of slice; the constraint the slice enforces is checkRoleConstraints.
// ---------------------------------------------------------------------------

test "BE_ROLE_01 agent plus approver pairing refused" {
    // SPEC BE-ROLE-01: a certificate MUST NOT carry both agent and approver.
    // An autonomous process cannot approve its own actions.
    try binding.checkRoleConstraints(binding.ROLE_AGENT);
    try binding.checkRoleConstraints(binding.ROLE_APPROVER);
    try std.testing.expectError(error.RoleAgentApprover, binding.checkRoleConstraints(binding.ROLE_AGENT | binding.ROLE_APPROVER));
}

test "BE_ROLE_02 agent plus executor pairing refused" {
    // SPEC BE-ROLE-02: a certificate MUST NOT carry both agent and executor.
    // An agent may request effects but may not be the thing that signs them.
    try binding.checkRoleConstraints(binding.ROLE_AGENT);
    try binding.checkRoleConstraints(binding.ROLE_EXECUTOR);
    try std.testing.expectError(error.RoleAgentExecutor, binding.checkRoleConstraints(binding.ROLE_AGENT | binding.ROLE_EXECUTOR));
}

test "BE_ROLE_04 approver plus executor pairing refused" {
    // SPEC BE-ROLE-04: a certificate MUST NOT carry both approver and executor.
    // Such an identity would sign its own Grants and then honour them.
    try binding.checkRoleConstraints(binding.ROLE_APPROVER);
    try binding.checkRoleConstraints(binding.ROLE_EXECUTOR);
    try std.testing.expectError(error.RoleApproverExecutor, binding.checkRoleConstraints(binding.ROLE_APPROVER | binding.ROLE_EXECUTOR));
}

// ---------------------------------------------------------------------------
// BE-ID-02: validate a certificate against the local trust set and clock.
// Rejection is unconditional; the validity window contains now_ms, every CA
// signature verifies over cert.tbs, and every CA key is trusted.
// ---------------------------------------------------------------------------

test "BE_ID_02 valid agent cert accepted against trusted CA set" {
    var wire: [512]u8 = undefined;
    const cert = cth.buildCertInto(
        &wire,
        cth.pubkeyOf(0xa1),
        binding.ROLE_AGENT,
        &[_]u8{0xc0},
        cth.CERT_NOT_BEFORE,
        cth.CERT_NOT_AFTER,
    );
    try binding.validateCert(cert, cth.trustedSet(), cth.CERT_NOT_BEFORE + 1);
}

test "BE_ID_02 cert outside validity window refused" {
    var wire: [512]u8 = undefined;
    const cert = cth.buildCertInto(
        &wire,
        cth.pubkeyOf(0xa1),
        binding.ROLE_AGENT,
        &[_]u8{0xc0},
        1000,
        2000,
    );
    // now after not_after -> expired.
    try std.testing.expectError(error.CertExpired, binding.validateCert(cert, cth.trustedSet(), 3000));
    // now before not_before -> not yet valid.
    try std.testing.expectError(error.CertExpired, binding.validateCert(cert, cth.trustedSet(), 500));
}

test "BE_ID_02 untrusted CA key refused" {
    var wire: [512]u8 = undefined;
    // Signed by CA 0xd0, which is NOT in the trusted set {0xc0, 0xc1, 0xc2}.
    const cert = cth.buildCertInto(
        &wire,
        cth.pubkeyOf(0xa1),
        binding.ROLE_AGENT,
        &[_]u8{0xd0},
        cth.CERT_NOT_BEFORE,
        cth.CERT_NOT_AFTER,
    );
    try std.testing.expectError(error.UntrustedCA, binding.validateCert(cert, cth.trustedSet(), cth.CERT_NOT_BEFORE + 1));
}

test "BE_ID_02 corrupted CA signature refused" {
    var wire: [512]u8 = undefined;
    const cert0 = cth.buildCertInto(
        &wire,
        cth.pubkeyOf(0xa1),
        binding.ROLE_AGENT,
        &[_]u8{0xc0},
        cth.CERT_NOT_BEFORE,
        cth.CERT_NOT_AFTER,
    );
    // Flip one byte inside the first CA's 64-byte signature. The CA key region
    // precedes it untouched, so ordering still holds and parseCert succeeds;
    // only the signature verify fails.
    const sig_off = cert0.tbs.len + 1 + 32; // tbs + ca_count + first CA key
    wire[sig_off] ^= 0xff;
    const wire_len = cert0.tbs.len + 1 + cert0.ca_sigs.len;
    const cert = try parser.session.parseCert(wire[0..wire_len]);
    try std.testing.expectError(error.BadCASignature, binding.validateCert(cert, cth.trustedSet(), cth.CERT_NOT_BEFORE + 1));
}

// ---------------------------------------------------------------------------
// BE-ID-04: an approver certificate needs >= 2 CA signatures (quorum). A
// compromised single CA must not be able to mint approver authority.
// ---------------------------------------------------------------------------

test "BE_ID_04 approver cert with one CA sig refused (no quorum)" {
    var wire: [512]u8 = undefined;
    const cert = cth.buildCertInto(
        &wire,
        cth.pubkeyOf(0xa1),
        binding.ROLE_APPROVER,
        &[_]u8{0xc0},
        cth.CERT_NOT_BEFORE,
        cth.CERT_NOT_AFTER,
    );
    try std.testing.expectError(error.ApproverNoQuorum, binding.validateCert(cert, cth.trustedSet(), cth.CERT_NOT_BEFORE + 1));
}

test "BE_ID_04 approver cert with two CA sigs accepted (quorum met)" {
    var wire: [512]u8 = undefined;
    const cert = cth.buildCertInto(
        &wire,
        cth.pubkeyOf(0xa1),
        binding.ROLE_APPROVER,
        &[_]u8{ 0xc0, 0xc1 },
        cth.PRIVILEGED_CERT_NOT_BEFORE,
        cth.PRIVILEGED_CERT_NOT_AFTER,
    );
    try binding.validateCert(cert, cth.trustedSet(), cth.PRIVILEGED_CERT_NOT_BEFORE + 1);
}

// ---------------------------------------------------------------------------
// BE-CA-01: issuing an approver certificate requires a quorum of >= 2 distinct
// CA keys, while every other certificate requires only one. BE-ID-04 is the
// receipt-side rejection of an under-signed approver cert; this binds the
// issuer obligation as a single rule with its two halves: the quorum gates the
// approver bit, and one CA signature suffices for any non-approver cert.
// ---------------------------------------------------------------------------

test "BE_CA_01 approver quorum is two, one suffices for non-approver" {
    // SPEC BE-CA-01: approver bit requires >= 2 distinct CA keys; other
    // certificates require one. One compromised CA key mints no approver.
    var wire: [512]u8 = undefined;

    // Non-approver (agent) cert with a single CA signature is accepted.
    const agent = cth.buildCertInto(
        &wire,
        cth.pubkeyOf(0xa1),
        binding.ROLE_AGENT,
        &[_]u8{0xc0},
        cth.CERT_NOT_BEFORE,
        cth.CERT_NOT_AFTER,
    );
    try binding.validateCert(agent, cth.trustedSet(), cth.CERT_NOT_BEFORE + 1);

    // Approver cert with only one CA signature is refused for lack of quorum.
    var wire2: [512]u8 = undefined;
    const approver_one = cth.buildCertInto(
        &wire2,
        cth.pubkeyOf(0xa2),
        binding.ROLE_APPROVER,
        &[_]u8{0xc0},
        cth.CERT_NOT_BEFORE,
        cth.CERT_NOT_AFTER,
    );
    try std.testing.expectError(error.ApproverNoQuorum, binding.validateCert(approver_one, cth.trustedSet(), cth.CERT_NOT_BEFORE + 1));
}

// ---------------------------------------------------------------------------
// BE-TR-01: bind an authenticated Noise static key to an Ed25519 identity.
// The cert passes BE-ID-02/03/04, then an Ed25519 signature by sig_pubkey over
// the Noise handshake hash h (domain 0x05) must verify. A session MUST NOT
// deliver application data upward until both hold.
// ---------------------------------------------------------------------------

// Mints a binding signature over (DOMAIN_BINDING || h) with the identity key.
fn bindingSig(id: Ed.KeyPair, h: [32]u8) [64]u8 {
    var msg: [33]u8 = undefined;
    msg[0] = binding.DOMAIN_BINDING;
    @memcpy(msg[1..], &h);
    const sig = Ed.KeyPair.sign(id, &msg, null) catch unreachable;
    return Ed.Signature.toBytes(sig);
}

test "BE_TR_01 valid cert and binding signature over handshake hash accepted" {
    const id = cth.keypair(0xa1);
    const id_pub = Ed.PublicKey.toBytes(id.public_key);
    var wire: [512]u8 = undefined;
    const cert = cth.buildCertInto(
        &wire,
        id_pub,
        binding.ROLE_AGENT,
        &[_]u8{0xc0},
        cth.CERT_NOT_BEFORE,
        cth.CERT_NOT_AFTER,
    );
    const h = cth.seedFrom(0x68); // stand-in Noise handshake hash
    const sig = bindingSig(id, h);
    try binding.bindSession(cert, &sig, &h, cth.trustedSet(), cth.CERT_NOT_BEFORE + 1);
}

test "BE_TR_01 binding signature over the wrong hash refused" {
    const id = cth.keypair(0xa1);
    const id_pub = Ed.PublicKey.toBytes(id.public_key);
    var wire: [512]u8 = undefined;
    const cert = cth.buildCertInto(
        &wire,
        id_pub,
        binding.ROLE_AGENT,
        &[_]u8{0xc0},
        cth.CERT_NOT_BEFORE,
        cth.CERT_NOT_AFTER,
    );
    const h = cth.seedFrom(0x68);
    // Sign over a different hash; the verify over h must fail.
    const sig = bindingSig(id, cth.seedFrom(0x69));
    try std.testing.expectError(error.BadBindingSig, binding.bindSession(cert, &sig, &h, cth.trustedSet(), cth.CERT_NOT_BEFORE + 1));
}

test "BE_TR_01 invalid cert refused before the binding signature is checked" {
    const id = cth.keypair(0xa1);
    const id_pub = Ed.PublicKey.toBytes(id.public_key);
    var wire: [512]u8 = undefined;
    // Expired cert: validateCert runs first and refuses, so even a valid
    // binding signature never reaches the sig check.
    const cert = cth.buildCertInto(&wire, id_pub, binding.ROLE_AGENT, &[_]u8{0xc0}, 1000, 2000);
    const h = cth.seedFrom(0x68);
    const sig = bindingSig(id, h);
    try std.testing.expectError(error.CertExpired, binding.bindSession(cert, &sig, &h, cth.trustedSet(), 3000));
}

// ---------------------------------------------------------------------------
// BE-REV-01: privileged certificate lifetime cap. Approver and executor
// certificates are limited to a 30-day window (2,592,000,000 ms).
// ---------------------------------------------------------------------------

test "BE_REV_01 approver cert with 30-day window accepted" {
    const id = cth.keypair(0xa1);
    const id_pub = Ed.PublicKey.toBytes(id.public_key);
    var wire: [512]u8 = undefined;
    // Exactly at the cap: not_after - not_before = 2,592,000,000 ms.
    const cert = cth.buildCertInto(&wire, id_pub, binding.ROLE_APPROVER, &[_]u8{ 0xc0, 0xc1 }, 1_699_000_000_000, 1_701_592_000_000);
    try binding.validateCert(cert, cth.trustedSet(), 1_700_000_000_000);
}

test "BE_REV_01 approver cert exceeding 30-day window refused" {
    const id = cth.keypair(0xa1);
    const id_pub = Ed.PublicKey.toBytes(id.public_key);
    var wire: [512]u8 = undefined;
    // 1 ms over the cap.
    const cert = cth.buildCertInto(&wire, id_pub, binding.ROLE_APPROVER, &[_]u8{ 0xc0, 0xc1 }, 1_699_000_000_000, 1_701_592_000_001);
    try std.testing.expectError(error.CertTooLongLived, binding.validateCert(cert, cth.trustedSet(), 1_700_000_000_000));
}

test "BE_REV_01 executor cert with 30-day window accepted" {
    const id = cth.keypair(0xa1);
    const id_pub = Ed.PublicKey.toBytes(id.public_key);
    var wire: [512]u8 = undefined;
    const cert = cth.buildCertInto(&wire, id_pub, binding.ROLE_EXECUTOR, &[_]u8{0xc0}, 1_699_000_000_000, 1_701_592_000_000);
    try binding.validateCert(cert, cth.trustedSet(), 1_700_000_000_000);
}

test "BE_REV_01 agent cert with 31.7-year window accepted (no cap)" {
    const id = cth.keypair(0xa1);
    const id_pub = Ed.PublicKey.toBytes(id.public_key);
    var wire: [512]u8 = undefined;
    // Wide window: 1e12..2e12 ms (31.7 years). No cap for agents.
    const cert = cth.buildCertInto(&wire, id_pub, binding.ROLE_AGENT, &[_]u8{0xc0}, 1_000_000_000_000, 2_000_000_000_000);
    try binding.validateCert(cert, cth.trustedSet(), 1_500_000_000_000);
}
