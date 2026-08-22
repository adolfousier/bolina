// binding.zig
//
// LANGUAGE.md session slice: the certificate identity chain (SPEC section 3.2,
// BE-ID-01..04) and the post-handshake session binding (SPEC section 4.1,
// BE-TR-01). This is the post-authentication surface: a hostile authenticated
// peer's certificate and binding-signature bytes reach this module, so every
// check fails closed and nothing is trusted on the strength of the encrypted
// session that carried it. The Noise handshake authenticates X25519 static
// keys; a certificate binds an Ed25519 identity key, and BE-TR-01 is the one
// act that binds the two, inside the session, after the handshake (BE-TR-07
// forbids certificates in the handshake itself).
//
// Zero-heap. Ed25519 is checked with the stdlib streaming Verifier so the
// one-byte BE-SIG-01 domain tag and the to-be-signed region are fed as two
// chunks; no buffer is allocated to prepend the tag. The certificate arrives
// already parsed (parser.session.Cert), and its CA-signature region is walked
// here as (ca_key || ca_sig) pairs, re-verifying every signature against the
// cert's to-be-signed bytes. The identity chain is its own concern; verify.zig
// (non-surface state) reaches in here for cert validation but binding.zig never
// reaches back, so the dependency runs one way.

const std = @import("std");
const parser = @import("parser.zig");

const Ed = std.crypto.sign.Ed25519;
const B2s = std.crypto.hash.blake2.Blake2s256;

const Cert = parser.session.Cert;

// Declared widths, domain tags, and role bits (SPEC 3.1, 3.2, BE-SIG-01).

pub const LEN_PUBKEY: usize = parser.LEN_PUBKEY; // 32, Ed25519 sig_pubkey
pub const LEN_SIG: usize = parser.session.LEN_CA_SIG; // 64, an Ed25519 signature
pub const LEN_OVERLAY_ADDR: usize = parser.session.LEN_OVERLAY_ADDR; // 16
pub const DOMAIN_CERT: u8 = parser.session.DOMAIN_CERT; // 0x01, CA signatures over the cert
pub const DOMAIN_BINDING: u8 = 0x05; // BE-SIG-01: handshake binding over Noise h

// Role bits (SPEC 3.1: bit 0 participant, 1 agent, 2 executor, 3 approver,
// 4 lighthouse, 5 relay). The three pairings BE-ROLE-01/02/04 forbid are the
// only role constraints a node enforces on a received certificate.
pub const ROLE_AGENT: u8 = 1 << 1;
pub const ROLE_EXECUTOR: u8 = 1 << 2;
pub const ROLE_APPROVER: u8 = 1 << 3;
pub const MAX_PRIVILEGED_LIFETIME_MS: u64 = 2_592_000_000; // BE-REV-01: 30-day cap

pub const APPROVER_QUORUM: u8 = 2; // BE-ID-04: approver cert needs >= 2 CA sigs
const OVERLAY_PREFIX: u8 = 0xfd; // BE-ID-01: fd00::/8 ULA prefix

// Errors. One distinct class per failed BE-ID / BE-TR check so a caller can
// report the reason a certificate or binding was rejected.

pub const BindingError = error{
    MalformedKey, // a pubkey is not a valid curve point
    BadCASignature, // BE-ID-02: a ca_sig does not verify over cert.tbs
    UntrustedCA, // BE-ID-02: a ca_key is not in the local trust set
    CertExpired, // BE-ID-02: local clock outside not_before..not_after
    CertTooLongLived, // BE-REV-01
    RoleAgentApprover, // BE-ID-03 / BE-ROLE-01: agent + approver
    RoleAgentExecutor, // BE-ID-03 / BE-ROLE-02: agent + executor
    RoleApproverExecutor, // BE-ID-03 / BE-ROLE-04: approver + executor
    ApproverNoQuorum, // BE-ID-04: approver bit set with < 2 CA signatures
    BadBindingSig, // BE-TR-01: binding sig does not verify over h
    KexPubkeyMismatch, // F1: cert kex_pubkey != remote static key from handshake
};

// BE-SIG-01 domain-separated Ed25519 verification (internal).
//
// Verifies `sig` over (tag || tbs) against `pubkey`, feeding the one-byte tag
// and the tbs region as two chunks so no tagged-message buffer is allocated.
// MalformedKey is an unparseable key; SignatureRejected is a verification
// failure the caller maps to its check-specific error.

const SigError = error{ MalformedKey, SignatureRejected };

fn verifySig(tag: u8, tbs: []const u8, sig: []const u8, pubkey: []const u8) SigError!void {
    if (pubkey.len != LEN_PUBKEY) return error.MalformedKey;
    if (sig.len != LEN_SIG) return error.SignatureRejected;
    const pk = Ed.PublicKey.fromBytes(pubkey[0..LEN_PUBKEY].*) catch return error.MalformedKey;
    // fromBytes is infallible for Signature (Zig 0.16); a non-canonical R or an
    // identity element surfaces at .verifier(pk) below, matching verify.zig.
    const signature = Ed.Signature.fromBytes(sig[0..LEN_SIG].*);
    var v = signature.verifier(pk) catch return error.SignatureRejected;
    const tag_bytes = [1]u8{tag};
    v.update(&tag_bytes);
    v.update(tbs);
    v.verify() catch return error.SignatureRejected;
}

// BE-ID-01: derive a peer's overlay address from its sig_pubkey.
//
// overlay_addr = 0xfd || BLAKE2s-256(sig_pubkey)[0..15], a 16-byte fd00::/8
// ULA. [0..15] is exclusive-end (first 15 bytes), giving 16 total (SPEC 3.2,
// section 11.3 test vector). The address is a commitment to the key: there is
// no resolution step to poison, and a node MUST NOT accept an address asserted
// by any other party (BE-ID-01).

pub fn deriveOverlayAddr(sig_pubkey: []const u8) [LEN_OVERLAY_ADDR]u8 {
    var full: [32]u8 = undefined;
    B2s.hash(sig_pubkey, &full, .{});
    var addr: [LEN_OVERLAY_ADDR]u8 = undefined;
    addr[0] = OVERLAY_PREFIX;
    @memcpy(addr[1..LEN_OVERLAY_ADDR], full[0 .. LEN_OVERLAY_ADDR - 1]);
    return addr;
}

// BE-ID-03: reject a certificate whose role_bits carry a forbidden pairing.
// BE-ROLE-01 forbids agent+approver, BE-ROLE-02 agent+executor, BE-ROLE-04
// approver+executor. Checked at receipt as well as issuance: a buggy or
// compromised CA MUST NOT mint a self-approving identity a peer accepts.

pub fn checkRoleConstraints(role_bits: u8) CertChainError!void {
    const agent = (role_bits & ROLE_AGENT) != 0;
    const approver = (role_bits & ROLE_APPROVER) != 0;
    const executor = (role_bits & ROLE_EXECUTOR) != 0;
    if (agent and approver) return error.RoleAgentApprover;
    if (agent and executor) return error.RoleAgentExecutor;
    if (approver and executor) return error.RoleApproverExecutor;
}

// BE-ID-02 / BE-ID-03 / BE-ID-04: validate a parsed certificate against the
// local trust set and clock. Rejection is unconditional; there is no
// warn-and-continue path (SPEC BE-ID-02).
//
// BE-ID-03: forbidden role pairings. BE-ID-04: an approver cert needs >= 2 CA
// sigs. BE-ID-02: the validity window contains now_ms, every (ca_key, ca_sig)
// verifies over cert.tbs (domain 0x01), and every ca_key is in the local trust
// set. The strictly-ascending pairwise-distinct CA-key ordering is a parse
// failure enforced by parseCert (SPEC 3.1), so it holds for every Cert this
// function receives and is not re-checked here.

pub fn validateCert(cert: Cert, trusted_ca_keys: []const []const u8, now_ms: u64) BindingError!void {
    try validateCertChain(cert, trusted_ca_keys);

    // Validity window: inclusive at not_before, exclusive at not_after (X.509
    // convention; a cert is expired the instant its not_after is reached).
    if (now_ms < cert.not_before or now_ms >= cert.not_after) return error.CertExpired;
}

// BE-HIST-01: every structural certificate check with the clock removed. This
// is what an audit of a committed signature runs: the validity window is the
// ONLY conjunct that reads a clock (now_ms), and BE-HIST-01 forbids rechecking
// it on committed signatures. Everything here is a pure function of the cert
// bytes and the trust set: role pairings (BE-ROLE-01/02/04), approver quorum
// (BE-ID-04), the BE-REV-01 lifetime-span cap (a property of the cert's own
// not_before/not_after span, not of any clock), and every CA signature over
// tbs verified against the local trust set (BE-ID-02). The function takes no
// time input at all, so the type system proves no clock check can hide here,
// and its narrow error set cannot name a clock failure.
pub const CertChainError = error{
    MalformedKey,
    BadCASignature,
    UntrustedCA,
    CertTooLongLived,
    RoleAgentApprover,
    RoleAgentExecutor,
    RoleApproverExecutor,
    ApproverNoQuorum,
};

pub fn validateCertNoClock(cert: Cert, trusted_ca_keys: []const []const u8) CertChainError!void {
    return validateCertChain(cert, trusted_ca_keys);
}

fn validateCertChain(cert: Cert, trusted_ca_keys: []const []const u8) CertChainError!void {
    try checkRoleConstraints(cert.role_bits);

    if ((cert.role_bits & ROLE_APPROVER) != 0 and cert.ca_sig_count < APPROVER_QUORUM)
        return error.ApproverNoQuorum;

    if ((cert.role_bits & (ROLE_APPROVER | ROLE_EXECUTOR)) != 0 and
        cert.not_after - cert.not_before > MAX_PRIVILEGED_LIFETIME_MS) return error.CertTooLongLived;

    const pair_len = parser.session.LEN_CA_KEY + parser.session.LEN_CA_SIG;
    var i: usize = 0;
    while (i < cert.ca_sig_count) : (i += 1) {
        const off = i * pair_len;
        const ca_key = cert.ca_sigs[off .. off + parser.session.LEN_CA_KEY];
        const ca_sig = cert.ca_sigs[off + parser.session.LEN_CA_KEY .. off + pair_len];
        verifySig(DOMAIN_CERT, cert.tbs, ca_sig, ca_key) catch |e| switch (e) {
            error.MalformedKey => return error.MalformedKey,
            error.SignatureRejected => return error.BadCASignature,
        };
        if (!inTrustSet(ca_key, trusted_ca_keys)) return error.UntrustedCA;
    }
}

fn inTrustSet(ca_key: []const u8, trusted: []const []const u8) bool {
    for (trusted) |k| {
        if (std.mem.eql(u8, k, ca_key)) return true;
    }
    return false;
}

// BE-TR-01: bind an authenticated Noise static key to an Ed25519 identity.
//
// Immediately after the handshake, each side sends, inside the encrypted
// session, its certificate and an Ed25519 signature by sig_pubkey over the
// Noise handshake hash h (domain 0x05). A session MUST NOT deliver application
// data upward until the peer's certificate passes BE-ID-01..04 AND that
// signature verifies against h. This function performs the certificate and
// signature checks; the caller flips session.bound on success (session.zig
// gates upward delivery on that flag).

// F1: bindSession now verifies that the cert's kex_pubkey matches the remote
// static key from the handshake. This prevents a session binding to a cert
// whose kex_pubkey doesn't match the actual key exchange key, which would
// allow a MITM to substitute their own kex key while using a valid cert.
pub fn bindSession(cert: Cert, binding_sig: []const u8, handshake_hash: []const u8, remote_kex_pubkey: []const u8, trusted_ca_keys: []const []const u8, now_ms: u64) BindingError!void {
    try validateCert(cert, trusted_ca_keys, now_ms);
    // F1: verify kex_pubkey binding. The cert's kex_pubkey must match the
    // remote static key from the handshake. Without this, an attacker could
    // present a valid cert with a different kex key.
    if (cert.kex_pubkey.len != remote_kex_pubkey.len or !std.mem.eql(u8, cert.kex_pubkey, remote_kex_pubkey)) {
        return error.KexPubkeyMismatch;
    }
    verifySig(DOMAIN_BINDING, handshake_hash, binding_sig, cert.sig_pubkey) catch |e| switch (e) {
        error.MalformedKey => return error.MalformedKey,
        error.SignatureRejected => return error.BadBindingSig,
    };
}
