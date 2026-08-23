// binding.zig
//
// Certificate identity chain (SPEC 3.2, BE-ID-01..04) and post-handshake
// session binding (SPEC 4.1, BE-TR-01): the post-authentication surface. A
// hostile authenticated peer's cert and binding-signature bytes reach this
// module, so every check fails closed; the encrypted session carrying them
// authenticates nothing here (BE-TR-07 keeps certs out of the handshake).
//
// Zero-heap: Ed25519 via the stdlib streaming Verifier fed the one-byte
// BE-SIG-01 domain tag and the tbs region as two chunks. The cert arrives
// parsed (parser.session.Cert); verify.zig (non-surface) reaches in for cert
// validation, binding.zig never reaches back: the dependency runs one way.

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

// BE-SIG-01 domain-separated Ed25519 verification (internal): verifies `sig`
// over (tag || tbs) against `pubkey`, tag and tbs fed as two chunks so no
// tagged-message buffer is allocated. MalformedKey = unparseable key;
// SignatureRejected = verification failure the caller maps per check.

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

// BE-ID-01: overlay_addr = 0xfd || BLAKE2s-256(sig_pubkey)[0..15], a 16-byte
// fd00::/8 ULA (first 15 hash bytes, 16 total; section 11.3 test vector). The
// address is a commitment to the key: no resolution step to poison, and a
// node MUST NOT accept an address asserted by any other party.

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

// BE-ID-02/03/04: validate a parsed certificate against the local trust set
// and clock; rejection is unconditional (no warn-and-continue path). The
// validity window must contain now_ms, every (ca_key, ca_sig) must verify over
// tbs (domain 0x01) against the local trust set, and the strictly-ascending
// pairwise-distinct CA ordering is parse-enforced (SPEC 3.1), not re-checked.

pub fn validateCert(cert: Cert, trusted_ca_keys: []const []const u8, now_ms: u64) BindingError!void {
    try validateCertChain(cert, trusted_ca_keys);

    // Validity window: inclusive at not_before, exclusive at not_after (X.509
    // convention; a cert is expired the instant its not_after is reached).
    if (now_ms < cert.not_before or now_ms >= cert.not_after) return error.CertExpired;
}

// BE-HIST-01: the audit path. validateCertNoClock is every structural cert
// check with the clock removed: no time parameter exists, so the type system
// proves no clock check can hide here, and the narrow CertChainError set
// cannot name a clock failure. Roles, quorum, the BE-REV-01 span cap (a
// property of the cert's own span, not of any clock), and every CA signature
// against the trust set are pure cert-byte functions.
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
// Right after the handshake, inside the encrypted session, each side sends
// its certificate plus an Ed25519 signature by sig_pubkey over the Noise
// handshake hash h (domain 0x05). No application data flows upward until the
// cert passes BE-ID-01..04 AND the signature verifies against h; the caller
// flips session.bound, which session.zig gates upward delivery on.

// F1: the cert's kex_pubkey must equal the handshake's remote static key,
// else a MITM substitutes its own kex key behind an otherwise valid cert.
pub fn bindSession(cert: Cert, binding_sig: []const u8, handshake_hash: []const u8, remote_kex_pubkey: []const u8, trusted_ca_keys: []const []const u8, now_ms: u64) BindingError!void {
    try validateCert(cert, trusted_ca_keys, now_ms);
    if (cert.kex_pubkey.len != remote_kex_pubkey.len or !std.mem.eql(u8, cert.kex_pubkey, remote_kex_pubkey)) {
        return error.KexPubkeyMismatch;
    }
    verifySig(DOMAIN_BINDING, handshake_hash, binding_sig, cert.sig_pubkey) catch |e| switch (e) {
        error.MalformedKey => return error.MalformedKey,
        error.SignatureRejected => return error.BadBindingSig,
    };
}
