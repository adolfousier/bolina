// historical.zig
//
// Historical audit path (BE-HIST-01/03/04). Validates that an envelope was
// historically valid at the time of its commitment. BE-HIST-01: no clock
// checks on committed signatures. BE-HIST-03: causal interval check (descendant
// of anchor, not descendant of revocation). BE-HIST-04: revocation is immediate
// for admission, causal-positioned for audit.
//
// This is verification state, not parser surface (D-045). Plain error set,
// not coverage.Branch. Tripwire: file must stay under 150 lines before
// markers bind.

const std = @import("std");
const ledger = @import("ledger.zig");
const dag = @import("dag.zig");
const parser = @import("parser.zig");
const binding = @import("binding.zig");

// ---------------------------------------------------------------------------
// Historical audit errors (BE-HIST-03).
// ---------------------------------------------------------------------------

pub const HistoricalError = error{
    NotDescendantOfAnchor, // BE-HIST-03: envelope not causally after anchor
    DescendantOfRevocation, // BE-HIST-03: envelope causally after revocation
    AnchorNotFound, // BE-HIST-02: sender has no anchor in the ledger
    // BE-HIST-01: certificate chain failures surfaced through the audit path.
    // Superset of binding.BindingError so the delegation below coerces without
    // a lossy switch. CertExpired is carried for set completeness only: the
    // NoClock chain takes no time input, so this path cannot emit it.
    MalformedKey,
    BadCASignature,
    UntrustedCA,
    CertExpired,
    CertTooLongLived,
    RoleAgentApprover,
    RoleAgentExecutor,
    RoleApproverExecutor,
    ApproverNoQuorum,
};

// ---------------------------------------------------------------------------
// Audit context: every input needed for historical validity checks.
// ---------------------------------------------------------------------------

pub const AuditContext = struct {
    ledger: *ledger.Ledger,
    dag: *dag.Dag,
    // BE-ID-02..04: the sender's certificate and CA trust set.
    sender_cert: parser.session.Cert,
    trusted_ca_keys: []const []const u8,
};

// ---------------------------------------------------------------------------
// Historical validity check (BE-HIST-01/03/04).
//
// Returns error if the envelope was not valid at the time of commitment.
// BE-HIST-01: no clock checks (cert validity at commit time is not rechecked).
// BE-HIST-03: the envelope must be a causal descendant of its anchor and
// must not be a causal descendant of a revocation. BE-HIST-04: revocation is
// immediate for admission (checked by ledger.isRevoked) and causal-positioned
// for audit (checked via DAG ancestry).
// ---------------------------------------------------------------------------

pub fn historicalValidity(
    env_hash: [32]u8,
    sender: [32]u8,
    ctx: AuditContext,
) HistoricalError!void {
    // BE-HIST-01: the sender's certificate is revalidated structurally, with
    // no clock. A committed signature stays valid after its cert expires; a
    // cert whose CHAIN was never sound was never valid at any time.
    try validateCertNoClock(ctx.sender_cert, ctx.trusted_ca_keys);

    // BE-HIST-03: check that the envelope is a causal descendant of its anchor.
    const anchor_hash = ctx.ledger.getAnchor(sender) orelse return error.AnchorNotFound;
    if (!ctx.dag.isAncestor(anchor_hash, env_hash)) {
        return error.NotDescendantOfAnchor;
    }

    // BE-HIST-04 causal form: the ledger exposes the revoke envelope's hash,
    // and the violation exists only when the audited envelope is a causal
    // DESCENDANT of that revoke. An envelope committed before the revocation
    // stays historically valid at commit time; admission (ledger.isRevoked)
    // remains the immediate gate for anything arriving now.
    if (ctx.ledger.getRevokeHash(sender)) |revoke_hash| {
        if (ctx.dag.isAncestor(revoke_hash, env_hash)) {
            return error.DescendantOfRevocation;
        }
    }
}

// ---------------------------------------------------------------------------
// BE-HIST-01 helper: validate a certificate at commit time WITHOUT clock.
//
// Delegates to binding.validateCertNoClock (the chain split lives there, next
// to the clocked validateCert it mirrors). Skips only the validity-window
// check (BE-ID-03): historical validity does not recheck the clock on
// committed signatures. Chain, role constraints, BE-REV-01 lifetime-span cap,
// and CA signatures are all still verified.
// ---------------------------------------------------------------------------

pub fn validateCertNoClock(cert: parser.session.Cert, trusted_ca_keys: []const []const u8) HistoricalError!void {
    return binding.validateCertNoClock(cert, trusted_ca_keys);
}
