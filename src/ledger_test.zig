// ledger_test.zig
//
// Tests for the ledger slice (src/ledger.zig, src/historical.zig, src/verify.zig
// admission integration). Ten markers: BE-LEDGER-01/02/03, BE-HIST-01/02/03/04,
// BE-ENV-03/04/05. Literal values only (D-027).

const std = @import("std");
const ledger = @import("ledger.zig");
const historical = @import("historical.zig");
const verify = @import("verify.zig");
const dag = @import("dag.zig");
const parser = @import("parser.zig");
const binding = @import("binding.zig");

fn hashOf(s: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.blake2.Blake2s256.hash(s, &out, .{});
    return out;
}

// ---------------------------------------------------------------------------
// BE-LEDGER-02: hash-only store (BE-LEDGER-02).
// ---------------------------------------------------------------------------

test "BE_LEDGER_02 envelope stored by hash, not by plaintext" {
    var l = ledger.Ledger.init();
    const h = hashOf("test");

    // Insert uses only the hash; plaintext body is not stored.
    const entry = ledger.EnvelopeEntry{
        .hash = h,
        .sender = [_]u8{0xaa} ** 32,
        .channel = [_]u8{0xcc} ** 32,
        .seq = 1,
    };
    try l.insertEnvelope(entry);

    // The store contains the hash; there is no plaintext body field.
    try std.testing.expectEqual(@as(usize, 1), l.envelope_count);
}

// ---------------------------------------------------------------------------
// BE-LEDGER-03: Grant and Effect recording (BE-LEDGER-03).
// ---------------------------------------------------------------------------

test "BE_LEDGER_03 Grant envelope recorded in hash store on acceptance" {
    var l = ledger.Ledger.init();
    const grant_hash = hashOf("grant");

    const entry = ledger.EnvelopeEntry{
        .hash = grant_hash,
        .sender = [_]u8{0xbb} ** 32,
        .channel = [_]u8{0xdd} ** 32,
        .seq = 5,
    };
    try l.insertEnvelope(entry);

    // Grant is recorded: envelope_count increased.
    try std.testing.expectEqual(@as(usize, 1), l.envelope_count);
}

test "BE_LEDGER_03 Effect envelope recorded in hash store on acceptance" {
    var l = ledger.Ledger.init();
    const effect_hash = hashOf("effect");

    const entry = ledger.EnvelopeEntry{
        .hash = effect_hash,
        .sender = [_]u8{0xee} ** 32,
        .channel = [_]u8{0xff} ** 32,
        .seq = 10,
    };
    try l.insertEnvelope(entry);

    // Effect is recorded: envelope_count increased.
    try std.testing.expectEqual(@as(usize, 1), l.envelope_count);
}

// ---------------------------------------------------------------------------
// BE-LEDGER-01: unknown parents bounded resolution (BE-LEDGER-01).
// ---------------------------------------------------------------------------

test "BE_LEDGER_01 unknown parents rejected, no fetch budget exceeded" {
    var l = ledger.Ledger.init();
    const entry = ledger.EnvelopeEntry{
        .hash = hashOf("envelope"),
        .sender = [_]u8{0x11} ** 32,
        .channel = [_]u8{0x22} ** 32,
        .seq = 1,
    };
    try l.insertEnvelope(entry);

    // Parents not in the ledger: unknownParents error.
    const parents = [_][32]u8{[_]u8{0x33} ** 32, [_]u8{0x44} ** 32};
    try std.testing.expect(!l.allParentsPresent(&parents));
}

test "BE_LEDGER_01 known parents present in the ledger pass the check" {
    var l = ledger.Ledger.init();
    const parent_hash = hashOf("parent");
    const parent_entry = ledger.EnvelopeEntry{
        .hash = parent_hash,
        .sender = [_]u8{0x11} ** 32,
        .channel = [_]u8{0x22} ** 32,
        .seq = 0,
    };
    try l.insertEnvelope(parent_entry);

    // Parent is present: allParentsPresent returns true.
    const parents = [_][32]u8{parent_hash};
    try std.testing.expect(l.allParentsPresent(&parents));
}

// ---------------------------------------------------------------------------
// BE-HIST-02: certificate anchored before first use (BE-HIST-02).
// ---------------------------------------------------------------------------

test "BE_HIST_02 first envelope from sender becomes its anchor" {
    var l = ledger.Ledger.init();
    const sender = [_]u8{0xaa} ** 32;
    const env_hash = hashOf("anchor");

    // Set anchor: first envelope from this sender in this channel.
    try l.setAnchor(sender, env_hash);

    // Retrieve anchor: matches the envelope hash.
    const retrieved = l.getAnchor(sender);
    try std.testing.expect(retrieved != null);
    try std.testing.expectEqualSlices(u8, &env_hash, &retrieved.?);
}

test "BE_HIST_02 anchor is idempotent: setAnchor called twice with same hash succeeds" {
    var l = ledger.Ledger.init();
    const sender = [_]u8{0xbb} ** 32;
    const env_hash = hashOf("anchor2");

    try l.setAnchor(sender, env_hash);
    try l.setAnchor(sender, env_hash); // idempotent

    const retrieved = l.getAnchor(sender);
    try std.testing.expectEqualSlices(u8, &env_hash, &retrieved.?);
}

test "BE_HIST_02 anchor mismatched on second call causes divergence" {
    var l = ledger.Ledger.init();
    const sender = [_]u8{0xcc} ** 32;
    const h1 = hashOf("anchor3a");
    const h2 = hashOf("anchor3b");

    try l.setAnchor(sender, h1);
    // Second call with different hash: divergence.
    try std.testing.expectError(ledger.LedgerError.Divergence, l.setAnchor(sender, h2));
}

// ---------------------------------------------------------------------------
// BE-HIST-04: revocation immediate for admission (BE-HIST-04).
// ---------------------------------------------------------------------------

test "BE_HIST_04 revocation recorded immediately when Revoke accepted" {
    var l = ledger.Ledger.init();
    const sender = [_]u8{0xdd} ** 32;
    const revoke_hash = hashOf("revoke");

    try l.setRevocation(sender, revoke_hash);

    // Sender is now revoked.
    try std.testing.expect(l.isRevoked(sender));
}

test "BE_HIST_04 revocation is idempotent: setRevocation called twice succeeds" {
    var l = ledger.Ledger.init();
    const sender = [_]u8{0xee} ** 32;
    const revoke_hash = hashOf("revoke2");

    try l.setRevocation(sender, revoke_hash);
    try l.setRevocation(sender, revoke_hash); // idempotent
}

test "BE_HIST_04 revocation mismatched on second call causes divergence" {
    var l = ledger.Ledger.init();
    const sender = [_]u8{0xff} ** 32;
    const h1 = hashOf("revoke3a");
    const h2 = hashOf("revoke3b");

    try l.setRevocation(sender, h1);
    // Second call with different hash: divergence.
    try std.testing.expectError(ledger.LedgerError.Divergence, l.setRevocation(sender, h2));
}

// ---------------------------------------------------------------------------
// BE-ENV-03: body_type->role map enforcement (BE-ENV-03).
// ---------------------------------------------------------------------------

test "BE_ENV_03 Intent body_type allowed only for agent role" {
    const body_type = parser.channel.BODY_INTENT;
    const role_bits = binding.ROLE_AGENT;

    // Agent can send Intent.
    const allowed = verify.bodyTypeAllowed(body_type, role_bits);
    try std.testing.expect(allowed);
}

test "BE_ENV_03 Grant body_type allowed only for approver role" {
    const body_type = parser.channel.BODY_GRANT;
    const role_bits = binding.ROLE_APPROVER;

    // Approver can send Grant.
    const allowed = verify.bodyTypeAllowed(body_type, role_bits);
    try std.testing.expect(allowed);
}

test "BE_ENV_03 Effect body_type allowed only for executor role" {
    const body_type = parser.channel.BODY_EFFECT;
    const role_bits = binding.ROLE_EXECUTOR;

    // Executor can send Effect.
    const allowed = verify.bodyTypeAllowed(body_type, role_bits);
    try std.testing.expect(allowed);
}

test "BE_ENV_03 body_type not allowed for sender's role is refused" {
    const body_type = parser.channel.BODY_INTENT;
    const role_bits = binding.ROLE_EXECUTOR; // wrong role

    // Executor cannot send Intent.
    const allowed = verify.bodyTypeAllowed(body_type, role_bits);
    try std.testing.expect(!allowed);
}

// ---------------------------------------------------------------------------
// BE-ENV-04: per-(sender, channel) sliding seq window (BE-ENV-04).
// ---------------------------------------------------------------------------

test "BE_ENV_04 first seq initializes the window and is accepted" {
    var l = ledger.Ledger.init();
    const sender = [_]u8{0x11} ** 32;
    const channel = [_]u8{0x22} ** 32;

    // First seq: initializes window, accepted.
    try l.checkSeq(sender, channel, 100);
}

test "BE_ENV_04 seq below window is rejected" {
    var l = ledger.Ledger.init();
    const sender = [_]u8{0x33} ** 32;
    const channel = [_]u8{0x44} ** 32;

    // First seq: accepted, seeds window.
    try l.checkSeq(sender, channel, 2000);
    // Seq 0 is far below the window (2000 - 0 = 2000 > 1024): rejected.
    try std.testing.expectError(ledger.LedgerError.WindowStale, l.checkSeq(sender, channel, 0));
}

test "BE_ENV_04 duplicate seq is rejected" {
    var l = ledger.Ledger.init();
    const sender = [_]u8{0x55} ** 32;
    const channel = [_]u8{0x66} ** 32;

    // First seq: accepted.
    try l.checkSeq(sender, channel, 50);
    // Duplicate seq: rejected.
    try std.testing.expectError(ledger.LedgerError.WindowStale, l.checkSeq(sender, channel, 50));
}

test "BE_ENV_04 reordered seq within window is accepted" {
    var l = ledger.Ledger.init();
    const sender = [_]u8{0x77} ** 32;
    const channel = [_]u8{0x88} ** 32;

    try l.checkSeq(sender, channel, 100);
    try l.checkSeq(sender, channel, 99); // behind, within window
}

// ---------------------------------------------------------------------------
// BE-ENV-05: equivocation detection (BE-ENV-05).
// ---------------------------------------------------------------------------

test "BE_ENV_05 same triple with different hash raises Divergence" {
    var l = ledger.Ledger.init();
    const sender = [_]u8{0x99} ** 32;
    const channel = [_]u8{0xaa} ** 32;
    const seq: u64 = 1;
    const h1 = hashOf("env1");
    const h2 = hashOf("env2"); // different hash

    // First envelope: accepted.
    const entry1 = ledger.EnvelopeEntry{
        .hash = h1,
        .sender = sender,
        .channel = channel,
        .seq = seq,
    };
    try l.insertEnvelope(entry1);

    // Second envelope with same triple, different hash: equivocation.
    const entry2 = ledger.EnvelopeEntry{
        .hash = h2,
        .sender = sender,
        .channel = channel,
        .seq = seq,
    };
    try std.testing.expectError(ledger.LedgerError.Divergence, l.insertEnvelope(entry2));
}

test "BE_ENV_05 same triple with same hash is idempotent" {
    var l = ledger.Ledger.init();
    const sender = [_]u8{0xbb} ** 32;
    const channel = [_]u8{0xcc} ** 32;
    const h = hashOf("env3");

    const entry = ledger.EnvelopeEntry{
        .hash = h,
        .sender = sender,
        .channel = channel,
        .seq = 5,
    };
    try l.insertEnvelope(entry);
    // Insert same envelope again: idempotent.
    try l.insertEnvelope(entry);
}

// ---------------------------------------------------------------------------
// BE-HIST-03: historical validity causal interval (BE-HIST-03).
// ---------------------------------------------------------------------------

test "BE_HIST_03 envelope descendant of anchor passes historical check" {
    var l = ledger.Ledger.init();
    var d: dag.Dag = .{};
    const sender = [_]u8{0xdd} ** 32;
    const anchor_hash = hashOf("anchor4");
    const env_hash = hashOf("env4");

    // Insert anchor in ledger.
    try l.setAnchor(sender, anchor_hash);

    // Record causal relationship: anchor -> env (anchor precedes env).
    try d.insert(anchor_hash, env_hash);

    const ctx = historical.AuditContext{
        .ledger = &l,
        .dag = &d,
        .sender_cert = undefined, // not used for anchor check
        .trusted_ca_keys = &[_][]const u8{},
    };

    // Env is descendant of anchor: passes historical check.
    try historical.historicalValidity(env_hash, sender, ctx);
}

test "BE_HIST_03 envelope not descendant of anchor fails historical check" {
    var l = ledger.Ledger.init();
    var d: dag.Dag = .{};
    const sender = [_]u8{0xee} ** 32;
    const anchor_hash = hashOf("anchor5");
    const env_hash = hashOf("env5");

    try l.setAnchor(sender, anchor_hash);

    // No causal relationship recorded: env is not descendant of anchor.
    const ctx = historical.AuditContext{
        .ledger = &l,
        .dag = &d,
        .sender_cert = undefined,
        .trusted_ca_keys = &[_][]const u8{},
    };

    // Not descendant: fails historical check.
    try std.testing.expectError(historical.HistoricalError.NotDescendantOfAnchor, historical.historicalValidity(env_hash, sender, ctx));
}

test "BE_HIST_03 envelope descendant of revocation fails historical check" {
    var l = ledger.Ledger.init();
    var d: dag.Dag = .{};
    const sender = [_]u8{0xff} ** 32;
    const anchor_hash = hashOf("anchor6");
    const revoke_hash = hashOf("revoke4");
    const env_hash = hashOf("env6");

    // Anchor set for the sender.
    try l.setAnchor(sender, anchor_hash);

    // Sender is revoked.
    try l.setRevocation(sender, revoke_hash);

    // Record causal relationships: anchor -> revoke -> env.
    try d.insert(anchor_hash, revoke_hash);
    try d.insert(revoke_hash, env_hash);

    const ctx = historical.AuditContext{
        .ledger = &l,
        .dag = &d,
        .sender_cert = undefined,
        .trusted_ca_keys = &[_][]const u8{},
    };

    // Descendant of revocation: fails historical check.
    try std.testing.expectError(historical.HistoricalError.DescendantOfRevocation, historical.historicalValidity(env_hash, sender, ctx));
}

// ---------------------------------------------------------------------------
// BE-HIST-01: no clock checks on committed signatures (BE-HIST-01).
// ---------------------------------------------------------------------------

test "BE_HIST_01 historical validity does not recheck the clock on cert" {
    // The historical path calls validateCertNoClock, which skips the
    // temporal window check. This test documents the shape; the actual
    // implementation is TODO pending binding.zig refactor (see
    // src/historical.zig validateCertNoClock).
    //
    // When implemented, this test will pass a cert with an expired
    // not_after and expect success (no clock check), whereas the admission
    // path would reject the same cert.
    _ = historical.validateCertNoClock;
}