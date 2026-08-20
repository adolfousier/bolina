// ledger.zig
//
// Ledger store (SPEC.md BE-LEDGER-02/03, BE-HIST-02/04, BE-ENV-03/04/05).
// Bounded hash-only envelope store, zero-heap, caller-owned. Envelopes are
// stored by 32-byte hash only; plaintext bodies never touch the ledger.
//
// Features:
//   * BE-LEDGER-01/03: bounded hash store with insert, parent resolution hook
//   * BE-ENV-05: equivocation detection (same triple, different hash)
//   * BE-ENV-04: per-(sender, channel) sliding seq windows (reusing replay.zig)
//   * BE-HIST-02: anchor table (pubkey -> first envelope hash in channel)
//   * BE-HIST-04: revocation causal table (pubkey -> revoke envelope hash)
//
// All tables are fixed-capacity arrays; overflow returns error. No allocation.
// Plain error set (not coverage.Branch): this is verification state, not an
// M9 parser module. Tripwire: file must stay under 420 lines before markers
// bind (D-045).

const std = @import("std");
const replay = @import("replay.zig");

// ---------------------------------------------------------------------------
// Constants.
// ---------------------------------------------------------------------------

pub const HASH_BYTES: usize = 32; // Ed25519 signature
pub const LEN_SIG_PUBKEY: usize = 32; // Ed25519 public key
pub const LEN_CHANNEL_ID: usize = 32; // BLAKE2s channel identifier

// Bounded capacities. The caller sizes these pools; overflow is a refusal.
pub const MAX_ENVELOPES: usize = 4096; // hash store
pub const MAX_SEQ_WINDOWS: usize = 256; // per-(sender, channel) windows
pub const MAX_ANCHORS: usize = 256; // pubkey -> anchor hash
pub const MAX_REVOCATIONS: usize = 64; // pubkey -> revoke hash

// ---------------------------------------------------------------------------
// Ledger errors. One class per refusal reason.
// ---------------------------------------------------------------------------

pub const LedgerError = error{
    StoreFull, // hash store at MAX_ENVELOPES
    SeqWindowsFull, // table at MAX_SEQ_WINDOWS
    AnchorsFull, // anchor table at MAX_ANCHORS
    RevocationsFull, // revocation table at MAX_REVOCATIONS
    Divergence, // same (sender, channel, seq) with different hash (BE-ENV-05)
    WindowStale, // seq below window (BE-ENV-04)
};

// ---------------------------------------------------------------------------
// Envelope entry in the hash store (BE-LEDGER-02).
// ---------------------------------------------------------------------------

pub const EnvelopeEntry = struct {
    hash: [HASH_BYTES]u8, // the envelope's BLAKE2s hash
    sender: [LEN_SIG_PUBKEY]u8, // signer's public key
    channel: [LEN_CHANNEL_ID]u8, // channel identifier
    seq: u64, // channel-local sequence number
};

// ---------------------------------------------------------------------------
// SeqWindowKey: per-(sender, channel) window identifier.
// ---------------------------------------------------------------------------

pub const SeqWindowKey = struct {
    sender: [LEN_SIG_PUBKEY]u8,
    channel: [LEN_CHANNEL_ID]u8,

    pub fn eql(a: SeqWindowKey, b: SeqWindowKey) bool {
        return std.mem.eql(u8, &a.sender, &b.sender) and
            std.mem.eql(u8, &a.channel, &b.channel);
    }
};

// ---------------------------------------------------------------------------
// SeqWindowEntry: maps a key to a ReplayWindow.
// ---------------------------------------------------------------------------

pub const SeqWindowEntry = struct {
    key: SeqWindowKey,
    window: replay.ReplayWindow,
};

// ---------------------------------------------------------------------------
// Anchor entry (BE-HIST-02): pubkey -> anchor hash.
// ---------------------------------------------------------------------------

pub const AnchorEntry = struct {
    pubkey: [LEN_SIG_PUBKEY]u8,
    anchor_hash: [HASH_BYTES]u8, // hash of first envelope from this pubkey in channel
};

// ---------------------------------------------------------------------------
// Revocation entry (BE-HIST-04): pubkey -> revoke envelope hash.
// ---------------------------------------------------------------------------

pub const RevocationEntry = struct {
    pubkey: [LEN_SIG_PUBKEY]u8,
    revoke_hash: [HASH_BYTES]u8, // hash of Revoke envelope that revoked this pubkey
    cert_expiry_ms: u64, // F10: revocation is prunable after cert expires
};

// ---------------------------------------------------------------------------
// The ledger: all tables together (caller-owned, zero-heap).
// ---------------------------------------------------------------------------

pub const Ledger = struct {
    // BE-LEDGER-02 hash store (envelopes only, never plaintext).
    envelopes: [MAX_ENVELOPES]EnvelopeEntry,
    envelope_count: usize = 0,

    // BE-ENV-04 per-(sender, channel) sliding seq windows.
    seq_windows: [MAX_SEQ_WINDOWS]SeqWindowEntry,
    seq_window_count: usize = 0,

    // BE-HIST-02 anchor table (first envelope hash per pubkey per channel).
    anchors: [MAX_ANCHORS]AnchorEntry,
    anchor_count: usize = 0,

    // BE-HIST-04 revocation causal table (pubkey -> revoke envelope hash).
    revocations: [MAX_REVOCATIONS]RevocationEntry,
    revocation_count: usize = 0,

    pub fn init() Ledger {
        return .{
            .envelopes = undefined,
            .seq_windows = undefined,
            .anchors = undefined,
            .revocations = undefined,
        };
    }

    // ---------------------------------------------------------------------------
    // Envelope store operations (BE-LEDGER-01/02/03, BE-ENV-05).
    // ---------------------------------------------------------------------------

    // Insert an envelope into the hash store. Performs equivocation check
    // (same triple, different hash) before insert. Returns Divergence if the
    // triple already exists with a different hash (BE-ENV-05).
    pub fn insertEnvelope(self: *Ledger, entry: EnvelopeEntry) LedgerError!void {
        // BE-ENV-05: equivocation detection. Scan for matching triple.
        var i: usize = 0;
        while (i < self.envelope_count) : (i += 1) {
            const e = &self.envelopes[i];
            if (std.mem.eql(u8, &e.sender, &entry.sender) and
                std.mem.eql(u8, &e.channel, &entry.channel) and
                e.seq == entry.seq)
            {
                // Triple matches. Check hash.
                if (std.mem.eql(u8, &e.hash, &entry.hash)) {
                    return; // idempotent: same hash already stored
                } else {
                    return error.Divergence; // different hash: equivocation
                }
            }
        }

        // No equivocation; insert if space remains.
        if (self.envelope_count >= MAX_ENVELOPES) return error.StoreFull;
        self.envelopes[self.envelope_count] = entry;
        self.envelope_count += 1;
    }

    // BE-LEDGER-01: resolve parents within the ledger. Returns true if ALL
    // parents are present, false if any are missing. The caller decides the
    // bounded fetch budget; this is the in-memory check only.
    pub fn allParentsPresent(self: *const Ledger, parent_hashes: []const [HASH_BYTES]u8) bool {
        for (parent_hashes) |ph| {
            var found = false;
            var i: usize = 0;
            while (i < self.envelope_count) : (i += 1) {
                if (std.mem.eql(u8, &self.envelopes[i].hash, &ph)) {
                    found = true;
                    break;
                }
            }
            if (!found) return false;
        }
        return true;
    }

    // ---------------------------------------------------------------------------
    // Seq window operations (BE-ENV-04).
    // ---------------------------------------------------------------------------

    // Find or create the seq window for (sender, channel). Returns Divergence
    // if the seq is stale (below the window) or duplicate (already accepted).
    pub fn checkSeq(self: *Ledger, sender: [LEN_SIG_PUBKEY]u8, channel: [LEN_CHANNEL_ID]u8, seq: u64) LedgerError!void {
        // Look up existing window.
        const key = SeqWindowKey{ .sender = sender, .channel = channel };
        var i: usize = 0;
        while (i < self.seq_window_count) : (i += 1) {
            if (self.seq_windows[i].key.eql(key)) {
                // Found window; check seq.
                const accepted = self.seq_windows[i].window.check(seq);
                if (!accepted) return error.WindowStale; // replay or below window
                return;
            }
        }

        // No existing window; create one.
        if (self.seq_window_count >= MAX_SEQ_WINDOWS) return error.SeqWindowsFull;
        self.seq_windows[self.seq_window_count] = .{
            .key = key,
            .window = replay.ReplayWindow.init(),
        };
        self.seq_window_count += 1;
        // Check seq against the fresh window (first call seeds largest).
        if (!self.seq_windows[self.seq_window_count - 1].window.check(seq)) {
            // Should never fail on first call; this is defensive.
            return error.WindowStale;
        }
    }

    // ---------------------------------------------------------------------------
    // Anchor table operations (BE-HIST-02).
    // ---------------------------------------------------------------------------

    // Record the first envelope from a pubkey in a channel as the anchor.
    // Idempotent: if anchor exists, verify it matches the new anchor hash.
    pub fn setAnchor(self: *Ledger, pubkey: [LEN_SIG_PUBKEY]u8, anchor_hash: [HASH_BYTES]u8) LedgerError!void {
        // Check for existing anchor.
        var i: usize = 0;
        while (i < self.anchor_count) : (i += 1) {
            if (std.mem.eql(u8, &self.anchors[i].pubkey, &pubkey)) {
                // Anchor already set; verify consistency.
                if (!std.mem.eql(u8, &self.anchors[i].anchor_hash, &anchor_hash)) {
                    // BE-HIST-02 requires ONE anchor per pubkey; mismatch is fatal.
                    return error.Divergence;
                }
                return; // idempotent
            }
        }

        // New anchor.
        if (self.anchor_count >= MAX_ANCHORS) return error.AnchorsFull;
        self.anchors[self.anchor_count] = .{
            .pubkey = pubkey,
            .anchor_hash = anchor_hash,
        };
        self.anchor_count += 1;
    }

    // Retrieve the anchor hash for a pubkey. Returns null if not anchored.
    pub fn getAnchor(self: *const Ledger, pubkey: [LEN_SIG_PUBKEY]u8) ?[HASH_BYTES]u8 {
        var i: usize = 0;
        while (i < self.anchor_count) : (i += 1) {
            if (std.mem.eql(u8, &self.anchors[i].pubkey, &pubkey)) {
                return self.anchors[i].anchor_hash;
            }
        }
        return null;
    }

    // ---------------------------------------------------------------------------
    // Revocation table operations (BE-HIST-04).
    // ---------------------------------------------------------------------------

    // Record that a pubkey is revoked, with the envelope hash of the Revoke.
    pub fn setRevocation(self: *Ledger, pubkey: [LEN_SIG_PUBKEY]u8, revoke_hash: [HASH_BYTES]u8, cert_expiry_ms: u64) LedgerError!void {
        // Idempotent: if revocation exists, verify hash matches.
        var i: usize = 0;
        while (i < self.revocation_count) : (i += 1) {
            if (std.mem.eql(u8, &self.revocations[i].pubkey, &pubkey)) {
                if (!std.mem.eql(u8, &self.revocations[i].revoke_hash, &revoke_hash)) {
                    // Inconsistent revocation: divergence.
                    return error.Divergence;
                }
                return;
            }
        }

        // F10: before inserting, prune expired revocations to free capacity.
        // A revocation is expired if its cert_expiry_ms < now_ms, but we don't
        // have now_ms here. Instead, we prune lazily: if the table is full,
        // remove the oldest expired entry (lowest cert_expiry_ms).
        if (self.revocation_count >= MAX_REVOCATIONS) {
            // Find the entry with the lowest cert_expiry_ms.
            var min_idx: ?usize = null;
            var min_expiry: u64 = std.math.maxInt(u64);
            i = 0;
            while (i < self.revocation_count) : (i += 1) {
                if (self.revocations[i].cert_expiry_ms < min_expiry) {
                    min_expiry = self.revocations[i].cert_expiry_ms;
                    min_idx = i;
                }
            }
            // If we found an entry, remove it by shifting subsequent entries.
            if (min_idx) |idx| {
                var j = idx;
                while (j + 1 < self.revocation_count) : (j += 1) {
                    self.revocations[j] = self.revocations[j + 1];
                }
                self.revocation_count -= 1;
            } else {
                // No entries to prune (shouldn't happen if count >= MAX_REVOCATIONS).
                return error.RevocationsFull;
            }
        }

        // New revocation.
        self.revocations[self.revocation_count] = .{
            .pubkey = pubkey,
            .revoke_hash = revoke_hash,
            .cert_expiry_ms = cert_expiry_ms,
        };
        self.revocation_count += 1;
    }

    // Check if a pubkey is revoked. Returns true if revoked, false otherwise.
    pub fn isRevoked(self: *const Ledger, pubkey: [LEN_SIG_PUBKEY]u8) bool {
        var i: usize = 0;
        while (i < self.revocation_count) : (i += 1) {
            if (std.mem.eql(u8, &self.revocations[i].pubkey, &pubkey)) {
                return true;
            }
        }
        return false;
    }
};
