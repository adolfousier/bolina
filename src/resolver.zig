// resolver.zig
//
// Canonical resource resolution (SPEC.md section 8.4, BE-RES-01 through 06).
// Non-surface, state over parsed values (D-018): consumes a proposed
// resource_id byte string and returns the canonical form drawn from the
// operator-declared set. The requester proposes, the executor resolves
// (BE-RES-01): everything downstream, lock, Grant, approval rendering,
// Effect, ledger, receives the canonical form this module returns, never the
// proposed spelling.
//
// Aliases are operator-declared entries (D-053): each maps one proposed
// spelling to exactly one canonical entry. No fuzzy or prefix matching;
// granularity is declared, not emergent (BE-RES-05). Resolution counts the
// distinct canonical entries the proposal reaches: zero refuses, more than
// one refuses (BE-RES-02), exactly one is the canonical form (BE-RES-03).
//
// Publication (BE-RES-05): the set serializes deterministically in
// declaration order and is signed Ed25519 under domain tag 0x08 (BE-SIG-01,
// SPEC v0.3.2-draft encoding clause). The channel publication vehicle is
// undeclared in SPEC; the signed state exists here and the daemon milestone
// carries it (D-053).
//
// Fixed-capacity arrays; overflow returns error. No allocation.
// Tripwire: non-surface, excluded from the M11 line budget (SPEC.md
// BE-SURF-03 non-surface list, placed ahead of creation by D-052).

const std = @import("std");
const Blake2s256 = std.crypto.hash.blake2.Blake2s256;
const Ed = std.crypto.sign.Ed25519;
const intent_mod = @import("intent.zig");
const channel = @import("parser/channel.zig");

// ---------------------------------------------------------------------------
// Constants (SPEC section 8.4 grammar).
// ---------------------------------------------------------------------------

pub const FP_BYTES: usize = 8; // BLAKE2s-256(sig_pubkey)[0..8] (BE-RES-06)
pub const FP_HEX_LEN: usize = 16; // rendered as lowercase hex (BE-RES-06)
pub const NS_MAX: usize = 32; // namespace: 1..32 of [a-z0-9-]
pub const PATH_MAX: usize = 180; // path: 1..180 of [a-z0-9-._/]
// "bol:" + fp + "/" + namespace + "/" + path
pub const ID_MAX: usize = 4 + FP_HEX_LEN + 1 + NS_MAX + 1 + PATH_MAX;
pub const DOMAIN_RESOURCE_SET: u8 = 0x08; // BE-SIG-01 tag (SPEC v0.3.2-draft)

pub const MAX_RESOURCES: usize = 32; // operator-declared set; overflow refuses
pub const MAX_ALIASES: usize = 64; // flat alias pool across the whole set

// ---------------------------------------------------------------------------
// Refusal reasons. One class per BE-RES rule where the SPEC names one.
// ---------------------------------------------------------------------------

pub const ResolveError = error{
    MalformedCanonical, // grammar violation in a declared canonical (8.4)
    SetFull, // MAX_RESOURCES declared
    AliasPoolFull, // MAX_ALIASES declared
    DuplicateEntry, // canonical already declared
    UnknownResource, // BE-RES-02: zero matches, no create-on-first-use
    AmbiguousResource, // BE-RES-02: more than one distinct canonical reached
    ForeignExecutor, // BE-RES-04: canonical fp is not this executor's
    BufferTooSmall, // caller scratch below serializedLen + tag byte
};

// ---------------------------------------------------------------------------
// Entries. Fixed-size copies: the resolver owns its bytes (D-018, the
// intent.zig idiom). An alias carries the index of the canonical entry it
// maps to; pool order is declaration order, which serialization preserves.
// ---------------------------------------------------------------------------

pub const Entry = struct {
    canonical: [ID_MAX]u8,
    len: usize,
};

pub const Alias = struct {
    bytes: [ID_MAX]u8,
    len: usize,
    entry: usize,
};

// ---------------------------------------------------------------------------
// executorFp (BE-RES-06): BLAKE2s-256(sig_pubkey)[0..8], rendered as 16
// lowercase hex chars. Two implementations deriving this differently produce
// disjoint namespaces and silently defeat BE-RES-03/04; this function is the
// single derivation site.
// ---------------------------------------------------------------------------

pub fn executorFp(sig_pubkey: []const u8, out: *[FP_HEX_LEN]u8) void {
    var digest: [Blake2s256.digest_length]u8 = undefined;
    Blake2s256.hash(sig_pubkey, &digest, .{});
    const hex = "0123456789abcdef";
    for (digest[0..FP_BYTES], 0..) |b, i| {
        out[i * 2] = hex[b >> 4];
        out[i * 2 + 1] = hex[b & 0x0f];
    }
}

// ---------------------------------------------------------------------------
// validateCanonical (SPEC section 8.4 grammar): "bol:" fp "/" namespace "/"
// path. The fp is 16 lowercase hex; the namespace is 1..32 of [a-z0-9-]; the
// path is 1..180 of [a-z0-9-._/] with no empty segment and no "." or ".."
// segment.
// ---------------------------------------------------------------------------

pub fn validateCanonical(id: []const u8) bool {
    if (id.len < 4 + FP_HEX_LEN + 3) return false; // bol: + fp + two slashes + min content
    if (!std.mem.eql(u8, id[0..4], "bol:")) return false;
    for (id[4 .. 4 + FP_HEX_LEN]) |c| if (!isHexLower(c)) return false;
    var pos: usize = 4 + FP_HEX_LEN;
    if (id[pos] != '/') return false;
    pos += 1;
    const ns_start = pos;
    while (pos < id.len and id[pos] != '/') : (pos += 1) {
        if (!isNsChar(id[pos])) return false;
    }
    const ns_len = pos - ns_start;
    if (ns_len < 1 or ns_len > NS_MAX) return false;
    if (pos >= id.len or id[pos] != '/') return false;
    pos += 1;
    const path_start = pos;
    var seg_len: usize = 0;
    var dots: usize = 0;
    while (pos < id.len) : (pos += 1) {
        const c = id[pos];
        if (!isPathChar(c) and c != '/') return false;
        if (c == '/') {
            if (segLenInvalid(seg_len, dots)) return false;
            seg_len = 0;
            dots = 0;
        } else {
            seg_len += 1;
            if (c == '.') dots += 1;
        }
    }
    if (segLenInvalid(seg_len, dots)) return false;
    const path_len = id.len - path_start;
    return path_len >= 1 and path_len <= PATH_MAX;
}

// A segment is invalid when empty, or exactly "." or ".." (section 8.4).
fn segLenInvalid(seg_len: usize, dots: usize) bool {
    return seg_len == 0 or (dots == seg_len and seg_len <= 2);
}

fn isHexLower(c: u8) bool {
    return (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
}

fn isNsChar(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9') or c == '-';
}

fn isPathChar(c: u8) bool {
    return isNsChar(c) or c == '.' or c == '_';
}

// ---------------------------------------------------------------------------
// The resolver.
// ---------------------------------------------------------------------------

pub const Resolver = struct {
    own_fp: [FP_HEX_LEN]u8, // rendered hex, derived at init (BE-RES-06)
    entries: [MAX_RESOURCES]Entry = undefined,
    entry_count: usize = 0,
    aliases: [MAX_ALIASES]Alias = undefined,
    alias_count: usize = 0,

    // init (BE-RES-06): the executor's own fingerprint derives from its
    // signing public key; every resolve checks the canonical against it.
    pub fn init(sig_pubkey: []const u8) Resolver {
        var r: Resolver = .{ .own_fp = undefined };
        executorFp(sig_pubkey, &r.own_fp);
        return r;
    }

    // add (BE-RES-05): declare a canonical resource. Granularity is an
    // explicit operator decision; the grammar check keeps every declared
    // canonical well-formed at construction, so resolve never returns a
    // malformed identifier to the lock, the Grant, or the ledger.
    pub fn add(self: *Resolver, canonical: []const u8) ResolveError!void {
        if (!validateCanonical(canonical)) return error.MalformedCanonical;
        if (canonical.len > ID_MAX) return error.MalformedCanonical;
        if (self.entry_count == MAX_RESOURCES) return error.SetFull;
        if (self.findEntry(canonical) != null) return error.DuplicateEntry;
        const e = &self.entries[self.entry_count];
        @memcpy(e.canonical[0..canonical.len], canonical);
        e.len = canonical.len;
        self.entry_count += 1;
    }

    // addAlias (BE-RES-03, D-053): map a proposed spelling to a declared
    // canonical. The target must already exist: an alias pointing at an
    // undeclared resource is a set-construction error, refused here rather
    // than becoming a resolve-time ambiguity.
    pub fn addAlias(self: *Resolver, canonical: []const u8, alias: []const u8) ResolveError!void {
        if (alias.len == 0 or alias.len > ID_MAX) return error.MalformedCanonical;
        const idx = self.findEntry(canonical) orelse return error.UnknownResource;
        if (self.alias_count == MAX_ALIASES) return error.AliasPoolFull;
        const a = &self.aliases[self.alias_count];
        @memcpy(a.bytes[0..alias.len], alias);
        a.len = alias.len;
        a.entry = idx;
        self.alias_count += 1;
    }

    // resolve (BE-RES-01/02/03/04): proposed spelling to canonical form.
    // Counts distinct canonical entries reached by exact match or declared
    // alias; zero refuses (no create-on-first-use), more than one refuses,
    // exactly one returns the canonical slice owned by the set. BE-RES-04
    // then refuses any canonical that does not carry this executor's fp.
    pub fn resolve(self: *const Resolver, proposed: []const u8) ResolveError![]const u8 {
        var found: ?usize = null;
        for (self.entries[0..self.entry_count], 0..) |e, i| {
            var hit = e.len == proposed.len and std.mem.eql(u8, e.canonical[0..e.len], proposed);
            if (!hit) hit = self.aliasHits(i, proposed);
            if (hit) {
                if (found) |f| if (f != i) return error.AmbiguousResource;
                if (found == null) found = i;
            }
        }
        const idx = found orelse return error.UnknownResource;
        const c = self.entries[idx].canonical[0..self.entries[idx].len];
        if (!std.mem.eql(u8, c[4 .. 4 + FP_HEX_LEN], &self.own_fp)) return error.ForeignExecutor;
        return c;
    }

    // serializedLen (BE-RES-05, SPEC v0.3.2-draft encoding clause).
    pub fn serializedLen(self: *const Resolver) usize {
        var n: usize = 0;
        for (self.entries[0..self.entry_count], 0..) |e, i| {
            n += 2 + e.len + 2;
            for (self.aliases[0..self.alias_count]) |a| {
                if (a.entry == i) n += 2 + a.len;
            }
        }
        return n;
    }

    // serialize (BE-RES-05): deterministic in declaration order. Per entry:
    // u16 canonical length + canonical bytes, u16 alias count, then per alias
    // u16 length + alias bytes. Big-endian, the repo's wire convention.
    pub fn serialize(self: *const Resolver, out: []u8) ResolveError!usize {
        if (out.len < self.serializedLen()) return error.BufferTooSmall;
        var pos: usize = 0;
        for (self.entries[0..self.entry_count], 0..) |e, i| {
            std.mem.writeInt(u16, out[pos..][0..2], @intCast(e.len), .big);
            pos += 2;
            @memcpy(out[pos..][0..e.len], e.canonical[0..e.len]);
            pos += e.len;
            var n_alias: usize = 0;
            for (self.aliases[0..self.alias_count]) |a| {
                if (a.entry == i) n_alias += 1;
            }
            std.mem.writeInt(u16, out[pos..][0..2], @intCast(n_alias), .big);
            pos += 2;
            for (self.aliases[0..self.alias_count]) |a| {
                if (a.entry != i) continue;
                std.mem.writeInt(u16, out[pos..][0..2], @intCast(a.len), .big);
                pos += 2;
                @memcpy(out[pos..][0..a.len], a.bytes[0..a.len]);
                pos += a.len;
            }
        }
        return pos;
    }

    // signResourceSet (BE-RES-05 + BE-SIG-01): Ed25519 over tag 0x08 followed
    // by the serialization, under the executor's own key pair. Scratch holds
    // the tagged serialization; 1 + serializedLen bytes suffice.
    pub fn signResourceSet(self: *const Resolver, keypair: Ed.KeyPair, scratch: []u8) ResolveError![64]u8 {
        if (scratch.len < 1 + self.serializedLen()) return error.BufferTooSmall;
        scratch[0] = DOMAIN_RESOURCE_SET;
        const n = try self.serialize(scratch[1..]);
        const sig = Ed.KeyPair.sign(keypair, scratch[0 .. 1 + n], null) catch unreachable;
        return Ed.Signature.toBytes(sig);
    }

    // verifyResourceSet (BE-RES-05): re-serialize and check the signature
    // under the declared executor key. A reviewer (or a peer, once the
    // publication vehicle exists) recomputes rather than trusts. Verifier
    // idiom matches verifySigned (verify.zig): strict on non-canonical R.
    pub fn verifyResourceSet(self: *const Resolver, sig: [64]u8, pubkey: Ed.PublicKey, scratch: []u8) ResolveError!bool {
        if (scratch.len < 1 + self.serializedLen()) return error.BufferTooSmall;
        scratch[0] = DOMAIN_RESOURCE_SET;
        const n = try self.serialize(scratch[1..]);
        const signature = Ed.Signature.fromBytes(sig);
        var v = signature.verifier(pubkey) catch return false;
        v.update(scratch[0 .. 1 + n]);
        v.verify() catch return false;
        return true;
    }

    // resolveAndAdmit (BE-RES-01/02/03/04): the executor-side admission gate.
    // Resolves the proposed resource_id to the canonical form BEFORE the lock
    // is touched; unknown, ambiguous, and foreign-fingerprint proposals
    // refuse without mutating the table (BE-RES-02/04). The entry admitted
    // carries the canonical bytes, so the lock and everything downstream of
    // it keys on the executor's form, never the requester's (BE-RES-01), and
    // two spellings of one resource collapse into one lock (BE-RES-03).
    pub fn resolveAndAdmit(self: *const Resolver, table: *intent_mod.Table, it: channel.Intent, now_ms: u64) (ResolveError || intent_mod.IntentError)!void {
        const canonical = try self.resolve(it.resource_id);
        var resolved = it;
        resolved.resource_id = canonical;
        try table.admit(resolved, now_ms);
    }

    // --- internal lookups --------------------------------------------------

    fn findEntry(self: *const Resolver, canonical: []const u8) ?usize {
        for (self.entries[0..self.entry_count], 0..) |e, i| {
            if (e.len == canonical.len and std.mem.eql(u8, e.canonical[0..e.len], canonical)) return i;
        }
        return null;
    }

    fn aliasHits(self: *const Resolver, entry_idx: usize, proposed: []const u8) bool {
        for (self.aliases[0..self.alias_count]) |a| {
            if (a.entry == entry_idx and a.len == proposed.len and
                std.mem.eql(u8, a.bytes[0..a.len], proposed)) return true;
        }
        return false;
    }
};
