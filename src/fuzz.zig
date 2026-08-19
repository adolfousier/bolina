// fuzz.zig
//
// Chaos fuzzer and differential oracle harness for the parser (BE-WIRE-02,
// BE-SURF-04, LANGUAGE.md O2, SPEC section 11.6). Built and run on demand via
// `zig build fuzz` / `zig build fuzz-corpus` / `zig build fuzz-diff`; main.zig
// never imports it, so it is not part of the shipped binary.
//
// Three modes, selected by the fuzz_mode build option at compile time:
//
// - chaos (default): feeds mutated-valid and fully-random byte streams to all
//   22 wired parse entry points for a wall-clock budget. Every array read in
//   the parser routes through Cursor.need(), so a ReleaseSafe panic here is a
//   genuine bounds-check gap (an out-of-bounds read), not a logic error. A
//   clean exit over N inputs means N inputs parsed with no out-of-bounds
//   access.
//
// - corpus: writes a deterministic corpus file of tagged records, one record
//   per entry: u8 structure_tag, u16 big-endian length, then the bytes
//   (D-056 corpus protocol). Per-structure streams: each structure is fuzzed
//   against its own seed lineage plus random bytes, same PRNG seed and same 5
//   mutation operators as chaos mode, so a fixed seed and budget reproduce
//   the file bit-for-bit.
//
// - diff: replays a corpus file, routes each record to its tagged parse
//   function, and prints one verdict line per record (A accept, R reject).
//   tools/refparse.py (the independent Python reference, D-056) replays the
//   SAME file; agreement on every record is the differential verdict. A
//   ReleaseSafe panic in diff mode is a defect, same as chaos.

const std = @import("std");
const parser = @import("parser.zig");
const relay = @import("relay.zig");
const vectors_json = @import("vectors").json;
const coverage = @import("coverage.zig");
const opts = @import("build_options");

const MAX_INPUT: usize = 4096;

// Corpus structure tags, shared verbatim with tools/refparse.py (D-056). One
// tag per parse entry point in the parser module: src/parser.zig,
// src/relay.zig, and src/parser/. The set is exhaustive by construction, and
// tools/prumo-verify M9 derives the exit-point denominator from those same
// files, so a new parse function that never gets a tag shows up as unreached
// coverage rather than as silence.
pub const TAG_ENVELOPE: u8 = 0x01;
pub const TAG_INTENT: u8 = 0x02;
pub const TAG_GRANT: u8 = 0x03;
pub const TAG_SPAN: u8 = 0x04;
pub const TAG_EFFECT: u8 = 0x05;
pub const TAG_CLAIM: u8 = 0x06;
pub const TAG_REFUSAL: u8 = 0x07;
pub const TAG_CONTROL_GENESIS: u8 = 0x08;
pub const TAG_CONTROL: u8 = 0x09;
pub const TAG_HS_INIT: u8 = 0x0A;
pub const TAG_HS_RESP: u8 = 0x0B;
pub const TAG_COOKIE: u8 = 0x0C;
pub const TAG_DATA_HEADER: u8 = 0x0D;
pub const TAG_RELAY_ROUTE: u8 = 0x0E;
pub const TAG_RELAY_REG: u8 = 0x0F;
pub const TAG_FRAGMENT: u8 = 0x10;
pub const TAG_LOOKUP_REQ: u8 = 0x11;
pub const TAG_LOOKUP_RESP: u8 = 0x12;
pub const TAG_CERT: u8 = 0x13;
pub const TAG_BINDING: u8 = 0x14;
pub const TAG_SYNC_REQ: u8 = 0x15;
pub const TAG_SYNC_RESP: u8 = 0x16;

// Tags are contiguous from 1, so the count doubles as the round-robin modulus
// and as the seed-table length.
pub const TAG_COUNT: u8 = TAG_SYNC_RESP;

// Synthetic minimal-valid seeds for the structures test/vectors.json does not
// carry. Each is built from its SPEC field table: type discriminators set,
// fixed-width fields zero-filled, counts at the smallest legal value.
//
// A seed is a mutation starting point, never an oracle input. If a seed were
// wrong, both parsers would simply reject it and the comparison would still
// agree, so the cost of a bad seed is lost accept-path coverage, never a false
// verdict. The oracle's independence rests on tools/refparse.py, not on these.
const SEED_GENESIS = [_]u8{2} ++ [_]u8{0} ** 2 ++ [_]u8{0} ** 16 ++ [_]u8{1} ++ [_]u8{0} ** 32 ++ [_]u8{1}; // SPEC 6.1b, 53 bytes
const SEED_CONTROL = [_]u8{ 2, 1 } ++ [_]u8{0} ** 32 ++ [_]u8{0} ** 2; // SPEC 6.1c, 36 bytes
const SEED_HS_INIT = [_]u8{1} ++ [_]u8{0} ** 143; // SPEC 4.1a type 1, 144 bytes
const SEED_HS_RESP = [_]u8{2} ++ [_]u8{0} ** 91; // SPEC 4.1a type 2, 92 bytes
const SEED_COOKIE = [_]u8{3} ++ [_]u8{0} ** 51; // SPEC 4.1a type 3, 52 bytes
const SEED_DATA = [_]u8{4} ++ [_]u8{0} ** 31; // SPEC 4.1a type 4, 16 header + 16 tag
const SEED_RELAY_ROUTE = [_]u8{5} ++ [_]u8{0} ** 19; // SPEC 5.2a type 5, 20 bytes
const SEED_RELAY_REG = [_]u8{6} ++ [_]u8{0} ** 123; // SPEC 5.2a type 6, 124 bytes
const SEED_FRAGMENT = [_]u8{0} ** 8 ++ [_]u8{ 0, 0 } ++ [_]u8{ 0, 1 } ++ [_]u8{0} ** 16; // SPEC 4.5, index 0 of 1
const SEED_LOOKUP_REQ = [_]u8{2} ++ [_]u8{0} ** 16; // SPEC 5.1a, 17 bytes
const SEED_LOOKUP_RESP = [_]u8{2} ++ [_]u8{0} ** 16 ++ [_]u8{0} ++ [_]u8{0} ** 2; // SPEC 5.1a, no endpoints, empty cert
const SEED_SYNC_REQ = [_]u8{2} ++ [_]u8{0} ** 32 ++ [_]u8{0} ++ [_]u8{ 0, 64 }; // SPEC 6.4, no haves, cap 64
const SEED_SYNC_RESP = [_]u8{2} ++ [_]u8{0} ** 32 ++ [_]u8{0} ++ [_]u8{0}; // SPEC 6.4, no envelopes, not truncated

// The cert seed is synthesized rather than taken from test/vectors.json, whose
// certificate carries ONE CA signature. SPEC 3.1 makes the signature list
// canonical (ca_sig_count 1..4, keys ascending and pairwise distinct) so that
// duplicate-key quorum forgery is a parse failure rather than a policy check,
// and a one-signature seed can never put a mutation near that rule: the
// ordering exit was unreachable by construction. This seed carries two
// ascending keys, which is the smallest shape that can be mutated out of
// order. The parser verifies no signatures, so zero-filled ones cost nothing.
// The real certificate is still exercised: the binding seed embeds it.
const SEED_CERT = [_]u8{ 2, 0 } ++ // version, role_bits
    [_]u8{0} ** 32 ++ [_]u8{0} ** 32 ++ // sig_pubkey, kex_pubkey
    [_]u8{0} ** 8 ++ [_]u8{0} ** 8 ++ // not_before, not_after
    [_]u8{ 0, 0 } ++ [_]u8{0} ++ // name_len = 0, scope_count = 0
    [_]u8{2} ++ // ca_sig_count = 2
    [_]u8{0} ** 96 ++ // pair 0: key 0x00.., sig
    [_]u8{1} ++ [_]u8{0} ** 95; // pair 1: key 0x01.. (ascending), sig

// Boundary seeds for the two length-field exits that generic mutation
// rarely reaches. The 5 mutation operators act on arbitrary bytes, so
// hitting a specific big-endian length field at an exact boundary value
// (cert_len = 0, or payload = 1385) is low-probability: across 1M records
// both exits stayed unreached. These seeds sit AT the boundary so their
// mutation lineage explores the exit itself plus its neighborhood
// (cert_len 0,1,2,... ; payload 1383,1384,1385,1386), guaranteeing the
// exits are exercised every corpus run. Same precedent as SEED_CERT:
// synthesize a seed to reach an exit that uniform mutation cannot.

// Binding message with cert_len = 0 (u16be). Reaches bind_cert_len_zero;
// the regular binding seed embeds a real certificate, so its cert_len is
// large and zeroing both length bytes needs two coincidental saturates.
const SEED_BIND_CERT_ZERO = [_]u8{0} ** 2 ++ [_]u8{0} ** 64; // cert_len=0 + 64-byte sig

// Data header with a 1385-byte payload, one past the 1384 BE-TR-05 ceiling
// (16-byte transport header + 1385). Reaches data_payload_oversize; the
// regular data seed is 32 bytes and extend adds at most 8, so mutation can
// never cross the 1400-byte total that the exit requires.
const SEED_DATA_OVERSIZE = [_]u8{4} ++ [_]u8{0} ** 3 ++ // msg_type=4, reserved
    [_]u8{0} ** 4 ++ [_]u8{0} ** 8 ++ // receiver_index, counter
    [_]u8{0} ** 1385; // payload: 1385 > 1384 ceiling

// Cert boundary seed for cert_scope_oversize: scope_count = 9, one past
// MAX_SCOPE(8). Minimal valid prefix up to the scope_count byte; the parser
// rejects before reading scope_ids, so no trailing bytes are needed.
const SEED_CERT_GROUP_OVER = [_]u8{ 2, 0 } ++ // version, role_bits
    [_]u8{0} ** 32 ++ [_]u8{0} ** 32 ++ // sig_pubkey, kex_pubkey
    [_]u8{0} ** 8 ++ [_]u8{0} ** 8 ++ // not_before, not_after
    [_]u8{ 0, 0 } ++ // name_len = 0
    [_]u8{9}; // scope_count = 9 > MAX_SCOPE(8)

// Cert boundary seed for cert_ca_order: two CA keys in DESCENDING order
// (pair 0 = 0x01.., pair 1 = 0x00..). SPEC 3.1 requires strictly ascending
// keys; a mutation of the ascending SEED_CERT rarely inverts the byte-order
// relation between two 32-byte keys, so the exit stays unreached at small
// budgets. Both parsers agree this is Malformed.
const SEED_CERT_CA_ORDER = [_]u8{ 2, 0 } ++ // version, role_bits
    [_]u8{0} ** 32 ++ [_]u8{0} ** 32 ++ // sig_pubkey, kex_pubkey
    [_]u8{0} ** 8 ++ [_]u8{0} ** 8 ++ // not_before, not_after
    [_]u8{ 0, 0 } ++ [_]u8{0} ++ // name_len=0, scope_count=0
    [_]u8{2} ++ // ca_sig_count = 2
    [_]u8{1} ++ [_]u8{0} ** 95 ++ // pair 0: key 0x01.. (descending first), sig
    [_]u8{0} ** 96;

fn decodeHex(a: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try a.alloc(u8, hex.len / 2);
    var i: usize = 0;
    while (i < hex.len) : (i += 2) {
        out[i / 2] = try std.fmt.parseInt(u8, hex[i .. i + 2], 16);
    }
    return out;
}

// One seed per tag, indexed by tag - 1. An array rather than a struct so the
// round-robin and the coverage denominator share one length.
const Seeds = [TAG_COUNT][]const u8;

fn loadSeeds(a: std.mem.Allocator) !Seeds {
    var parsed = try std.json.parseFromSlice(std.json.Value, a, vectors_json, .{});
    defer parsed.deinit();
    const s = parsed.value.object.get("structures").?.object;
    const env_wire = try decodeHex(a, s.get("envelope_intent").?.object.get("wire_hex").?.string);
    const grant_wire = try decodeHex(a, s.get("grant").?.object.get("wire_hex").?.string);
    const span_wire = try decodeHex(a, s.get("span").?.object.get("wire_hex").?.string);
    const claim_wire = try decodeHex(a, s.get("claim").?.object.get("wire_hex").?.string);
    const eff_env_wire = try decodeHex(a, s.get("effect").?.object.get("wire_hex").?.string);
    const cert_wire = try decodeHex(a, s.get("cert").?.object.get("wire_hex").?.string);
    const refusal_wire = try decodeHex(a, s.get("refusal").?.object.get("wire_hex").?.string);
    const env = try parser.channel.parseEnvelope(env_wire);
    const eff_env = try parser.channel.parseEnvelope(eff_env_wire);

    // BindingMessage is u16 cert_len || cert || [64] sig (BE-TR-01 under the
    // SPEC 2.2 encoding rules). It is built here rather than declared above
    // because it embeds a real certificate, which makes the cert walk
    // reachable through the binding path too.
    const bind = try a.alloc(u8, 2 + cert_wire.len + 64);
    std.mem.writeInt(u16, bind[0..2], @intCast(cert_wire.len), .big);
    @memcpy(bind[2 .. 2 + cert_wire.len], cert_wire);
    @memset(bind[2 + cert_wire.len ..], 0);

    // The intent/effect seeds are the envelope bodies, which alias their wires.
    // The span/claim seeds are full standalone structures (claim carries no sig).
    var seeds: Seeds = undefined;
    seeds[TAG_ENVELOPE - 1] = env_wire;
    seeds[TAG_INTENT - 1] = env.body;
    seeds[TAG_GRANT - 1] = grant_wire;
    seeds[TAG_SPAN - 1] = span_wire;
    seeds[TAG_EFFECT - 1] = eff_env.body;
    seeds[TAG_CLAIM - 1] = claim_wire;
    seeds[TAG_REFUSAL - 1] = refusal_wire;
    seeds[TAG_CONTROL_GENESIS - 1] = &SEED_GENESIS;
    seeds[TAG_CONTROL - 1] = &SEED_CONTROL;
    seeds[TAG_HS_INIT - 1] = &SEED_HS_INIT;
    seeds[TAG_HS_RESP - 1] = &SEED_HS_RESP;
    seeds[TAG_COOKIE - 1] = &SEED_COOKIE;
    seeds[TAG_DATA_HEADER - 1] = &SEED_DATA;
    seeds[TAG_RELAY_ROUTE - 1] = &SEED_RELAY_ROUTE;
    seeds[TAG_RELAY_REG - 1] = &SEED_RELAY_REG;
    seeds[TAG_FRAGMENT - 1] = &SEED_FRAGMENT;
    seeds[TAG_LOOKUP_REQ - 1] = &SEED_LOOKUP_REQ;
    seeds[TAG_LOOKUP_RESP - 1] = &SEED_LOOKUP_RESP;
    seeds[TAG_CERT - 1] = &SEED_CERT;
    seeds[TAG_BINDING - 1] = bind;
    seeds[TAG_SYNC_REQ - 1] = &SEED_SYNC_REQ;
    seeds[TAG_SYNC_RESP - 1] = &SEED_SYNC_RESP;
    return seeds;
}

fn seedForTag(seeds: Seeds, tag: u8) []const u8 {
    if (tag == 0 or tag > TAG_COUNT) return seeds[TAG_ENVELOPE - 1];
    return seeds[tag - 1];
}

// Apply the 5 measured mutation operators (bit flip, byte overwrite, truncate,
// saturate, extend) to a copy of `seed` in `buf`; returns the populated slice.
// PRNG consumption order is part of the deterministic corpus contract.
//
// extend exists because the other four can only preserve or shorten a length.
// Every fixed-size structure's trailing-byte exit (SPEC 2.2: unknown trailing
// bytes are a parse failure) is reachable ONLY by a buffer longer than the
// structure, so without extend those exits were unreachable by construction:
// the coverage report read 62/72 with ten *_trailing exits unreached, none of
// which was a property of the parser.
fn mutate(rnd: std.Random, seed: []const u8, buf: []u8) []const u8 {
    const len = @min(seed.len, buf.len);
    @memcpy(buf[0..len], seed[0..len]);
    var k: u8 = 1 + rnd.uintLessThan(u8, 3);
    while (k > 0) : (k -= 1) {
        const idx = rnd.uintLessThan(usize, len);
        switch (rnd.uintLessThan(u8, 5)) {
            0 => buf[idx] ^= (@as(u8, 1) << rnd.int(u3)), // bit flip
            1 => buf[idx] = rnd.int(u8), // byte overwrite
            2 => return buf[0 .. rnd.uintLessThan(usize, len) + 1], // truncate
            3 => buf[idx] = if (buf[idx] == 0) 0xFF else 0, // saturate
            else => { // extend: append 1..8 random bytes, buffer permitting
                if (len >= buf.len) continue;
                const extra = @min(1 + rnd.uintLessThan(usize, 8), buf.len - len);
                rnd.bytes(buf[len .. len + extra]);
                return buf[0 .. len + extra];
            },
        }
    }
    return buf[0..len];
}

// Produce one chaos fuzz input in `buf`; returns the populated slice.
fn nextInput(rnd: std.Random, seeds: Seeds, buf: []u8) []const u8 {
    if (rnd.uintLessThan(u8, 100) < 40) {
        // Mutate a valid seed, drawn uniformly over every wired structure.
        return mutate(rnd, seeds[rnd.uintLessThan(u8, TAG_COUNT)], buf);
    }
    // Fully random bytes, bounded length.
    const len = rnd.uintLessThan(usize, MAX_INPUT) + 1;
    rnd.bytes(buf[0..len]);
    return buf[0..len];
}

// Produce one corpus input for a FIXED structure tag: the structure's own
// seed lineage (40%) plus fully random bytes (60%), same ratio as chaos.
fn nextInputForTag(rnd: std.Random, seeds: Seeds, tag: u8, buf: []u8) []const u8 {
    if (rnd.uintLessThan(u8, 100) < 40) {
        return mutate(rnd, seedForTag(seeds, tag), buf);
    }
    const len = rnd.uintLessThan(usize, MAX_INPUT) + 1;
    rnd.bytes(buf[0..len]);
    return buf[0..len];
}

// Route one corpus record to its tagged parse entry point (D-056 diff mode).
// Unknown tags reject: the reference parser does the same (unknown_tag).
fn parseByTag(tag: u8, rec: []const u8) bool {
    switch (tag) {
        TAG_ENVELOPE => _ = parser.channel.parseEnvelope(rec) catch return false,
        TAG_INTENT => _ = parser.channel.parseIntent(rec) catch return false,
        TAG_GRANT => _ = parser.channel.parseGrant(rec) catch return false,
        TAG_SPAN => _ = parser.channel.parseSpan(rec) catch return false,
        TAG_EFFECT => _ = parser.channel.parseEffect(rec) catch return false,
        TAG_CLAIM => _ = parser.channel.parseClaim(rec) catch return false,
        TAG_REFUSAL => _ = parser.channel.parseRefusal(rec) catch return false,
        TAG_CONTROL_GENESIS => _ = parser.channel.parseControlGenesis(rec) catch return false,
        TAG_CONTROL => _ = parser.channel.parseControl(rec) catch return false,
        TAG_HS_INIT => _ = parser.parseHandshakeInitiation(rec) catch return false,
        TAG_HS_RESP => _ = parser.parseHandshakeResponse(rec) catch return false,
        TAG_COOKIE => _ = parser.parseCookieReply(rec) catch return false,
        TAG_DATA_HEADER => _ = parser.parseDataPacketHeader(rec) catch return false,
        TAG_RELAY_ROUTE => _ = relay.parseRelayRoute(rec) catch return false,
        TAG_RELAY_REG => _ = relay.parseRelayRegistration(rec) catch return false,
        TAG_FRAGMENT => _ = parser.session.parseFragmentHeader(rec) catch return false,
        TAG_LOOKUP_REQ => _ = parser.session.parseLookupRequest(rec) catch return false,
        TAG_LOOKUP_RESP => _ = parser.session.parseLookupResponse(rec) catch return false,
        TAG_CERT => _ = parser.session.parseCert(rec) catch return false,
        TAG_BINDING => _ = parser.session.parseBindingMessage(rec) catch return false,
        TAG_SYNC_REQ => _ = parser.sync.parseSyncRequest(rec) catch return false,
        TAG_SYNC_RESP => _ = parser.sync.parseSyncResponse(rec) catch return false,
        else => return false,
    }
    return true;
}

pub fn main(init: std.process.Init) !void {
    if (comptime opts.fuzz_mode == .corpus) return runCorpus(init);
    if (comptime opts.fuzz_mode == .diff) return runDiff(init);
    return runChaos();
}

// First CLI argument, if any (portable across targets).
fn arg1(init: std.process.Init, a: std.mem.Allocator) !?[:0]const u8 {
    var it = try std.process.Args.Iterator.initAllocator(init.minimal.args, a);
    defer it.deinit();
    _ = it.next(); // program name
    return it.next();
}

fn runChaos() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Budget comes from build_options (-Dfuzz-budget). The default is the full
    // ~1h run (7.3B inputs at ~2.0M inputs/s ReleaseSafe); the coverage step
    // shortens it via -Dfuzz-budget. The harness depends on no unstable
    // clock API: wall-clock is measured externally. A ReleaseSafe panic here is
    // a real parser bounds gap; a clean exit over N inputs means N inputs
    // parsed with no out-of-bounds access.
    const budget: u64 = opts.fuzz_budget;

    const seeds = try loadSeeds(a);

    var prng = std.Random.DefaultPrng.init(opts.fuzz_seed);
    const rnd = prng.random();
    var buf: [MAX_INPUT]u8 = undefined;
    var iter: u64 = 0;

    while (iter < budget) {
        const input = nextInput(rnd, seeds, &buf);
        // Every input goes through every entry point: BE-WIRE-02 totality is a
        // claim about all of them, so a bounds gap in any one is in scope.
        var tag: u8 = 1;
        while (tag <= TAG_COUNT) : (tag += 1) _ = parseByTag(tag, input);
        iter += 1;
        if (iter % 250_000_000 == 0) std.debug.print("fuzz progress: {d}M / {d}M\n", .{ iter / 1_000_000, budget / 1_000_000 });
    }
    std.debug.print("FUZZ DONE: {d} inputs ({d} parser calls), 0 panics\n", .{ iter, iter * TAG_COUNT });

    // Coverage report (SPEC section 11.6 / LANGUAGE.md O2). Only emitted when
    // built with -Dcoverage, which sets coverage.ENABLED comptime true. Manual
    // instrumentation IS the measurement: the toolchain's -ffuzz coverage has
    // no script-readable output, so hit_count is read directly here.
    printCoverageReport();
}

// SPEC section 11.6 receipt shape: exit points reached over the denominator,
// the unreached list, and the corpus description. Shared by chaos and diff
// modes; comptime-off unless built with -Dcoverage.
fn printCoverageReport() void {
    if (!coverage.ENABLED) return;
    var reached: usize = 0;
    for (0..coverage.COUNT) |i| {
        if (coverage.hit_count[i] > 0) reached += 1;
    }
    std.debug.print("COVERAGE: {d}/{d} exit points reached\n", .{ reached, coverage.COUNT });
    if (reached == coverage.COUNT) {
        std.debug.print("COVERAGE: no unreached exit points\n", .{});
    } else {
        std.debug.print("COVERAGE: unreached exit points:\n", .{});
        for (0..coverage.COUNT) |i| {
            if (coverage.hit_count[i] == 0) {
                std.debug.print("  - {s}\n", .{@tagName(@as(coverage.Branch, @enumFromInt(i)))});
            }
        }
    }
    std.debug.print("COVERAGE: corpus = 22 seeds, one per parse entry point (envelope, intent, grant, span, effect, claim, refusal from test/vectors.json; cert synthesized with a two-signature CA list; binding built from the real vectors cert; genesis, control, handshake initiation/response, cookie reply, data header, relay route/registration, fragment header, lookup request/response, sync request/response synthesized from their SPEC field tables), 5 mutation operators (bit flip, byte overwrite, truncate, saturate, extend), 40% mutated-seed / 60% fully-random, 4096-byte input cap; plus 4 boundary seeds (bind cert_len=0, data payload 1385, cert scope_count 9, cert descending CA keys) each emitted verbatim then as a 16-record mutated lineage to reach the length/ordering-field exits generic mutation cannot\n", .{});
}

// Corpus-emit mode (D-056 part two). Writes tagged records round-robin over
// the six structures: record i carries tag 1 + (i % 6). Deterministic for a
// fixed PRNG seed and budget. Usage:
//   zig build fuzz-corpus [-- OUT_PATH]          (default fuzz_corpus.bin)
fn runCorpus(init: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const out_path: []const u8 = (try arg1(init, a)) orelse "fuzz_corpus.bin";
    const budget: u64 = opts.corpus_budget;

    const seeds = try loadSeeds(a);

    var prng = std.Random.DefaultPrng.init(opts.fuzz_seed);
    const rnd = prng.random();
    var buf: [MAX_INPUT]u8 = undefined;

    const io: std.Io = init.io;
    const dir = std.Io.Dir.cwd();
    const file = try dir.createFile(io, out_path, .{});
    defer file.close(io);
    var wbuf: [64 * 1024]u8 = undefined;
    var writer = file.writer(io, &wbuf);

    // Boundary-seed phase: guarantee the two length-field exits generic
    // mutation rarely reaches (bind_cert_len_zero, data_payload_oversize)
    // are exercised every corpus. Each boundary seed is emitted verbatim
    // (certain hit of the target exit) plus a 16-record mutated lineage
    // (neighborhood exploration), on the same PRNG stream and mutate().
    const BSEEDS = [_]struct { tag: u8, bytes: []const u8 }{
        .{ .tag = TAG_BINDING, .bytes = &SEED_BIND_CERT_ZERO },
        .{ .tag = TAG_DATA_HEADER, .bytes = &SEED_DATA_OVERSIZE },
        .{ .tag = TAG_CERT, .bytes = &SEED_CERT_GROUP_OVER },
        .{ .tag = TAG_CERT, .bytes = &SEED_CERT_CA_ORDER },
    };
    var bheader: [3]u8 = undefined;
    for (BSEEDS) |bs| {
        bheader[0] = bs.tag;
        std.mem.writeInt(u16, bheader[1..3], @intCast(bs.bytes.len), .big);
        try writer.interface.writeAll(&bheader);
        try writer.interface.writeAll(bs.bytes);
        var mj: u8 = 0;
        while (mj < 16) : (mj += 1) {
            const m = mutate(rnd, bs.bytes, &buf);
            bheader[0] = bs.tag;
            std.mem.writeInt(u16, bheader[1..3], @intCast(m.len), .big);
            try writer.interface.writeAll(&bheader);
            try writer.interface.writeAll(m);
        }
    }
    var header: [3]u8 = undefined;
    var iter: u64 = 0;
    while (iter < budget) : (iter += 1) {
        const tag: u8 = @intCast(1 + iter % TAG_COUNT);
        const input = nextInputForTag(rnd, seeds, tag, &buf);
        header[0] = tag;
        std.mem.writeInt(u16, header[1..3], @intCast(input.len), .big);
        try writer.interface.writeAll(&header);
        try writer.interface.writeAll(input);
    }
    try writer.flush();
    const boundary_records: u64 = @as(u64, BSEEDS.len) * 17; // 1 verbatim + 16-record lineage each
    std.debug.print("CORPUS EMITTED: {d} records ({d} boundary + {d} random) to {s} (seed 0x{x})\n", .{ iter + boundary_records, boundary_records, iter, out_path, opts.fuzz_seed });
}

// Diff-replay mode (D-056 part three). Reads the corpus file, routes each
// record to its tagged parse entry point, prints one verdict line per record
// and a summary; the verdict stream matches the record count exactly. A
// framing defect (truncated record header or body) fails the run with a
// non-zero exit. Usage:
//   zig build fuzz-diff [-- CORPUS_PATH]         (default fuzz_corpus.bin)
fn runDiff(init: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const corpus_path: []const u8 = (try arg1(init, a)) orelse "fuzz_corpus.bin";
    const io: std.Io = init.io;
    const dir = std.Io.Dir.cwd();
    const data = try dir.readFileAlloc(io, corpus_path, a, .limited64(4 * 1024 * 1024 * 1024));

    // Every record is at least 3 framing bytes, so this bounds the count.
    const cap = data.len / 3 + 1;
    const tags = try a.alloc(u8, cap);
    const verdicts = try a.alloc(bool, cap);
    const n = replayVerdicts(data, tags, verdicts) catch |err| {
        std.debug.print("CORPUS {s} during replay\n", .{@errorName(err)});
        std.process.exit(1);
    };

    var obuf: [64 * 1024]u8 = undefined;
    var out = std.Io.File.stdout().writer(io, &obuf);
    var accepted: u64 = 0;
    var rejected: u64 = 0;
    for (0..n) |i| {
        if (verdicts[i]) accepted += 1 else rejected += 1;
        try out.interface.print("REC {d} TAG 0x{x:0>2} {s}\n", .{ i, tags[i], if (verdicts[i]) "A" else "R" });
    }
    try out.flush();
    std.debug.print("DIFF DONE: {d} records, {d} accepted, {d} rejected\n", .{ n, accepted, rejected });
    // SPEC section 11.6 receipt for the differential run (built with
    // -Dcoverage): exit points reached plus the corpus description.
    printCoverageReport();
}

pub const ReplayError = error{ FramingTruncated, RecordTruncated };

// Walk a corpus file (D-056 framing: u8 tag || u16 BE len || bytes), route
// every record to its tagged parse entry point, and record one verdict per
// record (true = accept). Returns the record count. `tags` and `verdicts`
// must hold at least data.len/3 + 1 slots. This is the single replay walk:
// diff mode prints from it, and the BE_SURF_04 binding test exercises it.
pub fn replayVerdicts(data: []const u8, tags: []u8, verdicts: []bool) ReplayError!usize {
    var pos: usize = 0;
    var idx: usize = 0;
    while (pos < data.len) {
        if (data.len - pos < 3) return error.FramingTruncated;
        const tag = data[pos];
        const len = std.mem.readInt(u16, data[pos + 1 ..][0..2], .big);
        pos += 3;
        if (data.len - pos < len) return error.RecordTruncated;
        tags[idx] = tag;
        verdicts[idx] = parseByTag(tag, data[pos .. pos + len]);
        pos += len;
        idx += 1;
    }
    return idx;
}

// v1 differential verdict (D-056 part three): positional comparison of two
// equal-length verdict streams, production side against reference side. Any
// mismatch is a divergence. Length mismatch is a framing/infrastructure
// failure handled by the caller, not a verdict divergence.
pub fn countDivergences(production: []const bool, reference: []const bool) usize {
    std.debug.assert(production.len == reference.len);
    var n: usize = 0;
    for (0..production.len) |i| {
        if (production[i] != reference[i]) n += 1;
    }
    return n;
}
