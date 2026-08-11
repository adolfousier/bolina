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
//   six wired parse entry points for a wall-clock budget. Every array read in
//   the parser routes through Cursor.need(), so a ReleaseSafe panic here is a
//   genuine bounds-check gap (an out-of-bounds read), not a logic error. A
//   clean exit over N inputs means N inputs parsed with no out-of-bounds
//   access.
//
// - corpus: writes a deterministic corpus file of tagged records, one record
//   per entry: u8 structure_tag, u16 big-endian length, then the bytes
//   (D-056 corpus protocol). Per-structure streams: each structure is fuzzed
//   against its own seed lineage plus random bytes, same PRNG seed and same 4
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
const vectors_json = @import("vectors").json;
const coverage = @import("coverage.zig");
const opts = @import("build_options");

const MAX_INPUT: usize = 4096;

// Corpus structure tags, shared verbatim with tools/refparse.py (D-056).
pub const TAG_ENVELOPE: u8 = 0x01;
pub const TAG_INTENT: u8 = 0x02;
pub const TAG_GRANT: u8 = 0x03;
pub const TAG_SPAN: u8 = 0x04;
pub const TAG_EFFECT: u8 = 0x05;
pub const TAG_CLAIM: u8 = 0x06;

fn decodeHex(a: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try a.alloc(u8, hex.len / 2);
    var i: usize = 0;
    while (i < hex.len) : (i += 2) {
        out[i / 2] = try std.fmt.parseInt(u8, hex[i .. i + 2], 16);
    }
    return out;
}

const Seeds = struct {
    env: []const u8,
    grant: []const u8,
    intent: []const u8,
    span: []const u8,
    effect: []const u8,
    claim: []const u8,
};

fn loadSeeds(a: std.mem.Allocator) !Seeds {
    var parsed = try std.json.parseFromSlice(std.json.Value, a, vectors_json, .{});
    defer parsed.deinit();
    const s = parsed.value.object.get("structures").?.object;
    const env_wire = try decodeHex(a, s.get("envelope_intent").?.object.get("wire_hex").?.string);
    const grant_wire = try decodeHex(a, s.get("grant").?.object.get("wire_hex").?.string);
    const span_wire = try decodeHex(a, s.get("span").?.object.get("wire_hex").?.string);
    const claim_wire = try decodeHex(a, s.get("claim").?.object.get("wire_hex").?.string);
    const eff_env_wire = try decodeHex(a, s.get("effect").?.object.get("wire_hex").?.string);
    const env = try parser.channel.parseEnvelope(env_wire);
    const eff_env = try parser.channel.parseEnvelope(eff_env_wire);
    // The intent/effect seeds are the envelope bodies, which alias their wires.
    // The span/claim seeds are full standalone structures (claim carries no sig).
    return .{
        .env = env_wire,
        .grant = grant_wire,
        .intent = env.body,
        .span = span_wire,
        .effect = eff_env.body,
        .claim = claim_wire,
    };
}

fn seedForTag(seeds: Seeds, tag: u8) []const u8 {
    return switch (tag) {
        TAG_ENVELOPE => seeds.env,
        TAG_INTENT => seeds.intent,
        TAG_GRANT => seeds.grant,
        TAG_SPAN => seeds.span,
        TAG_EFFECT => seeds.effect,
        else => seeds.claim,
    };
}

// Apply the 4 measured mutation operators (bit flip, byte overwrite,
// truncate, saturate) to a copy of `seed` in `buf`; returns the populated
// slice. PRNG consumption order is part of the deterministic corpus contract.
fn mutate(rnd: std.Random, seed: []const u8, buf: []u8) []const u8 {
    const len = @min(seed.len, buf.len);
    @memcpy(buf[0..len], seed[0..len]);
    var k: u8 = 1 + rnd.uintLessThan(u8, 3);
    while (k > 0) : (k -= 1) {
        const idx = rnd.uintLessThan(usize, len);
        switch (rnd.uintLessThan(u8, 4)) {
            0 => buf[idx] ^= (@as(u8, 1) << rnd.int(u3)), // bit flip
            1 => buf[idx] = rnd.int(u8), // byte overwrite
            2 => return buf[0 .. rnd.uintLessThan(usize, len) + 1], // truncate
            else => buf[idx] = if (buf[idx] == 0) 0xFF else 0, // saturate
        }
    }
    return buf[0..len];
}

// Produce one chaos fuzz input in `buf`; returns the populated slice.
fn nextInput(rnd: std.Random, seeds: Seeds, buf: []u8) []const u8 {
    if (rnd.uintLessThan(u8, 100) < 40) {
        // Mutate a valid seed.
        const seed = switch (rnd.uintLessThan(u8, 6)) {
            0 => seeds.env,
            1 => seeds.grant,
            2 => seeds.intent,
            3 => seeds.span,
            4 => seeds.effect,
            else => seeds.claim,
        };
        return mutate(rnd, seed, buf);
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

    var prng = std.Random.DefaultPrng.init(0x626f6c696e61); // "bolina"
    const rnd = prng.random();
    var buf: [MAX_INPUT]u8 = undefined;
    var iter: u64 = 0;

    while (iter < budget) {
        const input = nextInput(rnd, seeds, &buf);
        _ = parser.channel.parseEnvelope(input) catch {};
        _ = parser.channel.parseGrant(input) catch {};
        _ = parser.channel.parseIntent(input) catch {};
        _ = parser.channel.parseSpan(input) catch {};
        _ = parser.channel.parseEffect(input) catch {};
        _ = parser.channel.parseClaim(input) catch {};
        iter += 1;
        if (iter % 250_000_000 == 0) std.debug.print("fuzz progress: {d}M / {d}M\n", .{ iter / 1_000_000, budget / 1_000_000 });
    }
    std.debug.print("FUZZ DONE: {d} inputs ({d} parser calls), 0 panics\n", .{ iter, iter * 6 });

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
    std.debug.print("COVERAGE: corpus = 6 seeds (envelope, grant, intent, span, effect, claim from test/vectors.json), 4 mutation operators (bit flip, byte overwrite, truncate, saturate), 40% mutated-seed / 60% fully-random, 4096-byte input cap\n", .{});
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

    var prng = std.Random.DefaultPrng.init(0x626f6c696e61); // "bolina"
    const rnd = prng.random();
    var buf: [MAX_INPUT]u8 = undefined;

    const io: std.Io = init.io;
    const dir = std.Io.Dir.cwd();
    const file = try dir.createFile(io, out_path, .{});
    defer file.close(io);
    var wbuf: [64 * 1024]u8 = undefined;
    var writer = file.writer(io, &wbuf);

    var header: [3]u8 = undefined;
    var iter: u64 = 0;
    while (iter < budget) : (iter += 1) {
        const tag: u8 = @intCast(1 + iter % 6);
        const input = nextInputForTag(rnd, seeds, tag, &buf);
        header[0] = tag;
        std.mem.writeInt(u16, header[1..3], @intCast(input.len), .big);
        try writer.interface.writeAll(&header);
        try writer.interface.writeAll(input);
    }
    try writer.flush();
    std.debug.print("CORPUS EMITTED: {d} records to {s} (seed 0x626f6c696e61)\n", .{ iter, out_path });
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
    const data = try dir.readFileAlloc(io, corpus_path, a, .limited64(512 * 1024 * 1024));

    var obuf: [64 * 1024]u8 = undefined;
    var out = std.Io.File.stdout().writer(io, &obuf);
    var pos: usize = 0;
    var idx: u64 = 0;
    var accepted: u64 = 0;
    var rejected: u64 = 0;
    while (pos < data.len) {
        if (data.len - pos < 3) {
            try out.flush();
            std.debug.print("CORPUS FRAMING TRUNCATED at record {d}\n", .{idx});
            std.process.exit(1);
        }
        const tag = data[pos];
        const len = std.mem.readInt(u16, data[pos + 1 ..][0..2], .big);
        pos += 3;
        if (data.len - pos < len) {
            try out.flush();
            std.debug.print("CORPUS RECORD TRUNCATED at record {d}\n", .{idx});
            std.process.exit(1);
        }
        const rec = data[pos .. pos + len];
        pos += len;
        const ok = parseByTag(tag, rec);
        if (ok) accepted += 1 else rejected += 1;
        try out.interface.print("REC {d} TAG 0x{x:0>2} {s}\n", .{ idx, tag, if (ok) "A" else "R" });
        idx += 1;
    }
    try out.flush();
    std.debug.print("DIFF DONE: {d} records, {d} accepted, {d} rejected\n", .{ idx, accepted, rejected });
    // SPEC section 11.6 receipt for the differential run (built with
    // -Dcoverage): exit points reached plus the corpus description.
    printCoverageReport();
}
