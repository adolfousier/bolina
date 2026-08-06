// fuzz.zig
//
// Chaos fuzzer for the parser (BE-WIRE-02, LANGUAGE.md O2). Built and run on
// demand via `zig build fuzz`; main.zig never imports it, so it is not part
// of the shipped binary.
//
// Feeds mutated-valid and fully-random byte streams to parseEnvelope,
// parseGrant and parseIntent for a wall-clock budget. Every array read in the
// parser routes through Cursor.need(), so a ReleaseSafe panic here is a genuine
// bounds-check gap (an out-of-bounds read), not a logic error. A clean exit
// over N inputs means N inputs parsed with no out-of-bounds access.

const std = @import("std");
const parser = @import("parser.zig");
const vectors_json = @import("vectors").json;
const coverage = @import("coverage.zig");
const opts = @import("build_options");

const MAX_INPUT: usize = 4096;

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
};

fn loadSeeds(a: std.mem.Allocator) !Seeds {
    var parsed = try std.json.parseFromSlice(std.json.Value, a, vectors_json, .{});
    defer parsed.deinit();
    const s = parsed.value.object.get("structures").?.object;
    const env_wire = try decodeHex(a, s.get("envelope_intent").?.object.get("wire_hex").?.string);
    const grant_wire = try decodeHex(a, s.get("grant").?.object.get("wire_hex").?.string);
    const env = try parser.parseEnvelope(env_wire);
    // The intent seed is the envelope body, which already aliases env_wire.
    return .{ .env = env_wire, .grant = grant_wire, .intent = env.body };
}

// Produce one fuzz input in `buf`; returns the populated slice.
fn nextInput(rnd: std.Random, seeds: Seeds, buf: []u8) []const u8 {
    if (rnd.uintLessThan(u8, 100) < 40) {
        // Mutate a valid seed.
        const seed = switch (rnd.uintLessThan(u8, 3)) {
            0 => seeds.env,
            1 => seeds.grant,
            else => seeds.intent,
        };
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
    // Fully random bytes, bounded length.
    const len = rnd.uintLessThan(usize, MAX_INPUT) + 1;
    rnd.bytes(buf[0..len]);
    return buf[0..len];
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Budget comes from build_options (-Dfuzz-budget). The default is the full
    // ~1h run (7.3B inputs at ~2.0M inputs/s ReleaseSafe); the coverage step
    // shortens it via -Dfuzz-budget=4000000. The harness depends on no unstable
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
        _ = parser.parseEnvelope(input) catch {};
        _ = parser.parseGrant(input) catch {};
        _ = parser.parseIntent(input) catch {};
        iter += 1;
        if (iter % 250_000_000 == 0) std.debug.print("fuzz progress: {d}M / {d}M\n", .{ iter / 1_000_000, budget / 1_000_000 });
    }
    std.debug.print("FUZZ DONE: {d} inputs ({d} parser calls), 0 panics\n", .{ iter, iter * 3 });

    // Coverage report (SPEC section 11.6 / LANGUAGE.md O2). Only emitted when
    // built with -Dcoverage, which sets coverage.ENABLED comptime true. Manual
    // instrumentation IS the measurement: the toolchain's -ffuzz coverage has
    // no script-readable output, so hit_count is read directly here.
    if (coverage.ENABLED) {
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
        std.debug.print("COVERAGE: corpus = 3 seeds (envelope, grant, intent from test/vectors.json), 4 mutation operators (bit flip, byte overwrite, truncate, saturate), 40% mutated-seed / 60% fully-random, 4096-byte input cap\n", .{});
    }
}
