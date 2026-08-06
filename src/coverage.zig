// coverage.zig
//
// Hand-instrumented exit-point coverage for the parser (LANGUAGE.md O2,
// SPEC.md section 11.6). The Zig toolchain's -ffuzz coverage is consumed only
// by a WebSocket UI and emits no script-readable report (see the decision note
// in research/coverage-mechanism-decision.md), so coverage here is measured
// directly.
//
// Every rejection in parser.zig returns through reject() and every accepted
// return goes through accept(); parser.zig contains no raw `return error.` at
// all, zero exceptions (gate M9 in tools/prumo-verify). The wrappers are also
// the denominator source: M9 counts the reject/accept call sites in
// parser.zig at run time and fails unless the Branch enum below matches them
// one for one. The denominator is the code, not this file: a new exit point
// fails the gate until the enum grows, and a dead enum member fails it the
// other way (CONTRIBUTING.md section 2, gate-design law).
//
// Measurement unit, stated precisely: EXIT POINTS, not branches. One counter
// marks one exit site; a site shared by several readers (cursor_truncated is
// reached through u8r, u16be, u32be, u64be and take) reports reached when ANY
// path into it was taken. "N of M reached" therefore never claims more than
// exit-point reach (LANGUAGE.md section 4.1).
//
// Compile-time gated. ENABLED is true only in the `zig build coverage` run;
// in the test and shipped builds it is comptime false, so the counter logic
// inside reject()/accept() is dead-code eliminated and the wrappers compile
// to nothing. No unconditional increment on the 7.3B-input fuzz path.

const opts = @import("build_options");
const parser = @import("parser.zig");

pub const ENABLED: bool = opts.coverage_enabled;

// One member per exit point in parser.zig: the shared truncation rejection,
// every other rejection site, and every accepted return. Reach is "hit at
// least once".
pub const Branch = enum {
    cursor_truncated, // Cursor.need: a field read ran past the buffer end
    env_parent_oversize, // parseEnvelope: parent_count > MAX_PARENTS
    env_body_oversize, // parseEnvelope: body_len > MAX_BODY
    env_trailing, // parseEnvelope: bytes after the single envelope
    env_accepted, // parseEnvelope: returned a valid Envelope
    field16_oversize, // Cursor.field16: u16 length > declared max
    field32_oversize, // Cursor.field32: u32 length > declared max
    intent_trailing, // parseIntent: bytes after the single intent
    intent_accepted, // parseIntent: returned a valid Intent
    grant_trailing, // parseGrant: bytes after the single grant
    grant_accepted, // parseGrant: returned a valid Grant
};

pub const COUNT: usize = @typeInfo(Branch).@"enum".fields.len;
pub var hit_count: [COUNT]u64 = [_]u64{0} ** COUNT;

fn hit(b: Branch) void {
    if (!ENABLED) return;
    hit_count[@intFromEnum(b)] += 1;
}

// reject: the ONLY path by which parser.zig returns an error. The tag names
// the exit point (the coverage unit); the switch maps it to the error value
// and is total over the enum, so a tag added without a mapping is a compile
// error. The accepted tags map to @compileError: the tag is comptime-known at
// every call site, so the other arms are pruned and this fires only on
// genuine misuse, at compile time.
pub inline fn reject(comptime tag: Branch) parser.ParseError {
    hit(tag);
    return switch (tag) {
        .cursor_truncated => error.Truncated,
        .env_parent_oversize, .env_body_oversize, .field16_oversize, .field32_oversize => error.Oversize,
        .env_trailing, .intent_trailing, .grant_trailing => error.TrailingBytes,
        .env_accepted, .intent_accepted, .grant_accepted => @compileError("accepted exit points do not reject; use accept()"),
    };
}

// accept: marks an accepted return. Void on purpose: the parser returns its
// struct literal itself, so no parsed value type leaks into coverage.zig.
pub inline fn accept(comptime tag: Branch) void {
    hit(tag);
}
