// coverage.zig
//
// Hand-instrumented branch coverage for the parser (LANGUAGE.md O2, SPEC.md
// section 11.6). The Zig toolchain's -ffuzz coverage is consumed only by a
// WebSocket UI and emits no script-readable report (see the decision note in
// research/coverage-mechanism-decision.md), so coverage here is measured
// directly: every rejection point and accepted return in parser.zig calls
// hit(), and the fuzz harness prints how many enumerated branches were reached
// at least once, plus the unreached list.
//
// Compile-time gated. ENABLED is true only in the `zig build coverage` run; in
// the test and shipped builds it is comptime false, so each hit() call is
// dead-code eliminated and carries no state or cost.

const std = @import("std");
const opts = @import("build_options");

pub const ENABLED: bool = opts.coverage_enabled;

// One member per distinct branch in parser.zig: the shared bounds check, every
// rejection point, and every accepted return. Reach is "hit at least once".
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

pub inline fn hit(b: Branch) void {
    if (!ENABLED) return;
    hit_count[@intFromEnum(b)] += 1;
}
