// evidence_test_helpers.zig
//
// Shared fixtures and hook stubs for the attestation tests. Extracted from
// evidence_test.zig so that file stays under the CODE.md 500-line ceiling
// without duplicating the Ed25519 span-building setup (CODE.md: shared test
// helpers live in one place, never copy-pasted). This module has no test
// blocks of its own; it is compiled transitively because evidence_test.zig
// imports it.
//
// Everything here is deterministic: the executor keypair and every span field
// derive from fixed seeds (tools/gen-vectors.zig discipline), so a tampered
// signature is the only way a span can fail to verify, which is exactly what
// BE-EVID-01's sig path needs to exercise.

const std = @import("std");
const parser = @import("parser.zig");
const evidence = @import("evidence.zig");

pub const Ed = std.crypto.sign.Ed25519;

// Deterministic seed helpers. seedFrom(prefix) is byte i = prefix +% i, the
// same scheme the vector generator uses, so the executor identity here is the
// generator's executor identity.

pub fn seedFrom(prefix: u8) [32]u8 {
    var s: [32]u8 = undefined;
    for (&s, 0..) |*b, i| b.* = prefix +% @as(u8, @intCast(i));
    return s;
}

pub fn executorKeypair() Ed.KeyPair {
    return Ed.KeyPair.generateDeterministic(seedFrom(0x61)) catch unreachable;
}

pub fn idOf(prefix: u8) [16]u8 {
    var s: [16]u8 = undefined;
    for (&s, 0..) |*b, i| b.* = prefix +% @as(u8, @intCast(i));
    return s;
}

pub const SUBJECT = "bol:res/deploy-7";
pub const DIGEST = seedFrom(0x77);
pub const ENV = seedFrom(0xee); // stand-in for the claim's enclosing Utterance hash
pub const T_OBS: u64 = 1700000030000;

// Build a signed Span wire: tbs = version..executor, then Ed25519 over
// (DOMAIN_SPAN || tbs), matching signTagged in the generator and the streaming
// verifier in verify.zig. The bytes live in the arena the caller owns, so the
// returned Span's slices stay valid for the test (BE-WIRE-01, zero-heap).
pub fn spanWire(
    a: std.mem.Allocator,
    span_id: [16]u8,
    trace_id: [16]u8,
    resource_id: []const u8,
    method_id: u8,
    volatility: u8,
    origin: [32]u8,
    kp: Ed.KeyPair,
) ![]u8 {
    // Build the to-be-signed bytes (SPEC 7.1 layout) into a fixed stack buffer
    // with a cursor: zero-heap build, parser style. All field sizes are fixed
    // except resource_id (u16 length-prefixed; test fixtures stay small).
    var tbs: [400]u8 = undefined;
    var n: usize = 0;
    tbs[n] = 2; // version = 2
    n += 1;
    @memcpy(tbs[n..][0..16], &span_id);
    n += 16;
    @memcpy(tbs[n..][0..16], &trace_id);
    n += 16;
    var rl: [2]u8 = undefined;
    std.mem.writeInt(u16, &rl, @intCast(resource_id.len), .big);
    @memcpy(tbs[n..][0..2], &rl);
    n += 2;
    @memcpy(tbs[n..][0..resource_id.len], resource_id);
    n += resource_id.len;
    tbs[n] = method_id;
    n += 1;
    tbs[n] = volatility;
    n += 1;
    @memcpy(tbs[n..][0..32], &origin);
    n += 32;
    var ob: [8]u8 = undefined;
    std.mem.writeInt(u64, &ob, T_OBS, .big);
    @memcpy(tbs[n..][0..8], &ob);
    n += 8;
    @memcpy(tbs[n..][0..32], &DIGEST);
    n += 32;
    const pub_bytes = Ed.PublicKey.toBytes(kp.public_key);
    @memcpy(tbs[n..][0..32], &pub_bytes);
    n += 32;

    // Ed25519 over (DOMAIN_SPAN || tbs), matching signTagged (gen-vectors)
    // and the streaming verifier in verify.zig.
    var msg: [1 + 400]u8 = undefined;
    msg[0] = parser.channel.DOMAIN_SPAN;
    @memcpy(msg[1..][0..n], tbs[0..n]);
    const sig = try Ed.KeyPair.sign(kp, msg[0 .. 1 + n], null);
    const sig_bytes = Ed.Signature.toBytes(sig);

    const wire = try a.alloc(u8, n + parser.channel.LEN_SIG);
    @memcpy(wire[0..n], tbs[0..n]);
    @memcpy(wire[n..][0..parser.channel.LEN_SIG], &sig_bytes);
    return wire;
}

pub fn buildClaim(
    a: std.mem.Allocator,
    text: []const u8,
    subject: []const u8,
    confidence_q8: u8,
    span_ids: []const [16]u8,
) !parser.channel.Claim {
    const ids = try a.alloc(u8, span_ids.len * parser.channel.LEN_SPAN_REF);
    for (span_ids, 0..) |id, i| @memcpy(ids[i * parser.channel.LEN_SPAN_REF ..][0..parser.channel.LEN_SPAN_REF], &id);
    return .{
        .text = text,
        .subject = subject,
        .confidence_q8 = confidence_q8,
        .span_count = @intCast(span_ids.len),
        .span_ids = ids,
    };
}

// ---------------------------------------------------------------------------
// Hook stubs for ResolveContext. Function pointers cannot capture state, so
// each behavior is its own named function. The BE-EVID-09a/09b mixed cases
// branch on a fixed byte of the origin hash instead of shared mutable state:
// Zig runs test blocks on parallel threads, and two tests mutating one global
// is a data race. The origins used there are seedFrom(0xa1/0xa2/0xa3), whose
// byte 0 equals the prefix, so the hook is a pure function of the origin bytes.
// ---------------------------------------------------------------------------

pub fn roleExecutor(pubkey: []const u8) evidence.Role {
    _ = pubkey;
    return .executor;
}

pub fn roleNone(pubkey: []const u8) evidence.Role {
    _ = pubkey;
    return .none;
}

pub fn originEffect(o: []const u8) evidence.OriginState {
    _ = o;
    return .effect;
}

pub fn originAbsent(o: []const u8) evidence.OriginState {
    _ = o;
    return .absent;
}

pub fn originNonEffect(o: []const u8) evidence.OriginState {
    _ = o;
    return .non_effect;
}

// 09a: seedFrom(0xa2) is the pending origin, everything else an Effect.
pub fn origin09a(o: []const u8) evidence.OriginState {
    if (o[0] == 0xa2) return .absent;
    return .effect;
}

// 09b: seedFrom(0xa1) resolves to a non-Effect body, everything else Effect.
pub fn origin09b(o: []const u8) evidence.OriginState {
    if (o[0] == 0xa1) return .non_effect;
    return .effect;
}

pub fn neverSuperseded(rid: []const u8, o: []const u8, ce: []const u8) bool {
    _ = rid;
    _ = o;
    _ = ce;
    return false;
}

pub fn alwaysSuperseded(rid: []const u8, o: []const u8, ce: []const u8) bool {
    _ = rid;
    _ = o;
    _ = ce;
    return true;
}

pub fn ctx(
    role: *const fn ([]const u8) evidence.Role,
    origin: *const fn ([]const u8) evidence.OriginState,
    sup: *const fn ([]const u8, []const u8, []const u8) bool,
) evidence.ResolveContext {
    return .{ .role_of = role, .resolve_origin = origin, .is_superseded = sup };
}

pub const Tag = std.meta.Tag(evidence.ClaimState);

pub fn expectSupported(st: evidence.ClaimState, q8: u8) !void {
    try std.testing.expect(std.meta.activeTag(st) == .supported);
    try std.testing.expectEqual(q8, st.supported.effective_q8);
}

pub fn expectState(st: evidence.ClaimState, tag: Tag) !void {
    try std.testing.expect(std.meta.activeTag(st) == tag);
}
