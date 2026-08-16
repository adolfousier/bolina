// grant_trace.zig
//
// bolina.grant-trace.v1: test-only conformance instrumentation for the
// ZIG-TLA conformance pilot (model/ZIG-TLA-CONFORMANCE-BRIEF.md section 6).
// Comptime-gated by the build option `trace` (-Dtrace=true). When disabled,
// every emit call site compiles out and the production binary is untouched:
// zero heap, zero I/O, zero cost. When enabled, the wiring points in
// verify.zig, dispatch.zig and grant_ledger.zig append events to a fixed
// in-memory buffer; the harness snapshots it after a run and the projector
// maps events onto the TLA+ actions of model/Bolina.tla.
//
// Event contract (the two load-bearing details of the brief):
//   commit_consumed_11 is emitted only after the durable appendSync returns
//     successfully. An event before the append would turn attempted
//     durability into false evidence.
//   effect_start is the normative APPROVED -> EXECUTING transition (D-067).
//     record_executing_witness is the later durable bookkeeping echo and
//     must never be projected as authorization for the effect.
//
// mark_published and recover_mark_published carry now_ms = 0: the
// publication call path carries no clock. Ordering authority is the seq
// counter, monotonic within a process epoch. Crash/Restart is a
// harness-owned epoch boundary that resets the buffer.
//
// effect_refused (brief section 9.1, D-078): emitted instead of
//   effect_return when the executor declines the capability. A trace
//   ending in effect_refused must never be followed by mark_published or
//   record_executing_witness: publishing a grant whose effect never fired
//   would be false evidence under the D-067 correspondence rule. The
//   commit_consumed_11 row stands, so the trace ends in a durable,
//   unpublished orphan (BE-GRANT-01a).
//
// Single-threaded by design: the dispatch path runs under the verify frame
// lock, so the module-level buffer needs no synchronization.

const std = @import("std");
const opts = @import("build_options");

pub const enabled: bool = opts.trace_enabled;
pub const schema: []const u8 = "bolina.grant-trace.v1";

pub const CAP: usize = 256;

pub const Tag = enum(u8) {
    receive_intent = 1,
    reject_resource_conflict = 2,
    begin_verify = 3,
    verify_check = 4,
    commit_consumed_11 = 5,
    effect_start = 6,
    effect_return = 7,
    mark_published = 8,
    record_executing_witness = 9,
    recover_mark_published = 10,
    effect_refused = 11,
    trace_overflow = 255,
};

pub const NO_PC: u8 = 0xFF;

pub const Event = struct {
    tag: Tag,
    pc: u8,
    id: u64,
    now_ms: u64,
    seq: u32,
};

var events: [CAP]Event = undefined;
var len: usize = 0;
var seq_next: u32 = 0;
var overflow_count: usize = 0;

// Deterministic identity fingerprint (FNV-1a over the id bytes): stable
// across runs and builds, so recorded traces and expected traces compare
// by value.
pub fn fingerprint(id: []const u8) u64 {
    var h: u64 = 0xcbf29ce484222325;
    for (id) |b| {
        h ^= b;
        h *%= 0x100000001b3;
    }
    return h;
}

pub fn emit(tag: Tag, pc: u8, id_bytes: []const u8, now_ms: u64) void {
    if (!enabled) return;
    if (len == CAP) {
        if (overflow_count == 0) {
            // Exactly one marker on the first overflow, never a silent drop.
            events[CAP - 1] = .{ .tag = .trace_overflow, .pc = NO_PC, .id = 0, .now_ms = now_ms, .seq = seq_next };
            seq_next += 1;
        }
        overflow_count += 1;
        return;
    }
    events[len] = .{ .tag = tag, .pc = pc, .id = fingerprint(id_bytes), .now_ms = now_ms, .seq = seq_next };
    seq_next += 1;
    len += 1;
}

pub fn snapshot() []const Event {
    return events[0..len];
}

pub fn overflow() usize {
    return overflow_count;
}

pub fn reset() void {
    len = 0;
    seq_next = 0;
    overflow_count = 0;
}
