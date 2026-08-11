// tests.zig
//
// Aggregator root for `zig build test`. Every dedicated test module is imported
// here so the M1 bijection (SPEC section 11.1) has a single home that the test
// step compiles. Source modules stay production-only; tests live in *_test.zig.

comptime {
    _ = @import("parser_test.zig");
    _ = @import("verify_test.zig");
    _ = @import("vectors_test.zig");
    _ = @import("evidence_test.zig");
    _ = @import("evidence_record_test.zig");
    _ = @import("dag_test.zig");
    _ = @import("mac_test.zig");
    _ = @import("replay_test.zig");
    _ = @import("reassembly_test.zig");
    _ = @import("noise_test.zig");
    _ = @import("session_test.zig");
    _ = @import("binding_test.zig");
    _ = @import("relay_test.zig");
    _ = @import("ledger_test.zig");
    _ = @import("intent_test.zig");
    _ = @import("resolver_test.zig");
    _ = @import("render_test.zig");
    _ = @import("sync_test.zig");
    _ = @import("fuzz_test.zig");
    _ = @import("relay_store_test.zig");
    _ = @import("dispatch_test.zig");
    _ = @import("listener_test.zig");
    _ = @import("handshake_test.zig");
}
