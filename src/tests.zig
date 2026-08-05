// tests.zig
//
// Aggregator root for `zig build test`. Every dedicated test module is imported
// here so the M1 bijection (SPEC section 11.1) has a single home that the test
// step compiles. Source modules stay production-only; tests live in *_test.zig.

comptime {
    _ = @import("parser_test.zig");
}
