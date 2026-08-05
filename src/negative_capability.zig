// negative_capability.zig
//
// NEGATIVE COMPILE TEST (BE-GRANT-03b). This module MUST FAIL TO COMPILE.
// It is the canary that turns the capability-type property from a promise
// into a gate.
//
// Before VerifiedGrant became opaque {}, it was a struct with a public field,
// and a struct literal minted a "verified" grant outside the verification
// routine: every BE-GRANT-03 check skipped, no signature checked, no expiry,
// nothing. That was the forgery hole (Round 3 review, part 3).
//
// As an opaque type, VerifiedGrant cannot be value-constructed, so the literal
// in the comptime block below is a compile error. The `zig build negative`
// step runs the compiler on this file and asserts exit 1 (a compile failure).
// The day someone changes VerifiedGrant back to a constructible struct, this
// file compiles, the negative step fails the build, and the gate fires before
// the hole ships.
//
// The forgery sits in a top-level comptime block on purpose: Zig analyzes
// unreferenced function bodies lazily, so an error inside an unused fn never
// fires. A comptime block at the root is always analyzed, so the error is
// guaranteed.
//
// This file lives in src/ next to verify.zig (its import target) because a
// bare `zig build-obj` resolves @import relative to this file's directory,
// and the canary must fail on the TYPE, not on an import-path escape. It is
// NOT a build root: tests.zig, main.zig and fuzz.zig never import it, so it
// is never compiled by `zig build test` and is never in the shipped binary.
//
// The @ptrCast-only forgery path (fabricating the pointer) is gated separately
// by M8 (tools/prumo-verify), which permits @ptrCast in exactly the two
// boundary functions of verify.zig. This file guards the value-construction
// path.

const verify = @import("verify.zig");

// Value-constructing a capability with no checks run. Refused by the type
// system for an opaque type. The day this compiles, the gate has failed.
comptime {
    _ = &verify.VerifiedGrant{};
}
