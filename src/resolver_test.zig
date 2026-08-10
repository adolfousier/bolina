// resolver_test.zig
//
// Literal binding tests for src/resolver.zig (SPEC.md section 8.4,
// BE-RES-01 through 06). Literal expected values per D-027. Key fixtures via
// cert_test_helpers: executor E1 is keypair(0xE1), fp 549b6dd68ceeab0d;
// foreign executor E2 is keypair(0xE2), fp cc6009c6dabe53b1 (both measured
// by executorFp over the deterministic pubkeys, baked in as known vectors).
// The alias-collapse-into-lock half of BE-RES-03 and the downstream-canonical
// half of BE-RES-01 land with the intent-admission wiring (task 3).

const std = @import("std");
const resolver = @import("resolver.zig");
const h = @import("cert_test_helpers.zig");
const Ed = std.crypto.sign.Ed25519;

const R = resolver.Resolver;
const E = resolver.ResolveError;

const FP1 = "549b6dd68ceeab0d"; // executor E1 (BE-RES-06 vector)
const FP2 = "cc6009c6dabe53b1"; // executor E2 (BE-RES-06 vector)
const RES_A = "bol:" ++ FP1 ++ "/files/reports/q3.pdf";
const RES_B = "bol:" ++ FP1 ++ "/files/logs/app.log";
const RES_FOREIGN = "bol:" ++ FP2 ++ "/print/queue/main";

fn execResolver() R {
    return R.init(&h.pubkeyOf(0xE1));
}

test "BE_RES_06 fingerprint is BLAKE2s-256 first 8 bytes, 16 lowercase hex" {
    var fp: [resolver.FP_HEX_LEN]u8 = undefined;
    resolver.executorFp(&h.pubkeyOf(0xE1), &fp);
    try std.testing.expectEqualStrings(FP1, &fp);
    resolver.executorFp(&h.pubkeyOf(0xE2), &fp);
    try std.testing.expectEqualStrings(FP2, &fp);
    for (fp) |c| {
        const ok = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
        try std.testing.expect(ok); // lowercase hex only, raw key bytes never
    }
    // own_fp at init is the same derivation (BE-RES-04 depends on it)
    const r = execResolver();
    try std.testing.expectEqualStrings(FP1, &r.own_fp);
}

test "BE_RES_01 canonical form drawn from the declared set, grammar enforced" {
    var r = execResolver();
    try r.add(RES_A);
    // resolve returns the declared bytes verbatim: the canonical, not a copy
    // of the proposal (BE-RES-01: the executor's form, never the requester's)
    const got = try r.resolve(RES_A);
    try std.testing.expectEqualStrings(RES_A, got);

    // section 8.4 grammar: every malformed declaration refuses
    const malformed = [_][]const u8{
        "Bol:" ++ FP1 ++ "/files/x", // prefix is lowercase bol:
        "bol:" ++ FP1 ++ "/Files/x", // namespace [a-z0-9-] only
        "bol:" ++ FP1 ++ "/files/./x", // "." segment forbidden
        "bol:" ++ FP1 ++ "/files/../x", // ".." segment forbidden
        "bol:" ++ FP1 ++ "/files/a//b", // empty segment forbidden
        "bol:" ++ FP1 ++ "/files/", // trailing empty segment
        "bol:" ++ FP1 ++ "/files", // path absent
        "bol:549B6DD68CEEAB0D/files/x", // fp must be lowercase hex
        "bol:549b6dd68ceeab0/files/x", // fp is 16 hex chars, not 15
        "bol:" ++ FP1 ++ "/" ++ ("a" ** 33) ++ "/x", // namespace over 32
        "bol:" ++ FP1 ++ "/files/" ++ ("a" ** 181), // path over 180
    };
    for (malformed) |m| {
        try std.testing.expectError(E.MalformedCanonical, r.add(m));
    }
    // boundary shapes the grammar accepts: 32-char namespace, 180-char path,
    // dots inside a segment ("a..b" is not "." or "..")
    try r.add("bol:" ++ FP1 ++ "/" ++ ("a" ** 32) ++ "/x");
    try r.add("bol:" ++ FP1 ++ "/files/" ++ ("a" ** 180));
    try r.add("bol:" ++ FP1 ++ "/files/a..b/c.d");
}

test "BE_RES_02 unknown refuses, ambiguous refuses, nothing is created" {
    var r = execResolver();
    try r.add(RES_A);
    try r.add(RES_B);
    const before = r.entry_count;

    // zero matches: no create-on-first-use path exists
    try std.testing.expectError(E.UnknownResource, r.resolve("bol:" ++ FP1 ++ "/files/never-declared"));
    try std.testing.expectEqual(before, r.entry_count);

    // one alias on each of two entries: the same spelling reaches two
    // distinct canonicals and refuses
    try r.addAlias(RES_A, "the-file");
    try r.addAlias(RES_B, "the-file");
    try std.testing.expectError(E.AmbiguousResource, r.resolve("the-file"));

    // an alias for an undeclared canonical refuses at construction
    try std.testing.expectError(E.UnknownResource, r.addAlias("bol:" ++ FP1 ++ "/files/ghost", "spelling"));
}

test "BE_RES_03 declared aliases reach exactly one canonical" {
    var r = execResolver();
    try r.add(RES_A);
    try r.addAlias(RES_A, "q3-report");
    try r.addAlias(RES_A, "REPORT-Q3"); // arbitrary bytes: agents spell freely

    // two spellings, one resource: both return the same canonical bytes
    const via_alias1 = try r.resolve("q3-report");
    const via_alias2 = try r.resolve("REPORT-Q3");
    const via_canonical = try r.resolve(RES_A);
    try std.testing.expectEqualStrings(RES_A, via_alias1);
    try std.testing.expectEqualStrings(RES_A, via_alias2);
    try std.testing.expectEqualStrings(via_canonical, via_alias1);

    // a proposal matching the canonical exactly while aliased to the SAME
    // entry is one resource, not ambiguity (distinct-entry counting)
    try r.addAlias(RES_A, RES_A);
    const still_one = try r.resolve(RES_A);
    try std.testing.expectEqualStrings(RES_A, still_one);
}

test "BE_RES_04 executor refuses a canonical carrying a foreign fingerprint" {
    var r = execResolver();
    try r.add(RES_FOREIGN); // declared, well-formed, but not this executor's
    try std.testing.expectError(E.ForeignExecutor, r.resolve(RES_FOREIGN));
    // own-fp resources resolve fine in the same set
    try r.add(RES_A);
    try std.testing.expectEqualStrings(RES_A, try r.resolve(RES_A));
}

test "BE_RES_05 resource set publishes as signed state, tamper refuses" {
    var r = execResolver();
    try r.add(RES_A);
    try r.add(RES_B);
    try r.addAlias(RES_A, "q3-report");

    // encoding clause (SPEC v0.3.2-draft): first entry is u16 length big-endian
    // plus canonical bytes, then u16 alias count
    var buf: [1024]u8 = undefined;
    const n = try r.serialize(&buf);
    try std.testing.expectEqual(@as(usize, r.serializedLen()), n);
    try std.testing.expectEqual(@as(u8, 0), buf[0]);
    try std.testing.expectEqual(@as(u8, RES_A.len), buf[1]);
    try std.testing.expectEqualStrings(RES_A, buf[2 .. 2 + RES_A.len]);

    const kp = h.keypair(0xE1);
    var scratch: [1024]u8 = undefined;
    const sig = try r.signResourceSet(kp, &scratch);

    // signature verifies under the executor's declared key
    try std.testing.expect(try r.verifyResourceSet(sig, kp.public_key, &scratch));
    // and refuses under a different executor's key
    const kp2 = h.keypair(0xE2);
    try std.testing.expect(!(try r.verifyResourceSet(sig, kp2.public_key, &scratch)));
    // tamper after signing: a new alias changes the serialization, and the
    // old signature no longer binds the declared set
    try r.addAlias(RES_B, "late-addition");
    try std.testing.expect(!(try r.verifyResourceSet(sig, kp.public_key, &scratch)));
}

test "BE_RES_05 granularity is declared: capacities refuse, never grow" {
    var r = execResolver();
    try r.add(RES_A);
    // duplicate declaration refuses: one resource is declared once
    try std.testing.expectError(E.DuplicateEntry, r.add(RES_A));
    var id: [resolver.ID_MAX]u8 = undefined;
    for (1..resolver.MAX_RESOURCES) |i| {
        const len = std.fmt.bufPrint(&id, "bol:" ++ FP1 ++ "/ns/res-{d}", .{i}) catch unreachable;
        try r.add(len);
    }
    try std.testing.expectError(E.SetFull, r.add("bol:" ++ FP1 ++ "/ns/one-too-many"));
    for (0..resolver.MAX_ALIASES) |i| {
        const len = std.fmt.bufPrint(&id, "alias-{d}", .{i}) catch unreachable;
        try r.addAlias(RES_A, len);
    }
    try std.testing.expectError(E.AliasPoolFull, r.addAlias(RES_A, "overflow"));
}
