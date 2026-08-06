// vectors_test.zig
//
// Vectors harness, Task 9 (LANGUAGE.md section 4). Consumes test/vectors.json
// at compile time and exercises the whole slice against it: every positive
// structure parses and its Ed25519 signature verifies against the declared
// signer, and every negative vector is rejected. The parser and verifier stay
// zero-heap (BE-WIRE-01); this harness is test code and may allocate.

const std = @import("std");
const parser = @import("parser.zig");
const verify = @import("verify.zig");
const testing = std.testing;

const VectorsJson = @import("vectors").json;

// Decode a lowercase hex string into freshly allocated bytes.
fn decodeHex(a: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.BadHex;
    const out = try a.alloc(u8, hex.len / 2);
    var i: usize = 0;
    while (i < hex.len) : (i += 2) {
        out[i / 2] = try std.fmt.parseInt(u8, hex[i .. i + 2], 16);
    }
    return out;
}

// Helpers that panic on a missing key: a malformed vectors file is a
// generator bug, not a runtime condition worth propagating.
const Obj = std.json.ObjectMap;

fn str(o: Obj, key: []const u8) []const u8 {
    const v = o.get(key) orelse unreachable;
    return v.string;
}

// Find a negative vector by name.
fn negative(items: []const std.json.Value, name: []const u8) Obj {
    for (items) |n| {
        const nm = n.object.get("name") orelse continue;
        if (std.mem.eql(u8, nm.string, name)) return n.object;
    }
    @panic("negative vector not found");
}

test "vectors: envelope_intent parses and its signature verifies" {
    const a = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const al = arena.allocator();

    var j = try std.json.parseFromSlice(std.json.Value, a, VectorsJson, .{});
    defer j.deinit();
    const root = j.value.object;
    const structs = root.get("structures").?.object;
    const env = structs.get("envelope_intent").?.object;

    const wire = try decodeHex(al, str(env, "wire_hex"));
    const signer = try decodeHex(al, str(env, "signer_pubkey"));
    try testing.expectEqual(@as(u8, parser.DOMAIN_ENVELOPE), try hexByte(str(env, "domain_tag")));

    const e = try parser.parseEnvelope(wire);
    // BE-ENV-02: envelope sig verifies against sender before any body work.
    try verify.verifySigned(parser.DOMAIN_ENVELOPE, e.tbs, e.sig, signer);

    // The body is an Intent whose resource_id and action match the vector.
    const intent = try parser.parseIntent(e.body);
    const fields = env.get("fields").?.object;
    try testing.expectEqualStrings(str(fields, "body_resource_id"), intent.resource_id);
    try testing.expectEqualStrings(str(fields, "body_action_utf8"), intent.action);
}

test "vectors: grant parses and its signature verifies" {
    const a = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const al = arena.allocator();

    var j = try std.json.parseFromSlice(std.json.Value, a, VectorsJson, .{});
    defer j.deinit();
    const structs = j.value.object.get("structures").?.object;
    const grant = structs.get("grant").?.object;

    const wire = try decodeHex(al, str(grant, "wire_hex"));
    const approver = try decodeHex(al, str(grant, "signer_pubkey"));
    try testing.expectEqual(@as(u8, parser.DOMAIN_GRANT), try hexByte(str(grant, "domain_tag")));

    const g = try parser.parseGrant(wire);
    try verify.verifySigned(parser.DOMAIN_GRANT, g.tbs, g.sig, approver);

    // BE-GRANT-02: the stored action_digest is BLAKE2s of the intent action.
    const action_utf8 = str(grant.get("fields").?.object, "action_utf8");
    const digest = verify.actionDigest(action_utf8);
    try testing.expectEqualStrings(g.action_digest, &digest);
}

test "vectors: span signature verifies against executor" {
    const a = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const al = arena.allocator();

    var j = try std.json.parseFromSlice(std.json.Value, a, VectorsJson, .{});
    defer j.deinit();
    const span = j.value.object.get("structures").?.object.get("span").?.object;

    const tbs = try decodeHex(al, str(span, "tbs_hex"));
    const sig = try decodeHex(al, str(span, "sig_hex"));
    const signer = try decodeHex(al, str(span, "signer_pubkey"));
    try verify.verifySigned(parser.DOMAIN_SPAN, tbs, sig, signer);
}

test "vectors: span body parses against the canonical wire" {
    const a = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const al = arena.allocator();

    var j = try std.json.parseFromSlice(std.json.Value, a, VectorsJson, .{});
    defer j.deinit();
    const span = j.value.object.get("structures").?.object.get("span").?.object;
    const fields = span.get("fields").?.object;

    const wire = try decodeHex(al, str(span, "wire_hex"));
    const s = try parser.parseSpan(wire);

    try testing.expectEqual(@as(u8, 2), s.version);
    try testing.expectEqual(@as(u8, 1), s.method_id); // 1 -> DirectObservation (SPEC 7.4)
    try testing.expectEqual(@as(u8, 2), s.volatility); // stable
    try testing.expectEqual(@as(u64, 1700000030000), s.observed_at);
    try testing.expectEqual(@as(usize, 16), s.span_id.len);
    try testing.expectEqual(@as(usize, 16), s.trace_id.len);
    try testing.expectEqual(@as(usize, 32), s.origin.len);
    try testing.expectEqual(@as(usize, 32), s.digest.len);
    try testing.expectEqual(@as(usize, 32), s.executor.len);
    try testing.expectEqual(@as(usize, 64), s.sig.len);
    // tbs is the prefix, sig the trailer; both alias the input wire (zero heap).
    try testing.expectEqualSlices(u8, wire[0 .. wire.len - 64], s.tbs);
    try testing.expectEqualSlices(u8, wire[wire.len - 64 ..], s.sig);
    try testing.expectEqualStrings(str(fields, "resource_id"), s.resource_id);

    // The parsed tbs and sig must verify under domain 0x03, cross-checked.
    const signer = try decodeHex(al, str(span, "signer_pubkey"));
    try verify.verifySigned(parser.DOMAIN_SPAN, s.tbs, s.sig, signer);
}

test "vectors: effect body parses with one inline span" {
    const a = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const al = arena.allocator();

    var j = try std.json.parseFromSlice(std.json.Value, a, VectorsJson, .{});
    defer j.deinit();
    const eff = j.value.object.get("structures").?.object.get("effect").?.object;

    const env_wire = try decodeHex(al, str(eff, "wire_hex"));
    const env = try parser.parseEnvelope(env_wire);
    try testing.expectEqual(parser.BODY_EFFECT, env.body_type);

    const body = try parser.parseEffect(env.body);
    try testing.expectEqual(@as(u8, 1), body.ok);
    try testing.expectEqual(@as(i32, 0), body.exit_code);
    try testing.expectEqual(@as(u8, 1), body.span_count);
    try testing.expectEqual(@as(usize, 32), body.output_digest.len);

    // The inline span region holds exactly one full Span wire: it parses
    // standalone and its tbs/sig verify against the executor.
    const inline_span = try parser.parseSpan(body.spans);
    try testing.expectEqual(@as(u8, 1), inline_span.method_id);
    const signer = try decodeHex(al, str(eff, "signer_pubkey"));
    try verify.verifySigned(parser.DOMAIN_SPAN, inline_span.tbs, inline_span.sig, signer);
}

test "vectors: claim body parses with one span reference" {
    const a = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const al = arena.allocator();

    var j = try std.json.parseFromSlice(std.json.Value, a, VectorsJson, .{});
    defer j.deinit();
    const claim = j.value.object.get("structures").?.object.get("claim").?.object;
    const fields = claim.get("fields").?.object;

    const wire = try decodeHex(al, str(claim, "wire_hex"));
    const c = try parser.parseClaim(wire);

    try testing.expectEqualStrings(str(fields, "text"), c.text);
    try testing.expectEqualStrings(str(fields, "subject"), c.subject);
    try testing.expectEqual(@as(u8, 242), c.confidence_q8); // DirectObservation ceiling (SPEC 7.2)
    try testing.expectEqual(@as(u8, 1), c.span_count);
    try testing.expectEqual(@as(usize, 16), c.span_ids.len);
}

test "vectors: refusal signature verifies against approver" {
    const a = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const al = arena.allocator();

    var j = try std.json.parseFromSlice(std.json.Value, a, VectorsJson, .{});
    defer j.deinit();
    const refusal = j.value.object.get("structures").?.object.get("refusal").?.object;

    const tbs = try decodeHex(al, str(refusal, "tbs_hex"));
    const sig = try decodeHex(al, str(refusal, "sig_hex"));
    const signer = try decodeHex(al, str(refusal, "signer_pubkey"));
    try verify.verifySigned(parser.DOMAIN_REFUSAL, tbs, sig, signer);
}

test "vectors: cert is countersigned by two CAs over domain 0x01" {
    const a = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const al = arena.allocator();

    var j = try std.json.parseFromSlice(std.json.Value, a, VectorsJson, .{});
    defer j.deinit();
    const cert = j.value.object.get("structures").?.object.get("cert").?.object;

    const tbs = try decodeHex(al, str(cert, "tbs_hex"));
    const ca_sigs = cert.get("ca_sigs").?.array.items;
    try testing.expectEqual(@as(usize, 2), ca_sigs.len);
    for (ca_sigs) |entry| {
        const ca_key = try decodeHex(al, str(entry.object, "ca_key"));
        const ca_sig = try decodeHex(al, str(entry.object, "sig"));
        try verify.verifySigned(parser.DOMAIN_CERT, tbs, ca_sig, ca_key);
    }
}

test "vectors: truncated envelope trailer is rejected (BE-WIRE-02)" {
    const a = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const al = arena.allocator();

    var j = try std.json.parseFromSlice(std.json.Value, a, VectorsJson, .{});
    defer j.deinit();
    const items = j.value.object.get("negatives").?.array.items;
    const wire = try decodeHex(al, str(negative(items, "envelope_truncated_sig"), "wire"));
    try testing.expectError(error.Truncated, parser.parseEnvelope(wire));
}

test "vectors: trailing bytes after an envelope are rejected (BE-WIRE-02)" {
    const a = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const al = arena.allocator();

    var j = try std.json.parseFromSlice(std.json.Value, a, VectorsJson, .{});
    defer j.deinit();
    const items = j.value.object.get("negatives").?.array.items;
    const wire = try decodeHex(al, str(negative(items, "envelope_trailing_byte"), "wire"));
    try testing.expectError(error.TrailingBytes, parser.parseEnvelope(wire));
}

test "vectors: envelope signed over wrong domain tag fails verification (BE-SIG-01)" {
    const a = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const al = arena.allocator();

    var j = try std.json.parseFromSlice(std.json.Value, a, VectorsJson, .{});
    defer j.deinit();
    const root = j.value.object;
    const items = root.get("negatives").?.array.items;
    const signer = try decodeHex(al, str(root.get("structures").?.object.get("envelope_intent").?.object, "signer_pubkey"));
    const wire = try decodeHex(al, str(negative(items, "envelope_wrong_domain_tag"), "wire"));

    // The wire parses cleanly; only the signature is invalid for this domain.
    const e = try parser.parseEnvelope(wire);
    try testing.expectError(error.BadSignature, verify.verifySigned(parser.DOMAIN_ENVELOPE, e.tbs, e.sig, signer));
}

// Parse a single hex byte (the domain_tag field is "01".."06").
fn hexByte(hex: []const u8) !u8 {
    return try std.fmt.parseInt(u8, hex, 16);
}
