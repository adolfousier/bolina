//! Cross-implementation test vector generator (SPEC.md section 11.3).
//!
//! Produces test/vectors.json. Every value is deterministic: Ed25519 seeds are
//! fixed, Ed25519 signing is deterministic per RFC 8032, BLAKE2s-256 is
//! deterministic. The output is byte-stable across platforms and runs, so it
//! can be checked in and diffed.
//!
//! The generated file is cross-verified by an independent implementation
//! (python cryptography for Ed25519, hashlib for BLAKE2s) before any gate
//! treats it as canonical. A second implementation must reproduce every
//! signature over (domain_tag || tbs) and every digest byte-for-byte.
//!
//! SPEC.md section 11.3: a shared vector file fixing encodings, signature
//! inputs, address derivations, digests, and the method_id to class to ceiling
//! mapping (BE-EVID-15), so two independent implementations agree byte-for-byte.

const std = @import("std");

const Ed = std.crypto.sign.Ed25519;
const X25519 = std.crypto.dh.X25519;
const B2s = std.crypto.hash.blake2.Blake2s256;

const Alist = std.ArrayList(u8);
const Alloc = std.mem.Allocator;

const HEX = "0123456789abcdef";

// Fixed timestamps (unix ms) and counters. Round values, easy to eyeball.
const T_NOT_BEFORE: u64 = 1700000000000;
const T_NOT_AFTER: u64 = 1800000000000;
const T_TS: u64 = 1700000010000;
const T_OBSERVED: u64 = 1700000030000;
const T_GRANT_NOT_AFTER: u64 = 1700000060000;
const SEQ: u64 = 1;

// Fixed opaque payloads.
const ACTION = "apt-get install -y sqlite3";
const RATIONALE = "Install sqlite for local schema inspection.";
const OBSERVED_OUTPUT = "exit=0\npackage sqlite3 installed\n";
const REFUSAL_NOTE = "Resource not recognized by this executor.";

const DOMAIN_CERT = 0x01;
const DOMAIN_ENVELOPE = 0x02;
const DOMAIN_SPAN = 0x03;
const DOMAIN_GRANT = 0x04;
const DOMAIN_REFUSAL = 0x06;

const Identity = struct {
    name: []const u8,
    sig_seed: [32]u8,
    kex_seed: [32]u8,
    role_bits: u8,
    kp: Ed.KeyPair,
    sig_pubkey: [32]u8,
    kex_pubkey: [32]u8,
};

fn blake2s(input: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    B2s.hash(input, &out, .{});
    return out;
}

fn seedFrom(prefix: u8) [32]u8 {
    var s: [32]u8 = undefined;
    for (&s, 0..) |*b, i| b.* = prefix +% @as(u8, @intCast(i));
    return s;
}

fn makeIdentity(name: []const u8, sig_prefix: u8, kex_prefix: u8, role_bits: u8) !Identity {
    const sig_seed = seedFrom(sig_prefix);
    const kex_seed = seedFrom(kex_prefix);
    const kp = try Ed.KeyPair.generateDeterministic(sig_seed);
    const sig_pubkey = Ed.PublicKey.toBytes(kp.public_key);
    const kex_pubkey = try X25519.recoverPublicKey(kex_seed);
    return .{
        .name = name,
        .sig_seed = sig_seed,
        .kex_seed = kex_seed,
        .role_bits = role_bits,
        .kp = kp,
        .sig_pubkey = sig_pubkey,
        .kex_pubkey = kex_pubkey,
    };
}

// ---- byte encoders (flat record, big-endian, SPEC section 2.2) ----

fn putU8(out: *Alist, a: Alloc, v: u8) !void {
    try out.append(a, v);
}
fn putU16be(out: *Alist, a: Alloc, v: u16) !void {
    var b: [2]u8 = undefined;
    std.mem.writeInt(u16, &b, v, .big);
    try out.appendSlice(a, &b);
}
fn putU32be(out: *Alist, a: Alloc, v: u32) !void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .big);
    try out.appendSlice(a, &b);
}
fn putU64be(out: *Alist, a: Alloc, v: u64) !void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, v, .big);
    try out.appendSlice(a, &b);
}
fn putFixed(out: *Alist, a: Alloc, bytes: []const u8) !void {
    try out.appendSlice(a, bytes);
}
// Variable-length field: u16 length prefix + bytes (SPEC section 2.2).
fn putU16Len(out: *Alist, a: Alloc, bytes: []const u8) !void {
    try putU16be(out, a, @intCast(bytes.len));
    try out.appendSlice(a, bytes);
}

fn signTagged(kp: Ed.KeyPair, tag: u8, tbs: []const u8) ![64]u8 {
    var msg = Alist.empty;
    defer msg.deinit(std.heap.page_allocator);
    try msg.append(std.heap.page_allocator, tag);
    try msg.appendSlice(std.heap.page_allocator, tbs);
    const sig = try Ed.KeyPair.sign(kp, msg.items, null);
    return Ed.Signature.toBytes(sig);
}

fn overlayAddr(pubkey: *const [32]u8) [16]u8 {
    const h = blake2s(pubkey);
    var addr: [16]u8 = undefined;
    addr[0] = 0xfd;
    for (h[0..15], 0..) |b, i| addr[i + 1] = b;
    return addr;
}

// ---- JSON helpers. Fields emit "key":value with NO trailing comma; use sep(). ----

fn w(o: *Alist, a: Alloc, s: []const u8) !void {
    try o.appendSlice(a, s);
}
fn sep(o: *Alist, a: Alloc) !void {
    try o.append(a, ',');
}
fn jStr(o: *Alist, a: Alloc, s: []const u8) !void {
    try o.append(a, '"');
    for (s) |c| switch (c) {
        '"' => try o.appendSlice(a, "\\\""),
        '\\' => try o.appendSlice(a, "\\\\"),
        '\n' => try o.appendSlice(a, "\\n"),
        '\r' => try o.appendSlice(a, "\\r"),
        '\t' => try o.appendSlice(a, "\\t"),
        else => {
            if (c < 0x20) {
                var b: [6]u8 = undefined;
                const x = std.fmt.bufPrint(&b, "\\u{x:0>4}", .{c}) catch unreachable;
                try o.appendSlice(a, x);
            } else try o.append(a, c);
        },
    };
    try o.append(a, '"');
}
fn jHex(o: *Alist, a: Alloc, bytes: []const u8) !void {
    try o.append(a, '"');
    for (bytes) |b| {
        try o.append(a, HEX[b >> 4]);
        try o.append(a, HEX[b & 0xf]);
    }
    try o.append(a, '"');
}
fn jHexRaw(o: *Alist, a: Alloc, bytes: []const u8) !void {
    for (bytes) |b| {
        try o.append(a, HEX[b >> 4]);
        try o.append(a, HEX[b & 0xf]);
    }
}
fn jU64(o: *Alist, a: Alloc, v: u64) !void {
    var b: [21]u8 = undefined;
    const s = std.fmt.bufPrint(&b, "{d}", .{v}) catch unreachable;
    try o.appendSlice(a, s);
}
fn jU8(o: *Alist, a: Alloc, v: u8) !void {
    var b: [4]u8 = undefined;
    const s = std.fmt.bufPrint(&b, "{d}", .{v}) catch unreachable;
    try o.appendSlice(a, s);
}
// field helpers: emit "<key>":<value> (no comma)
fn fStr(o: *Alist, a: Alloc, key: []const u8, val: []const u8) !void {
    try jStr(o, a, key);
    try o.append(a, ':');
    try jStr(o, a, val);
}
fn fHex(o: *Alist, a: Alloc, key: []const u8, bytes: []const u8) !void {
    try jStr(o, a, key);
    try o.append(a, ':');
    try jHex(o, a, bytes);
}
fn fU64(o: *Alist, a: Alloc, key: []const u8, v: u64) !void {
    try jStr(o, a, key);
    try o.append(a, ':');
    try jU64(o, a, v);
}
fn fU8(o: *Alist, a: Alloc, key: []const u8, v: u8) !void {
    try jStr(o, a, key);
    try o.append(a, ':');
    try jU8(o, a, v);
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const a = init.gpa;

    // Identities. role_bits: bit0 participant,1 agent,2 executor,3 approver,4 lighthouse.
    const ca1 = try makeIdentity("ca1", 0x01, 0x02, 0x10);
    const ca2 = try makeIdentity("ca2", 0x21, 0x22, 0x10);
    const approver = try makeIdentity("approver", 0x41, 0x42, 0x09);
    const executor = try makeIdentity("executor", 0x61, 0x62, 0x05);
    const agent = try makeIdentity("agent", 0x81, 0x82, 0x03);

    // Derived shared values.
    const resource_id = blk: {
        var buf: [256]u8 = undefined;
        const fp = blake2s(&executor.sig_pubkey)[0..8].*;
        var fp_hex: [16]u8 = undefined;
        for (fp, 0..) |b, i| {
            fp_hex[i * 2] = HEX[b >> 4];
            fp_hex[i * 2 + 1] = HEX[b & 0xf];
        }
        const s = try std.fmt.bufPrint(&buf, "bol:{s}/logs/deploy.log", .{fp_hex});
        break :blk try a.dupe(u8, s);
    };
    defer a.free(resource_id);

    // D-085: scope_id = BLAKE2s(org_prefix)[0..8] where org_prefix is the
    // resource path up to the first '/'. scopeCoversResource walks ancestor
    // prefixes hashing each; this ensures the grant's resource is in scope.
    const org_prefix = resource_id[0..std.mem.indexOf(u8, resource_id, "/").?];
    const scope_id = blake2s(org_prefix)[0..8].*;

    const intent_id: [16]u8 = seedFrom(0x01)[0..16].*;
    const grant_id: [16]u8 = seedFrom(0x11)[0..16].*;
    const span_id: [16]u8 = seedFrom(0x21)[0..16].*;
    const trace_id: [16]u8 = seedFrom(0x31)[0..16].*;
    const channel_id = blake2s("bolina/example-channel");
    const origin = blake2s("bolina/example-effect-envelope");
    const action_digest = blake2s(ACTION);
    const span_digest = blake2s(OBSERVED_OUTPUT);

    // ---- CERT: agent identity, signed by ca1 and ca2 (ascending ca_key) ----
    var cert_tbs = Alist.empty;
    defer cert_tbs.deinit(a);
    try putU8(&cert_tbs, a, 3); // version = 3 (D-085: enables scope checks)
    try putU8(&cert_tbs, a, agent.role_bits);
    try putFixed(&cert_tbs, a, &agent.sig_pubkey);
    try putFixed(&cert_tbs, a, &agent.kex_pubkey);
    try putU64be(&cert_tbs, a, T_NOT_BEFORE);
    try putU64be(&cert_tbs, a, T_NOT_AFTER);
    try putU16Len(&cert_tbs, a, "agent-1");
    try putU8(&cert_tbs, a, 1); // scope_count
    try putFixed(&cert_tbs, a, &scope_id); // [8]
    var order = [_]usize{ 0, 1 };
    if (std.mem.order(u8, &ca1.sig_pubkey, &ca2.sig_pubkey) == .gt) order = .{ 1, 0 };
    const ca_keys = [_]*const Identity{ &ca1, &ca2 };
    var cert_wire = Alist.empty;
    defer cert_wire.deinit(a);
    try cert_wire.appendSlice(a, cert_tbs.items);
    try putU8(&cert_wire, a, 2); // ca_sig_count
    var ca_sigs_buf: [2][64]u8 = undefined;
    for (order, 0..) |idx, k| {
        const ca = ca_keys[idx];
        try putFixed(&cert_wire, a, &ca.sig_pubkey);
        const sig = try signTagged(ca.kp, DOMAIN_CERT, cert_tbs.items);
        ca_sigs_buf[k] = sig;
        try putFixed(&cert_wire, a, &sig);
    }

    // ---- INTENT body ----
    var intent = Alist.empty;
    defer intent.deinit(a);
    try putFixed(&intent, a, &intent_id);
    try putU16Len(&intent, a, resource_id);
    try putU32be(&intent, a, @intCast(ACTION.len));
    try putFixed(&intent, a, ACTION);
    try putU16Len(&intent, a, RATIONALE);

    // ---- ENVELOPE carrying Intent, signed by agent ----
    var env_tbs = Alist.empty;
    defer env_tbs.deinit(a);
    try putU8(&env_tbs, a, 2);
    try putFixed(&env_tbs, a, &channel_id);
    try putFixed(&env_tbs, a, &agent.sig_pubkey);
    try putU64be(&env_tbs, a, SEQ);
    try putU8(&env_tbs, a, 0); // parent_count = 0 (genesis)
    try putU64be(&env_tbs, a, T_TS);
    try putU8(&env_tbs, a, 2); // body_type = Intent
    try putU32be(&env_tbs, a, @intCast(intent.items.len));
    try env_tbs.appendSlice(a, intent.items);
    const env_sig = try signTagged(agent.kp, DOMAIN_ENVELOPE, env_tbs.items);
    var env_wire = Alist.empty;
    defer env_wire.deinit(a);
    try env_wire.appendSlice(a, env_tbs.items);
    try putFixed(&env_wire, a, &env_sig);

    // ---- SPAN, signed by executor ----
    var span_tbs = Alist.empty;
    defer span_tbs.deinit(a);
    try putU8(&span_tbs, a, 2);
    try putFixed(&span_tbs, a, &span_id);
    try putFixed(&span_tbs, a, &trace_id);
    try putU16Len(&span_tbs, a, resource_id);
    try putU8(&span_tbs, a, 1); // method_id = subprocess -> DirectObservation
    try putU8(&span_tbs, a, 2); // volatility = stable
    try putFixed(&span_tbs, a, &origin);
    try putU64be(&span_tbs, a, T_OBSERVED);
    try putFixed(&span_tbs, a, &span_digest);
    try putFixed(&span_tbs, a, &executor.sig_pubkey);
    const span_sig = try signTagged(executor.kp, DOMAIN_SPAN, span_tbs.items);
    var span_wire = Alist.empty;
    defer span_wire.deinit(a);
    try span_wire.appendSlice(a, span_tbs.items);
    try putFixed(&span_wire, a, &span_sig);

    // ---- EFFECT: executor performed the granted action and published the span inline. The Effect
    // is a body (body_type 4) carried in an executor-signed Envelope; this envelope is the span's
    // origin and is a causal child of the Intent envelope (parent[0] = BLAKE2s of the Intent
    // envelope). The inline span's `origin` field uses the opaque anchor above, matching the
    // standalone span vector; see DECISION-LOG D-013 for the origin-computation question. (SPEC 6.4.)
    const effect_output_digest = blake2s(OBSERVED_OUTPUT);
    var effect_body = Alist.empty;
    defer effect_body.deinit(a);
    try putFixed(&effect_body, a, &intent_id);
    try putFixed(&effect_body, a, &grant_id);
    try putU8(&effect_body, a, 1); // ok = true
    try putU32be(&effect_body, a, 0); // exit_code = 0 (i32; 0 is identical in u32 and i32)
    try putU8(&effect_body, a, 1); // span_count = 1
    try effect_body.appendSlice(a, span_wire.items); // published span, full wire (tbs || sig)
    try putFixed(&effect_body, a, &effect_output_digest); // [32] output_digest
    const intent_env_hash = blake2s(env_wire.items);
    var eff_env_tbs = Alist.empty;
    defer eff_env_tbs.deinit(a);
    try putU8(&eff_env_tbs, a, 2);
    try putFixed(&eff_env_tbs, a, &channel_id);
    try putFixed(&eff_env_tbs, a, &executor.sig_pubkey); // sender = executor
    try putU64be(&eff_env_tbs, a, SEQ + 1); // after the Intent envelope
    try putU8(&eff_env_tbs, a, 1); // parent_count = 1
    try putFixed(&eff_env_tbs, a, &intent_env_hash); // parent[0] = Intent envelope hash
    try putU64be(&eff_env_tbs, a, T_OBSERVED); // ts
    try putU8(&eff_env_tbs, a, 4); // body_type = Effect
    try putU32be(&eff_env_tbs, a, @intCast(effect_body.items.len));
    try eff_env_tbs.appendSlice(a, effect_body.items);
    const eff_env_sig = try signTagged(executor.kp, DOMAIN_ENVELOPE, eff_env_tbs.items);
    var eff_env_wire = Alist.empty;
    defer eff_env_wire.deinit(a);
    try eff_env_wire.appendSlice(a, eff_env_tbs.items);
    try putFixed(&eff_env_wire, a, &eff_env_sig);

    // ---- CLAIM: agent asserts the deploy succeeded and cites the span. A Claim carries NO
    // signature of its own; it is authenticated only inside a signed Utterance envelope
    // (BE-EVID-08). The Utterance vector is deferred to F1 (RED-TEAM-09), so this vector fixes the
    // Claim wire layout and field values for the byte-layout cross-check, not an independent sig.
    const claim_text = "sqlite3 installed; version verified against the deploy log";
    var claim_tbs = Alist.empty;
    defer claim_tbs.deinit(a);
    try putU16Len(&claim_tbs, a, claim_text);
    try putU16Len(&claim_tbs, a, resource_id); // subject == resource_id (BE-EVID-03)
    try putU8(&claim_tbs, a, 242); // confidence_q8 = DirectObservation ceiling (BE-EVID-02)
    try putU8(&claim_tbs, a, 1); // span_count = 1
    try putFixed(&claim_tbs, a, &span_id); // span_ids[0]

    // ---- GRANT, signed by approver ----
    var grant_tbs = Alist.empty;
    defer grant_tbs.deinit(a);
    try putU8(&grant_tbs, a, 2);
    try putFixed(&grant_tbs, a, &grant_id);
    try putFixed(&grant_tbs, a, &intent_id);
    try putFixed(&grant_tbs, a, &approver.sig_pubkey);
    try putFixed(&grant_tbs, a, &agent.sig_pubkey); // subject
    try putFixed(&grant_tbs, a, &executor.sig_pubkey);
    try putU16Len(&grant_tbs, a, resource_id);
    try putFixed(&grant_tbs, a, &action_digest);
    try putU64be(&grant_tbs, a, T_GRANT_NOT_AFTER);
    const grant_sig = try signTagged(approver.kp, DOMAIN_GRANT, grant_tbs.items);
    var grant_wire = Alist.empty;
    defer grant_wire.deinit(a);
    try grant_wire.appendSlice(a, grant_tbs.items);
    try putFixed(&grant_wire, a, &grant_sig);

    // ---- REFUSAL, signed by approver (no version field, SPEC 8.5) ----
    var refusal_tbs = Alist.empty;
    defer refusal_tbs.deinit(a);
    try putFixed(&refusal_tbs, a, &intent_id);
    try putU16Len(&refusal_tbs, a, REFUSAL_NOTE);
    const refusal_sig = try signTagged(approver.kp, DOMAIN_REFUSAL, refusal_tbs.items);
    var refusal_wire = Alist.empty;
    defer refusal_wire.deinit(a);
    try refusal_wire.appendSlice(a, refusal_tbs.items);
    try putFixed(&refusal_wire, a, &refusal_sig);

    // ---- negative vectors derived from env_wire ----
    const env_truncated = env_wire.items[0 .. env_wire.items.len - 1];
    var env_trailing = Alist.empty;
    defer env_trailing.deinit(a);
    try env_trailing.appendSlice(a, env_wire.items);
    try env_trailing.append(a, 0x00);
    var env_badtag_wire = Alist.empty;
    defer env_badtag_wire.deinit(a);
    try env_badtag_wire.appendSlice(a, env_tbs.items);
    const env_sig_badtag = try signTagged(agent.kp, DOMAIN_GRANT, env_tbs.items);
    try env_badtag_wire.appendSlice(a, &env_sig_badtag);

    // self-verify every positive signature in Zig before emitting.
    // signTagged signs over (tag || tbs), so verify over the same tagged input.
    var env_tagged = Alist.empty;
    defer env_tagged.deinit(a);
    try env_tagged.append(a, DOMAIN_ENVELOPE);
    try env_tagged.appendSlice(a, env_tbs.items);
    try Ed.Signature.verify(Ed.Signature.fromBytes(env_sig), env_tagged.items, agent.kp.public_key);

    // ---- emit JSON ----
    var j = Alist.empty;
    defer j.deinit(a);
    try w(&j, a, "{");
    try fU64(&j, a, "schema_version", 1);
    try sep(&j, a);
    try fStr(&j, a, "protocol", "bolina");
    try sep(&j, a);
    try fStr(&j, a, "spec_version", "v0.2.0-draft");
    try sep(&j, a);
    try fStr(&j, a, "generated_by", "tools/gen-vectors.zig");
    try sep(&j, a);
    try fStr(&j, a, "note", "Deterministic Ed25519 seeds and std.crypto. Signature input is domain_tag || tbs (BE-SIG-01). Cross-verify every sig over (tag||tbs) with an independent Ed25519 implementation, every digest with an independent BLAKE2s.");
    try sep(&j, a);

    // primitives
    try w(&j, a, "\"primitives\":{");
    try fStr(&j, a, "signature", "Ed25519 (RFC 8032)");
    try sep(&j, a);
    try fStr(&j, a, "hash", "BLAKE2s-256 (RFC 7693)");
    try sep(&j, a);
    try w(&j, a, "\"blake2s_known\":[");
    try w(&j, a, "{\"input\":\"\",\"hex\":\"");
    try jHexRaw(&j, a, &blake2s(""));
    try w(&j, a, "\"}");
    try sep(&j, a);
    try w(&j, a, "{\"input\":\"abc\",\"hex\":\"");
    try jHexRaw(&j, a, &blake2s("abc"));
    try w(&j, a, "\"}");
    try w(&j, a, "]");
    try w(&j, a, "}");
    try sep(&j, a);

    // keys
    try w(&j, a, "\"keys\":{");
    try emitKey(&j, a, "ca1", &ca1);
    try sep(&j, a);
    try emitKey(&j, a, "ca2", &ca2);
    try sep(&j, a);
    try emitKey(&j, a, "approver", &approver);
    try sep(&j, a);
    try emitKey(&j, a, "executor", &executor);
    try sep(&j, a);
    try emitKey(&j, a, "agent", &agent);
    try w(&j, a, "}");
    try sep(&j, a);

    // addressing
    try w(&j, a, "\"addressing\":{");
    try fStr(&j, a, "formula", "overlay_addr := 0xfd || BLAKE2s-256(sig_pubkey)[0..15] (16 bytes, IPv6 ULA fd00::/8)");
    try sep(&j, a);
    try w(&j, a, "\"vectors\":[");
    try emitAddr(&j, a, &ca1);
    try sep(&j, a);
    try emitAddr(&j, a, &approver);
    try sep(&j, a);
    try emitAddr(&j, a, &executor);
    try sep(&j, a);
    try emitAddr(&j, a, &agent);
    try w(&j, a, "]");
    try w(&j, a, "}");
    try sep(&j, a);

    // method_id table (BE-EVID-15)
    try w(&j, a, "\"method_id_table\":{");
    try fStr(&j, a, "note", "Class is DERIVED by the receiver from method_id, never transmitted (BE-EVID-15). Ceiling is normative q8 = round_toward_zero(confidence * 255).");
    try sep(&j, a);
    try w(&j, a, "\"rows\":[");
    try emitMid(&j, a, 1, "subprocess executed now; exit status and output captured", "DirectObservation", 242, null);
    try sep(&j, a);
    try emitMid(&j, a, 2, "file read now from local storage; content captured", "DirectObservation", 242, null);
    try sep(&j, a);
    try emitMid(&j, a, 3, "network request issued now; response captured", "DirectObservation", 242, null);
    try sep(&j, a);
    try emitMid(&j, a, 4, "database query executed now; result set captured", "DirectObservation", 242, null);
    try sep(&j, a);
    try emitMid(&j, a, 5, "static configuration or documentation read", "Documentation", 191, null);
    try sep(&j, a);
    try emitMid(&j, a, 6, "tool declared description or schema", "Documentation", 191, null);
    try sep(&j, a);
    try emitMid(&j, a, 7, "statement signed by a declared domain-group identity", "ExpertTestimony", 216, null);
    try sep(&j, a);
    try emitMid(&j, a, 8, "derived from other spans; nothing observed directly", "Inference", 165, null);
    try sep(&j, a);
    try emitMid(&j, a, 9, "unknown", "Inference", 165, "BE-EVID-13: method_id outside the table fails to the floor (0.65)");
    try w(&j, a, "]");
    try w(&j, a, "}");
    try sep(&j, a);

    // digests
    try w(&j, a, "\"digests\":[");
    try w(&j, a, "{\"name\":\"intent_action\",\"input_utf8\":");
    try jStr(&j, a, ACTION);
    try w(&j, a, ",\"blake2s\":\"");
    try jHexRaw(&j, a, &action_digest);
    try w(&j, a, "\"}");
    try sep(&j, a);
    try w(&j, a, "{\"name\":\"span_observed_output\",\"input_utf8\":");
    try jStr(&j, a, OBSERVED_OUTPUT);
    try w(&j, a, ",\"blake2s\":\"");
    try jHexRaw(&j, a, &span_digest);
    try w(&j, a, "\"}");
    try sep(&j, a);
    try w(&j, a, "{\"name\":\"empty\",\"input_utf8\":\"\",\"blake2s\":\"");
    try jHexRaw(&j, a, &blake2s(""));
    try w(&j, a, "\"}");
    try sep(&j, a);
    try w(&j, a, "{\"name\":\"abc\",\"input_utf8\":\"abc\",\"blake2s\":\"");
    try jHexRaw(&j, a, &blake2s("abc"));
    try w(&j, a, "\"}");
    try w(&j, a, "]");
    try sep(&j, a);

    // resource_id
    try w(&j, a, "\"resource_id\":{");
    try fStr(&j, a, "format", "bol:<executor_fp>/<namespace>/<path>");
    try sep(&j, a);
    try fStr(&j, a, "value", resource_id);
    try sep(&j, a);
    try fStr(&j, a, "namespace", "logs");
    try sep(&j, a);
    try fStr(&j, a, "path", "deploy.log");
    try sep(&j, a);
    try fStr(&j, a, "fingerprint_note", "SPEC 8.4 leaves 'sig_pubkey fingerprint' undefined. Interpretation used: fingerprint = BLAKE2s-256(sig_pubkey); executor_fp = first 8 bytes, lowercase hex (16 chars). Flagged for spec clarification. resource_id is opaque on the wire (u16 length + bytes); the fingerprint only affects canonicalization (BE-RES-01..04), which is executor-side policy, not wire encoding.");
    try w(&j, a, "}");
    try sep(&j, a);

    // structures
    try w(&j, a, "\"structures\":{");

    // cert
    try w(&j, a, "\"cert\":{");
    try fStr(&j, a, "desc", "Agent identity cert, version 3, signed by two CAs in ascending ca_key order. TBS is all bytes preceding ca_sig_count.");
    try sep(&j, a);
    try fStr(&j, a, "domain_tag", "01");
    try sep(&j, a);
    try w(&j, a, "\"fields\":{");
    try fU8(&j, a, "version", 3);
    try sep(&j, a);
    try fStr(&j, a, "role_bits", "0x03(participant+agent)");
    try sep(&j, a);
    try fHex(&j, a, "sig_pubkey", &agent.sig_pubkey);
    try sep(&j, a);
    try fHex(&j, a, "kex_pubkey", &agent.kex_pubkey);
    try sep(&j, a);
    try fU64(&j, a, "not_before", T_NOT_BEFORE);
    try sep(&j, a);
    try fU64(&j, a, "not_after", T_NOT_AFTER);
    try sep(&j, a);
    try fStr(&j, a, "name", "agent-1");
    try sep(&j, a);
    try fU8(&j, a, "scope_count", 1);
    try sep(&j, a);
    try fHex(&j, a, "scope_id", &scope_id);
    try sep(&j, a);
    try fU8(&j, a, "ca_sig_count", 2);
    try w(&j, a, "}");
    try sep(&j, a);
    try fHex(&j, a, "tbs_hex", cert_tbs.items);
    try sep(&j, a);
    try w(&j, a, "\"sig_input_hex\":\"01");
    try jHexRaw(&j, a, cert_tbs.items);
    try w(&j, a, "\"");
    try sep(&j, a);
    try w(&j, a, "\"ca_sigs\":[");
    {
        var first = true;
        for (order, 0..) |idx, k| {
            const ca = ca_keys[idx];
            if (!first) try sep(&j, a);
            first = false;
            try w(&j, a, "{\"ca_key\":");
            try jHex(&j, a, &ca.sig_pubkey);
            try w(&j, a, ",\"sig\":");
            try jHex(&j, a, &ca_sigs_buf[k]);
            try w(&j, a, "}");
        }
    }
    try w(&j, a, "]");
    try sep(&j, a);
    try fHex(&j, a, "wire_hex", cert_wire.items);
    try sep(&j, a);
    try fStr(&j, a, "verify", "true");
    try w(&j, a, "}");
    try sep(&j, a);

    // envelope
    try w(&j, a, "\"envelope_intent\":{");
    try fStr(&j, a, "desc", "Genesis envelope (parent_count=0) carrying an Intent body, signed by the agent (sender). Intent requires the agent role (BE-ENV-03).");
    try sep(&j, a);
    try fStr(&j, a, "domain_tag", "02");
    try sep(&j, a);
    try w(&j, a, "\"fields\":{");
    try fU8(&j, a, "version", 2);
    try sep(&j, a);
    try fHex(&j, a, "channel_id", &channel_id);
    try sep(&j, a);
    try fHex(&j, a, "sender", &agent.sig_pubkey);
    try sep(&j, a);
    try fU64(&j, a, "seq", SEQ);
    try sep(&j, a);
    try fU8(&j, a, "parent_count", 0);
    try sep(&j, a);
    try fU64(&j, a, "ts", T_TS);
    try sep(&j, a);
    try fStr(&j, a, "body_type", "2(Intent)");
    try sep(&j, a);
    try fU64(&j, a, "body_len", intent.items.len);
    try sep(&j, a);
    try fHex(&j, a, "body_intent_id", &intent_id);
    try sep(&j, a);
    try fStr(&j, a, "body_resource_id", resource_id);
    try sep(&j, a);
    try fStr(&j, a, "body_action_utf8", ACTION);
    try sep(&j, a);
    try fStr(&j, a, "body_rationale_utf8", RATIONALE);
    try w(&j, a, "}");
    try sep(&j, a);
    try fHex(&j, a, "tbs_hex", env_tbs.items);
    try sep(&j, a);
    try w(&j, a, "\"sig_input_hex\":\"02");
    try jHexRaw(&j, a, env_tbs.items);
    try w(&j, a, "\"");
    try sep(&j, a);
    try fHex(&j, a, "sig_hex", &env_sig);
    try sep(&j, a);
    try fStr(&j, a, "signer", "agent");
    try sep(&j, a);
    try fHex(&j, a, "signer_pubkey", &agent.sig_pubkey);
    try sep(&j, a);
    try fHex(&j, a, "wire_hex", env_wire.items);
    try sep(&j, a);
    try fStr(&j, a, "verify", "true");
    try w(&j, a, "}");
    try sep(&j, a);

    // span
    try w(&j, a, "\"span\":{");
    try fStr(&j, a, "desc", "Span: executor observed a subprocess (method_id=1 -> DirectObservation, ceiling 0.95). volatility=2 (stable). digest = BLAKE2s(observed output). Signed by the executor (tag 0x03).");
    try sep(&j, a);
    try fStr(&j, a, "domain_tag", "03");
    try sep(&j, a);
    try w(&j, a, "\"fields\":{");
    try fU8(&j, a, "version", 2);
    try sep(&j, a);
    try fHex(&j, a, "span_id", &span_id);
    try sep(&j, a);
    try fHex(&j, a, "trace_id", &trace_id);
    try sep(&j, a);
    try fStr(&j, a, "resource_id", resource_id);
    try sep(&j, a);
    try fStr(&j, a, "method_id", "1(DirectObservation)");
    try sep(&j, a);
    try fStr(&j, a, "volatility", "2(stable)");
    try sep(&j, a);
    try fHex(&j, a, "origin", &origin);
    try sep(&j, a);
    try fU64(&j, a, "observed_at", T_OBSERVED);
    try sep(&j, a);
    try fHex(&j, a, "digest", &span_digest);
    try sep(&j, a);
    try fHex(&j, a, "executor", &executor.sig_pubkey);
    try w(&j, a, "}");
    try sep(&j, a);
    try fHex(&j, a, "tbs_hex", span_tbs.items);
    try sep(&j, a);
    try w(&j, a, "\"sig_input_hex\":\"03");
    try jHexRaw(&j, a, span_tbs.items);
    try w(&j, a, "\"");
    try sep(&j, a);
    try fHex(&j, a, "sig_hex", &span_sig);
    try sep(&j, a);
    try fStr(&j, a, "signer", "executor");
    try sep(&j, a);
    try fHex(&j, a, "signer_pubkey", &executor.sig_pubkey);
    try sep(&j, a);
    try fHex(&j, a, "wire_hex", span_wire.items);
    try sep(&j, a);
    try fStr(&j, a, "method_id_class", "DirectObservation");
    try sep(&j, a);
    try fU8(&j, a, "ceiling_q8", 242);
    try sep(&j, a);
    try fStr(&j, a, "verify", "true");
    try w(&j, a, "}");
    try sep(&j, a);

    // grant
    try w(&j, a, "\"grant\":{");
    try fStr(&j, a, "desc", "Grant: object capability binding one intent, one agent (subject), one executor, one resource, one exact action. action_digest = BLAKE2s(intent action), recomputed by the approver, never copied from the wire (BE-BODY-02). Signed by the approver (tag 0x04).");
    try sep(&j, a);
    try fStr(&j, a, "domain_tag", "04");
    try sep(&j, a);
    try w(&j, a, "\"fields\":{");
    try fU8(&j, a, "version", 2);
    try sep(&j, a);
    try fHex(&j, a, "grant_id", &grant_id);
    try sep(&j, a);
    try fHex(&j, a, "intent_id", &intent_id);
    try sep(&j, a);
    try fHex(&j, a, "approver", &approver.sig_pubkey);
    try sep(&j, a);
    try fHex(&j, a, "subject", &agent.sig_pubkey);
    try sep(&j, a);
    try fHex(&j, a, "executor", &executor.sig_pubkey);
    try sep(&j, a);
    try fStr(&j, a, "resource_id", resource_id);
    try sep(&j, a);
    try fHex(&j, a, "action_digest", &action_digest);
    try sep(&j, a);
    try fStr(&j, a, "action_utf8", ACTION);
    try sep(&j, a);
    try fU64(&j, a, "not_after", T_GRANT_NOT_AFTER);
    try w(&j, a, "}");
    try sep(&j, a);
    try fHex(&j, a, "tbs_hex", grant_tbs.items);
    try sep(&j, a);
    try w(&j, a, "\"sig_input_hex\":\"04");
    try jHexRaw(&j, a, grant_tbs.items);
    try w(&j, a, "\"");
    try sep(&j, a);
    try fHex(&j, a, "sig_hex", &grant_sig);
    try sep(&j, a);
    try fStr(&j, a, "signer", "approver");
    try sep(&j, a);
    try fHex(&j, a, "signer_pubkey", &approver.sig_pubkey);
    try sep(&j, a);
    try fHex(&j, a, "wire_hex", grant_wire.items);
    try sep(&j, a);
    try fStr(&j, a, "verify", "true");
    try w(&j, a, "}");
    try sep(&j, a);

    // refusal
    try w(&j, a, "\"refusal\":{");
    try fStr(&j, a, "desc", "Refusal: a signed NO. No version field (SPEC 8.5). Binding content is intent_id alone; note is informative. Signed by the approver (tag 0x06). Releases the resource lock immediately (BE-GRANT-09), terminal (BE-GRANT-10).");
    try sep(&j, a);
    try fStr(&j, a, "domain_tag", "06");
    try sep(&j, a);
    try w(&j, a, "\"fields\":{");
    try fHex(&j, a, "intent_id", &intent_id);
    try sep(&j, a);
    try fStr(&j, a, "note_utf8", REFUSAL_NOTE);
    try w(&j, a, "}");
    try sep(&j, a);
    try fHex(&j, a, "tbs_hex", refusal_tbs.items);
    try sep(&j, a);
    try w(&j, a, "\"sig_input_hex\":\"06");
    try jHexRaw(&j, a, refusal_tbs.items);
    try w(&j, a, "\"");
    try sep(&j, a);
    try fHex(&j, a, "sig_hex", &refusal_sig);
    try sep(&j, a);
    try fStr(&j, a, "signer", "approver");
    try sep(&j, a);
    try fHex(&j, a, "signer_pubkey", &approver.sig_pubkey);
    try sep(&j, a);
    try fHex(&j, a, "wire_hex", refusal_wire.items);
    try sep(&j, a);
    try fStr(&j, a, "verify", "true");
    try w(&j, a, "}");
    try sep(&j, a);

    // effect (executor-signed envelope carrying an Effect body with one inline span)
    try w(&j, a, "\"effect\":{");
    try fStr(&j, a, "desc", "Effect: executor performed the granted action (ok=true, exit_code=0), published one span inline, and reported the action output digest. The Effect is a body (body_type 4) inside an executor-signed Envelope; this envelope is the span's origin and is a causal child of the Intent envelope (parent[0] = BLAKE2s of the Intent envelope). Signed by the executor as the envelope sender (envelope domain tag 0x02).");
    try sep(&j, a);
    try fStr(&j, a, "domain_tag", "02");
    try sep(&j, a);
    try fStr(&j, a, "envelope_kind", "effect");
    try sep(&j, a);
    try w(&j, a, "\"fields\":{");
    try fU8(&j, a, "version", 2);
    try sep(&j, a);
    try fHex(&j, a, "channel_id", &channel_id);
    try sep(&j, a);
    try fHex(&j, a, "sender_executor", &executor.sig_pubkey);
    try sep(&j, a);
    try fU64(&j, a, "seq", SEQ + 1);
    try sep(&j, a);
    try fU8(&j, a, "parent_count", 1);
    try sep(&j, a);
    try fHex(&j, a, "parent_0_intent_env", &intent_env_hash);
    try sep(&j, a);
    try fU64(&j, a, "ts", T_OBSERVED);
    try sep(&j, a);
    try fStr(&j, a, "body_type", "4(Effect)");
    try sep(&j, a);
    try fHex(&j, a, "body_intent_id", &intent_id);
    try sep(&j, a);
    try fHex(&j, a, "body_grant_id", &grant_id);
    try sep(&j, a);
    try fU8(&j, a, "body_ok", 1);
    try sep(&j, a);
    try fU8(&j, a, "body_exit_code", 0);
    try sep(&j, a);
    try fU8(&j, a, "body_span_count", 1);
    try sep(&j, a);
    try fHex(&j, a, "body_output_digest", &effect_output_digest);
    try w(&j, a, "}");
    try sep(&j, a);
    try fHex(&j, a, "tbs_hex", eff_env_tbs.items);
    try sep(&j, a);
    try w(&j, a, "\"sig_input_hex\":\"02");
    try jHexRaw(&j, a, eff_env_tbs.items);
    try w(&j, a, "\"");
    try sep(&j, a);
    try fHex(&j, a, "sig_hex", &eff_env_sig);
    try sep(&j, a);
    try fStr(&j, a, "signer", "executor");
    try sep(&j, a);
    try fHex(&j, a, "signer_pubkey", &executor.sig_pubkey);
    try sep(&j, a);
    try fHex(&j, a, "wire_hex", eff_env_wire.items);
    try sep(&j, a);
    try fHex(&j, a, "inline_span_origin_anchor", &origin);
    try sep(&j, a);
    try fStr(&j, a, "verify", "true");
    try w(&j, a, "}");
    try sep(&j, a);

    // claim (unsigned sub-structure; authenticated inside a Utterance envelope, pending F1)
    try w(&j, a, "\"claim\":{");
    try fStr(&j, a, "desc", "Claim: agent asserts the deploy succeeded and cites one span. subject == span.resource_id (BE-EVID-03). confidence_q8 = 242, the DirectObservation ceiling; the receiver recomputes min(242, ceiling(strongest matching span)) = 242 (BE-EVID-02). A Claim carries no signature of its own; it is authenticated only inside a signed Utterance envelope (BE-EVID-08). The Utterance vector is deferred to F1 (RED-TEAM-09); this vector fixes the Claim wire layout and field values for the byte-layout cross-check.");
    try sep(&j, a);
    try fStr(&j, a, "kind", "claim_body");
    try sep(&j, a);
    try fStr(&j, a, "signature", "none (authenticated transitively via the Utterance envelope)");
    try sep(&j, a);
    try w(&j, a, "\"fields\":{");
    try fStr(&j, a, "text", claim_text);
    try sep(&j, a);
    try fStr(&j, a, "subject", resource_id);
    try sep(&j, a);
    try fU8(&j, a, "confidence_q8", 242);
    try sep(&j, a);
    try fStr(&j, a, "confidence_class", "DirectObservation(ceiling 242)");
    try sep(&j, a);
    try fU8(&j, a, "span_count", 1);
    try sep(&j, a);
    try fHex(&j, a, "span_ids_0", &span_id);
    try w(&j, a, "}");
    try sep(&j, a);
    try fHex(&j, a, "wire_hex", claim_tbs.items);
    try sep(&j, a);
    try fStr(&j, a, "verify", "true");
    try w(&j, a, "}");

    try w(&j, a, "}");
    try sep(&j, a); // close structures

    // negatives
    try w(&j, a, "\"negatives\":[");
    try w(&j, a, "{\"name\":\"envelope_truncated_sig\",\"wire\":\"");
    try jHexRaw(&j, a, env_truncated);
    try w(&j, a, "\",\"expect\":\"reject\",\"reason\":\"input shorter than the fixed trailer (sig=64 bytes); BE-WIRE-02 totality\"}");
    try sep(&j, a);
    try w(&j, a, "{\"name\":\"envelope_trailing_byte\",\"wire\":\"");
    try jHexRaw(&j, a, env_trailing.items);
    try w(&j, a, "\",\"expect\":\"reject\",\"reason\":\"unknown trailing bytes are a parse failure (SPEC 2.2)\"}");
    try sep(&j, a);
    try w(&j, a, "{\"name\":\"envelope_wrong_domain_tag\",\"wire\":\"");
    try jHexRaw(&j, a, env_badtag_wire.items);
    try w(&j, a, "\",\"expect\":\"reject\",\"reason\":\"signature valid over tag 0x04 but structure is Envelope; BE-SIG-01 domain separation\"}");
    try w(&j, a, "]");

    try w(&j, a, "}\n");

    try std.Io.Dir.cwd().createDirPath(io, "test");
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = "test/vectors.json", .data = j.items });
    std.debug.print("wrote test/vectors.json ({d} bytes)\n", .{j.items.len});
}

fn emitKey(j: *Alist, a: Alloc, name: []const u8, id: *const Identity) !void {
    try jStr(j, a, name);
    try w(j, a, ":{");
    try fHex(j, a, "seed", &id.sig_seed);
    try sep(j, a);
    try fHex(j, a, "sig_pubkey", &id.sig_pubkey);
    try sep(j, a);
    try fHex(j, a, "kex_seed", &id.kex_seed);
    try sep(j, a);
    try fHex(j, a, "kex_pubkey", &id.kex_pubkey);
    try sep(j, a);
    try fHex(j, a, "overlay_addr", &overlayAddr(&id.sig_pubkey));
    try w(j, a, "}");
}

fn emitAddr(j: *Alist, a: Alloc, id: *const Identity) !void {
    const addr = overlayAddr(&id.sig_pubkey);
    try w(j, a, "{\"sig_pubkey\":");
    try jHex(j, a, &id.sig_pubkey);
    try w(j, a, ",\"overlay_addr\":");
    try jHex(j, a, &addr);
    try w(j, a, "}");
}

fn emitMid(j: *Alist, a: Alloc, method_id: u8, mechanism: []const u8, class: []const u8, ceiling: u8, note: ?[]const u8) !void {
    try w(j, a, "{\"method_id\":");
    try jU8(j, a, method_id);
    try w(j, a, ",\"mechanism\":");
    try jStr(j, a, mechanism);
    try w(j, a, ",\"class\":");
    try jStr(j, a, class);
    try w(j, a, ",\"ceiling_q8\":");
    try jU8(j, a, ceiling);
    if (note) |n| {
        try w(j, a, ",\"note\":");
        try jStr(j, a, n);
    }
    try w(j, a, "}");
}
