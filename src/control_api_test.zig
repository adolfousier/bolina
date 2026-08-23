// control_api_test.zig
//
// Literal binding tests for src/control_api.zig (D-091 P2). The API is a
// facade, so these pin the facade contract: F5 error table (400/409/422),
// idempotency echo (F4), ring drop-oldest semantics with monotonic seq,
// SSE replay filtering by cursor (F6) and Prometheus metrics shape.
// Transport behaviour lives in control_test.zig; resolver/intent deep
// behaviour lives in their own files. Fixtures reuse cert_test_helpers
// (executor E1, fp 549b6dd68ceeab0d).

const std = @import("std");
const api_mod = @import("control_api.zig");
const intent_mod = @import("intent.zig");
const resolver = @import("resolver.zig");
const h = @import("cert_test_helpers.zig");

const FP1 = "549b6dd68ceeab0d";
const RES_A = "bol:" ++ FP1 ++ "/files/reports/q3.pdf";
const RES_FOREIGN = "bol:cc6009c6dabe53b1/print/queue/main";

const ID_A_HEX = "aa" ** 16;

var shared_table: intent_mod.Table = undefined;

fn makeApi() struct { api: *api_mod.Api, ring: *api_mod.EventRing } {
    static_ring = .{};
    shared_table = intent_mod.Table.init();
    static_resolver = resolver.Resolver.init(&h.pubkeyOf(0xE1));
    static_resolver.add(RES_A) catch unreachable;
    static_api = .{
        .resolver = &static_resolver,
        .table = &shared_table,
        .ring = &static_ring,
    };
    return .{ .api = &static_api, .ring = &static_ring };
}

var static_api: api_mod.Api = undefined;
var static_ring: api_mod.EventRing = undefined;
var static_resolver: resolver.Resolver = undefined;

test "P2 ring: seq is monotonic, order oldest-first, drop-oldest counts overflow" {
    var ring: api_mod.EventRing = .{};
    const id1 = [_]u8{0x11} ** 16;
    const id2 = [_]u8{0x22} ** 16;
    ring.publish(.grant_consumed, id1, 100);
    ring.publish(.grant_published, id2, 200);
    try std.testing.expectEqual(@as(u64, 3), ring.next_seq);
    try std.testing.expectEqual(@as(usize, 2), ring.count);
    try std.testing.expectEqual(@as(u64, 0), ring.dropped_total);

    // Fill past cap: oldest entries drop, dropped_total counts every loss.
    var i: usize = 0;
    while (i < api_mod.RING_CAP + 5) : (i += 1) {
        var gid: [16]u8 = undefined;
        @memset(&gid, @intCast(i % 256));
        ring.publish(.grant_consumed, gid, @intCast(300 + i));
    }
    try std.testing.expectEqual(@as(u64, 7), ring.dropped_total);
    // Oldest survivor is seq 8 (1..7 dropped after wrap refill).
    var out: [16384]u8 = undefined;
    var api_stub: api_mod.Api = undefined;
    api_stub = .{ .resolver = undefined, .table = undefined, .ring = &ring };
    const res = try api_stub.eventsSseBody(&out, 0);
    try std.testing.expectEqual(@as(u16, 200), res.status);
    // First frame must be id: 8 (the first surviving sequence).
    try std.testing.expect(std.mem.startsWith(u8, out[0..res.body_len], "id: 8\n"));
}

test "P2 postIntent: happy path admits pending and echoes the hex id" {
    const f = makeApi();
    var buf: [512]u8 = undefined;
    var body: [512]u8 = undefined;
    const raw = std.fmt.bufPrint(&body, "{{\"intent_id\":\"{s}\",\"resource_id\":\"{s}\",\"action\":\"read\",\"rationale\":\"e2e\"}}", .{ ID_A_HEX, RES_A }) catch unreachable;
    const res = try f.api.postIntent(raw, &buf, 1000);
    try std.testing.expectEqual(@as(u16, 202), res.status);
    try std.testing.expect(std.mem.startsWith(u8, buf[0..res.body_len], "accepted " ++ ID_A_HEX));
    try std.testing.expectEqual(@as(u64, 1), f.api.admitted_total);
    try std.testing.expectEqual(@as(usize, 1), f.api.table.len);
    try std.testing.expectEqual(intent_mod.State.pending, f.api.table.entries[0].state);
}

test "P2 postIntent: second intent on the same resource reads 409 conflict" {
    const f = makeApi();
    var out: [512]u8 = undefined;
    const mk = struct {
        fn call(a: *api_mod.Api, o: []u8, hex: []const u8, now: u64) !u16 {
            var b: [512]u8 = undefined;
            const raw = std.fmt.bufPrint(&b, "{{\"intent_id\":\"{s}\",\"resource_id\":\"{s}\",\"action\":\"r\",\"rationale\":\"x\"}}", .{ hex, RES_A }) catch unreachable;
            return (try a.postIntent(raw, o, now)).status;
        }
    }.call;
    try std.testing.expectEqual(@as(u16, 202), try mk(f.api, &out, ID_A_HEX, 1000));
    try std.testing.expectEqual(@as(u16, 409), try mk(f.api, &out, "bb" ** 16, 1001));
    try std.testing.expectEqual(@as(u64, 1), f.api.refused_conflict_total);
}

test "P2 postIntent: unknown resource and foreign executor read 422" {
    const f = makeApi();
    var out: [512]u8 = undefined;
    var b: [512]u8 = undefined;
    const raw = std.fmt.bufPrint(&b, "{{\"intent_id\":\"{s}\",\"resource_id\":\"bol:{s}/files/ghost\",\"action\":\"r\",\"rationale\":\"x\"}}", .{ ID_A_HEX, FP1 }) catch unreachable;
    const res = try f.api.postIntent(raw, &out, 1000);
    try std.testing.expectEqual(@as(u16, 422), res.status);
    try std.testing.expectEqual(@as(u64, 1), f.api.refused_unprocessable_total);

    var b2: [512]u8 = undefined;
    const raw2 = std.fmt.bufPrint(&b2, "{{\"intent_id\":\"{s}\",\"resource_id\":\"{s}\",\"action\":\"r\",\"rationale\":\"x\"}}", .{ ID_A_HEX, RES_FOREIGN }) catch unreachable;
    const res2 = try f.api.postIntent(raw2, &out, 1001);
    try std.testing.expectEqual(@as(u16, 422), res2.status);
}

test "P2 postIntent: malformed JSON family all read 400" {
    const f = makeApi();
    var out: [512]u8 = undefined;
    // bad hex
    var b1: [512]u8 = undefined;
    const r1 = try f.api.postIntent(std.fmt.bufPrint(&b1, "{{\"intent_id\":\"zz\",\"resource_id\":\"{s}\",\"action\":\"r\",\"rationale\":\"x\"}}", .{RES_A}) catch unreachable, &out, 1000);
    try std.testing.expectEqual(@as(u16, 400), r1.status);
    // missing field
    const r2 = try f.api.postIntent("{\"intent_id\":\"" ++ ID_A_HEX ++ "\",\"action\":\"r\"}", &out, 1000);
    try std.testing.expectEqual(@as(u16, 400), r2.status);
    // wrong id length
    var b3: [512]u8 = undefined;
    const r3 = try f.api.postIntent(std.fmt.bufPrint(&b3, "{{\"intent_id\":\"aabb\",\"resource_id\":\"{s}\",\"action\":\"r\",\"rationale\":\"x\"}}", .{RES_A}) catch unreachable, &out, 1000);
    try std.testing.expectEqual(@as(u16, 400), r3.status);
    // escape attempt fails closed
    var b4: [512]u8 = undefined;
    const r4 = try f.api.postIntent(std.fmt.bufPrint(&b4, "{{\"intent_id\":\"{s}\",\"resource_id\":\"bol:x\\\\/y\",\"action\":\"r\",\"rationale\":\"x\"}}", .{ID_A_HEX}) catch unreachable, &out, 1000);
    try std.testing.expectEqual(@as(u16, 400), r4.status);
    try std.testing.expectEqual(@as(u64, 4), f.api.bad_request_total);
}

test "P2 getIntentState: pending found by decoded id, unknown reads 404" {
    const f = makeApi();
    var out: [512]u8 = undefined;
    var b: [512]u8 = undefined;
    const raw = std.fmt.bufPrint(&b, "{{\"intent_id\":\"{s}\",\"resource_id\":\"{s}\",\"action\":\"r\",\"rationale\":\"x\"}}", .{ ID_A_HEX, RES_A }) catch unreachable;
    _ = try f.api.postIntent(raw, &out, 1000);

    const hex: [32]u8 = ID_A_HEX[0..].*;
    const id_bytes = api_mod.parseIdHex(&hex).?;
    const hit = try f.api.getIntentState(id_bytes, &out);
    try std.testing.expectEqual(@as(u16, 200), hit.status);
    try std.testing.expectEqualStrings("pending\n", out[0..hit.body_len]);

    const other = [_]u8{'c'} ** 32;
    const miss = try f.api.getIntentState(api_mod.parseIdHex(&other).?, &out);
    try std.testing.expectEqual(@as(u16, 404), miss.status);
}

test "P2 eventsSseBody: cursor filters, frame carries tag and grant id hex" {
    const f = makeApi();
    var out: [16384]u8 = undefined;
    const g1 = [_]u8{0xAB} ** 16;
    f.ring.publish(.grant_consumed, g1, 500);
    f.ring.publish(.grant_published, g1, 600);

    const none = try f.api.eventsSseBody(&out, 2);
    try std.testing.expectEqualStrings(": no new events\n\n", out[0..none.body_len]);

    const both = try f.api.eventsSseBody(&out, 0);
    const text = out[0..both.body_len];
    try std.testing.expect(std.mem.indexOf(u8, text, "id: 1\nevent: grant_consumed\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "\"grant_id\":\"abababababababababababababababab\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "\"ts_ms\":600}") != null);

    const since_one = try f.api.eventsSseBody(&out, 1);
    try std.testing.expect(std.mem.startsWith(u8, out[0..since_one.body_len], "id: 2\n"));
}

test "P2 metrics: counters render one per line with values" {
    const f = makeApi();
    var out: [2048]u8 = undefined;
    f.api.admitted_total = 3;
    f.ring.dropped_total = 1;
    const res = try f.api.metricsBody(&out, 9, 2, 4);
    try std.testing.expectEqual(@as(u16, 200), res.status);
    const text = out[0..res.body_len];
    try std.testing.expect(std.mem.indexOf(u8, text, "bolina_intents_admitted_total 3\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "bolina_events_dropped_total 1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "bolina_control_requests_total 9\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "bolina_control_auth_refused_total 2\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "bolina_control_timeouts_total 4\n") != null);
}

test "P2 parseSince: absent query reads zero, junk reads error" {
    try std.testing.expectEqual(@as(u64, 0), try api_mod.Api.parseSince("/v1/events"));
    try std.testing.expectEqual(@as(u64, 5), try api_mod.Api.parseSince("/v1/events?since=5"));
    try std.testing.expectError(api_mod.ApiError.MalformedTarget, api_mod.Api.parseSince("/v1/events?page=2"));
    try std.testing.expectError(api_mod.ApiError.MalformedTarget, api_mod.Api.parseSince("/v1/events?since=x"));
}
