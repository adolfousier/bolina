// http_parse_test.zig
//
// v0.6 control plane: unit tests for the pure HTTP parser. Every pinned
// rejection gets a test (F5 table), plus the incremental contract that
// makes fragmented streams survivable (F2) and the smuggling guards
// (single-SP line, obs-fold, colon-space, TE refusal).

const std = @import("std");
const hp = @import("http_parse.zig");

test "GET parses: method, target with query, zero body" {
    const req = try hp.parse("GET /v1/events?since=7 HTTP/1.1\r\nHost: x\r\n\r\n");
    try std.testing.expectEqual(hp.Method.get, req.method);
    try std.testing.expectEqualStrings("/v1/events?since=7", req.target);
    try std.testing.expectEqual(@as(usize, 0), req.content_length);
}

test "POST with complete body parses; body slices exactly clen bytes" {
    const raw = "POST /v1/intents HTTP/1.1\r\nContent-Length: 11\r\n\r\nhello world";
    const req = try hp.parse(raw);
    try std.testing.expectEqual(hp.Method.post, req.method);
    try std.testing.expectEqual(@as(usize, 11), req.content_length);
    const body = raw[req.body_start..][0..req.content_length];
    try std.testing.expectEqualStrings("hello world", body);
}

test "incremental feed: fragmented headers stay Incomplete until whole, then parse" {
    const full = "POST /x HTTP/1.1\r\nContent-Length: 2\r\n\r\nok";
    const half = hp.parse(full[0..20]);
    try std.testing.expectError(error.Incomplete, half); // mid-header-line cut
    const req = try hp.parse(full); // caller appended the rest
    try std.testing.expectEqual(@as(usize, 2), req.content_length);
    // Body split from headers is also just Incomplete, never a misparse.
    try std.testing.expectError(error.Incomplete, hp.parse(full[0 .. full.len - 1]));
}

test "header block without terminator grows past cap and dies HeadersTooLarge" {
    var buf: [hp.HEADER_CAP]u8 = undefined;
    @memset(&buf, 'a');
    buf[0] = 'G'; // shape does not matter: no CRLFCRLF anywhere
    try std.testing.expectError(error.HeadersTooLarge, hp.parse(&buf));
}

test "pinned rejections: version, method, chunked, length-required" {
    try std.testing.expectError(error.UnsupportedVersion, hp.parse("GET / HTTP/2.0\r\n\r\n"));
    try std.testing.expectError(error.MalformedRequest, hp.parse("GET / HTTX/1.1\r\n\r\n"));
    try std.testing.expectError(error.UnsupportedMethod, hp.parse("PUT / HTTP/1.1\r\n\r\n"));
    try std.testing.expectError(
        error.ChunkedNotSupported,
        hp.parse("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"),
    );
    try std.testing.expectError(error.LengthRequired, hp.parse("POST / HTTP/1.1\r\nHost: x\r\n\r\n"));
}

test "duplicate Content-Length equal values pass; conflicting refuse" {
    const dup_ok = try hp.parse("POST / HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc");
    try std.testing.expectEqual(@as(usize, 3), dup_ok.content_length);
    try std.testing.expectError(
        error.ConflictingLength,
        hp.parse("POST / HTTP/1.1\r\nContent-Length: 3\r\ncontent-length: 4\r\n\r\nabcd"),
    );
}

test "smuggling guards: obs-fold, space before colon, double-SP request line" {
    try std.testing.expectError(
        error.MalformedRequest,
        hp.parse("GET / HTTP/1.1\r\n X-Fold: on\r\nHost: x\r\n\r\n"),
    );
    try std.testing.expectError(
        error.MalformedRequest,
        hp.parse("GET / HTTP/1.1\r\nHost : x\r\n\r\n"),
    );
    try std.testing.expectError(
        error.MalformedRequest,
        hp.parse("GET  /double-space HTTP/1.1\r\n\r\n"),
    );
    try std.testing.expectError(
        error.MalformedRequest,
        hp.parse("GET /no-version-target\r\n\r\n"),
    );
}

test "body cap enforced at declaration time, before bytes arrive" {
    const big = try std.fmt.allocPrint(std.testing.allocator, "POST / HTTP/1.1\r\nContent-Length: {d}\r\n\r\n", .{hp.BODY_CAP + 1});
    defer std.testing.allocator.free(big);
    try std.testing.expectError(error.BodyTooLarge, hp.parse(big));
    // At exactly the cap the parser demands the bytes instead: Incomplete.
    const edge = try std.fmt.allocPrint(std.testing.allocator, "POST / HTTP/1.1\r\nContent-Length: {d}\r\n\r\n", .{hp.BODY_CAP});
    defer std.testing.allocator.free(edge);
    try std.testing.expectError(error.Incomplete, hp.parse(edge));
}
