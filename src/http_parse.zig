// http_parse.zig
//
// v0.6 control plane (D-091): pure incremental HTTP/1.x request parser for
// the local sidecar surface. No I/O, no allocation: parse() scans a caller
// buffer and returns slices INTO it, so the connection state machine owns
// buffering entirely and this module stays trivially testable (section
// 11.4 order: parser first, sockets later).
//
// The subset is deliberately tiny - GET/POST, HTTP/1.0-1.1, Content-Length
// bodies only - because every feature past that is attack surface a
// loopback sidecar does not need. Rejections are explicit errors the state
// machine maps to pinned status codes (F5 table lives in control.zig):
//   HeadersTooLarge     431   MalformedRequest     400
//   UnsupportedVersion  505   UnsupportedMethod    405
//   ChunkedNotSupported 501   LengthRequired       411
//   ConflictingLength   400   BodyTooLarge         413
// error.Incomplete is NOT a failure: it means "feed me more bytes", which
// is how a stream that fragments headers mid-line survives (F2).
//
// Smuggling posture: strict single-SP request line, no obs-fold, no space
// before the header colon (RFC 9110 3.2.4 guards), any Transfer-Encoding
// refused outright, duplicate Content-Length only when byte-equal. There
// is exactly one way to frame a request here.

const std = @import("std");

pub const HEADER_CAP: usize = 8192;
pub const BODY_CAP: usize = 64 * 1024;

pub const ParseError = error{
    Incomplete, // need more bytes; retry with a longer buffer
    HeadersTooLarge, // no terminator within HEADER_CAP
    MalformedRequest, // request line or header syntax violated
    UnsupportedVersion, // well-formed but not HTTP/1.0-1.1
    UnsupportedMethod, // well-formed but not GET/POST
    ChunkedNotSupported, // Transfer-Encoding present; CL-only plane
    LengthRequired, // POST without Content-Length
    ConflictingLength, // duplicate Content-Length, differing values
    BodyTooLarge, // Content-Length above BODY_CAP
};

pub const Method = enum { get, post };

// Request: views into the caller's buffer, valid until the caller refills
// or compacts it. body_start is where the body begins; the state machine
// slices body_start .. body_start + content_length itself once enough
// bytes exist (parse refuses early so a short body reads back Incomplete).
// authorization is the raw header value ("" when absent); control.zig
// strips the Bearer prefix and verifies against its own token.
pub const Request = struct {
    method: Method,
    target: []const u8,
    content_length: usize,
    body_start: usize,
    authorization: []const u8,
};

// parse: one attempt over buf. Incremental contract: with a partial
// request it returns error.Incomplete and the caller appends more bytes;
// nothing about buf mutates and no progress state is kept here.
pub fn parse(buf: []const u8) ParseError!Request {
    // Header block must terminate inside the cap. A buffer AT the cap with
    // no terminator is refused: slowloris dies on size, never on time (the
    // 5s deadline in control.zig is the second gate).
    const term = std.mem.indexOf(u8, buf, "\r\n\r\n") orelse {
        if (buf.len >= HEADER_CAP) return error.HeadersTooLarge;
        return error.Incomplete;
    };

    // Request line: exactly three tokens separated by single SPs. Empty
    // tokens, repeated SPs, tabs: all MalformedRequest, no recovery.
    const line_end = std.mem.indexOf(u8, buf, "\r\n") orelse unreachable;
    var it = std.mem.splitScalar(u8, buf[0..line_end], ' ');
    const m = it.next() orelse return error.MalformedRequest;
    const t = it.next() orelse return error.MalformedRequest;
    const v = it.next() orelse return error.MalformedRequest;
    if (it.next() != null) return error.MalformedRequest;
    if (m.len == 0 or t.len == 0 or v.len == 0) return error.MalformedRequest;

    const method: Method =
        if (std.mem.eql(u8, m, "GET")) .get else if (std.mem.eql(u8, m, "POST")) .post else return error.UnsupportedMethod;

    // Version: prefix must be sane (else syntax, not semantics) and the
    // exact minor accepted. HTTP/2+ never arrives on this plane.
    if (!std.mem.startsWith(u8, v, "HTTP/")) return error.MalformedRequest;
    if (!std.mem.eql(u8, v, "HTTP/1.1") and !std.mem.eql(u8, v, "HTTP/1.0"))
        return error.UnsupportedVersion;

    // Target: origin-form only ("/path?query"), printable ASCII, no bare
    // controls hiding inside (a stray \n would have broken the line split
    // anyway; the scan makes it explicit rather than incidental).
    if (t[0] != '/') return error.MalformedRequest;
    for (t) |c| {
        if (c <= 0x20 or c == 0x7f) return error.MalformedRequest;
    }

    // Headers: Name: value lines between the request line and the
    // terminator. Names matched ASCII-case-insensitively; values trimmed on
    // the left only, so a trailing space in a number is a syntax error.
    var pos: usize = line_end + 2;
    var content_length: ?usize = null;
    var authorization: []const u8 = "";
    while (pos < term) {
        if (buf[pos] == ' ' or buf[pos] == '\t') return error.MalformedRequest; // obs-fold
        const nl = std.mem.indexOfPos(u8, buf, pos, "\r\n") orelse return error.MalformedRequest;
        const hline = buf[pos..nl];
        pos = nl + 2;
        const colon = std.mem.indexOfScalar(u8, hline, ':') orelse return error.MalformedRequest;
        const name = hline[0..colon];
        if (name.len == 0) return error.MalformedRequest;
        const last = name[name.len - 1];
        if (last == ' ' or last == '\t') return error.MalformedRequest; // smuggling guard
        var val = hline[colon + 1 ..];
        while (val.len > 0 and (val[0] == ' ' or val[0] == '\t')) val = val[1..];
        if (val.len == 0) return error.MalformedRequest;
        if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) return error.ChunkedNotSupported;
        if (std.ascii.eqlIgnoreCase(name, "authorization")) authorization = val;
        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            const n = std.fmt.parseInt(usize, val, 10) catch return error.MalformedRequest;
            if (content_length) |prev| {
                if (prev != n) return error.ConflictingLength;
            }
            content_length = n;
        }
    }

    // Length rules: POST declares its body or the request is refused; GET
    // defaults to zero but may declare one. Cap before completeness so an
    // oversized declaration dies without waiting for its bytes.
    const body_start: usize = term + 4;
    const clen: usize = switch (method) {
        .get => content_length orelse 0,
        .post => content_length orelse return error.LengthRequired,
    };
    if (clen > BODY_CAP) return error.BodyTooLarge;
    if (buf.len < body_start + clen) return error.Incomplete;

    return .{ .method = method, .target = t, .content_length = clen, .body_start = body_start, .authorization = authorization };
}
