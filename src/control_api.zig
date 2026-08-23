// v0.6 control plane API (D-091 P2): the /v1/* facade over EXISTING
// dispatch/resolver/intent functions. Anti god-mode is structural: no
// handler here mutates grants or the ledger directly. POST /v1/intents
// reaches admission ONLY through Resolver.resolveAndAdmit, the same call
// handleTransport makes for a wire Intent; events are read from a bounded
// ring fed by Dispatch at its own ledger-commit sites (drop-oldest,
// documented); /metrics only reads counters.
//
// SSE shape decision (documented tradeoff): GET /v1/events returns a
// BOUNDED replay as one text/event-stream response (every event with
// seq > since that fits the write cap, then Connection: close). Clients
// poll by cursor; long-lived push stays additive later and never breaks
// /v1/. The ring seq is monotonic in-process; after a daemon restart
// cursors reset (the durable source of truth remains the ledger file).

const std = @import("std");
const channel = @import("parser/channel.zig");
const resolver_mod = @import("resolver.zig");
const intent_mod = @import("intent.zig");

pub const RING_CAP: usize = 256;
pub const ID_HEX_LEN: usize = channel.LEN_INTENT_ID * 2;
pub const BODY_MAX: usize = 4096;
const ACTION_MAX: usize = 256;
const RATIONALE_MAX: usize = 512;

pub const EventTag = enum(u8) {
    grant_consumed,
    grant_published,
    revocation_recorded,

    pub fn name(self: EventTag) []const u8 {
        return switch (self) {
            .grant_consumed => "grant_consumed",
            .grant_published => "grant_published",
            .revocation_recorded => "revocation_recorded",
        };
    }
};

pub const RingEntry = struct {
    seq: u64 = 0,
    tag: EventTag = .grant_consumed,
    id: [channel.LEN_GRANT_ID]u8 = [_]u8{0} ** channel.LEN_GRANT_ID,
    ts_ms: u64 = 0,
};

// Fixed-capacity drop-oldest ring. next_seq never resets while the process
// lives; overflow counts silently discarded oldest entries (surfaced in
// /metrics so a gap is visible, never silent).
pub const EventRing = struct {
    entries: [RING_CAP]RingEntry = undefined,
    head: usize = 0,
    count: usize = 0,
    next_seq: u64 = 1,
    dropped_total: u64 = 0,

    pub fn publish(self: *EventRing, tag: EventTag, id: [channel.LEN_GRANT_ID]u8, now_ms: u64) void {
        const e = &self.entries[self.head];
        e.* = .{ .seq = self.next_seq, .tag = tag, .id = id, .ts_ms = now_ms };
        self.next_seq += 1;
        if (self.count == RING_CAP) self.dropped_total += 1 else self.count += 1;
        self.head = (self.head + 1) % RING_CAP;
    }
};

pub const ApiError = error{
    MalformedBody,
    MalformedTarget,
    OutBufferTooSmall,
};

pub const IntentOutcome = struct {
    status: u16, // 202 accepted, 400/409/422/200/404 per the F5 table
    body_len: usize,
};

pub const Api = struct {
    resolver: *resolver_mod.Resolver,
    table: *intent_mod.Table,
    ring: *EventRing,
    // Surfaced counters (/metrics reads these).
    admitted_total: u64 = 0,
    refused_conflict_total: u64 = 0,
    refused_unprocessable_total: u64 = 0,
    bad_request_total: u64 = 0,

    // postIntent: flat JSON {intent_id, resource_id, action, rationale}
    // -> hex-decoded 16-byte id -> resolveAndAdmit. Error map is the F5
    // contract: syntax/bad-hex/oversize 400, ResourceHeld/TableFull 409,
    // resolver semantics (unknown/ambiguous/foreign) 422. Body echoes the
    // hex id so a client never parses Zig types to learn what landed.
    pub fn postIntent(self: *Api, body: []const u8, out: []u8, now_ms: u64) ApiError!IntentOutcome {
        var hex_buf: [ID_HEX_LEN]u8 = undefined;
        var id_buf: [channel.LEN_INTENT_ID]u8 = undefined;
        var res_buf: [channel.MAX_RESOURCE]u8 = undefined;
        var act_buf: [ACTION_MAX]u8 = undefined;
        var rat_buf: [RATIONALE_MAX]u8 = undefined;

        const bad = IntentOutcome{ .status = 400, .body_len = BAD_BODY.len };
        const ok_str = extractString(body, "intent_id", &hex_buf);
        if (ok_str == null or ok_str.? != ID_HEX_LEN or !hexDecode16(&hex_buf, &id_buf)) {
            self.bad_request_total += 1;
            return bad;
        }
        const res_len_o = extractString(body, "resource_id", &res_buf);
        const act_len_o = extractString(body, "action", &act_buf);
        const rat_len_o = extractString(body, "rationale", &rat_buf);
        if (res_len_o == null or act_len_o == null or rat_len_o == null) {
            self.bad_request_total += 1;
            return bad;
        }
        const it = channel.Intent{
            .intent_id = &id_buf,
            .resource_id = res_buf[0..res_len_o.?],
            .action = act_buf[0..act_len_o.?],
            .rationale = rat_buf[0..rat_len_o.?],
        };

        if (self.resolver.resolveAndAdmit(self.table, it, now_ms)) {
            self.admitted_total += 1;
            const text = std.fmt.bufPrint(out, "accepted {s}\n", .{hex_buf[0..]}) catch return error.OutBufferTooSmall;
            return .{ .status = 202, .body_len = text.len };
        } else |e| switch (e) {
            error.ResourceHeld, error.TableFull => {
                self.refused_conflict_total += 1;
                const text = std.fmt.bufPrint(out, "conflict {s}\n", .{hex_buf[0..]}) catch return error.OutBufferTooSmall;
                return .{ .status = 409, .body_len = text.len };
            },
            // F4 idempotency: a retried intent_id still PENDING is the SAME
            // admission, not an error; the transport path treats it as a
            // no-op and so does HTTP. Not counted again in admitted_total.
            error.DuplicateIntentId => {
                const text = std.fmt.bufPrint(out, "accepted {s}\n", .{hex_buf[0..]}) catch return error.OutBufferTooSmall;
                return .{ .status = 202, .body_len = text.len };
            },
            else => {
                self.refused_unprocessable_total += 1;
                if (UNPROCESSABLE.len > out.len) return error.OutBufferTooSmall;
                @memcpy(out[0..UNPROCESSABLE.len], UNPROCESSABLE);
                return .{ .status = 422, .body_len = UNPROCESSABLE.len };
            },
        }
    }

    // getIntentState: linear scan over live table entries for the decoded
    // id; state renders as its SPEC word. Unknown id reads 404 (len 0).
    pub fn getIntentState(self: *Api, id_bytes: [channel.LEN_INTENT_ID]u8, out: []u8) ApiError!IntentOutcome {
        for (self.table.entries[0..self.table.len]) |*e| {
            if (!std.mem.eql(u8, e.intent_id[0..], &id_bytes)) continue;
            const word: []const u8 = switch (e.state) {
                .pending => "pending\n",
                .executing => "executing\n",
                .expired => "expired\n",
                .rejected => "rejected\n",
            };
            if (word.len > out.len) return error.OutBufferTooSmall;
            @memcpy(out[0..word.len], word);
            return .{ .status = 200, .body_len = word.len };
        }
        return .{ .status = 404, .body_len = 0 };
    }

    // metricsBody: Prometheus text format, one metric per line. Control's
    // own counters arrive as parameters so this module stays transport-free.
    pub fn metricsBody(self: *Api, out: []u8, ctl_requests: u64, ctl_auth_refused: u64, ctl_timeouts: u64) ApiError!IntentOutcome {
        const text = std.fmt.bufPrint(out,
            \\# TYPE bolina_intents_admitted_total counter
            \\bolina_intents_admitted_total {d}
            \\bolina_intents_refused_conflict_total {d}
            \\bolina_intents_refused_unprocessable_total {d}
            \\bolina_events_dropped_total {d}
            \\bolina_control_requests_total {d}
            \\bolina_control_auth_refused_total {d}
            \\bolina_control_timeouts_total {d}
            \\
        , .{
            self.admitted_total,
            self.refused_conflict_total,
            self.refused_unprocessable_total,
            self.ring.dropped_total,
            ctl_requests,
            ctl_auth_refused,
            ctl_timeouts,
        }) catch return error.OutBufferTooSmall;
        return .{ .status = 200, .body_len = text.len };
    }

    // eventsSseBody: bounded SSE replay of every ring event with seq >
    // since, oldest first. Frames are appended until the buffer is full;
    // the cursor fetches the rest (replay paginado, F6).
    pub fn eventsSseBody(self: *Api, out: []u8, since: u64) ApiError!IntentOutcome {
        var used: usize = 0;
        var wrote: usize = 0;
        var i: usize = 0;
        while (i < self.ring.count) : (i += 1) {
            const idx = (self.ring.head + RING_CAP - self.ring.count + i) % RING_CAP;
            const e = self.ring.entries[idx];
            if (e.seq <= since) continue;
            var hex_buf: [channel.LEN_GRANT_ID * 2]u8 = undefined;
            hexEncode(&e.id, &hex_buf);
            const frame = std.fmt.bufPrint(out[used..], SSE_FRAME_FMT, .{
                e.seq,        e.tag.name(), e.seq, e.tag.name(),
                hex_buf[0..], e.ts_ms,
            }) catch break; // window full: stop, cursor paginates the rest
            used += frame.len;
            wrote += 1;
        }
        if (wrote == 0) {
            if (SSE_NONE.len > out.len) return error.OutBufferTooSmall;
            @memcpy(out[0..SSE_NONE.len], SSE_NONE);
            return .{ .status = 200, .body_len = SSE_NONE.len };
        }
        return .{ .status = 200, .body_len = used };
    }

    pub fn parseSince(target: []const u8) ApiError!u64 {
        const q = std.mem.indexOfScalar(u8, target, '?') orelse return 0;
        const rest = target[q + 1 ..];
        const eq = std.mem.indexOfScalar(u8, rest, '=') orelse return error.MalformedTarget;
        if (!std.mem.eql(u8, rest[0..eq], "since")) return error.MalformedTarget;
        return std.fmt.parseUnsigned(u64, rest[eq + 1 ..], 10) catch error.MalformedTarget;
    }
};

const BAD_BODY = "bad request\n";
const UNPROCESSABLE = "unprocessable intent\n";
const SSE_NONE = ": no new events\n\n";
const SSE_FRAME_FMT = "id: {d}\nevent: {s}\ndata: {{\"seq\":{d},\"tag\":\"{s}\",\"grant_id\":\"{s}\",\"ts_ms\":{d}}}\n\n";

// --- minimal flat-JSON field extraction ---------------------------------
// Hand-rolled on purpose: zero heap, zero deps, flat object only, string
// values only. Nested structures, duplicate keys and oversized values all
// fail closed (400). No escape decoding: control-plane ids are plain hex.

fn findKeyValue(buf: []const u8, key: []const u8) ?usize {
    var pat_buf: [64]u8 = undefined;
    if (key.len + 4 > pat_buf.len) return null;
    const pat = std.fmt.bufPrint(&pat_buf, "\"{s}\":", .{key}) catch return null;
    const at = std.mem.indexOf(u8, buf, pat) orelse return null;
    var v = at + pat.len;
    while (v < buf.len and (buf[v] == ' ' or buf[v] == '\t')) : (v += 1) {}
    if (v >= buf.len or buf[v] != '"') return null;
    return v + 1;
}

// Returns written length, null when absent/malformed/oversized. Backslash
// escapes terminate the scan (fail closed): none of our fields need them.
fn extractString(buf: []const u8, key: []const u8, out: []u8) ?usize {
    const pos = findKeyValue(buf, key) orelse return null;
    var w: usize = 0;
    var i = pos;
    while (i < buf.len) {
        const ch = buf[i];
        if (ch == '"') return w;
        if (ch == '\\') return null;
        if (w >= out.len) return null;
        out[w] = ch;
        w += 1;
        i += 1;
    }
    return null; // unterminated string
}

// parseIdHex: public decode entry for transport-side path matching.
pub fn parseIdHex(hex: *const [ID_HEX_LEN]u8) ?[channel.LEN_INTENT_ID]u8 {
    var out: [channel.LEN_INTENT_ID]u8 = undefined;
    if (!hexDecode16(hex, &out)) return null;
    return out;
}

fn hexDecode16(hex: *const [ID_HEX_LEN]u8, out: *[channel.LEN_INTENT_ID]u8) bool {
    var i: usize = 0;
    while (i < channel.LEN_INTENT_ID) : (i += 1) {
        const hi = hexVal(hex[i * 2]) orelse return false;
        const lo = hexVal(hex[i * 2 + 1]) orelse return false;
        out[i] = (hi << 4) | lo;
    }
    return true;
}

fn hexVal(ch: u8) ?u8 {
    return switch (ch) {
        '0'...'9' => ch - '0',
        'a'...'f' => ch - 'a' + 10,
        'A'...'F' => ch - 'A' + 10,
        else => null,
    };
}

fn hexEncode(src: []const u8, out: []u8) void {
    const digits = "0123456789abcdef";
    for (src, 0..) |b, i| {
        out[i * 2] = digits[b >> 4];
        out[i * 2 + 1] = digits[b & 0xf];
    }
}
