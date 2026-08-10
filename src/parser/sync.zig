// parser/sync.zig
//
// Zero-heap, total wire-format parsers for Bolina's backfill surface
// (SPEC.md section 6.4): SyncRequest and SyncResponse, the third sub-unit
// of the post-authentication unit (BE-SURF-03, D-054). Session messages,
// not channel messages: they carry no parents, never enter the ledger, and
// are never fanned out. Same discipline as the sibling sub-units (D-032):
// big-endian (SPEC 2.2), no allocation (returned slices alias the caller
// buffer), version parsed but not rejected here (SPEC 2.2), every error
// exit through coverage.reject and every accepted return through
// coverage.accept (gate M9).

const coverage = @import("../coverage.zig");
const parser = @import("../parser.zig");

const Cursor = parser.Cursor;
const ParseError = parser.ParseError;

pub const LEN_CHANNEL_ID: usize = 32; // channel identifier (SPEC 6.4)
pub const MAX_HAVE: u8 = 64; // have_count bound (SPEC 6.4 grammar)

// SyncRequest (SPEC 6.4). max_envelopes is parsed and carried, never
// rejected here: BE-SYNC-02's min(max_envelopes, 64) is responder policy
// applied by the engine (src/sync.zig), the same parse-carry / apply-later
// split as version.
pub const SyncRequest = struct {
    version: u8,
    channel_id: []const u8, // LEN_CHANNEL_ID bytes
    have_count: u8,
    have_hashes: []const u8, // have_count * LEN_CHANNEL_ID bytes flat, aliases the caller buffer
    max_envelopes: u16,
};

pub fn parseSyncRequest(buf: []const u8) ParseError!SyncRequest {
    var c = Cursor{ .buf = buf };
    const version = try c.u8r();
    const channel_id = try c.take(LEN_CHANNEL_ID);
    const have_count = try c.u8r();
    if (have_count > MAX_HAVE) return coverage.reject(.sync_req_have_oversize);
    const have_hashes = try c.take(@as(usize, have_count) * LEN_CHANNEL_ID);
    const max_envelopes = try c.u16be();
    if (c.pos != buf.len) return coverage.reject(.sync_req_trailing);
    coverage.accept(.sync_req_accepted);
    return .{ .version = version, .channel_id = channel_id, .have_count = have_count, .have_hashes = have_hashes, .max_envelopes = max_envelopes };
}

// SyncResponse (SPEC 6.4): header, envelope_count (u32 len, bytes) entries
// read as one flat region (the ca_sigs convention: a region the caller
// re-walks), then the truncated flag. Entries are not walked internally:
// BE-SYNC-05 runs each through parseEnvelope + verify before adoption
// (src/sync.zig). Buffer bounds per entry are enforced by the cursor.
pub const SyncResponse = struct {
    version: u8,
    channel_id: []const u8, // LEN_CHANNEL_ID bytes
    envelope_count: u8,
    items: []const u8, // (u32 len, bytes) * envelope_count flat, aliases the caller buffer
    truncated: bool,
};

pub fn parseSyncResponse(buf: []const u8) ParseError!SyncResponse {
    var c = Cursor{ .buf = buf };
    const version = try c.u8r();
    const channel_id = try c.take(LEN_CHANNEL_ID);
    const envelope_count = try c.u8r();
    const items_start = c.pos;
    var i: usize = 0;
    while (i < envelope_count) : (i += 1) {
        const len = try c.u32be();
        _ = try c.take(@as(usize, len));
    }
    const items = buf[items_start..c.pos];
    const truncated = try c.u8r();
    if (truncated > 1) return coverage.reject(.sync_resp_truncated_range);
    if (c.pos != buf.len) return coverage.reject(.sync_resp_trailing);
    coverage.accept(.sync_resp_accepted);
    return .{ .version = version, .channel_id = channel_id, .envelope_count = envelope_count, .items = items, .truncated = truncated == 1 };
}
