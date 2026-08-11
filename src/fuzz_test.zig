// fuzz_test.zig
//
// Binding test for BE-SURF-04 (differential fuzzing, SPEC section 11.6,
// D-056). Honest scope: this binds the v1 verdict differential (accept/reject
// agreement) over the structures currently wired into the corpus (envelope,
// intent, grant, span, effect, claim). The independent reference parser lives
// outside the Zig tree by construction (tools/refparse.py, Python, written
// from the SPEC field tables alone, D-056 part one); the end-to-end agreement
// run is tools/fuzz_diff.py, enforced at M4. What this test makes observable
// inside the suite is the replay-and-compare machinery itself: corpus framing,
// tagged routing to the parse entry points, and the positional verdict
// comparison that flags any injected divergence (D-041 decision 2 shape: the
// marker binds on the property, not on a vibe).

const std = @import("std");
const testing = std.testing;
const fuzz = @import("fuzz.zig");

// Synthetic valid Envelope (SPEC 6.2 field table, structural only):
// version 2, zero ids and keys, seq 0, parent_count 0, ts 0, body_type 1,
// body_len 0, zero sig. 151 bytes; parseEnvelope accepts it because every
// fixed and declared length fits and no bytes trail.
const ENV_LEN: usize = 151;

fn syntheticEnvelope() [ENV_LEN]u8 {
    var env: [ENV_LEN]u8 = std.mem.zeroes([ENV_LEN]u8);
    env[0] = 2; // version
    env[82] = 1; // body_type: Utterance
    return env;
}

test "BE_SURF_04 differential replay flags an injected divergence and agrees on honest verdicts" {
    const env = syntheticEnvelope();

    // Corpus of three records (D-056 framing: u8 tag || u16 BE len || bytes):
    // rec0 valid envelope, rec1 envelope truncated one byte, rec2 unknown tag.
    var corpus: [3 + ENV_LEN + 3 + (ENV_LEN - 1) + 3 + 4]u8 = undefined;
    var pos: usize = 0;

    corpus[pos] = fuzz.TAG_ENVELOPE;
    std.mem.writeInt(u16, corpus[pos + 1 ..][0..2], ENV_LEN, .big);
    @memcpy(corpus[pos + 3 ..][0..ENV_LEN], &env);
    pos += 3 + ENV_LEN;

    corpus[pos] = fuzz.TAG_ENVELOPE;
    std.mem.writeInt(u16, corpus[pos + 1 ..][0..2], ENV_LEN - 1, .big);
    @memcpy(corpus[pos + 3 ..][0 .. ENV_LEN - 1], env[0 .. ENV_LEN - 1]);
    pos += 3 + ENV_LEN - 1;

    corpus[pos] = 0x7F; // not a corpus tag: the reference rejects as unknown
    std.mem.writeInt(u16, corpus[pos + 1 ..][0..2], 4, .big);
    @memcpy(corpus[pos + 3 ..][0..4], env[0..4]);
    pos += 3 + 4;

    var tags: [8]u8 = undefined;
    var verdicts: [8]bool = undefined;
    const n = try fuzz.replayVerdicts(corpus[0..pos], &tags, &verdicts);
    try testing.expectEqual(@as(usize, 3), n);
    try testing.expectEqual(fuzz.TAG_ENVELOPE, tags[0]);
    try testing.expect(verdicts[0]); // valid envelope: production accepts
    try testing.expect(!verdicts[1]); // truncated wire: production rejects
    try testing.expect(!verdicts[2]); // unknown tag: production rejects

    // Injected divergence: a doctored reference verdict stream that rejects
    // the record the production parser accepts. The positional comparison
    // MUST flag exactly one divergence at that record.
    const doctored_ref = [3]bool{ false, false, false };
    try testing.expectEqual(@as(usize, 1), fuzz.countDivergences(verdicts[0..n], &doctored_ref));

    // Honest agreement: a reference stream matching the production verdicts
    // flags nothing.
    const honest_ref = [3]bool{ true, false, false };
    try testing.expectEqual(@as(usize, 0), fuzz.countDivergences(verdicts[0..n], &honest_ref));

    // Framing defects fail the replay outright; they never emit silent
    // verdicts (a truncated record body, then a truncated record header).
    try testing.expectError(error.RecordTruncated, fuzz.replayVerdicts(corpus[0 .. pos - 1], &tags, &verdicts));
    var tail: [3 + ENV_LEN + 3 + ENV_LEN - 1 + 3 + 4 + 2]u8 = undefined;
    @memcpy(tail[0..pos], corpus[0..pos]);
    tail[pos] = 0xAA;
    tail[pos + 1] = 0xBB;
    try testing.expectError(error.FramingTruncated, fuzz.replayVerdicts(tail[0 .. pos + 2], &tags, &verdicts));
}
