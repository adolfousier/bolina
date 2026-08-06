// replay_test.zig
//
// Tests for the sliding-window anti-replay filter (src/replay.zig, SPEC.md
// section 4.3 BE-TR-03). One test binds the spec item by name (BE_TR_03); the
// rest use descriptive names so they cannot name an undeclared BE item and
// become orphans under the M1 bijection.

const std = @import("std");
const replay = @import("replay.zig");

const testing = std.testing;

test "BE_TR_03 first packet seeds the window and a replay of it is rejected" {
    var rw = replay.ReplayWindow.init();
    try testing.expect(rw.check(1_000)); // first packet seeds largest
    try testing.expect(!rw.check(1_000)); // exact duplicate: replay
}

test "an exact duplicate counter is rejected as a replay" {
    var rw = replay.ReplayWindow.init();
    _ = rw.check(50);
    _ = rw.check(51);
    try testing.expect(rw.check(52));
    try testing.expect(!rw.check(52)); // seen just now
    try testing.expect(!rw.check(51)); // seen earlier
}

test "reordered packets inside the window are accepted" {
    var rw = replay.ReplayWindow.init();
    // Deliver out of order within the window; all distinct, all fresh.
    _ = rw.check(100);
    try testing.expect(rw.check(97)); // behind the head, inside window
    try testing.expect(rw.check(99));
    try testing.expect(rw.check(98));
    try testing.expect(rw.check(96));
    // Now the gaps are filled; replaying any of them fails.
    try testing.expect(!rw.check(96));
    try testing.expect(!rw.check(100));
}

test "a counter below the window is rejected" {
    var rw = replay.ReplayWindow.init();
    _ = rw.check(1034); // 1024 + 10: jump the head far ahead (literal, not WINDOW_BITS)
    // The first seed is now 1024 below the head: outside the window.
    try testing.expect(!rw.check(10));
}

test "an advance keeps recent counters visible to a later reorder" {
    var rw = replay.ReplayWindow.init();
    _ = rw.check(1000);
    _ = rw.check(999);
    _ = rw.check(1500); // jump the head by 500; oldest counters age out
    // 999 is 501 below the new head, still inside the 1024 window, not yet seen
    // relative to the advanced bitmap, so a reorder to it is accepted. (It was
    // seen before, but the exercise here is the window's reach after an advance,
    // so use a counter that was never seen.)
    try testing.expect(rw.check(1499)); // one behind the head: in window, fresh
    try testing.expect(rw.check(1001)); // 499 behind the head: in window, fresh
    try testing.expect(!rw.check(1000)); // seen: replay
}

test "a jump beyond the window width clears the bitmap entirely" {
    var rw = replay.ReplayWindow.init();
    _ = rw.check(1);
    _ = rw.check(2);
    _ = rw.check(1029); // 1024 + 5: gap wider than the window (literal)
    // Everything before is now below the window and forgotten.
    try testing.expect(!rw.check(1));
    try testing.expect(!rw.check(2));
    try testing.expect(rw.check(1028)); // 1024 + 4: in the fresh window (literal)
}

test "counter 0 is a legal first counter, not a sentinel" {
    var rw = replay.ReplayWindow.init();
    try testing.expect(rw.check(0)); // first packet seeds largest at 0
    try testing.expect(!rw.check(0)); // replay
    try testing.expect(rw.check(1)); // in window, fresh
}

test "scrambled distinct counters within one window are all accepted then all rejected on replay" {
    var rw = replay.ReplayWindow.init();
    const base: u64 = 2000;
    // A pseudo-random walk of 512 distinct offsets in [0, 1023], accepted in any
    // order; then re-send the same set and every one must be a replay.
    var accepted: usize = 0;
    var i: u64 = 0;
    while (i < 512) : (i += 1) { // 1024 / 2 distinct offsets (literal)
        // Scatter offsets with a stride coprime to the window so order is scrambled.
        const off = (i * 7) % 1024; // mod the declared window width (literal)
        if (rw.check(base + off)) accepted += 1;
    }
    try testing.expectEqual(@as(usize, 512), accepted); // all distinct -> all accepted

    i = 0;
    var rejected: usize = 0;
    while (i < 512) : (i += 1) { // 1024 / 2 distinct offsets (literal)
        const off = (i * 7) % 1024; // mod the declared window width (literal)
        if (!rw.check(base + off)) rejected += 1;
    }
    try testing.expectEqual(@as(usize, 512), rejected); // all now replays
}
