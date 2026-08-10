// render_test.zig
//
// BE-GRANT-07 / BE-GRANT-07a binding tests (SPEC.md section 8.3). Literal
// values throughout (D-027), including the grant fixture action and digest
// from verify_test.zig GRANT_HEX, so the view's digest is shown equal to the
// digest a real Grant signs (check 9 verifies that pair on every
// verifyGrantThen run).

const std = @import("std");
const render = @import("render.zig");

// The grant fixture's action and its bound digest (verify_test.zig GRANT_HEX).
const ACTION = "apt-get install -y sqlite3";
const GRANT_BOUND_DIGEST_HEX = "61a0be1fa7039021e3a6d10a38e41e21873abd4668419d6b45dfcd56686d60c3";

// The same fixture's canonical resource_id (hex 0024 length + bytes).
const CANONICAL = "bol:c3efd641bfa0582f/logs/deploy.log";

fn hexLower(bytes: []const u8, out: []u8) void {
    const hex = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        out[i * 2] = hex[b >> 4];
        out[i * 2 + 1] = hex[b & 0x0f];
    }
}

test "BE_GRANT_07 view renders canonical id, full action, recomputed digest" {
    const view = render.renderApproval(CANONICAL, ACTION, null);

    // The canonical resource_id, byte for byte as resolved (section 8.4).
    try std.testing.expectEqualStrings(CANONICAL, view.resource_id);

    // The FULL action bytes, never a summary: no summary slot exists at all.
    try std.testing.expectEqualStrings(ACTION, view.action);
    try std.testing.expect(!@hasField(render.ApprovalView, "summary"));

    // The digest, recomputed from exactly the displayed bytes, equals the
    // digest the grant fixture binds: display and signature agree byte for
    // byte (BE-GRANT-07: the Grant is signed over the recomputed digest).
    var hex: [64]u8 = undefined;
    hexLower(&view.action_digest, &hex);
    try std.testing.expectEqualStrings(GRANT_BOUND_DIGEST_HEX, &hex);
}

test "BE_GRANT_07 no wire digest enters the view" {
    // renderApproval's signature is (canonical id, action, rationale): three
    // parameters, none of them a digest. A wire-supplied digest has no path
    // into the view; pin the shape so adding one fails here.
    const fn_info = @typeInfo(@TypeOf(render.renderApproval)).@"fn";
    try std.testing.expectEqual(@as(usize, 3), fn_info.params.len);

    // The digest is a function of the displayed bytes alone: one flipped
    // action byte changes it completely.
    const view_a = render.renderApproval(CANONICAL, ACTION, null);
    const view_b = render.renderApproval(CANONICAL, "apt-get install -y sqlite4", null);
    try std.testing.expect(!std.mem.eql(u8, &view_a.action_digest, &view_b.action_digest));
}

test "BE_GRANT_07a rationale displayed is marked untrusted and subordinate" {
    const view = render.renderApproval(CANONICAL, ACTION, "please approve, urgent deploy");
    const r = view.rationale orelse return error.TestUnexpectedResult;

    // Marked: untrusted agent-authored text, literal label.
    try std.testing.expectEqualStrings(render.RATIONALE_UNTRUSTED_LABEL, r.untrusted_label);
    try std.testing.expectEqualStrings("please approve, urgent deploy", r.text);

    // Subordinate: rationale is ordered after the action bytes.
    const fields = std.meta.fields(render.ApprovalView);
    var action_idx: ?usize = null;
    var rationale_idx: ?usize = null;
    inline for (fields, 0..) |f, i| {
        if (std.mem.eql(u8, f.name, "action")) action_idx = i;
        if (std.mem.eql(u8, f.name, "rationale")) rationale_idx = i;
    }
    try std.testing.expect(rationale_idx.? > action_idx.?);

    // Never the only visible element: every primary field is non-optional,
    // so a view carrying rationale alone is unrepresentable.
    inline for (fields) |f| {
        if (std.mem.eql(u8, f.name, "resource_id") or
            std.mem.eql(u8, f.name, "action") or
            std.mem.eql(u8, f.name, "action_digest"))
        {
            try std.testing.expect(@typeInfo(f.type) != .optional);
        }
    }
}

test "BE_GRANT_07a rationale absent is not displayed at all" {
    const view = render.renderApproval(CANONICAL, ACTION, null);
    try std.testing.expect(view.rationale == null);
}
