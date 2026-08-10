// render.zig
//
// What the human sees (SPEC.md section 8.3, BE-GRANT-07/07a).
// Non-surface, pure function over parsed values (D-018, D-052): builds the
// approval view the approving interface displays. The view's digest is
// recomputed here from exactly the bytes the view displays, through the same
// primitive the Grant binding uses (verify.actionDigest, BE-GRANT-02), so
// what the human reads and what the Grant signs agree by construction. No
// wire digest can enter this module: renderApproval takes no digest argument
// (BE-GRANT-07).
//
// rationale handling (BE-GRANT-07a): displayed rationale is typed untrusted,
// ordered after the action bytes, and the view's primary content is never
// optional, so rationale can never be the only element visible.
//
// Fixed shape; no allocation.
// Tripwire: non-surface, excluded from the M11 line budget (SPEC.md
// BE-SURF-03 non-surface list, placed ahead of creation by D-052).

const std = @import("std");
const verify = @import("verify.zig");
const channel = @import("parser/channel.zig");

// BE-GRANT-07a: displayed rationale MUST be marked untrusted agent text.
pub const RATIONALE_UNTRUSTED_LABEL: []const u8 = "untrusted, agent-authored";

// The marking is the type: any rationale that reaches a view carries the
// label. There is no path that displays rationale without it.
pub const Rationale = struct {
    text: []const u8,
    untrusted_label: []const u8 = RATIONALE_UNTRUSTED_LABEL,
};

// ApprovalView (BE-GRANT-07): field order IS render order. Primary content
// first, rationale last (visually subordinate, BE-GRANT-07a). Primary fields
// are non-optional: a view without them is unrepresentable, so rationale can
// never be the only element visible (BE-GRANT-07a).
pub const ApprovalView = struct {
    resource_id: []const u8, // canonical form, resolved by the executor (section 8.4)
    action: []const u8, // full action bytes, never a summary
    action_digest: [channel.LEN_ACTION_DIGEST]u8, // recomputed over `action`
    rationale: ?Rationale = null, // null = not displayed at all
};

// renderApproval (BE-GRANT-07): the digest is recomputed from exactly the
// bytes the view carries. The signature has no digest parameter, so a digest
// taken from any wire field has no path into the view, and no agent-produced
// summary replaces the action bytes.
pub fn renderApproval(canonical_resource_id: []const u8, action: []const u8, rationale: ?[]const u8) ApprovalView {
    return .{
        .resource_id = canonical_resource_id,
        .action = action,
        .action_digest = verify.actionDigest(action),
        .rationale = if (rationale) |r| .{ .text = r } else null,
    };
}
