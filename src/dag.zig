// dag.zig
//
// LANGUAGE.md section 4 implementation slice, item 4: the causal DAG that backs
// BE-EVID-05 supersession (SPEC section 7.3). A span signed at a volatile
// resource is superseded when a later Effect on the same resource_id is visible
// at the claim. "Later" and "visible" are both causal, not temporal, so the
// question is one of ancestry in a directed acyclic graph of envelopes.
//
// Each node is a 32-byte envelope hash (the same bytes a Span's `origin` field
// carries, and the same bytes a claim's enclosing Utterance hashes to). An edge
// insert(parent, child) records that `child` causally depends on `parent`:
// parent happened-before child. isAncestor(a, d) asks whether `a` is a STRICT
// proper ancestor of `d` (a happened-before d, and a is not d).
//
// Strict ancestry is structural, not a special case: the traversal never
// visits the start node as its own ancestor because self-loops are rejected at
// insert, so isAncestor(x, x) is false. That is BE-EVID-05a made concrete. A
// superseding Effect that is the span's own origin Effect (the Effect that
// published the span) is never its own ancestor, so it never supersedes itself.
//
// Zero-heap and caller-owned (BE-WIRE-01): the caller declares the Dag on its
// own frame and the structure never allocates. Capacity is fixed; an insert
// past capacity is an error the caller chose by sizing the pool. isAncestor
// uses an explicit work queue and a visited bitmap, never recursion
// (BE-DEP-02 shape), so a thousand-deep chain cannot overflow the stack and a
// diamond is walked once per node. Cycles are impossible by construction: an
// edge that would close a cycle is rejected at insert by the same isAncestor
// primitive, so the graph stays acyclic without trusting insertion order.

const std = @import("std");

pub const NODE_BYTES: usize = 32;
pub const Node = [NODE_BYTES]u8;

// Fixed capacity. The caller owns a Dag value of this size; 128 envelopes is
// far past any single claim's causal neighbourhood and keeps the value under
// 8 KB. Past capacity, insert returns error.Overflow rather than allocate.
pub const MAX_NODES: usize = 128;
pub const MAX_PARENTS: usize = 8;

pub const DagError = error{
    Overflow, // node pool or per-node parent list full
    Cyclic, // edge would close a cycle (parent already descends from child)
    NotNode, // a slice passed as a Node is not exactly NODE_BYTES
};

pub const Dag = struct {
    nodes: [MAX_NODES]Node = std.mem.zeroes([MAX_NODES]Node),
    node_count: usize = 0,
    parents: [MAX_NODES][MAX_PARENTS]u16 = std.mem.zeroes([MAX_NODES][MAX_PARENTS]u16),
    parent_count: [MAX_NODES]u8 = std.mem.zeroes([MAX_NODES]u8),
    visited: [MAX_NODES]bool = std.mem.zeroes([MAX_NODES]bool),
    queue: [MAX_NODES]u16 = std.mem.zeroes([MAX_NODES]u16),

    // Linear scan for a node's index. The pool is small and the alternative, a
    // hash index, would add state and collision handling for no gain at this
    // capacity. Returns null if the hash is not interned.
    pub fn indexOf(self: *const Dag, hash: Node) ?u16 {
        var i: usize = 0;
        while (i < self.node_count) : (i += 1) {
            if (std.mem.eql(u8, &self.nodes[i], &hash)) return @intCast(i);
        }
        return null;
    }

    pub fn contains(self: *const Dag, hash: Node) bool {
        return self.indexOf(hash) != null;
    }

    // Add a node if absent and return its index. The hot path for insert.
    fn intern(self: *Dag, hash: Node) DagError!u16 {
        if (self.indexOf(hash)) |idx| return idx;
        if (self.node_count >= MAX_NODES) return error.Overflow;
        const idx: u16 = @intCast(self.node_count);
        self.nodes[idx] = hash;
        self.parent_count[idx] = 0;
        self.node_count += 1;
        return idx;
    }

    // Record that `child` causally depends on `parent`. Rejects a self-loop
    // (BE-EVID-05a strict) and any edge that would close a cycle, by checking
    // whether `parent` already descends from `child`. Rejects a parent list
    // full per node. Idempotent on a repeat of the exact same edge.
    pub fn insert(self: *Dag, parent: Node, child: Node) DagError!void {
        if (std.mem.eql(u8, &parent, &child)) return error.Cyclic; // self-loop

        const pidx = try self.intern(parent);
        const cidx = try self.intern(child);

        // Cycle guard: if child is already an ancestor of parent, wiring
        // parent as a parent of child would close a loop. isAncestor is strict,
        // so this never confuses a node with itself.
        if (self.isAncestorIdx(cidx, pidx)) return error.Cyclic;

        // Idempotent: skip if parent is already recorded for child.
        const pc = self.parent_count[cidx];
        var k: usize = 0;
        while (k < pc) : (k += 1) {
            if (self.parents[cidx][k] == pidx) return;
        }
        if (pc >= MAX_PARENTS) return error.Overflow;
        self.parents[cidx][pc] = pidx;
        self.parent_count[cidx] = pc + 1;
    }

    // isAncestor by index: is `ancestor` a strict proper ancestor of
    // `descendant`? BFS from descendant over parent links, work queue + visited
    // bitmap, no recursion. The start node is never its own ancestor because we
    // only ever inspect parents, and a node is its own parent only via a
    // self-loop, which insert forbids.
    fn isAncestorIdx(self: *Dag, ancestor: u16, descendant: u16) bool {
        if (ancestor == descendant) return false;

        // Reuse the caller-owned visited bitmap and queue buffers (zero-heap).
        // Reset only the nodes we touch, by tracking the high-water mark.
        var head: usize = 0;
        var tail: usize = 0;
        var touched: [MAX_NODES]u16 = std.mem.zeroes([MAX_NODES]u16);
        var touched_n: usize = 0;

        self.queue[tail] = descendant;
        tail += 1;
        self.visited[descendant] = true;
        touched[touched_n] = descendant;
        touched_n += 1;

        while (head < tail) {
            const cur = self.queue[head];
            head += 1;
            const pc = self.parent_count[cur];
            var k: usize = 0;
            while (k < pc) : (k += 1) {
                const p = self.parents[cur][k];
                if (p == ancestor) {
                    self.resetVisited(&touched, touched_n);
                    return true;
                }
                if (!self.visited[p]) {
                    self.visited[p] = true;
                    touched[touched_n] = p;
                    touched_n += 1;
                    self.queue[tail] = p;
                    tail += 1;
                }
            }
        }
        self.resetVisited(&touched, touched_n);
        return false;
    }

    fn resetVisited(self: *Dag, touched: *const [MAX_NODES]u16, n: usize) void {
        var i: usize = 0;
        while (i < n) : (i += 1) self.visited[touched[i]] = false;
    }

    // Public hash-keyed ancestry. Returns false if either node is unknown,
    // because a missing node has no causal position (fail-closed).
    pub fn isAncestor(self: *Dag, ancestor: Node, descendant: Node) bool {
        const a = self.indexOf(ancestor) orelse return false;
        const d = self.indexOf(descendant) orelse return false;
        return self.isAncestorIdx(a, d);
    }

    // BE-EVID-05/05a supersession predicate (DAG half). A span published at
    // `origin` is superseded by `effect` relative to a claim in `claim` iff
    // `effect` is a strict causal descendant of `origin` (origin happened
    // before effect, origin is not effect) AND `effect` is a strict causal
    // ancestor of `claim` (effect is visible at the claim). Both conjuncts are
    // strict ancestry, so the origin Effect never supersedes its own span and
    // an effect that lands at or after the claim does not count.
    //
    // The resource_id match (effect_resource(effect) == span.resource_id) is
    // the production resource-index concern and is NOT checked here: this
    // predicate answers the causal question only, so the caller (the
    // is_superseded hook) supplies the candidate effect for a given resource.
    pub fn supersedes(self: *Dag, origin: Node, effect: Node, claim: Node) bool {
        return self.isAncestor(origin, effect) and self.isAncestor(effect, claim);
    }
};

// Convert a 32-byte slice (a Span's origin field, or a claim envelope hash) to
// a Node. Returns NotNode if the slice is not exactly NODE_BYTES, so a
// malformed caller cannot read past the slice.
pub fn nodeFromSlice(s: []const u8) DagError!Node {
    if (s.len != NODE_BYTES) return error.NotNode;
    var n: Node = undefined;
    @memcpy(&n, s);
    return n;
}
