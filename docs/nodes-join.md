# Join Node

Collects N parallel branches of **one execution** (same `trace_id`) and merges
their payloads into a single message.

The engine passes messages 1:1 (message passing, no implicit merging). A
trigger with two downstream nodes produces **two separate messages** — fields
from both branches never meet in one payload. `Join` closes this gap without
changing engine semantics.

## When to use it

After a fan-out that must be combined again:

```
        ┌─ addr-user ──┐
Trigger ┤              ├─ Join → Open → Master
        └─ addr-space ─┘
```

Without `Join`, `Open` would fire **twice**, once per branch message, each
missing the other branch's fields.

## Fields

| Field       | Default | Meaning                                                       |
|-------------|---------|---------------------------------------------------------------|
| `inputs`    | `2`     | Number of expected source nodes (parallel branches), must be ≥ 2 |
| `timeoutMs` | `10000` | Time to wait for the remaining branches from the first message |

## Behavior

- **Collect:** every incoming message is stored under its `source_node`.
  Branches are counted by *distinct source nodes*, so a branch emitting
  multiple messages does not double-count.
- **Merge:** once `inputs` distinct sources arrived, payloads are shallow-
  merged into one object (later branches overwrite duplicate keys — branches
  should emit disjoint fields) and emitted on `output`.
- **Fail-fast:** an incoming message containing a non-null `error` field is
  immediately forwarded on `error` and the trace entry is discarded. The
  join does not wait for slower branches once one branch already failed.
- **Timeout:** entries older than `timeoutMs` are lazily removed on the next
  invocation. No background task, no memory leak from dangling traces.
  A timed-out trace is dropped (the flow's own timeout handling applies).

## Message shape

Input: any payload (one per branch).

Output on `output`: shallow merge of all branch payloads.

Output on `error`: the failing branch's payload as-is (contains `error`).

## Notes

- State is per node instance and per `trace_id`. Concurrent executions of the
  same flow do not interfere.
- Works with any node types upstream; branches do not need to be symmetric.
- Pairs naturally with the engine's `dispatch_outputs` behavior: a node with a
  single outgoing edge forwards everything, so error branches of the sources
  should be wired to the flow's error handling, not through `Join` (unless
  fail-fast pass-through is desired, which is the default here).

## Relation to the `source_node` fix

`Join` relies on `msg.source_node` identifying the **emitting** node. Before
the engine fix (see CHANGELOG), messages kept the trigger's id forever, and
`Join` could not distinguish branches. If you run an older engine build,
fan-in patterns silently misbehave — this is why `Join` ships together with
the `dispatch_outputs` fix.
