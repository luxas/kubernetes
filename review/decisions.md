# Review decisions log (orchestrator judgement calls)

| ID | Stage | Decision | Reason |
|---|---|---|---|
| O-1 | 1 | `shipped.md` is a synthesis; the four subagent inventories are kept verbatim as `shipped/{A,B,C,D}-*.md` | 2400 lines of inventory are reference material; rewriting them would lose citations |
| O-2 | 1 | Appendix B's claim that the enforcer plugin is default-off was annotated as wrong rather than edited out | Keep the subagent's text auditable; `plugins.go:193` is the authority |
| O-3 | 2 | #137513 and #137633 reviewed by two agents each, reports kept intact under one file with an orchestrator header; overlapping thread audits noted, not deduplicated | Independent second opinions are more valuable than a merged table; dedup happens in `followups.md` |
| O-4 | 2 | Accepted every reviewer file after structural checks (five sections, thread total reconciles with the JSONL line count, HEAD path:line on findings) and spot-verification of the strongest security claims (field-selector fail-open, corrupt-object delete) | Full re-review of 3000 lines by the orchestrator would duplicate Stage 3 |
| O-5 | 3 | Security reviewer kept blind to Stage 2 output | Independent confirmation of the classifier-hole and failurePolicy findings was the point; it reproduced both |
| O-6 | 3 | Allowed the tests reviewer to download etcd via `hack/install-etcd.sh` despite the general no-network rule | The user required non-vacuity checks; one integration run was the only way to classify "integration-blind" mutations |
| O-7 | 3 | Mutation list fixed in advance (8 mandatory + 2 optional) and the reviewer added 7 hypothesis-driven variants | Keeps the exercise bounded and ties each mutation to a Stage 2 claim |
| O-8 | 4 | `summary.md` written by the orchestrator, not a subagent | It is the synthesis of five files already in context; a sixth agent would add nothing |
| O-9 | 4 | Where Stage 3 files disagree (D-3 Allow-error handling; D-6 enforcer position), both positions are surfaced to the user rather than resolved | Both change stated KEP semantics; user-level per plan §3 |
| O-10 | 4 | Stage 5 will assume the D-1..D-7 recommendations unless the user overrides | Avoids a second round-trip; each is reversible in the KEP text |
