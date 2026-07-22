# Review: Extend the Authorizer interface with conditions-aware methods (6d78dfd60cf)

- **SHA:** `6d78dfd60cfeddcd3e47a92306571eab155ea7ce`
- **Author date:** 2026-03-15 (committer date 2026-05-08 — rebased later)
- **Subject:** Extend the Authorizer interface with conditions-aware methods.
- **Reachable on:** dangling; reachable by SHA only. Was superseded on the current branch by later, squashed commits.
- **Size:** 3 files, +425 / -4

## What this commit does

Grows the `authorizer.Authorizer` interface (`staging/src/k8s.io/apiserver/pkg/authorization/authorizer/interfaces.go`) with two new methods: `ConditionsAwareAuthorize(ctx, attrs) ConditionsAwareDecision` and `EvaluateConditions(ctx, decision, data) (Decision, string, error)`. Introduces a new sibling file `conditions.go` that defines the `ConditionsAwareDecision` value type (currently only carrying unconditional variants), constructors, and helper methods. `AuthorizerFunc` gains default implementations of both new methods so existing usages continue to compile. Includes a comprehensive table-driven test of the `ConditionsAwareDecision` value type.

This is the *first* commit of the conditional-authz series; it establishes the vocabulary the rest of the KEP builds on. The conditional (`ConditionsMap`) and union (`Union`) variants promised by the docstring are TODO'd for follow-up commits.

## Files touched

- Production
  - `staging/src/k8s.io/apiserver/pkg/authorization/authorizer/interfaces.go` (edit)
  - `staging/src/k8s.io/apiserver/pkg/authorization/authorizer/conditions.go` (new)
- Tests
  - `staging/src/k8s.io/apiserver/pkg/authorization/authorizer/conditions_test.go` (new)

## Findings

### Critical (must fix before merge)

None. The interface grows in a way that would ordinarily break every out-of-tree `Authorizer` implementation, but commit 03 (`69a8b4dd7a9`) is expected to migrate all in-tree callers, and the plan for external callers is documented in the added godocs.

### Important (should fix)


### Nits

### Questions


## What's well done

- The default implementations on `AuthorizerFunc` are exactly the right shape: legacy code compiles unchanged, and the new methods return sensible fail-closed defaults. This is the pattern any downstream implementer will copy.
- The test file (`conditions_test.go:33+`) exercises the constructor, the derived `AuthorizerFunc.ConditionsAwareAuthorize`, and the zero-value / unknown-mode paths with the same table entries — a nice way to encode the "three shapes must agree" invariant. The `wantString` field pins the exact `String()` output, which is future-proof if the format is deliberately part of the API.
- The `ConditionsAwareDecisionFromParts` design decision — take the exact `(Decision, reason, error)` tuple the legacy `Authorize` returns — makes the migration story mechanical for the caller. Combined with the copy-paste snippet in the interface godoc, this is a well-designed migration ramp.
- Reasoning for the `unconditionalDecision Decision` field placement, with the comment explaining that `Decision(0) == DecisionDeny` makes the zero value coincide with Deny (`conditions.go:44–47`), is exactly the right kind of load-bearing comment.

## Tests

### Test files touched
- `staging/src/k8s.io/apiserver/pkg/authorization/authorizer/conditions_test.go` — new file, 194 lines. Single `TestConditionsAwareDecision` function driving a table of 6 test cases.

### Coverage

### Structure

### Stale comments

## Verdict

**LGTM with nits.** The interface change is well-designed and the migration ramp is thoughtful. The main non-nit items are the docstring/state mismatches (five vs. three variants, invariant comment, `UnconditionalParts` semantics) — these will bite reviewers doing archaeology later. All are documentation-level fixes.
