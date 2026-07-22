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

1. **Docstring on `ConditionsAwareDecision` overstates what this commit ships.** `conditions.go:32–40` promises five variants (`Allow`, `Deny`, `NoOpinion`, `Conditional`, `Union`) but only three are implemented here. `Conditional` and `Union` are marked TODO in `FailClosedDecision` (`conditions.go:145–148`) and `ConditionsData` is an empty struct (`conditions.go:198–200`). A reader picking this commit up in isolation will be confused about state vs. plan. Prefer either narrowing the docstring ("three variants today; two more variants in follow-up") or landing this commit together with commit 08 (`9d7f6593151`) which adds the `ConditionsMap` variant.
2. **The invariant comment is not currently true.** `conditions.go:98` reads `INVARIANT: Exactly one of Is* must return true at all times.` but `IsUnconditional()` (`conditions.go:117–119`) returns `true` for any of Allow/Deny/NoOpinion — so *two* `Is*` predicates return `true` simultaneously (e.g. `IsAllowed() && IsUnconditional()`). Either rename `IsUnconditional` to `IsUnconditional*Category*` (mental group name) or amend the comment to say "exactly one of {`IsAllowed`, `IsDenied`, `IsNoOpinion`, `IsConditional`, `IsUnion`} returns true".
3. **`UnconditionalParts` godoc is inconsistent with behaviour.** `conditions.go:125–128` says "This function is meant to be called when IsUnconditional() == true", but the `default` branch handles the non-unconditional case by folding to `FailClosedDecision()`. The current code is safer than the docstring implies — reword to "safe to call even for conditional decisions; folds to FailClosedDecision() as a fallback" so callers know they can rely on it in bridge shims.
4. **`ConditionsData` is a placeholder empty struct.** `conditions.go:198–200`. Referenced by `Authorizer.EvaluateConditions` in the interface. Anyone implementing the interface today has to accept a value they can't inspect; the follow-up interfaces.go changes (later commits) evolve this into a rich interface. Consider gating this whole file behind the same commit where it becomes useful, or at minimum, make `ConditionsData` an interface with no methods now so its identity doesn't change later.
5. **`ConditionsAwareDecisionFromParts` on an unknown `Decision` value returns a Deny that surfaces the raw int enum in the reason.** `conditions.go:79–86`: `fmt.Errorf("unknown unconditional decision type: %d", unconditional)`. The value could originate from anywhere, but the fail-closed behaviour is correct. Consider whether this error should be `%!v(int=42)` style or explicitly `<internal>` to avoid the impression that these ints are a public contract.

### Nits

- `conditions.go:23` imports `utilerrors "k8s.io/apimachinery/pkg/util/errors"`. Every other file in the package uses the alias `utilerrors` too, so this is fine — verified.
- `conditions.go:33–34` comment says "The zero value (ConditionsAwareDecision{}) is equivalent to ConditionsAwareDecisionDeny()." The constructor takes `(reason, err)`, so equivalence is only structural under `reason=""`, `err=nil`. Minor: pin the exact equivalence, e.g. `ConditionsAwareDecision{} == ConditionsAwareDecisionDeny("", nil)`.
- `interfaces.go:100–115` — the two new method docstrings are excellent and give implementers a copy-pastable snippet. Nice.
- `interfaces.go:129–132` — `AuthorizerFunc.EvaluateConditions` uses named return-value shadowing implicitly via the `_ ConditionsData` param naming; consider `(_ Decision, _ string, err error)` with `err = ErrorConditionEvaluationNotSupported` for symmetry with the docstring "fail closed and return authorizer.DecisionDeny, ...".
- `interfaces.go:230–232` — updated docstring for `DecisionNoOpinion` mentions unioned authorizers, but this commit doesn't ship the union authorizer changes. Minor doc-vs-code timing issue.
- Test file uses `t.Context()` (Go 1.24+) — good, but verify all Kubernetes tree modules are on Go 1.24 already. `conditions_test.go:31`. (Spot check: yes, staging modules use go1.24 in the current tree.)

### Questions

- Why is `String()` (`conditions.go:170–197`) emitting `Deny` even when the decision is not (yet) `Conditional` or `Union`? The `if !d.IsAllowed() && !d.IsNoOpinion()` fallthrough means any future variant automatically prints as `Deny`, which will silently mask bugs after `ConditionsMap`/`Union` land. Consider adding a `panic` or a distinctive prefix (`<internal>`) for `default`.
- Rationale for choosing `errors.New` for `ErrorConditionEvaluationNotSupported` vs. an interface / typed error? Not blocking; single sentinel is fine.

## What's well done

- The default implementations on `AuthorizerFunc` are exactly the right shape: legacy code compiles unchanged, and the new methods return sensible fail-closed defaults. This is the pattern any downstream implementer will copy.
- The test file (`conditions_test.go:33+`) exercises the constructor, the derived `AuthorizerFunc.ConditionsAwareAuthorize`, and the zero-value / unknown-mode paths with the same table entries — a nice way to encode the "three shapes must agree" invariant. The `wantString` field pins the exact `String()` output, which is future-proof if the format is deliberately part of the API.
- The `ConditionsAwareDecisionFromParts` design decision — take the exact `(Decision, reason, error)` tuple the legacy `Authorize` returns — makes the migration story mechanical for the caller. Combined with the copy-paste snippet in the interface godoc, this is a well-designed migration ramp.
- Reasoning for the `unconditionalDecision Decision` field placement, with the comment explaining that `Decision(0) == DecisionDeny` makes the zero value coincide with Deny (`conditions.go:44–47`), is exactly the right kind of load-bearing comment.

## Verdict

**LGTM with nits.** The interface change is well-designed and the migration ramp is thoughtful. The main non-nit items are the docstring/state mismatches (five vs. three variants, invariant comment, `UnconditionalParts` semantics) — these will bite reviewers doing archaeology later. All are documentation-level fixes.
