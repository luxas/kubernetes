# Context: What is already implemented

**Current state:** `Decision` is `type Decision int` with `DecisionDeny`, `DecisionAllow`, `DecisionNoOpinion` as iota constants. The `Authorize` method returns `(Decision, string, error)`.

**Existing PoC state:** The PoC already added `DecisionConditionalAllow` (3) and `DecisionConditionalDeny` (4) as additional int constants. The KEP proposes migrating to a struct-based Decision with methods instead.

**Action — defer the struct migration to a follow-up PR.** The struct migration proposed in the KEP (constructor functions `DecisionAllow(reason)`, `DecisionDeny(reason)`, etc.) is a large-scale refactor touching hundreds of call sites. We should do it, in the following rewrite PR:

1. Introduce the `Decision` struct with `IsAllowed()`, `IsDenied()`, `IsNoOpinion()`, `IsConditional()`, `IsConcrete()`, `Reason()`, `CanBecomeAllowed()` methods.
2. Introduce `DecisionAllow(reason)`, `DecisionDeny(reason)`, `DecisionNoOpinion(reason)`, `DecisionConditional(conditionSets)` constructor functions.
3. Change `Authorizer` interface to return `(Decision, error)` instead of `(Decision, string, error)`.
4. Mechanically rewrite all ~10 call sites across the repo. Use `sed`/`gofmt` scripting.
5. Remove the old `int`-based constants.

**Files affected:**
- `staging/src/k8s.io/apiserver/pkg/authorization/authorizer/interfaces.go`
- Every file that calls `Authorize()` or implements the `Authorizer` interface (~10 files)

**Risk:** Purely mechanical, but large diff. Can be done as a separate PR merged before functional changes.
