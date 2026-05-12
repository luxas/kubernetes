# Strategies for Showing Equivalence Between the Lean Model and Production Go Code

## Problem Statement

We have a formal Lean 4 model (`plan/ConditionalAuthz.lean`) that proves the
correctness of Kubernetes' two-phase conditional authorization. We need to
establish that the production Go code faithfully implements the same semantics
as the Lean model. The Lean proof is only as valuable as the correspondence
between the model and the real code.

The key functions to verify correspondence for:

| Lean function | Go implementation | Location |
|---|---|---|
| `idealChain` | `unionAuthzHandler.Authorize` | `pkg/authorization/union/union.go` |
| `authzPhase` | `unionAuthzHandler.ConditionsAwareAuthorize` | `pkg/authorization/union/union.go:73-96` |
| `evaluateUnion` | `unionAuthzHandler.EvaluateConditions` | `pkg/authorization/union/union.go:99-152` |
| `unionCanBecomeAllowed` | `conditionsAwareDecisionUnionSlice.CanBecomeAllowed` | `pkg/authorization/authorizer/conditions.go` |
| `withAuthorizationFilter` | `withAuthorization` | `pkg/endpoints/filters/authorization.go:70-151` |
| `conditionsEnforcer` | `conditionsEnforcer.Validate` | `pkg/admission/plugin/authorizer/conditionsenforcer/` |
| `pipeline` | composition of the above | kube-apiserver handler chain |
| `ConditionsMap.Evaluate` | `ConditionsMap.Evaluate` | `pkg/authorization/authorizer/conditions.go:700-870` |

## Strategy 0: Line-by-Line Transpilation of Go to Lean (Strongest)

### Approach

Mechanically transpile the production Go functions into Lean 4, preserving the
exact control flow, branching structure, and variable names. Then prove the
equivalence theorems directly on the transpiled code. This eliminates the
model-vs-code gap entirely: the Lean proof is about the actual production
logic, not an abstraction of it.

### Why this is the strongest approach

The abstract model in `ConditionalAuthz.lean` uses axioms like `ax_allow`,
`ax_conditional`, etc. to link the ideal function to the two-phase split.
These axioms are *assumed* correct — they represent the contract a correct
authorizer must uphold, but are not themselves proven.

With transpilation:
- No axioms are needed. The transpiled Go code IS the implementation.
- Any production bug (off-by-one in a loop, missing case in a switch, wrong
  short-circuit condition) will appear in the transpiled Lean and either
  break the proof or require the prover to work around it — surfacing the bug.
- The proof applies to the actual control flow, not to an idealized model.

### Transpilation rules (Go → Lean)

| Go construct | Lean equivalent |
|---|---|
| `for _, x := range slice { ... }` | Recursive function over `List` |
| `switch x { case A: ...; case B: ... }` | `match x with \| A => ... \| B => ...` |
| `if cond { return x }; ...` | `if cond then x else ...` or `match ... with` |
| Mutable accumulator variable | Threaded function argument |
| `var decisions []T; decisions = append(...)` | Build list via cons (prepend) + reverse, or accumulator |
| Method on struct `(s *S) Foo(...)` | Function `Foo (s : S) ...` |
| `nil` / zero value | `Option.none` or explicit default |
| Error returns `(T, error)` | Model as `T` (errors are orthogonal to correctness) |
| Index correlation (`decisions[i]` ↔ `authzHandler[i]`) | Paired structure (like `UnionEntry`) |

### What the transpiled code looks like

For example, `unionAuthzHandler.ConditionsAwareAuthorize` (union.go:73-96):

```go
func (authzHandler unionAuthzHandler) ConditionsAwareAuthorize(ctx context.Context, a authorizer.Attributes) authorizer.ConditionsAwareDecision {
    var decisions []authorizer.ConditionsAwareDecision
    for _, currAuthzHandler := range authzHandler {
        decision := currAuthzHandler.ConditionsAwareAuthorize(ctx, a)
        decisions = append(decisions, decision)
        if decision.ContainsAllowOrDeny() {
            return authorizer.ConditionsAwareDecisionUnion(decisions...)
        }
    }
    return authorizer.ConditionsAwareDecisionUnion(decisions...)
}
```

Transpiles to:

```lean
def conditionsAwareAuthorize
    (handlers : List Authorizer) (attrs : Attrs)
    (acc : List ConditionsAwareDecision) -- threaded accumulator
    : ConditionsAwareDecision :=
  match handlers with
  | [] => conditionsAwareDecisionUnion acc
  | handler :: rest =>
    let decision := handler.conditionsAwareAuthorize attrs
    let acc' := acc ++ [decision]
    if decision.containsAllowOrDeny then
      conditionsAwareDecisionUnion acc'
    else
      conditionsAwareAuthorize rest attrs acc'
```

Similarly, `unionAuthzHandler.EvaluateConditions` (union.go:99-152):

```go
for i, unevaluatedSubDecision := range unevaluatedDecision.UnionedDecisions() {
    if unevaluatedSubDecision.IsAllowed() || unevaluatedSubDecision.IsDenied() {
        return unevaluatedSubDecision.UnconditionalParts()
    }
    if unevaluatedSubDecision.IsNoOpinion() {
        decision, reason, err = DecisionNoOpinion, ...
    } else {
        decision, reason, err = authzHandler[i].EvaluateConditions(...)
    }
    switch decision {
    case DecisionAllow, DecisionDeny: return decision, reason, err
    case DecisionNoOpinion: // continue
    }
}
return DecisionNoOpinion, ...
```

Transpiles to:

```lean
def evaluateConditions
    (handlers : List Authorizer)
    (subDecisions : List ConditionsAwareDecision)
    (data : ConditionsData)
    : UnconditionalDecision :=
  match handlers, subDecisions with
  | [], [] => .NoOpinion
  | handler :: hRest, subD :: dRest =>
    if subD.isAllowed then .Allow
    else if subD.isDenied then .Deny
    else
      let decision :=
        if subD.isNoOpinion then .NoOpinion
        else handler.evaluateConditions subD data
      match decision with
      | .Allow | .Deny => decision
      | .NoOpinion => evaluateConditions hRest dRest data
  | _, _ => .NoOpinion  -- length mismatch (impossible by construction)
```

### What to prove

The main theorem is the same as in the abstract model, but now proven
on the transpiled production code:

```lean
theorem transpiled_authorization_equivalence :
    ∀ handlers attrs data,
    transpiled_idealChain handlers attrs data =
    transpiled_pipeline handlers attrs data
```

Where `transpiled_idealChain` is the transpiled `Authorize()` and
`transpiled_pipeline` is the composition of transpiled
`ConditionsAwareAuthorize`, `withAuthorization`, and `conditionsEnforcer.Validate`.

### Advantages

- **Zero model-vs-code gap**: the proof is about the actual code
- **Bugs surface as proof failures**: any logic error in Go becomes a
  stuck proof in Lean
- **Reviewable**: a Go developer can read the transpiled Lean side-by-side
  with the Go and verify the correspondence

### Disadvantages

- **Manual effort**: each Go function must be hand-transpiled (though the
  process is mechanical)
- **Maintenance**: when the Go code changes, the transpiled Lean must be
  updated
- **Complexity**: Go idioms (error handling, context, mutable state) add
  noise to the transpiled Lean. Must decide what to model vs. abstract away.
  Errors and HTTP response writing are side-effects orthogonal to the
  authorization decision; reasonable to strip them.
- **Abstraction boundary**: at some point you still abstract away the
  authorizer implementations (RBAC, webhook, etc.) as opaque functions.
  The transpilation covers the *framework* (union, filter, enforcer),
  not every possible authorizer.

### Relationship to the abstract model

The abstract model and the transpilation are complementary:

1. The **abstract model** proves the *design* is correct: any authorizer
   chain satisfying the axioms produces equivalent results.
2. The **transpilation** proves the *implementation* matches the design:
   the actual Go control flow produces the same results as the abstract model.

Together they form a chain: `design correct ∧ implementation = design ⟹ implementation correct`.

### Execution plan

1. Transpile `union.Authorize` → `transpiled_idealChain`
2. Transpile `union.ConditionsAwareAuthorize` → `transpiled_authzPhase`
3. Transpile `union.EvaluateConditions` → `transpiled_evaluateUnion`
4. Transpile `CanBecomeAllowed` → `transpiled_unionCanBecomeAllowed`
5. Transpile `withAuthorization` filter → `transpiled_withAuthorizationFilter`
6. Transpile `conditionsEnforcer.Validate` → `transpiled_conditionsEnforcer`
7. Transpile `ConditionsMap.Evaluate` → `transpiled_conditionsMapEvaluate`
8. Prove `transpiled_idealChain = transpiled_pipeline` (the main theorem)
9. Optionally prove the transpiled code matches the abstract model
   (bridging lemma), which then gives all abstract-model theorems for free

## Strategy 1: Structured Property-Based Testing with hegel-go (Recommended First)

### Approach

Use [hegel-go](https://github.com/hegeldev/hegel-go) to generate arbitrary
authorizer chains, ConditionsMaps, and admission data. For each generated
scenario, run both:

1. The Go implementation's `ConditionsAwareAuthorize` + `EvaluateConditions` pipeline
2. A Go "reference oracle" that directly mirrors the Lean model's `idealChain`

Assert that the outputs match.

### Why hegel-go

- Property-based testing with automatic shrinking finds minimal counterexamples
- Stateful testing (`RunStateful`) can model the multi-stage request lifecycle
- Generators can produce structured authorization decision trees
- Integrates with Antithesis for deeper exploration when ready
- Works with standard `go test`; no special infrastructure needed initially

### What to generate

1. **Authorizer chains** of length 1..N, where each authorizer's behavior is
   defined by a lookup table mapping (attrs, data) pairs to decisions
2. **ConditionsMaps** with varying numbers of Allow/Deny/NoOpinion conditions
3. **Admission data** (the condition evaluation inputs)
4. **Decision trees** (Union of leaf decisions) to test `evaluateUnion` and
   `unionCanBecomeAllowed` in isolation

### Properties to test

- `isAllowed(idealChain(...)) == isAllowed(pipeline(...))`
  (the main theorem from the Lean model)
- `evaluateUnion(authzPhase(chain, attrs), data) == idealChain(chain, attrs, data)`
  (the core semantic lemma)
- `unionCanBecomeAllowed(entries) == false` implies
  `evaluateUnion(entries, data) != Allow` (cba soundness)
- `ConditionsMap.Evaluate` priority ordering: Deny > NoOpinion > Allow

### Implementation plan

See `plan/authz_oracle_test.go` for the concrete implementation.

### Antithesis integration (future)

Once the hegel-go tests pass locally, they can run on Antithesis for
significantly deeper exploration:

```
# When ready, run on Antithesis for millions of test cases
antithesis run --image <test-image> --duration 1h
```

Antithesis's deterministic simulation can explore orderings and interleavings
that local testing misses.

## Strategy 2: Direct Transliteration Testing

### Approach

Write a Go package (`pkg/authorization/authorizer/leanmodel/`) that is a
line-by-line transliteration of the Lean model into Go. Each Lean function
becomes an equivalent Go function with the same structure. Then test that the
transliteration produces the same output as the production code for all inputs.

### Advantages

- Maximum fidelity: the Go transliteration is obviously correct by inspection
- Can be code-reviewed side-by-side with the Lean model
- Tests are simple equality checks

### Disadvantages

- Manual effort to maintain the transliteration as the Lean model evolves
- Doesn't prove the transliteration itself is correct (just that it matches the
  production code)

### Structure

```go
package leanmodel

// Direct transliteration of ConditionalAuthz.lean

type UnconditionalDecision int
const (
    Allow UnconditionalDecision = iota
    Deny
    NoOpinion
)

func IdealChain(chain []Authorizer, attrs Attrs, data Data) UnconditionalDecision { ... }
func AuthzPhase(chain []Authorizer, attrs Attrs) []UnionEntry { ... }
func EvaluateUnion(entries []UnionEntry, data Data) UnconditionalDecision { ... }
func UnionCanBecomeAllowed(entries []UnionEntry) bool { ... }
func Pipeline(chain []Authorizer, attrs Attrs, data Data) UnconditionalDecision { ... }
```

## Strategy 3: Lean 4 FFI to Go via C Bridge

### Approach

Compile the Lean model to a shared library (Lean compiles to C), and call it
from Go via cgo. This gives a true oracle: the actual Lean code runs, not a
transliteration.

### Steps

1. Add `@[export]` annotations to key Lean functions
2. Compile with `lean --c` to get C code, then compile to `.so`/`.dylib`
3. Write cgo bindings in Go
4. In tests, call both the Go implementation and the Lean oracle

### Advantages

- Zero transliteration gap: the oracle IS the formal model
- Any divergence is a real bug

### Disadvantages

- Complex build setup (Lean → C → shared library → cgo)
- Data serialization between Go and C/Lean types
- Lean's runtime has its own memory management (reference counting)
- Build/CI complexity

### Feasibility

Medium. Lean 4 does compile to C and supports `@[export]`, but the marshalling
of complex types (lists, structures with function fields) is non-trivial.
Best suited for leaf functions like `evaluateConditionsMap` that operate on
simple data.

## Strategy 4: Bidirectional Specification Testing via JSON

### Approach

Define a JSON schema for test vectors. Generate test vectors from both the
Lean model (via a Lean program that outputs JSON) and the Go tests. Cross-
validate: Lean-generated vectors are consumed by Go tests, and Go-generated
vectors are consumed by Lean validators.

### Structure

```json
{
  "chain": [
    {"authorize_result": "Conditional", "cm_index": 0, "evaluate_result": "Allow"},
    {"authorize_result": "NoOpinion"},
    {"authorize_result": "Allow"}
  ],
  "expected_ideal": "Allow",
  "expected_pipeline": "Allow",
  "expected_cba": true
}
```

### Advantages

- Language-agnostic: test vectors can be consumed by any implementation
- Can be checked into the repo as regression fixtures
- Easy to add new test cases

### Disadvantages

- Limited to the space of test vectors generated
- Doesn't cover all possible inputs (unlike property-based testing)
- Requires maintaining the JSON schema

## Strategy 5: Formal Extraction (Lean → Go)

### Approach

Use or build a Lean 4 → Go code extractor that produces Go code directly from
the Lean definitions. The extracted code is correct by construction.

### Status

No mature Lean 4 → Go extractor exists today. Lean 4 has extraction to C
(built-in) and experimental extraction to other targets. Building a Go
extractor would be a significant project.

### When to consider

If the conditional authorization model grows complex enough that manual
transliteration becomes error-prone, investing in an extractor pays off.
For the current model (~500 lines of Lean), manual transliteration is
sufficient.

## Recommended Execution Order

1. **Strategy 1 (hegel-go)**: Implement first. Fast to set up, gives high
   confidence with automatic shrinking. Already implemented in
   `plan/authz_oracle_test.go`. The oracle functions in that file serve double
   duty as the Strategy 2 transliteration.

2. **Strategy 0 (Go → Lean transpilation)**: The strongest long-term approach.
   Transpile the production Go into Lean and prove theorems on the transpiled
   code. This eliminates the model-vs-code gap. Do this once the hegel-go
   tests have built confidence that the abstract model is correct.

3. **Strategy 4 (JSON fixtures)**: Generate golden test vectors from the
   Lean model and check them into the repo as regression tests.

4. **Strategy 3 (Lean FFI)**: Consider for leaf functions like
   `ConditionsMap.Evaluate` where C interop is straightforward.

5. **Strategy 5 (extraction)**: Long-term aspiration, not needed now.
