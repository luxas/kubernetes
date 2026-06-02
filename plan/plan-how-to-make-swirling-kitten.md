# Plan: Thread `Attributes` and `ConditionsData` through `ConditionalAuthzFromScratch.lean`

## Context

`plan/ConditionalAuthzFromScratch.lean` currently models each `Authorizer` as a record of **pre-bound** outputs (`authorize : Decision`, `conditionsAwareAuthorize : ConditionsAwareDecision`, `evaluateConditions : Decision`) linked by `AuthorizerContract`. That is convenient for proofs but does not look anything like the real Go code, where each method takes `(ctx, Attributes)` or `(ctx, decision, ConditionsData)` and computes a result.

The goal is to refactor the file so its types and function signatures mirror Go in `staging/src/k8s.io/apiserver/pkg/authorization/{authorizer,union}/`:

- Add an `Attributes` struct (mirrors `AttributesRecord` in `interfaces.go:138-154`).
- Replace the stub `ConditionsData { object, oldObject }` with the real shape from `conditions.go:993-1040` (`ConditionsData` wrapping an optional `ConditionsDataAdmissionControl`).
- Convert each `Authorizer` field and each union function to take/thread these structs.
- Per the user: "objects can be represented as plain strings" — collapse `user.Info`, `runtime.Object`, `schema.GroupVersionResource`, `schema.GroupVersionKind`, `fields.Requirements`, `labels.Requirements` to plain `String`. No deep modeling of selectors.

## New / modified types

### `Attributes` (new)

Concrete `structure` mirroring `AttributesRecord`. `IsReadOnly` is derived from `Verb` (matches Go at `interfaces.go:164-166`). Selector requirements collapse to `String`; their parse errors are dropped (orthogonal to authorization correctness).

```lean
structure Attributes where
  user             : String
  verb             : String
  namespace        : String
  apiGroup         : String
  apiVersion       : String
  resource         : String
  subresource      : String
  name             : String
  resourceRequest  : Bool
  path             : String
  fieldSelector    : String
  labelSelector    : String
  deriving Repr, DecidableEq

def Attributes.isReadOnly (a : Attributes) : Bool :=
  a.verb = "get" || a.verb = "list" || a.verb = "watch"
```

### `ConditionsData` (replace the existing stub)

Match Go's nested layout. Go's comment on `ConditionsData.AdmissionControl` ("Callers must verify that this is non-nil") justifies `Option`.

```lean
structure ConditionsDataAdmissionControl where
  name             : String
  namespace        : String
  resource         : String   -- collapsed GroupVersionResource
  subresource      : String
  operation        : String   -- AdmissionOperation
  operationOptions : String   -- collapsed runtime.Object
  isDryRun         : Bool
  object           : String   -- collapsed runtime.Object
  oldObject        : String
  kind             : String   -- collapsed GroupVersionKind
  userInfo         : String   -- collapsed user.Info
  deriving Repr, DecidableEq

structure ConditionsData where
  admissionControl : Option ConditionsDataAdmissionControl
  deriving Repr, DecidableEq
```

The old two-field `ConditionsData` is removed.

### `ConditionsMap.evaluate` becomes data-aware

```lean
structure ConditionsMap where
  hasDenyCondition  : Bool
  hasAllowCondition : Bool
  evaluate          : ConditionsData → Decision
  ax_at_least_one_allow_or_deny :
    hasDenyCondition = true ∨ hasAllowCondition = true
  ax_no_allow_cond_implies_never_allow :
    ¬hasAllowCondition → ∀ d, evaluate d ≠ .Allow
  ax_no_deny_cond_implies_never_deny  :
    ¬hasDenyCondition  → ∀ d, evaluate d ≠ .Deny
```

`ConditionsMap.Ideal` and `ConditionsAwareDecision.Ideal` gain a `ConditionsData` parameter. `unionIdealAuthorize` also threads it. `FailClosedDecision`, `CanBecomeAllowed`, `ContainsAllowOrDeny` stay **data-free** — they're metadata predicates over the decision tree, not the request payload (matches Go).

Drop `deriving Repr, DecidableEq` from `ConditionsMap` once `evaluate` is a function (Lean can't synthesize either for function fields). Quick grep confirms nothing in the file depends on `DecidableEq ConditionsMap` or `Repr ConditionsMap` — the `deriving` was speculative. Downstream `Repr ConditionsAwareDecision` also gets dropped.

### `AuthorizerContract`

```lean
def AuthorizerContract
    (conditionsAwareAuthorize : ConditionsAwareDecision)
    (authorize : Decision)
    (evaluateConditions : ConditionsData → Decision) : Prop :=
  match conditionsAwareAuthorize with
  | .Allow     => authorize = .Allow     ∧ ∀ d, evaluateConditions d = .Deny
  | .Deny      => authorize = .Deny      ∧ ∀ d, evaluateConditions d = .Deny
  | .NoOpinion => authorize = .NoOpinion ∧ ∀ d, evaluateConditions d = .Deny
  | .ConditionsMap _ | .Union _ =>
      (∀ d, evaluateConditions d = conditionsAwareAuthorize.Ideal d) ∧
      match conditionsAwareAuthorize.FailClosedDecision with
      | .Deny => authorize = .Deny
      | _     => authorize = .NoOpinion
```

The Allow/Deny/NoOpinion legs assert `∀ d, evaluateConditions d = .Deny`, which matches Go's default `AuthorizerFunc.EvaluateConditions` returning `DecisionDeny` unconditionally (`interfaces.go:122-124`).

### `Authorizer`

```lean
structure Authorizer where
  authorize                : Attributes → Decision
  conditionsAwareAuthorize : Attributes → ConditionsAwareDecision
  evaluateConditions       : ConditionsAwareDecision → ConditionsData → Decision
  ax_authorizer : ∀ a,
    AuthorizerContract
      (conditionsAwareAuthorize a)
      (authorize a)
      (fun d => evaluateConditions (conditionsAwareAuthorize a) d)

def Authorizer.idealAuthorize
    (a : Authorizer) (attrs : Attributes) (d : ConditionsData) : Decision :=
  (a.conditionsAwareAuthorize attrs).Ideal d
```

`evaluateConditions` takes the `ConditionsAwareDecision` argument explicitly, exactly as in Go (`interfaces.go:107`). The contract's third slot is the partial application at the authorizer's own decision.

## Union function signatures

```lean
def unionAuthorize : List Authorizer → Attributes → Decision
def unionConditionsAwareAuthorize :
    List Authorizer → Attributes → List (Authorizer × ConditionsAwareDecision)
def unionEvaluateConditions :
    List (Authorizer × ConditionsAwareDecision) → ConditionsData → Decision
def unionIdeal : List Authorizer → Attributes → ConditionsData → Decision
```

Key design call: `unionEvaluateConditions` does **not** take `Attributes`. This matches Go (`union.go:99`: `EvaluateConditions(ctx, decision, data)` — no attrs). The decision captured per-authorizer in `unionConditionsAwareAuthorize` already encodes the attrs-dependent result.

## Critical files

- `plan/ConditionalAuthzFromScratch.lean` — the only file modified
- `staging/src/k8s.io/apiserver/pkg/authorization/authorizer/interfaces.go` (read-only reference)
- `staging/src/k8s.io/apiserver/pkg/authorization/authorizer/conditions.go` (read-only reference)
- `staging/src/k8s.io/apiserver/pkg/authorization/union/union.go` (read-only reference)

## Proof porting matrix

| Theorem | Change kind |
|---|---|
| `contract_conditional` (private helper) | Project the new `∀ d` quantifier; conclusion gains `∀ d, a.evaluateConditions (.ConditionsMap cm) d = cm.evaluate d`. Mechanical. |
| `evaluate_eq_ideal` | Gain `(attrs : Attributes) (d : ConditionsData)`; conclusion becomes `unionEvaluateConditions (unionConditionsAwareAuthorize handlers attrs) d = unionIdeal handlers attrs d`. ConditionsMap case instantiates `contract_conditional` at the same `d`. Mostly mechanical. |
| `conditionsMap_failClosed_deny_or_noOpinion` | **No change.** Depends only on `hasDenyCondition`. |
| `failClosed_deny_or_noOpinion` / `foldFailClosed_deny_or_noOpinion` (mutual) | **No change.** `FailClosedDecision` is data-free. |
| `failClosed_not_deny_implies_ideal_not_deny` / `foldFailClosed_not_deny_implies_ideal_not_deny` (mutual) | Add `(d : ConditionsData)`; conclusion becomes `d.Ideal data ≠ .Deny`. Inner use of `cm.ax_no_deny_cond_implies_never_deny` instantiates at `d`. Mechanical. |
| `metadata_allow_implies_ideal_allow` | Add `(attrs : Attributes) (d : ConditionsData)`. Both sides reference them. Body structure preserved. |
| `unionAuthorize_no_allow_when_no_unconditional` | Add `(attrs : Attributes)`. The hypothesis `∀ a ∈ handlers, a.conditionsAwareAuthorize ≠ .Allow ∧ … ≠ .Deny` becomes `∀ a ∈ handlers, a.conditionsAwareAuthorize attrs ≠ .Allow ∧ … ≠ .Deny`. Mechanical. |

There is no existing `mkUnionAuthorizer` (the file currently has only a commented-out TODO at lines 158-159 of the pre-refactor file), so we add nothing there in this refactor.

## Staged migration (each stage compiles green before moving on)

1. **Types only.** Add `Attributes`, `ConditionsDataAdmissionControl`; rewrite `ConditionsData`. Nothing references them yet — file still compiles.
2. **Make `ConditionsMap.evaluate` data-aware.** Update its two `ax_no_*_cond_implies_never_*` axioms to `∀ d`. Update `ConditionsMap.Ideal`, `ConditionsAwareDecision.Ideal`, `unionIdealAuthorize` to thread `ConditionsData`. Port the mutual `failClosed_not_deny_implies_ideal_not_deny` block (purely mechanical: add `d`, instantiate the deny-axiom at `d`). Drop `deriving Repr, DecidableEq` from `ConditionsMap` and `ConditionsAwareDecision`.
3. **Make `Authorizer` attrs-aware.** Generalize `AuthorizerContract` to `evaluateConditions : ConditionsData → Decision` with `∀ d`. Convert the three `Authorizer` fields to functions over `Attributes` (and the new `evaluateConditions` shape). Update `ax_authorizer` to `∀ a, …`. Update `Authorizer.idealAuthorize`. Re-prove `contract_conditional` — it now needs to introduce the `∀ d` quantifier.
4. **Thread `attrs` through union functions and their proofs.** Update `unionAuthorize`, `unionConditionsAwareAuthorize`, `unionIdeal` signatures and recursive calls. Update `evaluate_eq_ideal`, `metadata_allow_implies_ideal_allow`, `unionAuthorize_no_allow_when_no_unconditional`. `unionEvaluateConditions` does NOT gain `attrs` (Go-faithful).
5. **Verification.** Add `#check` lines pinning the new signatures, e.g.

   ```lean
   #check (Authorizer.authorize : Authorizer → Attributes → Decision)
   #check (Authorizer.evaluateConditions :
            Authorizer → ConditionsAwareDecision → ConditionsData → Decision)
   #check (unionEvaluateConditions :
            List (Authorizer × ConditionsAwareDecision) → ConditionsData → Decision)
   ```

Stages 1, 2, 4 are essentially syntactic. Stage 3 is where care is needed because `ax_authorizer` is now a `∀` and `contract_conditional` must project it.

## Verification

- After each stage, run `lake env lean ../ConditionalAuthzFromScratch.lean` from `/Users/luxas/upbound/kubernetes/plan/lean-authz` and confirm exit code `0` with no errors or warnings.
- After stage 5, confirm the `#check` lines print the expected types in the build output.
- Cross-check by reading the resulting `Authorizer` and union signatures side-by-side with `interfaces.go:89-108` and `union.go:46-152` — the Lean shape should now visually match Go's three-method interface and the union loop signatures.
- No tests to run (this is a proof-only file); the proof of correctness is that the file type-checks.
