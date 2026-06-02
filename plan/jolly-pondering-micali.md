# Plan: Model the union authorizer as a structure with Go-transliterated methods

## Context

The current `mkUnionAuthorizer` is incorrect: it sets `evaluateConditions := ca.Ideal`, but `Ideal` is the **specification** (the claim to prove), not the implementation. The Go code never calls `Ideal` — it calls `EvaluateConditions`, which happens to produce the same result. That equivalence is the core theorem.

We need to restructure so that:
1. The union's three methods are exact Go transliterations
2. The `AuthorizerContract` is **proven** to hold, not assumed
3. `Ideal` remains purely a specification function, never used in any implementation

### The core contract tension

`AuthorizerContract` for `Union _` requires `authorize` to be Deny or NoOpinion — never Allow. But `unionAuthorize` CAN return Allow when a sub-handler unconditionally allows.

**Resolution**: Go's `ConditionsAwareDecisionUnion` constructor simplifies the result — if a sub-handler returns Allow/Deny, it returns that leaf directly (not wrapped in Union). The `Union` variant only appears when all sub-decisions are NoOpinion or conditional, in which case `unionAuthorize` can indeed only return Deny or NoOpinion.

This means we must model `conditionsAwareDecisionUnion` to make the contract provable.

## File: `plan/ConditionalAuthzFromScratch.lean`

### Step 1: Remove current `mkUnionAuthorizer` (lines 263-312)

### Step 2: Add Go-transliterated standalone functions

#### 2a. `collectEntries` — the loop body of `ConditionsAwareAuthorize`

Transliteration of Go's `ConditionsAwareAuthorize` loop (union.go:73-96). Models the index correlation `decisions[i] ↔ authzHandler[i]` as explicit pairing. Short-circuits on `ContainsAllowOrDeny` (for leaf decisions: Allow/Deny).

```lean
def collectEntries : List Authorizer → List (Authorizer × ConditionsAwareDecision)
  | [] => []
  | h :: rest =>
    let d := h.conditionsAwareAuthorize
    match d with
    | .Allow | .Deny => [(h, d)]
    | _ => (h, d) :: collectEntries rest
```

#### 2b. `conditionsAwareDecisionUnion` — Go's constructor (conditions.go:931-991)

Scans the list for the first non-NoOpinion decision. Returns:
- NoOpinion if all are NoOpinion (or list is empty)
- The leaf if the first non-NoOpinion is Allow/Deny
- `Union ds` otherwise (first non-NoOpinion is conditional)

```lean
def conditionsAwareDecisionUnion (ds : List ConditionsAwareDecision) : ConditionsAwareDecision :=
  match ds with
  | [] => .NoOpinion
  | [d] => match d with
    | .Allow | .Deny | .NoOpinion => d
    | _ => .Union [d]
  | _ => firstNonNoOpinion ds
where
  firstNonNoOpinion (all : List ConditionsAwareDecision)
    : List ConditionsAwareDecision → ConditionsAwareDecision
    | [] => .NoOpinion
    | d :: rest => match d with
      | .NoOpinion => firstNonNoOpinion all rest
      | .Allow => d
      | .Deny => d
      | _ => .Union all
```

Note: the helper threads `all` (the original full list) because Go's `break` falls through to `return Union(decisions)` using the original slice.

#### 2c. `unionAuthorize` — Go's `Authorize` (union.go:46-70)

```lean
def unionAuthorize : List Authorizer → Decision
  | [] => .NoOpinion
  | h :: rest =>
    match h.authorize with
    | .Allow => .Allow | .Deny => .Deny | .NoOpinion => unionAuthorize rest
```

#### 2d. `unionEvaluateConditions` — Go's `EvaluateConditions` (union.go:98-152)

Operates on the paired entries (models `authzHandler[i].EvaluateConditions`):

```lean
def unionEvaluateConditions : List (Authorizer × ConditionsAwareDecision) → Decision
  | [] => .NoOpinion
  | (h, d) :: rest =>
    match d with
    | .Allow => .Allow | .Deny => .Deny | .NoOpinion => unionEvaluateConditions rest
    | .ConditionsMap _ | .Union _ =>
      match h.evaluateConditions with
      | .Allow => .Allow | .Deny => .Deny | .NoOpinion => unionEvaluateConditions rest
```

#### 2e. `unionIdeal` — specification (not in Go, this IS the claim)

```lean
def unionIdeal : List Authorizer → Decision
  | [] => .NoOpinion
  | h :: rest =>
    match h.idealAuthorize with
    | .Allow => .Allow | .Deny => .Deny | .NoOpinion => unionIdeal rest
```

### Step 3: Define `UnionAuthorizer` structure and methods

```lean
structure UnionAuthorizer where
  handlers : List Authorizer

namespace UnionAuthorizer

def entries (u : UnionAuthorizer) := collectEntries u.handlers

def authorize (u : UnionAuthorizer) : Decision :=
  unionAuthorize u.handlers

def conditionsAwareAuthorize (u : UnionAuthorizer) : ConditionsAwareDecision :=
  conditionsAwareDecisionUnion (u.entries.map Prod.snd)

def evaluateConditions (u : UnionAuthorizer) : Decision :=
  match u.conditionsAwareAuthorize with
  | .Allow | .Deny | .NoOpinion => .Deny
  | _ => unionEvaluateConditions u.entries
```

The `evaluateConditions` conditional matches Go's actual behavior: the `withAuthorization` filter never calls `EvaluateConditions` when `ConditionsAwareAuthorize` returns a leaf. The `.Deny` default for leaf cases satisfies the contract's convention.

### Step 4: Prove key lemmas

#### 4a. `conditionsAwareDecisionUnion_preserves_ideal`

```
(conditionsAwareDecisionUnion ds).Ideal = unionIdealAuthorize ds
```

Case-split on what `conditionsAwareDecisionUnion` returns:
- NoOpinion (all NoOpinion) → `NoOpinion.Ideal = NoOpinion = unionIdealAuthorize [NoOpinion, ...]` ✓
- Allow/Deny leaf → `Allow.Ideal = Allow`, and `unionIdealAuthorize` also returns Allow/Deny (it scans past NoOpinions and hits the leaf) ✓
- `Union ds` → `(Union ds).Ideal = unionIdealAuthorize ds` by definition ✓

#### 4b. `evaluate_eq_ideal` (restore from previous proof)

```
unionEvaluateConditions (collectEntries handlers) = unionIdeal handlers
```

Induction on handlers, case-split on `conditionsAwareAuthorize`, use per-authorizer contract. Previously proven.

#### 4c. `unionAuthorize_consistent_with_conditionsAwareDecisionUnion`

When `conditionsAwareDecisionUnion (collectEntries handlers |>.map Prod.snd)` returns:
- `.Allow` → `unionAuthorize handlers = .Allow`
- `.Deny` → `unionAuthorize handlers = .Deny`
- `.NoOpinion` → `unionAuthorize handlers = .NoOpinion`
- `.Union _` → `unionAuthorize handlers` matches `FailClosedDecision`:
  - No sub-handler returned unconditional Allow/Deny (by construction of `conditionsAwareDecisionUnion`)
  - Sub-handlers with NoOpinion `conditionsAwareAuthorize` have `authorize = NoOpinion`
  - Sub-handlers with conditional `conditionsAwareAuthorize` have `authorize = Deny` or `NoOpinion`
  - So `unionAuthorize` returns Deny iff some handler has `authorize = Deny`, which corresponds to `FailClosedDecision = Deny`

### Step 5: Prove `satisfies_contract` and define `toAuthorizer`

```lean
theorem satisfies_contract (u : UnionAuthorizer) :
    AuthorizerContract u.conditionsAwareAuthorize u.authorize u.evaluateConditions := by
  -- Case-split on what conditionsAwareDecisionUnion returns
  -- Leaf cases: trivial from 4c
  -- Union case: use 4a + 4b for evaluateConditions, 4c for authorize
  sorry -- to be proven during implementation

def toAuthorizer (u : UnionAuthorizer) : Authorizer := {
  authorize := u.authorize,
  conditionsAwareAuthorize := u.conditionsAwareAuthorize,
  evaluateConditions := u.evaluateConditions,
  ax_authorizer := u.satisfies_contract
}

end UnionAuthorizer
```

### Step 6: Restore `contract_conditional` helper

Needed by `evaluate_eq_ideal` for the ConditionsMap case.

## Proof strategy summary

The contract proof decomposes into:

```
                    evaluateConditions = Ideal(conditionsAwareAuthorize)
                              ↑
          ┌─────────────────────────────────────────┐
          │                                         │
  unionEvaluateConditions    =    unionIdeal    =    Ideal(conditionsAwareDecisionUnion(...))
  (entries)                       (handlers)         
          ↑                         ↑                         ↑
     evaluate_eq_ideal        bridge lemma       conditionsAwareDecisionUnion
     (per-authorizer            (trivial)            _preserves_ideal
      contracts)
```

## Verification

```
lean plan/ConditionalAuthzFromScratch.lean
```

Should compile with no errors. Target: no `sorry`. If some proof is too complex, mark with `sorry` and document what remains.
