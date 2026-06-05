# Plan: Update Lean model to match current Go authorization code

## Context

The Go authorization code has evolved significantly since the Lean model was last updated.
The Lean project (5 files in a Lake project at repo root) compiles cleanly but no longer
faithfully mirrors the Go code in several important ways. This plan covers updating the
Lean model to match, for every instance of divergence.

**Go source directory**: `staging/src/k8s.io/apiserver/pkg/authorization/`
**Lean source directory**: `ConditionalAuthorization/` (root of repo)

---

## Side-by-side comparison: every divergence

### 1. `Authorizer` interface: missing `AuthorizerName`

**Go** (interfaces.go:103-127):
```go
type Authorizer interface {
    Authorize(ctx, a) (Decision, string, error)
    ConditionsAwareAuthorize(ctx, a) ConditionsAwareDecision
    EvaluateConditions(ctx, decision, data) (Decision, string, error)
    AuthorizerName() string   // ← NEW
}
```

**Lean** (Spec.lean:27-41):
```lean
structure Authorizer where
    authorize : Attributes → Decision
    conditionsAwareAuthorize : Attributes → ConditionsAwareDecision
    evaluateConditions : ConditionsAwareDecision → ConditionsData → Decision
    ax_authorizer : ...
```

**Delta**: Add `name : String` field to `Authorizer`. Used for correlating decisions
to authorizers during `EvaluateConditions`.

---

### 2. `ConditionsMap.FailClosedDecision` → `FailureDecision` + `PossibleDecisions`

**Go** (conditionsmap.go:49-106):
```go
func (c ConditionsMap) FailureDecision() Decision {
    if c.PossibleDecisions().Has(DecisionDeny) { return DecisionDeny }
    return DecisionNoOpinion
}
func (c ConditionsMap) PossibleDecisions() sets.Set[Decision] {
    possibleDecisions := sets.New(DecisionNoOpinion)
    if len(c.allowConditions) > 0 { possibleDecisions.Insert(DecisionAllow) }
    if len(c.denyConditions) > 0  { possibleDecisions.Insert(DecisionDeny)  }
    return possibleDecisions
}
```

**Lean** (Authorizer.lean:61-68):
```lean
def ConditionsMap.FailClosedDecision (c : ConditionsMap) : Decision :=
    if c.hasDenyCondition then .Deny else .NoOpinion
def ConditionsMap.CanBecomeAllowed (c : ConditionsMap) : Bool := c.hasAllowCondition
```

**Delta**:
- Rename `FailClosedDecision` → `FailureDecision` on both `ConditionsMap` and `ConditionsAwareDecision`
- Add `ConditionsMap.PossibleDecisions : ConditionsMap → Finset Decision`
- Redefine `FailureDecision` via `PossibleDecisions` to match Go's indirection
- Subsume `CanBecomeAllowed` into `PossibleDecisions` (it becomes `.Allow ∈ cm.PossibleDecisions`)
- Update all references (including in Go.lean / proofs)

---

### 3. `ConditionsAwareDecision.FailClosedDecision` → `FailureDecision` + `PossibleDecisions`

**Go** (conditionsawaredecision.go:187-192, 307-320):
```go
func (d ConditionsAwareDecision) FailureDecision() Decision {
    if d.PossibleDecisions().Has(DecisionDeny) { return DecisionDeny }
    return DecisionNoOpinion
}
func (d ConditionsAwareDecision) PossibleDecisions() sets.Set[Decision] {
    switch {
    case d.IsAllow():         return sets.New(DecisionAllow)
    case d.IsNoOpinion():     return sets.New(DecisionNoOpinion)
    case d.IsConditionsMap(): return d.ConditionsMap().PossibleDecisions()
    case d.IsUnion():         return d.union.PossibleDecisions()
    default:                  return sets.New(DecisionDeny)
    }
}
```

**Lean** (Authorizer.lean:82-94):
```lean
def ConditionsAwareDecision.FailClosedDecision : ConditionsAwareDecision → Decision
    | .Allow     => .NoOpinion
    | .NoOpinion => .NoOpinion
    | .Deny      => .Deny
    | .ConditionsMap c => c.FailClosedDecision
    | .Union authorizers => foldFailClosed authorizers
```

**Delta**:
- Add `ConditionsAwareDecision.PossibleDecisions : ConditionsAwareDecision → Finset Decision`
- Redefine `FailureDecision` via `PossibleDecisions` (matching Go's implementation)
- For `Union`, `PossibleDecisions` recurses through named sub-decisions with short-circuit
  (matching `ConditionsAwareDecisionUnion.PossibleDecisions` in union.go:76-88)

---

### 4. `ConditionsAwareDecision.Union` carries named pairs, not bare decisions

**Go** (conditionsawaredecision.go:59-67):
```go
type ConditionsAwareDecision struct {
    decisionType  conditionsAwareDecisionType
    conditionsMap ConditionsMap
    union         ConditionsAwareDecisionUnion  // ← carries named pairs
    reason string
    err    error
}
```

Where `ConditionsAwareDecisionUnion` (union.go:35-37):
```go
type ConditionsAwareDecisionUnion struct {
    inner []namedConditionsAwareDecision  // ← (name, decision) pairs
    errs  []error
}
```

**Lean** (Authorizer.lean:72-77):
```lean
inductive ConditionsAwareDecision where
    | Allow | Deny | NoOpinion
    | ConditionsMap (cm: ConditionsMap)
    | Union (decisions : List ConditionsAwareDecision)  -- ← bare list
```

**Delta**: Change `Union` to carry named pairs:
```lean
    | Union (decisions : List (String × ConditionsAwareDecision))
```

This ripples through every function that pattern-matches on `Union`:
`FailureDecision`, `ContainsAllowOrDeny`, `CanBecomeAllowed`, `Ideal`, `unionIdealAuthorize`,
all mutual proofs, and the entire Go.lean file.

---

### 5. `ConditionsAwareDecisionUnion` constructor — `Add` + `ToDecision`

**Go** (union.go:40-145): The `ConditionsAwareDecisionUnion` has `Add()` with:
- Name uniqueness validation for conditional decisions
- Error tracking for duplicates
- Short-circuit: stops adding after first Allow/Deny

And `ToDecision()` with three-case logic:
1. Errors → fail closed (`FailureDecision + error`)
2. Single possible decision → unconditional leaf
3. Otherwise → `Union` wrapping

**Lean**: No equivalent exists. The current code directly constructs `.Union (subDecisions ...)`.

**Delta**: Model `ConditionsAwareDecisionUnion` as a structure with:
```lean
structure ConditionsAwareDecisionUnion where
    inner : List (String × ConditionsAwareDecision)
    hasError : Bool  -- simplification: track whether any errors occurred
```

With methods `Add`, `ContainsAllowOrDeny`, `PossibleDecisions`, `FailureDecision`, `ToDecision`.

For proof tractability, we can simplify the error case (since the main theorem assumes
no errors — i.e., names are unique). The key insight is that `ToDecision` can return
a leaf directly when it knows the outcome, and this must be reflected in the contract proof.

**Decision on complexity**: Model the error-free path only (unique names precondition).
The `ToDecision` optimization (single possible decision → leaf) is what makes the contract
provable (Allow/Deny never appear in a Union variant). We MUST model this.

---

### 6. `union.ConditionsAwareAuthorize` uses `Add` + `ToDecision`

**Go** (union.go:76-98):
```go
func (authzHandler unionAuthzHandler) ConditionsAwareAuthorize(ctx, a) ConditionsAwareDecision {
    var decisions ConditionsAwareDecisionUnion
    for _, currAuthzHandler := range authzHandler {
        decision := currAuthzHandler.ConditionsAwareAuthorize(ctx, a)
        decisions.Add(currAuthzHandler.AuthorizerName(), decision)
        if decisions.ContainsAllowOrDeny() {
            return decisions.ToDecision()
        }
    }
    return decisions.ToDecision()
}
```

**Lean** (Union.lean:45-55):
```lean
def UnionAuthorizer.conditionsAwareAuthorize (u : UnionAuthorizer) (attrs : Attributes)
    : ConditionsAwareDecision :=
    .Union (subDecisions u.handlers)
where subDecisions ...
```

**Delta**: Rewrite to use `ConditionsAwareDecisionUnion.Add` + `.ToDecision()`, passing
`h.name` as the authorizer name. The result may be a leaf (Allow/Deny/NoOpinion) instead
of always being `.Union`.

---

### 7. `union.EvaluateConditions` uses name-based lookup instead of index

**Go** (union.go:102-163):
```go
for currentAuthorizerName, unevaluatedSubDecision := range unevaluatedDecision.UnionedDecisions() {
    ...
    decision, reason, err = authzHandler.evaluateConditions(ctx, currentAuthorizerName, unevaluatedSubDecision, data)
    ...
}
// where evaluateConditions does:
func (authzHandler unionAuthzHandler) evaluateConditions(ctx, authorizerName, ...) {
    authorizer, err := authzHandler.getAuthorizerWithName(authorizerName)
    return authorizer.EvaluateConditions(ctx, unevaluatedSubDecision, data)
}
```

**Lean** (Union.lean:62-83):
```lean
def UnionAuthorizer.evaluateConditions ... :=
    match decision with
    | .Union ds => walk u.handlers ds
where walk : List Authorizer → List ConditionsAwareDecision → Decision
    | h :: hRest, d :: dRest => ...  -- positional zip
```

**Delta**: Replace positional `walk` with name-based lookup:
- `Union` now carries `List (String × ConditionsAwareDecision)`
- Iterate over `(name, subDecision)` pairs
- Look up authorizer by name in `u.handlers`
- Need helper `getAuthorizerWithName : List Authorizer → String → Option Authorizer`

---

### 8. `CanBecomeAllowed` → subsumed into `PossibleDecisions`

**Go**: No longer has standalone `CanBecomeAllowed()` on `ConditionsAwareDecision`.
Instead uses `PossibleDecisions().Has(DecisionAllow)`.

The `CanBecomeAllowed` concept only survives on `ConditionsMap` as a trivial check
and is no longer exposed on `ConditionsAwareDecision`.

**Lean** (Authorizer.lean:113-125): Has `ConditionsAwareDecision.CanBecomeAllowed` and 
`unionSlice.CanBecomeAllowed` (Go.lean:142-187).

**Delta**: Remove standalone `CanBecomeAllowed` on `ConditionsAwareDecision`. Replace
with `PossibleDecisions` throughout. Keep `ConditionsMap.CanBecomeAllowed` for backwards
compatibility or subsume into `PossibleDecisions`.

---

### 9. `ContainsAllowOrDeny` on `ConditionsAwareDecision` — structural change

**Go** (conditionsawaredecision.go:196-204):
```go
func (d ConditionsAwareDecision) ContainsAllowOrDeny() bool {
    if d.IsAllow() || d.IsDeny() { return true }
    if d.IsNoOpinion() || d.IsConditionsMap() { return false }
    return d.union.ContainsAllowOrDeny()
}
```

Where `d.union.ContainsAllowOrDeny()` (union.go:67-74) iterates named pairs:
```go
func (unionMap ConditionsAwareDecisionUnion) ContainsAllowOrDeny() bool {
    for _, subDecision := range unionMap.inner {
        if subDecision.d.ContainsAllowOrDeny() { return true }
    }
    return false
}
```

**Lean** (Authorizer.lean:97-106): Same structure but iterates bare `List ConditionsAwareDecision`.

**Delta**: Update to iterate over `List (String × ConditionsAwareDecision)`, ignoring
the name component.

---

### 10. `ConditionsMap` constructor changed signature

**Go** (conditionsmap.go:122-167):
```go
func ConditionsAwareDecisionConditionsMap(
    denyConditions []Condition,
    noOpinionConditions []Condition,
    allowConditions []Condition,
) ConditionsAwareDecision
```

Now takes three separate lists instead of a single `[]Condition` list.

**Lean** (ConditionsMapReal.lean:705-722): Takes `conditions : List Condition` and
`featureGateOn : Bool`, processing all conditions in one loop.

**Delta**: Update ConditionsMapReal's constructor to take three separate lists. The
feature gate is removed. Also affects the builder state logic.

---

## Implementation plan

### Phase 1: Update `Authorizer.lean` (types and basic functions)

**File**: `ConditionalAuthorization/Authorizer.lean`

1. **Add `name` to `Authorizer` (via Spec.lean)** — actually, `Authorizer` is in Spec.lean.
   In Authorizer.lean, just update the `Union` variant and functions.

2. **Add `PossibleDecisions` type and functions**:
   ```lean
   def ConditionsMap.PossibleDecisions (c : ConditionsMap) : Finset Decision :=
       {.NoOpinion} ∪ (if c.hasDenyCondition then {.Deny} else ∅)
                    ∪ (if c.hasAllowCondition then {.Allow} else ∅)
   ```
   
   Note: Using `Finset Decision` requires `import Mathlib.Data.Finset.Basic` or similar.
   Alternative: model as a simple predicate `Decision → Bool` or `Decision → Prop`.
   
   **Recommendation**: Use `Decision → Bool` for simplicity — avoids heavy Finset imports:
   ```lean
   def ConditionsMap.possibleDecisions (c : ConditionsMap) : Decision → Bool
       | .NoOpinion => true
       | .Allow => c.hasAllowCondition
       | .Deny => c.hasDenyCondition
   ```

3. **Rename `FailClosedDecision` → `FailureDecision`** on both `ConditionsMap` and
   `ConditionsAwareDecision`. Redefine through `PossibleDecisions`:
   ```lean
   def ConditionsMap.FailureDecision (c : ConditionsMap) : Decision :=
       if c.possibleDecisions .Deny then .Deny else .NoOpinion
   ```

4. **Change `Union` to carry named pairs**:
   ```lean
   | Union (decisions : List (String × ConditionsAwareDecision))
   ```

5. **Update every function matching on `Union`**:
   - `FailureDecision` / `foldFailClosed`
   - `ContainsAllowOrDeny` / `anyContainsAllowOrDeny`
   - `CanBecomeAllowed` / `anyCanBecomeAllowed` (or remove if subsumed)
   - `unionIdealAuthorize`
   - `Ideal`
   - `PossibleDecisions` (new, for `ConditionsAwareDecision`)

6. **Add `ConditionsAwareDecision.PossibleDecisions`** (mutual recursion with union helper):
   ```lean
   mutual
   def ConditionsAwareDecision.possibleDecisions : ConditionsAwareDecision → Decision → Bool
       | .Allow, .Allow => true
       | .Deny, .Deny => true
       | .NoOpinion, .NoOpinion => true
       | .ConditionsMap cm, d => cm.possibleDecisions d
       | .Union ds, d => unionPossibleDecisions ds d
       | _, _ => false
   def unionPossibleDecisions : List (String × ConditionsAwareDecision) → Decision → Bool
       ...
   end
   ```

7. **Redefine `ConditionsAwareDecision.FailureDecision`** via `possibleDecisions`:
   ```lean
   def ConditionsAwareDecision.FailureDecision (d : ConditionsAwareDecision) : Decision :=
       if d.possibleDecisions .Deny then .Deny else .NoOpinion
   ```

### Phase 2: Update `Spec.lean` (Authorizer structure and contract)

**File**: `ConditionalAuthorization/Spec.lean`

1. **Add `name : String` to `Authorizer`**:
   ```lean
   structure Authorizer where
       name : String
       authorize : Attributes → Decision
       conditionsAwareAuthorize : Attributes → ConditionsAwareDecision
       evaluateConditions : ConditionsAwareDecision → ConditionsData → Decision
       ax_authorizer : ...
   ```

2. **Update all proofs** that construct or deconstruct `Authorizer` to include `name`.

3. **Rename `FailClosedDecision` → `FailureDecision`** in `AuthorizerContract` and proofs
   (likely no direct references, but check).

### Phase 3: Update `Union.lean` (core union logic)

**File**: `ConditionalAuthorization/Union.lean`

1. **Model `ConditionsAwareDecisionUnion`** — a builder structure:
   ```lean
   structure ConditionsAwareDecisionUnion where
       inner : List (String × ConditionsAwareDecision)
   ```
   
   (Omit `errs` — model the error-free path. Add a precondition for name uniqueness
   where needed.)

2. **`Add` method**:
   ```lean
   def ConditionsAwareDecisionUnion.Add (u : ConditionsAwareDecisionUnion)
       (name : String) (d : ConditionsAwareDecision) : ConditionsAwareDecisionUnion :=
       if u.ContainsAllowOrDeny then u
       else ⟨u.inner ++ [(name, d)]⟩
   ```

3. **`ContainsAllowOrDeny`**:
   ```lean
   def ConditionsAwareDecisionUnion.ContainsAllowOrDeny (u : ConditionsAwareDecisionUnion) : Bool :=
       u.inner.any (fun (_, d) => d.ContainsAllowOrDeny)
   ```

4. **`PossibleDecisions`** (union.go:76-88):
   ```lean
   def ConditionsAwareDecisionUnion.possibleDecisions (u : ConditionsAwareDecisionUnion) : Decision → Bool :=
       go u.inner
   where go : List (String × ConditionsAwareDecision) → Decision → Bool
       | [], .NoOpinion => true
       | [], _ => false
       | (_, d) :: rest, dec =>
           if d.ContainsAllowOrDeny then
               d.possibleDecisions dec  -- short-circuit, drop default NoOpinion if Allow/Deny present
           else
               d.possibleDecisions dec || go rest dec
   ```

5. **`ToDecision`** — the key constructor (union.go:93-145):
   ```lean
   def ConditionsAwareDecisionUnion.ToDecision (u : ConditionsAwareDecisionUnion) : ConditionsAwareDecision :=
       -- Single possible decision optimization
       if singleAllow u then .Allow
       else if singleDeny u then .Deny
       else if singleNoOpinion u then .NoOpinion
       else .Union u.inner
   ```
   
   Need to carefully model the "single possible decision" check. This is what allows
   the contract to be proven: when `ToDecision` returns a leaf, `authorize` agrees;
   when it returns `Union`, all sub-decisions are conditional/NoOpinion so `authorize`
   can only be Deny/NoOpinion.

6. **Update `UnionAuthorizer.conditionsAwareAuthorize`** to use `Add` + `ToDecision`:
   ```lean
   def UnionAuthorizer.conditionsAwareAuthorize (u : UnionAuthorizer) (attrs : Attributes)
       : ConditionsAwareDecision :=
       (buildUnion u.handlers attrs).ToDecision
   where buildUnion : List Authorizer → Attributes → ConditionsAwareDecisionUnion
       | [], _ => ⟨[]⟩
       | h :: rest, attrs =>
           let d := h.conditionsAwareAuthorize attrs
           let u := ConditionsAwareDecisionUnion.Add ⟨...⟩ h.name d
           if u.ContainsAllowOrDeny then u
           else buildUnion rest attrs  -- ← but need to thread accumulated state
   ```
   
   Actually, model as a fold to match Go's loop:
   ```lean
   def buildUnionFold (handlers : List Authorizer) (attrs : Attributes)
       : ConditionsAwareDecisionUnion :=
       handlers.foldl (fun acc h =>
           acc.Add h.name (h.conditionsAwareAuthorize attrs)
       ) ⟨[]⟩
   ```

7. **Update `UnionAuthorizer.evaluateConditions`** for name-based lookup:
   ```lean
   def getAuthorizerWithName (handlers : List Authorizer) (name : String) : Option Authorizer :=
       match handlers.filter (fun a => a.name == name) with
       | [a] => some a
       | _ => none
   
   def UnionAuthorizer.evaluateConditions (u : UnionAuthorizer)
       (decision : ConditionsAwareDecision) (data : ConditionsData) : Decision :=
       match decision with
       | .Allow => .Allow | .Deny => .Deny | .NoOpinion => .NoOpinion
       | .ConditionsMap _ => decision.FailureDecision
       | .Union ds => walkNamed u.handlers ds data
   where walkNamed (handlers : List Authorizer)
       : List (String × ConditionsAwareDecision) → ConditionsData → Decision
       | [], _ => .NoOpinion
       | (name, d) :: rest, data =>
           match d with
           | .Allow => .Allow | .Deny => .Deny
           | .NoOpinion => walkNamed handlers rest data
           | .ConditionsMap _ | .Union _ =>
               match getAuthorizerWithName handlers name with
               | some a => match a.evaluateConditions d data with
                   | .Allow => .Allow | .Deny => .Deny
                   | .NoOpinion => walkNamed handlers rest data
               | none => d.FailureDecision  -- fail closed
   ```

8. **Add uniqueness precondition** to `UnionAuthorizer`:
   ```lean
   structure UnionAuthorizer where
       handlers : List Authorizer
       ax_unique_names : handlers.map (·.name) |>.Nodup  -- or Pairwise (· ≠ ·)
   ```

### Phase 4: Update `Go.lean` (Do-style transliterations)

**File**: `ConditionalAuthorization/Go.lean`

Propagate all renames and structural changes:
- `FailClosedDecision` → `FailureDecision` in all `Do` functions and proofs
- `Union (List CAD)` → `Union (List (String × CAD))` in all pattern matches
- `CanBecomeAllowed` → `PossibleDecisions` if still needed
- Union Do functions iterate named pairs
- `conditionsAwareAuthorizeDo` uses `Add` + `ToDecision`
- `evaluateConditionsDo` uses name-based lookup via `zip` → named iteration

### Phase 5: Update `ConditionsMapReal.lean`

**File**: `ConditionalAuthorization/ConditionsMapReal.lean`

1. **Update constructor signature** to take three separate lists (matching Go):
   ```lean
   def ConditionsAwareDecisionConditionsMap
       (denyConditions noOpinionConditions allowConditions : List Condition)
       : ConstructorResult
   ```
   Remove `featureGateOn` parameter (Go removed it).

2. **Rename `FailClosedDecision` → `FailureDecision`** in the real ConditionsMap.

3. **Add `PossibleDecisions`** on the real ConditionsMap:
   ```lean
   def ConditionsMap.PossibleDecisions (c : ConditionsMap) : Decision → Bool
       | .NoOpinion => true
       | .Allow => !c.allowConditions.isEmpty
       | .Deny => !c.denyConditions.isEmpty
   ```

4. **Add short-circuit case**: When only NoOpinion conditions exist, return NoOpinion directly
   (conditionsmap.go:143-145).

### Phase 6: Update proofs

**Critical proofs that break**:

1. **All mutual proofs** in Spec.lean and Authorizer.lean that recurse on
   `ConditionsAwareDecision` — the `Union` case now has `List (String × CAD)` instead
   of `List CAD`. Each helper like `foldFailClosed`, `anyContainsAllowOrDeny`, etc.
   needs its signature and induction updated. Mostly mechanical: add `(_, d)` destructuring.

2. **`evaluate_eq_ideal`** (Union.lean:91-132) — the core equivalence. This is the most
   impacted proof:
   - Changes from positional walk to name-based lookup
   - Requires proving that `getAuthorizerWithName` finds the right authorizer
   - Needs the uniqueness precondition on `UnionAuthorizer`

3. **`satisfies_contract`** (Union.lean:230-254) — the main contract theorem.
   - `conditionsAwareAuthorize` may now return a leaf (via `ToDecision` optimization)
   - When it returns a leaf, the contract's leaf arms apply directly
   - When it returns `Union`, the conditional arms apply as before
   - Need to prove `ToDecision` preserves `Ideal`

4. **Bridge lemmas** in Go.lean (all the `XxxDo_eq` proofs) — mostly mechanical
   signature updates.

5. **`walk_subDecisionsDo_eq_idealAuthorize`** — must be rewritten for name-based matching.

6. **`composition_do_eq_ideal`** — the headline theorem. Should still hold but needs
   updated sub-lemmas.

### Key new lemma needed

**`ToDecision_preserves_ideal`**: For any `ConditionsAwareDecisionUnion u`:
```
u.ToDecision.Ideal data = unionIdealAuthorize u.inner data
```

This is the analogue of the old `conditionsAwareDecisionUnion_preserves_ideal`.
Case analysis on what `ToDecision` returns:
- Leaf (Allow/Deny/NoOpinion) → follows from `PossibleDecisions` having a single element
- `Union inner` → by definition of `Ideal` on Union

---

## Order of implementation

1. `Authorizer.lean`: Change `Union` type, add `PossibleDecisions`, rename `FailureDecision`,
   update all functions and their mutual proofs
2. `Spec.lean`: Add `name` to `Authorizer`, update per-authorizer lemmas
3. `Union.lean`: Add `ConditionsAwareDecisionUnion`, rewrite union methods and proofs
4. `Go.lean`: Propagate all changes to Do-style transliterations and bridge proofs
5. `ConditionsMapReal.lean`: Update constructor signature, add `PossibleDecisions`, rename

Each step should compile before moving to the next. Steps 1 and 2 have no dependency
between them and can be done in either order, but both must be done before step 3.

---

## Verification

After each file change:
```bash
cd /Users/luxas/upbound/kubernetes && lake build 2>&1 | tail -5
```

Target: `Build completed successfully` with no `sorry`.
If proofs get stuck, mark with `sorry` and document what remains.
