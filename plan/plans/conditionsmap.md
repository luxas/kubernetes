# Plan: Faithful Go transliteration of `ConditionsMap` in a standalone namespace

## Context

The existing Lean `ConditionsMap` (`ConditionalAuthorization/Authorizer.lean:52-65`) is **heavily abstracted**: it has only `hasDenyCondition : Bool`, `hasAllowCondition : Bool`, and `evaluate : ConditionsData → Decision`, plus three axioms relating them. The actual per-condition machinery (lists of `Condition`s per effect, per-condition evaluation results with True/False/Error/Unevaluatable, the phased Deny→NoOpinion→Allow loop) was collapsed into a single opaque `evaluate` function plus axioms.

This is fine for the rest of the spec proofs — but it doesn't let us **prove anything about why** `evaluate` returns what it returns. The user wants a *faithful* transliteration of Go's `ConditionsMap` (especially `Evaluate` in `staging/src/k8s.io/apiserver/pkg/authorization/authorizer/conditions.go:700-870`), so we can state and prove theorems like "Evaluate returns Allow only if some allow condition evaluated to true" — soundness statements that connect the result back to the per-condition semantics.

The new module is **standalone** (own namespace, no entanglement with the rest of the existing model). It can reuse `Decision` and `ConditionsData` from `ConditionalAuthorization.Authorizer` but defines its own `ConditionsMap`, `Condition`, `ConditionEffect`, `ConditionEvaluationResult`, and an `EvaluateResult` return type. No existing file is modified.

## New file

`ConditionalAuthorization/ConditionsMapReal.lean` — namespace `ConditionalAuthorization.ConditionsMapReal`.

Imports: `ConditionalAuthorization.Authorizer` (only for the `Decision` and `ConditionsData` types — everything else is fresh).

Add to `ConditionalAuthorization.lean` root: `import ConditionalAuthorization.ConditionsMapReal`.

## Types to define

```lean
namespace ConditionalAuthorization.ConditionsMapReal

open ConditionalAuthorization.Authorizer (Decision ConditionsData)

/-- Mirrors Go's `ConditionEffect` (conditions.go:336-342). -/
inductive ConditionEffect where
  | Deny | NoOpinion | Allow
  deriving DecidableEq, Repr

/-- Mirrors Go's `ConditionEvaluationResult` (conditions.go:373-416). Four-way enum:
    a condition either evaluated successfully to True/False, errored during evaluation,
    or could not be evaluated by the chosen evaluator. -/
inductive ConditionEvaluationResult where
  | True            -- IsTrue
  | False           -- IsFalse
  | Error           -- IsError (carries an error in Go; collapsed here)
  | Unevaluatable   -- IsUnevaluatable
  deriving DecidableEq, Repr

/-- Mirrors Go's `Condition` interface (conditions.go:418-455). Optional Go fields
    (`GetType`, `GetDescription`, `GetCondition`, `DeepCopy`) are collapsed; what
    matters for `Evaluate`'s semantics is `id`, `effect`, and the per-data evaluator. -/
structure Condition where
  id : String
  effect : ConditionEffect
  evaluate : ConditionsData → ConditionEvaluationResult

/-- Mirrors Go's `ConditionsMap` (conditions.go:348-358). Three lists, one per effect. -/
structure ConditionsMap where
  denyConditions      : List Condition
  noOpinionConditions : List Condition
  allowConditions     : List Condition

/-- The four possible outcomes of `Evaluate`: a final Decision, or a partially-evaluated
    `ConditionsMap` (Go calls this a "refined" decision). Mirrors what Go's `Evaluate`
    returns as a `ConditionsAwareDecision`. -/
inductive EvaluateResult where
  | Allow
  | Deny
  | NoOpinion
  | Refined (refined : ConditionsMap)
```

## Methods (faithful to Go)

Direct transliterations — same control flow as Go:

```lean
def ConditionsMap.Length (c : ConditionsMap) : Nat :=
  c.denyConditions.length + c.noOpinionConditions.length + c.allowConditions.length

def ConditionsMap.Conditions (c : ConditionsMap) : List Condition :=
  c.denyConditions ++ c.noOpinionConditions ++ c.allowConditions

def ConditionsMap.DenyConditions      (c : ConditionsMap) : List Condition := c.denyConditions
def ConditionsMap.NoOpinionConditions (c : ConditionsMap) : List Condition := c.noOpinionConditions
def ConditionsMap.AllowConditions     (c : ConditionsMap) : List Condition := c.allowConditions

/-- Go (conditions.go:364-371). -/
def ConditionsMap.FailClosedDecision (c : ConditionsMap) : Decision :=
  if c.denyConditions.isEmpty then .NoOpinion else .Deny

/-- Go (conditions.go:465-467). -/
def ConditionsMap.CanBecomeAllowed (c : ConditionsMap) : Bool :=
  !c.allowConditions.isEmpty
```

### The `Evaluate` function — phased Deny → NoOpinion → Allow loop

Faithful transliteration of Go's `ConditionsMap.Evaluate` (conditions.go:700-870). Uses an inner helper that splits a per-effect list of conditions into four buckets (True, False, Error, Unevaluatable) by applying `evalCond`.

```lean
/-- Per-iteration outcome of evaluating one condition list, exposing the four bucket counts
    Go's loop tracks (`appliedReasons`, `errors`, `unevaluated`, plus implicit "all false"). -/
structure PhaseResult where
  trues        : List Condition   -- Go's appliedXReasons (the conditions that evaluated True)
  errors       : List Condition   -- Go's xErrors (conditions whose evalResult.IsError())
  unevaluated  : List Condition   -- Go's unevaluatedXConditions

def evalPhase (conds : List Condition) (evalCond : Condition → ConditionEvaluationResult)
    : PhaseResult := …  -- single fold accumulating into the three buckets

def ConditionsMap.Evaluate (c : ConditionsMap) (data : ConditionsData)
    (evaluateFunc : Option (Condition → ConditionsData → ConditionEvaluationResult) := none)
    : EvaluateResult :=
  -- evalCond mirrors Go's evalCond closure: try cond.evaluate first; if Unevaluatable
  -- and evaluateFunc is provided, fall back to it.
  let evalCond := fun cond =>
    let primary := cond.evaluate data
    match evaluateFunc with
    | none => primary
    | some f =>
      match primary with
      | .Unevaluatable => f cond data
      | _              => primary
  -- Phase 1: denies
  if !c.denyConditions.isEmpty then
    let denyPhase := evalPhase c.denyConditions evalCond
    if !denyPhase.trues.isEmpty then .Deny
    else if !denyPhase.errors.isEmpty then .Deny  -- fail-closed
    else if !denyPhase.unevaluated.isEmpty then
      .Refined { denyConditions := denyPhase.unevaluated
                 noOpinionConditions := c.noOpinionConditions
                 allowConditions := c.allowConditions }
    else  -- all denies False → fall through
      evalNoOpinionPhase c data evalCond
  else
    evalNoOpinionPhase c data evalCond
where
  evalNoOpinionPhase (c …) … := …  -- same shape: True → NoOpinion; Error → NoOpinion;
                                    --   Unevaluated → Refined (if allows exist) else NoOpinion
                                    --   all False → evalAllowPhase
  evalAllowPhase (c …) … := …      -- True → Allow; Error → NoOpinion;
                                    --   Unevaluated → Refined; all False → NoOpinion default
```

The three phases are nested `where`-helpers so the public surface is just
`ConditionsMap.Evaluate`. Each helper is a direct line-by-line translation of one
of Go's three loop blocks. Total ~80 lines for `Evaluate` and the phase helpers.

## Theorems (soundness one-direction)

All in the same namespace. Each says: "if Evaluate returned X, then a condition matching
predicate P must have been involved." Pure soundness — no axioms required.

### 1. Allow soundness
```lean
theorem evaluate_Allow_implies_some_allow_True
    (c : ConditionsMap) (data : ConditionsData)
    (ef : Option (Condition → ConditionsData → ConditionEvaluationResult))
    (h : c.Evaluate data ef = .Allow)
    : ∃ cond ∈ c.allowConditions, evalCondOf cond data ef = .True
```
(where `evalCondOf` packages the same `evalCond` closure as `Evaluate` uses).

### 2. Deny soundness
```lean
theorem evaluate_Deny_implies_some_deny_True_or_Error
    … (h : c.Evaluate data ef = .Deny)
    : ∃ cond ∈ c.denyConditions, evalCondOf cond data ef ∈ ({.True, .Error} : Set _)
```
Captures both: (a) a deny condition evaluated True → Deny; (b) no deny True but at least
one Error → fail-closed Deny. The disjunction matches Go's two paths to Deny.

### 3. NoOpinion soundness (the trickiest case — multiple paths)
```lean
theorem evaluate_NoOpinion_implies_…
    … (h : c.Evaluate data ef = .NoOpinion)
    : (∃ cond ∈ c.noOpinionConditions, evalCondOf cond data ef ∈ {.True, .Error}) ∨
      (∀ cond ∈ c.denyConditions ∪ c.noOpinionConditions ∪ c.allowConditions,
         evalCondOf cond data ef ∈ {.False, .Error}) ∨
      (c.allowConditions ≠ [] ∧ all allow conditions evaluated to False or Error,
       with at least one Error)
```
Three NoOpinion-yielding paths from Go:
  - A noOpinion was True / errored.
  - All conditions False (the default NoOpinion).
  - Allow phase had errors but no True allow (NoOpinion + warnings).

We'll state this as three separate constructor theorems for clarity:
- `evaluate_NoOpinion_path1_noOpinion_matched`
- `evaluate_NoOpinion_path2_default_all_false`
- `evaluate_NoOpinion_path3_allow_errored_no_match`

### 4. Refined soundness
```lean
theorem evaluate_Refined_implies_some_unevaluated
    … (h : c.Evaluate data ef = .Refined r)
    : ∃ cond ∈ c.Conditions, evalCondOf cond data ef = .Unevaluatable
```
A Refined result is only emitted when some condition couldn't be evaluated.

### 5. Bonus invariants (the load-bearing facts from the abstracted version)
```lean
/-- The bit-flag fact that the old `ConditionsMap` had as an axiom: if there are no
    allow conditions, `Evaluate` cannot return `.Allow`. (Matches the spirit of
    `ax_no_allow_cond_implies_never_allow` in `Authorizer.lean`.) -/
theorem allowConditions_empty_implies_never_Allow
    (c : ConditionsMap) (h : c.allowConditions = [])
    : ∀ data ef, c.Evaluate data ef ≠ .Allow

/-- Analogue for Deny. -/
theorem denyConditions_empty_implies_never_Deny
    (c : ConditionsMap) (h : c.denyConditions = [])
    : ∀ data ef, c.Evaluate data ef ≠ .Deny
```

These are *theorems* in the faithful model — not axioms. They follow from the soundness lemmas above (`evaluate_Allow_implies_some_allow_True` plus `allowConditions = []`).

### 6. Concrete FailClosedDecision invariant
```lean
theorem FailClosedDecision_eq_Deny_iff
    (c : ConditionsMap) : c.FailClosedDecision = .Deny ↔ c.denyConditions ≠ []

theorem FailClosedDecision_AllowOrNoOpinion
    (c : ConditionsMap) : c.FailClosedDecision = .Deny ∨ c.FailClosedDecision = .NoOpinion
```

## Proof strategy

Each soundness theorem unfolds `Evaluate`, walks the three phases, and at each branch
either (a) shows the result couldn't be the one we're disproving, or (b) extracts the
required witness from the phase that triggered the result. The `evalPhase` helper is
proved correct first (a single auxiliary lemma per bucket — "if `evalPhase conds f`'s
`trues` is non-empty, then `∃ cond ∈ conds, f cond = .True`"). All later soundness
proofs reduce to these.

Roughly:
- `evalPhase` correctness lemmas (3 of them, one per bucket): ~15 lines total via list induction.
- Soundness theorems: ~30 lines each (case-split on the three phases via Go's flow).
- Empty-list corollaries: ~5 lines each (just contradict the soundness witness).

Total: ~250-300 lines for the whole file.

## Critical files

- **New**: `/Users/luxas/upbound/kubernetes/ConditionalAuthorization/ConditionsMapReal.lean`
- **Modified (single line)**: `/Users/luxas/upbound/kubernetes/ConditionalAuthorization.lean` (add `import ConditionalAuthorization.ConditionsMapReal`)

## Files unaffected

- `Authorizer.lean`, `Spec.lean`, `Union.lean`, `Go.lean` — all untouched. The new namespace is fully isolated. The simplified `ConditionsMap` in `Authorizer.lean` is **not** replaced — it continues to serve the existing spec proofs via its axioms. The new `ConditionsMapReal` is parallel, not a drop-in replacement.

## Verification

From `/Users/luxas/upbound/kubernetes/`:

1. `lake build` → exit 0, no `sorry`s, no warnings, no `admit`s.
2. `grep -n "sorry\|admit" ConditionalAuthorization/ConditionsMapReal.lean` → nothing.
3. The build output prints `#check` lines confirming the headline signatures:
   ```
   ConditionalAuthorization.ConditionsMapReal.ConditionsMap.Evaluate :
     ConditionsMap → ConditionsData →
     Option (Condition → ConditionsData → ConditionEvaluationResult) →
     EvaluateResult
   ConditionalAuthorization.ConditionsMapReal.evaluate_Allow_implies_some_allow_True :
     ∀ (c : ConditionsMap) (data : ConditionsData)
       (ef : Option (Condition → ConditionsData → ConditionEvaluationResult))
       (_ : c.Evaluate data ef = .Allow),
       ∃ cond ∈ c.allowConditions, evalCondOf cond data ef = .True
   ```
4. Side-by-side reading: the body of `ConditionsMap.Evaluate` and Go's
   `conditions.go:700-870` agree line-by-line on the three phases.

## Out of scope (explicitly)

- **Relating `ConditionsMapReal` to the existing `ConditionsMap`** — the old model is opaque (just `evaluate : ConditionsData → Decision`), so the only way to relate them would be to *axiomatise* a translation, which defeats the point of building the faithful model. If you later want this bridge, it'd be a separate theorem like `∃ evaluate, ConditionsMap.mk hasDeny hasAllow evaluate (axioms) = abstract_view_of (real : ConditionsMapReal)`.
- **Hooking `ConditionsMapReal` into `ConditionsAwareDecision`** — that would require parallel `ConditionsAwareDecisionReal`, `idealAuthorize`, etc. Massive duplication. Better to keep `ConditionsMapReal` as a standalone study of Go's conditions logic.
- **Modeling Go's `ConditionsAwareDecisionConditionsMap` constructor** (conditions.go:533-635) with its ID uniqueness, label validation, and feature-gate checks — not part of `Evaluate`'s semantics. Out of scope.
- **Property-based equivalence**: e.g. `if all conditions are evaluable, then Evaluate returns one of Allow/Deny/NoOpinion (never Refined)`. Easy follow-up theorem if useful, but not requested.
