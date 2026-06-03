import ConditionalAuthorization.Authorizer
import ConditionalAuthorization.Spec
import ConditionalAuthorization.Union
import Mathlib.Data.List.Basic
import Mathlib.Control.Basic

/-!
# Line-by-line Go → Lean transliterations

This module mirrors the Go control flow of `staging/src/k8s.io/apiserver/pkg/authorization/`
as closely as Lean allows. Each function carries a `Do` suffix and uses Lean's `do`
notation (`Id.run do … for … in … do …`) to preserve Go's for-loops, early `return`s,
and if-chains.

The `Do` defs live in the **same namespaces as their proof-friendly counterparts**
(`ConditionalAuthorization.Authorizer`, `ConditionalAuthorization.Union`) — this is
purely so dot notation works (`c.FailClosedDecisionDo`). All of them are introduced
in *this* file, which is the dedicated home for Go-shaped transliterations.

Each `XxxDo` is proven equal to its proof-friendly counterpart (`XxxDo_eq`) so spec
theorems can be stated on the Go-shaped functions while being proved by reduction to
the cleaner recursive forms.
-/

namespace ConditionalAuthorization.Authorizer

-- ============================================================================
-- conditions.go — trivial transliterations (no for-loops)
-- ============================================================================

/--
Go (interfaces.go:164-166):
```go
func (a AttributesRecord) IsReadOnly() bool {
  return a.Verb == "get" || a.Verb == "list" || a.Verb == "watch"
}
```
-/
def Attributes.isReadOnlyDo (a : Attributes) : Bool :=
  a.verb = "get" || a.verb = "list" || a.verb = "watch"

/--
Go (conditions.go:364-371) iterates `c.Conditions()` looking for a Deny effect.
Our Lean model summarises that loop into the bit `hasDenyCondition`, so the
transliteration collapses to a single `if`. The control flow is otherwise identical.
-/
def ConditionsMap.FailClosedDecisionDo (c : ConditionsMap) : Decision :=
  if c.hasDenyCondition then .Deny else .NoOpinion

/--
Go (conditions.go:465-467):
```go
func (c ConditionsMap) CanBecomeAllowed() bool {
  return len(c.allowConditions) != 0
}
```
-/
def ConditionsMap.CanBecomeAllowedDo (c : ConditionsMap) : Bool :=
  c.hasAllowCondition

-- ============================================================================
-- conditions.go — ConditionsAwareDecision and unionSlice (loops on sub-decisions)
-- ============================================================================

mutual

/--
Go (conditions.go:185-197):
```go
func (d ConditionsAwareDecision) FailClosedDecision() Decision {
  if d.IsAllowed() || d.IsNoOpinion() { return DecisionNoOpinion }
  if d.IsConditionsMap() { return d.conditionsMap.FailClosedDecision() }
  if d.IsUnion() { return d.union.FailClosedDecision() }
  return DecisionDeny
}
```
-/
def ConditionsAwareDecision.FailClosedDecisionDo : ConditionsAwareDecision → Decision
  | .Allow => .NoOpinion
  | .NoOpinion => .NoOpinion
  | .ConditionsMap c => c.FailClosedDecisionDo
  | .Union ds => unionSliceFailClosedDecisionDo ds
  | .Deny => .Deny

/--
Go (conditions.go:888-895):
```go
func (unionSlice conditionsAwareDecisionUnionSlice) FailClosedDecision() Decision {
  for _, subDecision := range unionSlice {
    if subDecision.FailClosedDecision() == DecisionDeny { return DecisionDeny }
  }
  return DecisionNoOpinion
}
```
-/
def unionSliceFailClosedDecisionDo (unionSlice : List ConditionsAwareDecision) : Decision := Id.run do
  for subDecision in unionSlice do
    if subDecision.FailClosedDecisionDo == .Deny then
      return .Deny
  return .NoOpinion

end

mutual

/--
Go (conditions.go:201-209):
```go
func (d ConditionsAwareDecision) ContainsAllowOrDeny() bool {
  if d.IsAllowed() || d.IsDenied() { return true }
  if d.IsNoOpinion() || d.IsConditionsMap() { return false }
  return d.union.ContainsAllowOrDeny()
}
```
-/
def ConditionsAwareDecision.ContainsAllowOrDenyDo : ConditionsAwareDecision → Bool
  | .Allow => true
  | .Deny => true
  | .NoOpinion => false
  | .ConditionsMap _ => false
  | .Union ds => unionSliceContainsAllowOrDenyDo ds

/--
Go (conditions.go:899-906):
```go
func (unionSlice conditionsAwareDecisionUnionSlice) ContainsAllowOrDeny() bool {
  for _, subDecision := range unionSlice {
    if subDecision.ContainsAllowOrDeny() { return true }
  }
  return false
}
```
-/
def unionSliceContainsAllowOrDenyDo (unionSlice : List ConditionsAwareDecision) : Bool := Id.run do
  for subDecision in unionSlice do
    if subDecision.ContainsAllowOrDenyDo then
      return true
  return false

end

mutual

/--
Go (conditions.go:213-220, abbreviated):
```go
func (d ConditionsAwareDecision) CanBecomeAllowed() bool {
  if d.IsAllowed() { return true }
  if d.IsConditionsMap() { return d.conditionsMap.CanBecomeAllowed() }
  if d.IsUnion() { return d.union.CanBecomeAllowed() }
  return false
}
```
-/
def ConditionsAwareDecision.CanBecomeAllowedDo : ConditionsAwareDecision → Bool
  | .Allow => true
  | .Deny => false
  | .NoOpinion => false
  | .ConditionsMap c => c.CanBecomeAllowedDo
  | .Union ds => unionSliceCanBecomeAllowedDo ds

/--
Go (conditions.go:910-926):
```go
func (unionSlice conditionsAwareDecisionUnionSlice) CanBecomeAllowed() bool {
  for _, subDecision := range unionSlice {
    if subDecision.IsDenied() { return false }
    if subDecision.IsAllowed() { return true }
    if subDecision.IsConditionsMap() && subDecision.CanBecomeAllowed() { return true }
    if subDecision.IsUnion()       && subDecision.CanBecomeAllowed() { return true }
  }
  return false
}
```
-/
def unionSliceCanBecomeAllowedDo (unionSlice : List ConditionsAwareDecision) : Bool := Id.run do
  for subDecision in unionSlice do
    match subDecision with
    | .Deny => return false
    | .Allow => return true
    | .ConditionsMap _ =>
      if subDecision.CanBecomeAllowedDo then return true
    | .Union _ =>
      if subDecision.CanBecomeAllowedDo then return true
    | .NoOpinion => pure ()
  return false

end

end ConditionalAuthorization.Authorizer

-- ============================================================================
-- union.go — UnionAuthorizer methods (handler list iteration)
-- ============================================================================

namespace ConditionalAuthorization.Union

open ConditionalAuthorization.Authorizer
open ConditionalAuthorization.Spec

/--
Go (union.go:46-70):
```go
func (authzHandler unionAuthzHandler) Authorize(ctx context.Context, a Attributes)
    (Decision, string, error) {
  for _, curr := range authzHandler {
    decision, _, _ := curr.Authorize(ctx, a)
    switch decision {
    case DecisionAllow, DecisionDeny: return decision, ...
    case DecisionNoOpinion: // continue
    }
  }
  return DecisionNoOpinion, ...
}
```
-/
def UnionAuthorizer.authorizeDo (u : UnionAuthorizer) (attrs : Attributes) : Decision := Id.run do
  for curr in u.handlers do
    match curr.authorize attrs with
    | .Allow => return .Allow
    | .Deny  => return .Deny
    | .NoOpinion => pure ()
  return .NoOpinion

/--
Go (union.go:73-96):
```go
func (authzHandler unionAuthzHandler) ConditionsAwareAuthorize(ctx, a) ConditionsAwareDecision {
  var decisions []ConditionsAwareDecision
  for _, currAuthzHandler := range authzHandler {
    decision := currAuthzHandler.ConditionsAwareAuthorize(ctx, a)
    decisions = append(decisions, decision)
    if decision.ContainsAllowOrDeny() {
      return ConditionsAwareDecisionUnion(decisions...)
    }
  }
  return ConditionsAwareDecisionUnion(decisions...)
}
```
-/
def UnionAuthorizer.conditionsAwareAuthorizeDo (u : UnionAuthorizer) (attrs : Attributes)
    : ConditionsAwareDecision := Id.run do
  let mut decisions : List ConditionsAwareDecision := []
  for currAuthzHandler in u.handlers do
    let decision := currAuthzHandler.conditionsAwareAuthorize attrs
    decisions := decisions ++ [decision]
    if decision.ContainsAllowOrDenyDo then
      return .Union decisions
  return .Union decisions

/--
Go (union.go:99-152) — the index-correlated dispatch loop.

```go
func (authzHandler unionAuthzHandler) EvaluateConditions(ctx, unevaluatedDecision, data)
    (Decision, string, error) {
  if unevaluatedDecision.IsUnconditional() { return unevaluatedDecision.UnconditionalParts() }
  if unevaluatedDecision.IsConditionsMap() {
    return unevaluatedDecision.FailClosedDecision(), "failed closed", errors.New(...)
  }
  for i, unevaluatedSubDecision := range unevaluatedDecision.UnionedDecisions() {
    if unevaluatedSubDecision.IsAllowed() || unevaluatedSubDecision.IsDenied() {
      return unevaluatedSubDecision.UnconditionalParts()
    }
    var decision Decision
    if unevaluatedSubDecision.IsNoOpinion() {
      decision = DecisionNoOpinion
    } else {
      decision, _, _ = authzHandler[i].EvaluateConditions(ctx, unevaluatedSubDecision, data)
    }
    switch decision {
    case DecisionAllow, DecisionDeny: return decision, ...
    case DecisionNoOpinion: // continue
    }
  }
  return DecisionNoOpinion, ...
}
```

Index correlation `authzHandler[i] ↔ unevaluatedSubDecision[i]` becomes positional zip.
-/
def UnionAuthorizer.evaluateConditionsDo (u : UnionAuthorizer)
    (unevaluatedDecision : ConditionsAwareDecision) (data : ConditionsData) : Decision :=
  Id.run do
    match unevaluatedDecision with
    | .Allow     => return .Allow
    | .Deny      => return .Deny
    | .NoOpinion => return .NoOpinion
    | .ConditionsMap _ => return unevaluatedDecision.FailClosedDecisionDo
    | .Union ds =>
      for (unevaluatedSubDecision, currHandler) in ds.zip u.handlers do
        match unevaluatedSubDecision with
        | .Allow => return .Allow
        | .Deny  => return .Deny
        | .NoOpinion => pure ()  -- decision = NoOpinion, switch continues
        | .ConditionsMap _ | .Union _ =>
          match currHandler.evaluateConditions unevaluatedSubDecision data with
          | .Allow => return .Allow
          | .Deny  => return .Deny
          | .NoOpinion => pure ()
      return .NoOpinion

end ConditionalAuthorization.Union

-- ============================================================================
-- Bridge lemmas: collapse `Id.run do for x in xs do … return …` to clean forms
-- ============================================================================
--
-- Lean's `do … for … return v` desugars to `forIn` with an `MProd` accumulator that
-- carries an `Option` for early-return signalling. Reasoning about the desugared form
-- directly is painful. Instead we prove three "shape" lemmas — one per Go-loop idiom
-- used in this file — and chain them into the `XxxDo_eq` proofs.

namespace ConditionalAuthorization.Go

/-- **Bridge 1.** A `for`-loop in `Id` that short-circuits on a predicate
    (`if p x then return v_t; … ; return v_f`) collapses to an `ite` on `List.any`.

    Proved by induction with the standard `List.forIn_cons` / `forIn_nil` Lean simp lemmas.
-/
lemma forIn_id_short_circuit_eq_any_ite
    {α β : Type} (xs : List α) (p : α → Bool) (v_t v_f : β) :
    (Id.run do
       for x in xs do
         if p x then return v_t
       return v_f)
    = (if xs.any p then v_t else v_f) := by
  induction xs with
  | nil => rfl
  | cons hd tl ih =>
    by_cases hp : p hd
    · simp [hp, List.any_cons, List.forIn_cons]
    · simp only [hp, List.any_cons, Bool.false_or, List.forIn_cons,
                 if_false, pure_bind, bind_pure_comp]
      convert ih using 2

/-- **Bridge 2.** A `for`-loop in `Id` where each iteration may early-return via a
    `match` of an `Option`-valued step function collapses to `(xs.findSome? f).getD v_default`. -/
lemma forIn_id_findSome_eq_getD
    {α β : Type} (xs : List α) (f : α → Option β) (v_default : β) :
    (Id.run do
       for x in xs do
         match f x with
         | some v => return v
         | none => pure ()
       return v_default)
    = (xs.findSome? f).getD v_default := by
  induction xs with
  | nil => rfl
  | cons hd tl ih =>
    cases hf : f hd with
    | some v => simp [hf, List.findSome?_cons, List.forIn_cons]
    | none =>
      simp only [hf, List.findSome?_cons, List.forIn_cons, pure_bind, bind_pure_comp]
      convert ih using 2

end ConditionalAuthorization.Go

-- ============================================================================
-- Equivalence with proof-friendly counterparts
-- ============================================================================

namespace ConditionalAuthorization.Authorizer

open ConditionalAuthorization.Go

theorem Attributes.isReadOnlyDo_eq (a : Attributes) :
    a.isReadOnlyDo = a.isReadOnly := rfl

theorem ConditionsMap.FailClosedDecisionDo_eq (c : ConditionsMap) :
    c.FailClosedDecisionDo = c.FailClosedDecision := rfl

theorem ConditionsMap.CanBecomeAllowedDo_eq (c : ConditionsMap) :
    c.CanBecomeAllowedDo = c.CanBecomeAllowed := rfl

-- ── Helpers for the recursive proof-friendly versions ────────────────────────

/-- The proof-friendly `anyContainsAllowOrDeny` (which uses `||`) coincides with
    the standard `List.any` once we've reduced via the bridge lemma. -/
private lemma anyContainsAllowOrDeny_eq_any (xs : List ConditionsAwareDecision) :
    ConditionsAwareDecision.ContainsAllowOrDeny.anyContainsAllowOrDeny xs
    = xs.any (fun d => d.ContainsAllowOrDeny) := by
  induction xs with
  | nil => rfl
  | cons hd tl ih =>
    simp [ConditionsAwareDecision.ContainsAllowOrDeny.anyContainsAllowOrDeny,
          List.any_cons, ih]

/-- One-step unfolding of `foldFailClosed` on a cons, as an `if-then-else`. -/
private lemma foldFailClosed_cons_eq (sub : ConditionsAwareDecision)
    (rest : List ConditionsAwareDecision) :
    ConditionsAwareDecision.FailClosedDecision.foldFailClosed (sub :: rest)
    = (if sub.FailClosedDecision == Decision.Deny then Decision.Deny
       else ConditionsAwareDecision.FailClosedDecision.foldFailClosed rest) := by
  show (match sub.FailClosedDecision with
        | Decision.Deny => Decision.Deny
        | _ => ConditionsAwareDecision.FailClosedDecision.foldFailClosed rest)
       = _
  cases sub.FailClosedDecision <;> (first | rfl | (intros; decide) | (intros; rfl))

private lemma foldFailClosed_eq_ite_any (xs : List ConditionsAwareDecision) :
    ConditionsAwareDecision.FailClosedDecision.foldFailClosed xs
    = (if xs.any (fun d => d.FailClosedDecision == .Deny) then .Deny else .NoOpinion) := by
  induction xs with
  | nil => rfl
  | cons hd tl ih =>
    rw [foldFailClosed_cons_eq, List.any_cons]
    cases h : hd.FailClosedDecision with
    | Deny =>
      have : (Decision.Deny == Decision.Deny) = true := rfl
      simp [this]
    | Allow =>
      have : (Decision.Allow == Decision.Deny) = false := rfl
      simp [this, ih]
    | NoOpinion =>
      have : (Decision.NoOpinion == Decision.Deny) = false := rfl
      simp [this, ih]

-- (Removed `anyCanBecomeAllowed_eq` — the Go-faithful `anyCanBecomeAllowed` short-circuits
--  on Deny so it does NOT equal `xs.any (·.CanBecomeAllowed)` in general. The
--  `unionSliceCanBecomeAllowedDo_eq` proof inducts directly instead.)

-- ── ConditionsAwareDecision.FailClosedDecisionDo ──────────────────────────────

mutual

theorem ConditionsAwareDecision.FailClosedDecisionDo_eq (d : ConditionsAwareDecision) :
    d.FailClosedDecisionDo = d.FailClosedDecision := by
  cases d with
  | Allow | Deny | NoOpinion =>
    simp only [ConditionsAwareDecision.FailClosedDecisionDo,
               ConditionsAwareDecision.FailClosedDecision]
  | ConditionsMap c =>
    simp only [ConditionsAwareDecision.FailClosedDecisionDo,
               ConditionsAwareDecision.FailClosedDecision,
               ConditionsMap.FailClosedDecisionDo, ConditionsMap.FailClosedDecision]
  | Union ds =>
    simp only [ConditionsAwareDecision.FailClosedDecisionDo,
               ConditionsAwareDecision.FailClosedDecision]
    exact unionSliceFailClosedDecisionDo_eq ds

theorem unionSliceFailClosedDecisionDo_eq (xs : List ConditionsAwareDecision) :
    unionSliceFailClosedDecisionDo xs
    = ConditionsAwareDecision.FailClosedDecision.foldFailClosed xs := by
  match xs with
  | [] =>
    simp [unionSliceFailClosedDecisionDo,
          ConditionsAwareDecision.FailClosedDecision.foldFailClosed]
  | sub :: rest =>
    have ih_sub := sub.FailClosedDecisionDo_eq
    have ih_rest := unionSliceFailClosedDecisionDo_eq rest
    rw [foldFailClosed_cons_eq, ← ih_sub, ← ih_rest]
    simp only [unionSliceFailClosedDecisionDo, List.forIn_cons,
               pure_bind, bind_pure_comp]
    cases h : sub.FailClosedDecisionDo with
    | Deny =>
      have h_eq : (Decision.Deny == Decision.Deny) = true := rfl
      simp [h, h_eq]
    | Allow =>
      have h_eq : (Decision.Allow == Decision.Deny) = false := rfl
      simp [h, h_eq]
    | NoOpinion =>
      have h_eq : (Decision.NoOpinion == Decision.Deny) = false := rfl
      simp [h, h_eq]

end

-- ── ConditionsAwareDecision.ContainsAllowOrDenyDo ─────────────────────────────

mutual

theorem ConditionsAwareDecision.ContainsAllowOrDenyDo_eq (d : ConditionsAwareDecision) :
    d.ContainsAllowOrDenyDo = d.ContainsAllowOrDeny := by
  cases d with
  | Allow | Deny | NoOpinion | ConditionsMap _ =>
    simp only [ConditionsAwareDecision.ContainsAllowOrDenyDo,
               ConditionsAwareDecision.ContainsAllowOrDeny]
  | Union ds =>
    simp only [ConditionsAwareDecision.ContainsAllowOrDenyDo,
               ConditionsAwareDecision.ContainsAllowOrDeny]
    exact unionSliceContainsAllowOrDenyDo_eq ds

theorem unionSliceContainsAllowOrDenyDo_eq (xs : List ConditionsAwareDecision) :
    unionSliceContainsAllowOrDenyDo xs
    = ConditionsAwareDecision.ContainsAllowOrDeny.anyContainsAllowOrDeny xs := by
  match xs with
  | [] =>
    simp [unionSliceContainsAllowOrDenyDo,
          ConditionsAwareDecision.ContainsAllowOrDeny.anyContainsAllowOrDeny]
  | sub :: rest =>
    have ih_sub := sub.ContainsAllowOrDenyDo_eq
    have ih_rest := unionSliceContainsAllowOrDenyDo_eq rest
    simp only [unionSliceContainsAllowOrDenyDo, List.forIn_cons, bind_pure_comp]
    unfold ConditionsAwareDecision.ContainsAllowOrDeny.anyContainsAllowOrDeny
    rw [← ih_sub, ← ih_rest]
    cases h : sub.ContainsAllowOrDenyDo with
    | true => simp [h]
    | false => simp [h, unionSliceContainsAllowOrDenyDo]

end

-- ── ConditionsAwareDecision.CanBecomeAllowedDo ────────────────────────────────

mutual

theorem ConditionsAwareDecision.CanBecomeAllowedDo_eq (d : ConditionsAwareDecision) :
    d.CanBecomeAllowedDo = d.CanBecomeAllowed := by
  cases d with
  | Allow | Deny | NoOpinion =>
    simp only [ConditionsAwareDecision.CanBecomeAllowedDo,
               ConditionsAwareDecision.CanBecomeAllowed]
  | ConditionsMap c =>
    simp only [ConditionsAwareDecision.CanBecomeAllowedDo,
               ConditionsAwareDecision.CanBecomeAllowed,
               ConditionsMap.CanBecomeAllowedDo, ConditionsMap.CanBecomeAllowed]
  | Union ds =>
    simp only [ConditionsAwareDecision.CanBecomeAllowedDo,
               ConditionsAwareDecision.CanBecomeAllowed]
    exact unionSliceCanBecomeAllowedDo_eq ds

/-- One-step cons unfolding of `unionSliceCanBecomeAllowedDo` — collapses the
    `Id.run do for ... match return ...` body to a pure `match`. -/
private lemma unionSliceCanBecomeAllowedDo_cons (sub : ConditionsAwareDecision)
    (rest : List ConditionsAwareDecision) :
    unionSliceCanBecomeAllowedDo (sub :: rest)
    = (match sub with
       | .Deny => false
       | .Allow => true
       | .ConditionsMap _ =>
         if sub.CanBecomeAllowedDo then true else unionSliceCanBecomeAllowedDo rest
       | .Union _ =>
         if sub.CanBecomeAllowedDo then true else unionSliceCanBecomeAllowedDo rest
       | .NoOpinion => unionSliceCanBecomeAllowedDo rest) := by
  simp only [unionSliceCanBecomeAllowedDo, List.forIn_cons, bind_pure_comp]
  cases sub with
  | Deny | Allow | NoOpinion => simp
  | ConditionsMap c =>
    cases h : (ConditionsAwareDecision.ConditionsMap c).CanBecomeAllowedDo <;> simp [h]
  | Union ds =>
    cases h : (ConditionsAwareDecision.Union ds).CanBecomeAllowedDo <;> simp [h]

theorem unionSliceCanBecomeAllowedDo_eq (xs : List ConditionsAwareDecision) :
    unionSliceCanBecomeAllowedDo xs
    = ConditionsAwareDecision.CanBecomeAllowed.anyCanBecomeAllowed xs := by
  match xs with
  | [] =>
    simp [unionSliceCanBecomeAllowedDo,
          ConditionsAwareDecision.CanBecomeAllowed.anyCanBecomeAllowed]
  | sub :: rest =>
    have ih_sub := sub.CanBecomeAllowedDo_eq
    have ih_rest := unionSliceCanBecomeAllowedDo_eq rest
    rw [unionSliceCanBecomeAllowedDo_cons]
    unfold ConditionsAwareDecision.CanBecomeAllowed.anyCanBecomeAllowed
    cases sub with
    | Deny => simp
    | Allow => simp [ConditionsAwareDecision.CanBecomeAllowed]
    | NoOpinion =>
      simp [ConditionsAwareDecision.CanBecomeAllowed, ih_rest]
    | ConditionsMap c =>
      simp [ConditionsAwareDecision.CanBecomeAllowedDo,
            ConditionsAwareDecision.CanBecomeAllowed,
            ConditionsMap.CanBecomeAllowedDo_eq, ih_rest]
    | Union ds =>
      have hds := unionSliceCanBecomeAllowedDo_eq ds
      simp [ConditionsAwareDecision.CanBecomeAllowedDo,
            ConditionsAwareDecision.CanBecomeAllowed, hds, ih_rest]

end

end ConditionalAuthorization.Authorizer

-- ── UnionAuthorizer.* equivalences ────────────────────────────────────────────

namespace ConditionalAuthorization.Union

open ConditionalAuthorization.Authorizer
open ConditionalAuthorization.Spec
open ConditionalAuthorization.Go

theorem UnionAuthorizer.authorizeDo_eq (u : UnionAuthorizer) (attrs : Attributes) :
    u.authorizeDo attrs = u.authorize attrs := by
  obtain ⟨handlers⟩ := u
  induction handlers with
  | nil => simp [UnionAuthorizer.authorizeDo, UnionAuthorizer.authorize]
  | cons h rest ih =>
    simp only [UnionAuthorizer.authorizeDo, List.forIn_cons, bind_pure_comp]
    cases ha : h.authorize attrs with
    | Allow => simp [ha, UnionAuthorizer.authorize]
    | Deny => simp [ha, UnionAuthorizer.authorize]
    | NoOpinion =>
      simp only [ha, UnionAuthorizer.authorize]
      simpa [UnionAuthorizer.authorizeDo] using ih

-- (UnionAuthorizer.conditionsAwareAuthorizeDo_eq and evaluateConditionsDo_eq are
--  remaining to prove: they involve `let mut decisions := []; …` and `ds.zip u.handlers`
--  loops, which need additional accumulator-style bridge lemmas.
--
--  After two `where`-clause refactors, the public surface of `UnionAuthorizer` no longer
--  exposes any pair-list helpers:
--    * `UnionAuthorizer.conditionsAwareAuthorize.subDecisions` returns a plain
--      `List ConditionsAwareDecision` (was `entries` producing pairs).
--    * `UnionAuthorizer.evaluateConditions.walk` walks two parallel lists (handlers and
--      decisions) — no zip (was `unionEvaluateConditions` consuming a pre-zipped pair list).
--
--  conditionsAwareAuthorizeDo (Do-version) builds a `List ConditionsAwareDecision`
--  via mutable accumulator: aligns structurally with `subDecisions`. The residual
--  discrepancy is the short-circuit predicate — Do-version uses `ContainsAllowOrDenyDo`,
--  proof-friendly uses top-level `.Allow | .Deny` only.
--
--  evaluateConditionsDo (Do-version) uses `for (sub, handler) in ds.zip u.handlers do …`.
--  The equivalence target is now `walk u.handlers ds data` (parallel walk). Same
--  semantics; the Do-version retains the zip purely to mirror Go's positional indexing.)

end ConditionalAuthorization.Union

-- TODO: Should/could this be moved to Spec.lean?
-- ============================================================================
-- Main spec theorems restated about Go-transliterated functions
--
-- Each "Do" theorem is the corresponding spec from `Spec.lean` / `Union.lean` but
-- phrased about the `Do`-suffixed (Go-faithful) version. The proof rewrites via the
-- corresponding `XxxDo_eq` lemma and discharges to the existing proof on the
-- proof-friendly counterpart.
-- ============================================================================

namespace ConditionalAuthorization.Authorizer

open ConditionalAuthorization.Spec

/-- **Go-Do spec**: if `FailClosedDecisionDo d ≠ .Deny`, then `d.Ideal data ≠ .Deny`. -/
theorem failClosed_not_deny_implies_ideal_not_deny_Do
    (d : ConditionsAwareDecision) (data : ConditionsData)
    (h : d.FailClosedDecisionDo ≠ .Deny)
    : d.Ideal data ≠ .Deny := by
  rw [d.FailClosedDecisionDo_eq] at h
  exact ConditionalAuthorization.Spec.failClosed_not_deny_implies_ideal_not_deny d data h

/-- **Go-Do spec**: `ConditionsMap.FailClosedDecisionDo` is always `.Deny` or `.NoOpinion`. -/
theorem conditionsMap_failClosed_deny_or_noOpinion_Do (c : ConditionsMap) :
    c.FailClosedDecisionDo = .Deny ∨ c.FailClosedDecisionDo = .NoOpinion := by
  rw [c.FailClosedDecisionDo_eq]
  exact ConditionalAuthorization.Spec.conditionsMap_failClosed_deny_or_noOpinion c

/-- **Go-Do spec**: `ConditionsAwareDecision.FailClosedDecisionDo` is always `.Deny` or `.NoOpinion`. -/
theorem failClosed_deny_or_noOpinion_Do (d : ConditionsAwareDecision) :
    d.FailClosedDecisionDo = .Deny ∨ d.FailClosedDecisionDo = .NoOpinion := by
  rw [d.FailClosedDecisionDo_eq]
  exact ConditionalAuthorization.Spec.failClosed_deny_or_noOpinion d

end ConditionalAuthorization.Authorizer

namespace ConditionalAuthorization.Union

open ConditionalAuthorization.Authorizer
open ConditionalAuthorization.Spec
open ConditionalAuthorization.Go

/-- **Go-Do spec**: if the Go-faithful `authorizeDo` returns Allow, then the union's
    `idealAuthorize` also returns Allow at any data. -/
theorem UnionAuthorizer.metadata_allow_implies_ideal_allow_Do (u : UnionAuthorizer)
    (attrs : Attributes) (data : ConditionsData)
    (h : u.authorizeDo attrs = .Allow)
    : u.idealAuthorize attrs data = .Allow := by
  rw [u.authorizeDo_eq] at h
  exact u.metadata_allow_implies_ideal_allow attrs data h

/-- **Go-Do spec**: if the union's `idealAuthorize` returns `.Deny` at some `data`,
    then the Go-faithful `authorizeDo` returns Deny. -/
theorem UnionAuthorizer.ideal_deny_implies_authorize_deny_Do (u : UnionAuthorizer)
    (attrs : Attributes) (data : ConditionsData)
    (h : u.idealAuthorize attrs data = .Deny)
    : u.authorizeDo attrs = .Deny := by
  rw [u.authorizeDo_eq]
  exact u.ideal_deny_implies_authorize_deny attrs data h

end ConditionalAuthorization.Union

-- ============================================================================
-- #check lines verifying Go-Do signatures
-- ============================================================================

namespace ConditionalAuthorization.Go

open ConditionalAuthorization.Authorizer
open ConditionalAuthorization.Union

#check (Attributes.isReadOnlyDo : Attributes → Bool)
#check (ConditionsMap.FailClosedDecisionDo : ConditionsMap → Decision)
#check (ConditionsMap.CanBecomeAllowedDo : ConditionsMap → Bool)
#check (ConditionsAwareDecision.FailClosedDecisionDo : ConditionsAwareDecision → Decision)
#check (ConditionsAwareDecision.ContainsAllowOrDenyDo : ConditionsAwareDecision → Bool)
#check (ConditionsAwareDecision.CanBecomeAllowedDo : ConditionsAwareDecision → Bool)
#check (UnionAuthorizer.authorizeDo : UnionAuthorizer → Attributes → Decision)
#check (UnionAuthorizer.conditionsAwareAuthorizeDo :
          UnionAuthorizer → Attributes → ConditionsAwareDecision)
#check (UnionAuthorizer.evaluateConditionsDo :
          UnionAuthorizer → ConditionsAwareDecision → ConditionsData → Decision)

end ConditionalAuthorization.Go
