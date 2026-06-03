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
-- Equivalence with proof-friendly counterparts
-- ============================================================================

namespace ConditionalAuthorization.Authorizer

theorem Attributes.isReadOnlyDo_eq (a : Attributes) :
    a.isReadOnlyDo = a.isReadOnly := rfl

theorem ConditionsMap.FailClosedDecisionDo_eq (c : ConditionsMap) :
    c.FailClosedDecisionDo = c.FailClosedDecision := rfl

theorem ConditionsMap.CanBecomeAllowedDo_eq (c : ConditionsMap) :
    c.CanBecomeAllowedDo = c.CanBecomeAllowed := rfl

-- ── ConditionsAwareDecision.FailClosedDecisionDo ──────────────────────────────

mutual

theorem ConditionsAwareDecision.FailClosedDecisionDo_eq (d : ConditionsAwareDecision) :
    d.FailClosedDecisionDo = d.FailClosedDecision := by
  cases d with
  | Allow | Deny | NoOpinion =>
    simp [ConditionsAwareDecision.FailClosedDecisionDo,
          ConditionsAwareDecision.FailClosedDecision]
  | ConditionsMap _ =>
    simp [ConditionsAwareDecision.FailClosedDecisionDo,
          ConditionsAwareDecision.FailClosedDecision,
          ConditionsMap.FailClosedDecisionDo, ConditionsMap.FailClosedDecision]
  | Union ds =>
    simp only [ConditionsAwareDecision.FailClosedDecisionDo,
               ConditionsAwareDecision.FailClosedDecision]
    exact unionSliceFailClosedDecisionDo_eq ds

theorem unionSliceFailClosedDecisionDo_eq (xs : List ConditionsAwareDecision) :
    unionSliceFailClosedDecisionDo xs
    = ConditionsAwareDecision.FailClosedDecision.foldFailClosed xs := by
  induction xs with
  | nil =>
    simp [unionSliceFailClosedDecisionDo,
          ConditionsAwareDecision.FailClosedDecision.foldFailClosed]
  | cons sub rest ih =>
    have ih_sub := sub.FailClosedDecisionDo_eq
    -- Step the for-loop on (sub :: rest) by one iteration. With mathlib's
    -- monad/`Id.run`/forIn simp lemmas, the inner `if` reduces and the rest
    -- becomes the recursive call.
    simp only [unionSliceFailClosedDecisionDo,
               List.forIn_cons, List.forIn_nil,
               Id.run, bind_pure_comp, Functor.map_pure]
    unfold ConditionsAwareDecision.FailClosedDecision.foldFailClosed
    rw [← ih_sub]
    cases h : sub.FailClosedDecisionDo with
    | Deny =>
      simp [h]
    | Allow =>
      simp only [h, beq_iff_eq, reduceCtorEq, if_false, ite_false]
      exact ih
    | NoOpinion =>
      simp only [h, beq_iff_eq, reduceCtorEq, if_false, ite_false]
      exact ih

end

-- ── ConditionsAwareDecision.ContainsAllowOrDenyDo ─────────────────────────────

mutual

theorem ConditionsAwareDecision.ContainsAllowOrDenyDo_eq (d : ConditionsAwareDecision) :
    d.ContainsAllowOrDenyDo = d.ContainsAllowOrDeny := by
  cases d with
  | Allow | Deny | NoOpinion | ConditionsMap _ =>
    simp [ConditionsAwareDecision.ContainsAllowOrDenyDo,
          ConditionsAwareDecision.ContainsAllowOrDeny]
  | Union ds =>
    simp only [ConditionsAwareDecision.ContainsAllowOrDenyDo,
               ConditionsAwareDecision.ContainsAllowOrDeny]
    exact unionSliceContainsAllowOrDenyDo_eq ds

theorem unionSliceContainsAllowOrDenyDo_eq (xs : List ConditionsAwareDecision) :
    unionSliceContainsAllowOrDenyDo xs
    = ConditionsAwareDecision.ContainsAllowOrDeny.anyContainsAllowOrDeny xs := by
  match xs with
  | [] => rfl
  | sub :: rest =>
    have ih_sub : sub.ContainsAllowOrDenyDo = sub.ContainsAllowOrDeny :=
      sub.ContainsAllowOrDenyDo_eq
    have ih_rest := unionSliceContainsAllowOrDenyDo_eq rest
    show (Id.run do
      for subDecision in sub :: rest do
        if subDecision.ContainsAllowOrDenyDo then
          return true
      return false) = _
    unfold ConditionsAwareDecision.ContainsAllowOrDeny.anyContainsAllowOrDeny
    rw [← ih_sub, ← ih_rest]
    simp [Id.run]
    cases h : sub.ContainsAllowOrDenyDo with
    | true => simp [h]
    | false => simp [h]

end

-- ── ConditionsAwareDecision.CanBecomeAllowedDo ────────────────────────────────

mutual

theorem ConditionsAwareDecision.CanBecomeAllowedDo_eq (d : ConditionsAwareDecision) :
    d.CanBecomeAllowedDo = d.CanBecomeAllowed := by
  cases d with
  | Allow | Deny | NoOpinion =>
    simp [ConditionsAwareDecision.CanBecomeAllowedDo,
          ConditionsAwareDecision.CanBecomeAllowed]
  | ConditionsMap _ =>
    simp [ConditionsAwareDecision.CanBecomeAllowedDo,
          ConditionsAwareDecision.CanBecomeAllowed,
          ConditionsMap.CanBecomeAllowedDo, ConditionsMap.CanBecomeAllowed]
  | Union ds =>
    simp only [ConditionsAwareDecision.CanBecomeAllowedDo,
               ConditionsAwareDecision.CanBecomeAllowed]
    exact unionSliceCanBecomeAllowedDo_eq ds

theorem unionSliceCanBecomeAllowedDo_eq (xs : List ConditionsAwareDecision) :
    unionSliceCanBecomeAllowedDo xs
    = ConditionsAwareDecision.CanBecomeAllowed.anyCanBecomeAllowed xs := by
  match xs with
  | [] => rfl
  | sub :: rest =>
    have ih_sub : sub.CanBecomeAllowedDo = sub.CanBecomeAllowed :=
      sub.CanBecomeAllowedDo_eq
    have ih_rest := unionSliceCanBecomeAllowedDo_eq rest
    show (Id.run do
      for subDecision in sub :: rest do
        match subDecision with
        | .Deny => return false
        | .Allow => return true
        | .ConditionsMap _ =>
          if subDecision.CanBecomeAllowedDo then return true
        | .Union _ =>
          if subDecision.CanBecomeAllowedDo then return true
        | .NoOpinion => pure ()
      return false) = _
    unfold ConditionsAwareDecision.CanBecomeAllowed.anyCanBecomeAllowed
    rw [← ih_sub, ← ih_rest]
    simp [Id.run]
    cases sub with
    | Allow =>
      simp [ConditionsAwareDecision.CanBecomeAllowedDo,
            ConditionsAwareDecision.CanBecomeAllowed]
    | Deny =>
      simp [ConditionsAwareDecision.CanBecomeAllowedDo,
            ConditionsAwareDecision.CanBecomeAllowed]
    | NoOpinion =>
      simp [ConditionsAwareDecision.CanBecomeAllowedDo,
            ConditionsAwareDecision.CanBecomeAllowed]
    | ConditionsMap c =>
      simp only [ConditionsAwareDecision.CanBecomeAllowedDo,
                 ConditionsAwareDecision.CanBecomeAllowed]
      cases c.CanBecomeAllowedDo <;> simp
    | Union ds =>
      simp only [ConditionsAwareDecision.CanBecomeAllowedDo,
                 ConditionsAwareDecision.CanBecomeAllowed]
      cases unionSliceCanBecomeAllowedDo ds <;> simp

end

end ConditionalAuthorization.Authorizer

-- ── UnionAuthorizer.* equivalences ────────────────────────────────────────────

namespace ConditionalAuthorization.Union

open ConditionalAuthorization.Authorizer
open ConditionalAuthorization.Spec

theorem UnionAuthorizer.authorizeDo_eq (u : UnionAuthorizer) (attrs : Attributes) :
    u.authorizeDo attrs = u.authorize attrs := by
  obtain ⟨handlers⟩ := u
  induction handlers with
  | nil => rfl
  | cons h rest ih =>
    show (Id.run do
      for curr in h :: rest do
        match curr.authorize attrs with
        | .Allow => return .Allow
        | .Deny => return .Deny
        | .NoOpinion => pure ()
      return .NoOpinion) = _
    rw [show ((⟨h :: rest⟩ : UnionAuthorizer).authorize attrs)
          = (match h.authorize attrs with
             | .Allow => .Allow
             | .Deny  => .Deny
             | .NoOpinion => (⟨rest⟩ : UnionAuthorizer).authorize attrs)
        from rfl]
    rw [← ih]
    simp [Id.run, UnionAuthorizer.authorizeDo]
    cases h.authorize attrs <;> simp

end ConditionalAuthorization.Union
