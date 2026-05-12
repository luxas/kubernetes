/-!
# Transpiled Go → Lean 4: Kubernetes Conditional Authorization

Line-by-line transpilation of the production Go code, with proofs.

We transpile the **framework** (union authorizer, filter, enforcer) faithfully.
Individual authorizers remain abstract — represented by a `Handler` with a
coherence axiom linking its two-phase output to its single-phase output.

## Go source → Lean mapping

- `union.Authorize`                           → `Authorize`
- `union.ConditionsAwareAuthorize` (loop)     → `BuildEntries`
- `union.EvaluateConditions` (loop)           → `EvaluateConditions`
- `unionSlice.CanBecomeAllowed`               → `SliceCanBecomeAllowed`
- `withAuthorization` + `conditionsEnforcer`   → `Pipeline`

## Main results

- `evaluateEntries_eq_authorize` : core semantics, no axiom gap
- `cba_sound` : canBecomeAllowed soundness
- `transpiled_allows_iff` : isAllowed(Authorize) ↔ isAllowed(Pipeline)
-/

namespace TranspiledAuthz

-- ============================================================================
-- Types
-- ============================================================================

inductive Decision where
  | Deny | Allow | NoOpinion
  deriving Repr, DecidableEq, BEq

inductive LeafDecision where
  | Allow | Deny | NoOpinion | ConditionsMap
  deriving Repr, DecidableEq

structure Handler where
  authorize              : Decision
  conditionsAwareAuthorize : LeafDecision
  cmCanBecomeAllowed     : Bool
  evaluateConditions     : Decision

structure CoherentHandler extends Handler where
  ax_allow : toHandler.conditionsAwareAuthorize = .Allow →
    toHandler.authorize = .Allow
  ax_deny : toHandler.conditionsAwareAuthorize = .Deny →
    toHandler.authorize = .Deny
  ax_noOpinion : toHandler.conditionsAwareAuthorize = .NoOpinion →
    toHandler.authorize = .NoOpinion
  ax_conditional : toHandler.conditionsAwareAuthorize = .ConditionsMap →
    toHandler.authorize = toHandler.evaluateConditions
  ax_cba_sound : toHandler.conditionsAwareAuthorize = .ConditionsMap →
    toHandler.cmCanBecomeAllowed = false →
    toHandler.evaluateConditions ≠ .Allow

-- ============================================================================
-- Transpiled: union.Authorize (union.go:46-70)
-- ============================================================================

def UnionAuthorize : List Handler → Decision
  | [] => .NoOpinion
  | h :: rest =>
    match h.authorize with
    | .Allow     => .Allow
    | .Deny      => .Deny
    | .NoOpinion => UnionAuthorize rest

-- ============================================================================
-- Transpiled: union.ConditionsAwareAuthorize (union.go:73-96)
-- Builds the entry list, short-circuiting on ContainsAllowOrDeny.
-- ============================================================================

def UnionConditionsAwareAuthorize : List Handler → List (Handler × LeafDecision)
  | [] => []
  | h :: rest =>
    let d := h.conditionsAwareAuthorize
    match d with
    | .Allow | .Deny => [(h, d)]  -- ContainsAllowOrDeny → short-circuit
    | .NoOpinion | .ConditionsMap => (h, d) :: UnionConditionsAwareAuthorize rest

-- ============================================================================
-- Transpiled: union.EvaluateConditions loop (union.go:117-149)
-- on the paired (handler, decision) entries.
--
-- The Go code iterates `for i, subD := range unionedDecisions` and uses
-- `authzHandler[i]` — we pair them as `(Handler × LeafDecision)`.
-- ============================================================================

def UnionEvaluateConditions : List (Handler × LeafDecision) → Decision
  | [] => .NoOpinion
  | (h, d) :: rest =>
    match d with
    | .Allow     => .Allow
    | .Deny      => .Deny
    | .NoOpinion => UnionEvaluateConditions rest
    | .ConditionsMap =>
      match h.evaluateConditions with
      | .Allow     => .Allow
      | .Deny      => .Deny
      | .NoOpinion => UnionEvaluateConditions rest

-- ============================================================================
-- Transpiled: unionSlice.CanBecomeAllowed (conditions.go:910-926)
-- ============================================================================

def UnionSliceCanBecomeAllowed : List (Handler × LeafDecision) → Bool
  | [] => false
  | (h, d) :: rest =>
    match d with
    | .Deny         => false
    | .Allow        => true
    | .NoOpinion    => UnionSliceCanBecomeAllowed rest
    | .ConditionsMap => h.cmCanBecomeAllowed || UnionSliceCanBecomeAllowed rest

-- ============================================================================
-- Transpiled: withAuthorization + conditionsEnforcer combined
-- (authorization.go:70-151 + conditionsenforcer.go:87-147)
--
-- The filter checks: (1) IsAllowed? → Allow. (2) CanBecomeAllowed? →
-- evaluate. (3) else → Deny. The enforcer evaluates or passes through.
-- We combine them since the enforcer just calls EvaluateConditions.
-- ============================================================================

def Pipeline (handlers : List Handler) : Decision :=
  let entries := UnionConditionsAwareAuthorize handlers
  -- Step 1 (filter): check if unconditionally allowed.
  -- This happens when the first entry is Allow (short-circuited by BuildEntries).
  -- EvaluateEntries on such an entry returns Allow, so we can uniformly
  -- check CanBecomeAllowed (which is true for an Allow entry).
  -- Step 2 (filter): check CanBecomeAllowed
  if UnionSliceCanBecomeAllowed entries then
    -- Step 3 (enforcer): evaluate
    UnionEvaluateConditions entries
  else
    .Deny

-- ============================================================================
-- Core semantic lemma
-- ============================================================================

/-- `EvaluateEntries` on the entry list from `BuildEntries` equals `Authorize`.
    This is the transpilation of the Go comment at union.go:111:
    "This logic directly maps 1:1 with Authorize()" -/
theorem evaluateEntries_eq_authorize
    (handlers : List CoherentHandler)
    : UnionEvaluateConditions (UnionConditionsAwareAuthorize (handlers.map CoherentHandler.toHandler))
    = UnionAuthorize (handlers.map CoherentHandler.toHandler) := by
  induction handlers with
  | nil => rfl
  | cons ch rest ih =>
    simp only [List.map, UnionAuthorize]
    -- Unfold BuildEntries and EvaluateEntries for the head
    show UnionEvaluateConditions (UnionConditionsAwareAuthorize (ch.toHandler :: rest.map CoherentHandler.toHandler))
       = match ch.toHandler.authorize with
         | .Allow => .Allow | .Deny => .Deny | .NoOpinion => UnionAuthorize (rest.map CoherentHandler.toHandler)
    -- Case split on phase-1 result
    cases hca : ch.toHandler.conditionsAwareAuthorize with
    | Allow =>
      -- BuildEntries returns [(ch, Allow)]; EvaluateEntries returns Allow
      -- ax_allow: authorize = Allow
      simp only [UnionConditionsAwareAuthorize, hca, UnionEvaluateConditions, ch.ax_allow hca]
    | Deny =>
      simp only [UnionConditionsAwareAuthorize, hca, UnionEvaluateConditions, ch.ax_deny hca]
    | NoOpinion =>
      -- BuildEntries continues; both sides recurse
      simp only [UnionConditionsAwareAuthorize, hca, UnionEvaluateConditions, ch.ax_noOpinion hca]
      exact ih
    | ConditionsMap =>
      -- BuildEntries continues; EvaluateEntries checks evaluateConditions
      simp only [UnionConditionsAwareAuthorize, hca, UnionEvaluateConditions]
      rw [ch.ax_conditional hca]
      cases heval : ch.toHandler.evaluateConditions with
      | Allow     => simp
      | Deny      => simp
      | NoOpinion => exact ih

-- ============================================================================
-- CanBecomeAllowed soundness
-- ============================================================================

/-- When `SliceCBA` is false, `EvaluateEntries` never returns Allow. -/
theorem cba_sound
    (handlers : List CoherentHandler)
    (hcba : UnionSliceCanBecomeAllowed (UnionConditionsAwareAuthorize (handlers.map CoherentHandler.toHandler)) = false)
    : UnionEvaluateConditions (UnionConditionsAwareAuthorize (handlers.map CoherentHandler.toHandler)) ≠ .Allow := by
  induction handlers with
  | nil => simp [UnionConditionsAwareAuthorize, UnionEvaluateConditions]
  | cons ch rest ih =>
    simp only [List.map] at *
    -- Unfold BuildEntries in both the goal and hcba, keyed on hca
    cases hca : ch.toHandler.conditionsAwareAuthorize with
    | Allow =>
      -- SliceCBA [(ch, Allow)] = true, contradicts hcba = false
      simp [UnionConditionsAwareAuthorize, hca, UnionSliceCanBecomeAllowed] at hcba
    | Deny =>
      -- EvaluateEntries [(ch, Deny)] = Deny ≠ Allow
      simp [UnionConditionsAwareAuthorize, hca, UnionEvaluateConditions]
    | NoOpinion =>
      -- Recurse: both SliceCBA and EvaluateEntries pass through
      have hcba' : UnionSliceCanBecomeAllowed (UnionConditionsAwareAuthorize (List.map CoherentHandler.toHandler rest)) = false := by
        simp [UnionConditionsAwareAuthorize, hca, UnionSliceCanBecomeAllowed] at hcba; exact hcba
      have goal := ih hcba'
      simp [UnionConditionsAwareAuthorize, hca, UnionEvaluateConditions]; exact goal
    | ConditionsMap =>
      -- Split hcba into cmCanBecomeAllowed = false ∧ rest cba = false
      have hcba' : ch.toHandler.cmCanBecomeAllowed = false
                 ∧ UnionSliceCanBecomeAllowed (UnionConditionsAwareAuthorize (List.map CoherentHandler.toHandler rest)) = false := by
        simp [UnionConditionsAwareAuthorize, hca, UnionSliceCanBecomeAllowed, Bool.or_eq_false_iff] at hcba; exact hcba
      obtain ⟨hcba_cm, hcba_rest⟩ := hcba'
      have h_not_allow := ch.ax_cba_sound hca hcba_cm
      -- Unfold and case-split on evaluateConditions
      simp only [UnionConditionsAwareAuthorize, hca, UnionEvaluateConditions]
      cases heval : ch.toHandler.evaluateConditions with
      | Allow     => exact absurd heval h_not_allow
      | Deny      => simp
      | NoOpinion => exact ih hcba_rest

-- ============================================================================
-- Main theorem
-- ============================================================================

def isAllowed : Decision → Bool
  | .Allow => true
  | _      => false

/-- **Main theorem**: The pipeline allows a request iff `Authorize` allows it.
    Proven on the transpiled production code — no model gap. -/
theorem transpiled_allows_iff
    (handlers : List CoherentHandler)
    : isAllowed (UnionAuthorize (handlers.map CoherentHandler.toHandler))
    = isAllowed (Pipeline (handlers.map CoherentHandler.toHandler)) := by
  simp only [Pipeline]
  -- Rewrite Authorize as EvaluateEntries using the core lemma
  rw [← evaluateEntries_eq_authorize handlers]
  -- Now both sides talk about EvaluateEntries on BuildEntries.
  -- Case split on SliceCBA.
  cases hcba : UnionSliceCanBecomeAllowed (UnionConditionsAwareAuthorize (handlers.map CoherentHandler.toHandler)) with
  | true =>
    -- Pipeline evaluates → same result
    simp
  | false =>
    -- Pipeline returns Deny; EvaluateEntries ≠ Allow (by cba_sound)
    simp [isAllowed]
    have h := cba_sound handlers hcba
    cases heval : UnionEvaluateConditions (UnionConditionsAwareAuthorize (handlers.map CoherentHandler.toHandler)) with
    | Allow     => exact absurd heval h
    | Deny      => rfl
    | NoOpinion => rfl

/-- **Full equality** when the pipeline proceeds (cba = true). -/
theorem transpiled_eq_when_cba
    (handlers : List CoherentHandler)
    (hcba : UnionSliceCanBecomeAllowed (UnionConditionsAwareAuthorize (handlers.map CoherentHandler.toHandler)) = true)
    : UnionAuthorize (handlers.map CoherentHandler.toHandler)
    = Pipeline (handlers.map CoherentHandler.toHandler) := by
  simp only [Pipeline, hcba, ite_true]
  exact (evaluateEntries_eq_authorize handlers).symm

end TranspiledAuthz
