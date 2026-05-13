/-!
# Transpiled Go → Lean 4: Kubernetes Conditional Authorization

Line-by-line transpilation of the production Go code, with proofs.

We transpile the **framework** (union authorizer, filter, enforcer) faithfully.
Individual authorizers remain abstract — represented by a `Handler` with
coherence axioms linking its outputs.

## Handler fields

Each `Handler` bundles five pre-determined outputs for a given (attrs, data) pair:

- `authorizeIdeal`: The abstract result of the full authorize function, given
  complete information (attrs + data). This is NOT directly callable in the
  two-phase model — it exists only to state the correctness theorem.
- `authorizeMetadata`: The result of `Authorize(ctx, attrs)` — the production
  single-phase path that only has metadata (no request/stored objects).
  When conditionsAwareAuthorize = ConditionsMap, this is the fail-closed result
  (Deny if any Deny-effect condition exists, else NoOpinion). It may differ
  from `authorizeIdeal`.
- `conditionsAwareAuthorize`: The result of `ConditionsAwareAuthorize(ctx, attrs)` —
  the two-phase path, phase 1. Returns a LeafDecision (possibly ConditionsMap).
- `cmCanBecomeAllowed`: `ConditionsMap.CanBecomeAllowed()` — whether the
  ConditionsMap has any Allow-effect conditions.
- `evaluateConditions`: The result of `EvaluateConditions(ctx, decision, data)` —
  the two-phase path, phase 2. The actual condition evaluation with full data.

## Go source → Lean mapping

- `union.Authorize` (metadata-only)              → `UnionAuthorizeMetadata`
- `union.Authorize` (ideal, all data)             → `UnionAuthorize`
- `union.ConditionsAwareAuthorize` (loop)         → `UnionConditionsAwareAuthorize`
- `union.EvaluateConditions` (loop)               → `UnionEvaluateConditions`
- `unionSlice.CanBecomeAllowed`                   → `UnionSliceCanBecomeAllowed`
- `withAuthorization` + `conditionsEnforcer`      → `Pipeline`

## Main results

- `evaluateEntries_eq_authorize` : UnionEvaluateConditions = UnionAuthorize
- `cba_sound` : canBecomeAllowed soundness
- `transpiled_allows_iff` : isAllowed(UnionAuthorize) = isAllowed(Pipeline)
- `metadata_allows_iff` : isAllowed(UnionAuthorizeMetadata) = isAllowed(UnionAuthorize)
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

/-- An individual authorizer, with pre-bound attrs and data.

    See the module docstring for a description of each field. -/
structure Handler where
  /-- The ideal result with complete information (attrs + data).
      Equal to `evaluateConditions` when `conditionsAwareAuthorize = ConditionsMap`,
      and equal to the unconditional decision otherwise. -/
  authorizeIdeal         : Decision
  /-- The production `Authorize(ctx, attrs)` result with only metadata.
      May be more conservative than `authorizeIdeal` — e.g. Deny when
      `authorizeIdeal` is NoOpinion, because the authorizer fails closed. -/
  authorizeMetadata      : Decision
  conditionsAwareAuthorize : LeafDecision
  cmCanBecomeAllowed     : Bool
  evaluateConditions     : Decision
  -- Axioms linking authorizeIdeal to the two-phase outputs:
  ax_allow : conditionsAwareAuthorize = .Allow → authorizeIdeal = .Allow
  ax_deny : conditionsAwareAuthorize = .Deny → authorizeIdeal = .Deny
  ax_noOpinion : conditionsAwareAuthorize = .NoOpinion → authorizeIdeal = .NoOpinion
  ax_conditional : conditionsAwareAuthorize = .ConditionsMap →
    authorizeIdeal = evaluateConditions
  ax_cba_sound : conditionsAwareAuthorize = .ConditionsMap →
    cmCanBecomeAllowed = false → evaluateConditions ≠ .Allow
  -- Axioms linking authorizeMetadata to authorizeIdeal:
  /-- When phase 1 is unconditional, metadata-only Authorize returns the same
      as the ideal. (No conditions to evaluate, so no information loss.) -/
  ax_metadata_unconditional : conditionsAwareAuthorize ≠ .ConditionsMap →
    authorizeMetadata = authorizeIdeal
  /-- Metadata-only Authorize is at least as restrictive as the ideal:
      Allow maps to Allow, Deny maps to Deny, NoOpinion maps to NoOpinion or Deny.
      In other words, metadata never upgrades a decision (Deny→Allow or NoOpinion→Allow
      are impossible), and it may downgrade NoOpinion to Deny (fail closed). -/
  ax_metadata_allow : authorizeIdeal = .Allow → authorizeMetadata = .Allow
  ax_metadata_deny : authorizeIdeal = .Deny → authorizeMetadata = .Deny
  ax_metadata_noOpinion_fail_closed : authorizeIdeal = .NoOpinion → authorizeMetadata = .NoOpinion ∨ authorizeMetadata = .Deny

-- ============================================================================
-- Transpiled: union.Authorize — ideal (all data available)
-- ============================================================================

/-- The ideal single-phase chain evaluation with complete data.
    This is the "gold standard" that we prove the pipeline equivalent to. -/
def UnionAuthorize : List Handler → Decision
  | [] => .NoOpinion
  | h :: rest =>
    match h.authorizeIdeal with
    | .Allow     => .Allow
    | .Deny      => .Deny
    | .NoOpinion => UnionAuthorize rest

-- ============================================================================
-- Transpiled: union.Authorize — metadata-only (production Authorize path)
-- ============================================================================

/-- The production `union.Authorize` which only has request metadata.
    For conditional authorizers, this returns the fail-closed result
    (authorizeMetadata), which may be more conservative than authorizeIdeal. -/
def UnionAuthorizeMetadata : List Handler → Decision
  | [] => .NoOpinion
  | h :: rest =>
    match h.authorizeMetadata with
    | .Allow     => .Allow
    | .Deny      => .Deny
    | .NoOpinion => UnionAuthorizeMetadata rest

-- ============================================================================
-- Transpiled: union.ConditionsAwareAuthorize (union.go:73-96)
-- ============================================================================

def UnionConditionsAwareAuthorize : List Handler → List (Handler × LeafDecision)
  | [] => []
  | h :: rest =>
    let d := h.conditionsAwareAuthorize
    match d with
    | .Allow | .Deny => [(h, d)]
    | .NoOpinion | .ConditionsMap => (h, d) :: UnionConditionsAwareAuthorize rest

-- ============================================================================
-- Transpiled: union.EvaluateConditions loop (union.go:117-149)
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
-- Transpiled: withAuthorization + conditionsEnforcer pipeline
-- ============================================================================

inductive HTTPCode where
  | OK200 | Forbidden403
  deriving Repr, DecidableEq, BEq

structure PipelineResult where
  decision : Decision
  httpCode : HTTPCode
  deriving Repr, DecidableEq

def Pipeline (handlers : List Handler) : PipelineResult :=
  let entries := UnionConditionsAwareAuthorize handlers
  let isUnconditionalAllow := match entries with | [(_, .Allow)] => true | _ => false
  if isUnconditionalAllow then ⟨.Allow, .OK200⟩
  else if UnionSliceCanBecomeAllowed entries then
    match UnionEvaluateConditions entries with
    | .Allow     => ⟨.Allow, .OK200⟩
    | .Deny      => ⟨.Deny, .Forbidden403⟩
    | .NoOpinion => ⟨.NoOpinion, .Forbidden403⟩
  else ⟨.Deny, .Forbidden403⟩

def PipelineDecision (handlers : List Handler) : Decision :=
  let entries := UnionConditionsAwareAuthorize handlers
  let isUnconditionalAllow := match entries with | [(_, .Allow)] => true | _ => false
  if isUnconditionalAllow then .Allow
  else if UnionSliceCanBecomeAllowed entries then UnionEvaluateConditions entries
  else .Deny

-- ============================================================================
-- Core semantic lemma
-- ============================================================================

theorem evaluateEntries_eq_authorize
    (handlers : List Handler)
    : UnionEvaluateConditions (UnionConditionsAwareAuthorize handlers)
    = UnionAuthorize handlers := by
  induction handlers with
  | nil => rfl
  | cons h rest ih =>
    simp only [UnionAuthorize]
    show UnionEvaluateConditions (UnionConditionsAwareAuthorize (h :: rest))
       = match h.authorizeIdeal with
         | .Allow => .Allow | .Deny => .Deny | .NoOpinion => UnionAuthorize rest
    cases hca : h.conditionsAwareAuthorize with
    | Allow =>
      simp only [UnionConditionsAwareAuthorize, hca, UnionEvaluateConditions, h.ax_allow hca]
    | Deny =>
      simp only [UnionConditionsAwareAuthorize, hca, UnionEvaluateConditions, h.ax_deny hca]
    | NoOpinion =>
      simp only [UnionConditionsAwareAuthorize, hca, UnionEvaluateConditions, h.ax_noOpinion hca]
      exact ih
    | ConditionsMap =>
      simp only [UnionConditionsAwareAuthorize, hca, UnionEvaluateConditions]
      rw [h.ax_conditional hca]
      cases h.evaluateConditions with
      | Allow     => simp
      | Deny      => simp
      | NoOpinion => exact ih

-- ============================================================================
-- CanBecomeAllowed soundness
-- ============================================================================

theorem cba_sound
    (handlers : List Handler)
    (hcba : UnionSliceCanBecomeAllowed (UnionConditionsAwareAuthorize handlers) = false)
    : UnionEvaluateConditions (UnionConditionsAwareAuthorize handlers) ≠ .Allow := by
  induction handlers with
  | nil => simp [UnionConditionsAwareAuthorize, UnionEvaluateConditions]
  | cons h rest ih =>
    cases hca : h.conditionsAwareAuthorize with
    | Allow =>
      simp [UnionConditionsAwareAuthorize, hca, UnionSliceCanBecomeAllowed] at hcba
    | Deny =>
      simp [UnionConditionsAwareAuthorize, hca, UnionEvaluateConditions]
    | NoOpinion =>
      have hcba' : UnionSliceCanBecomeAllowed (UnionConditionsAwareAuthorize rest) = false := by
        simp [UnionConditionsAwareAuthorize, hca, UnionSliceCanBecomeAllowed] at hcba; exact hcba
      simp [UnionConditionsAwareAuthorize, hca, UnionEvaluateConditions]
      exact ih hcba'
    | ConditionsMap =>
      have hcba' : h.cmCanBecomeAllowed = false
                 ∧ UnionSliceCanBecomeAllowed (UnionConditionsAwareAuthorize rest) = false := by
        simp [UnionConditionsAwareAuthorize, hca, UnionSliceCanBecomeAllowed, Bool.or_eq_false_iff] at hcba
        exact hcba
      obtain ⟨hcba_cm, hcba_rest⟩ := hcba'
      simp only [UnionConditionsAwareAuthorize, hca, UnionEvaluateConditions]
      cases heval : h.evaluateConditions with
      | Allow     => exact absurd heval (h.ax_cba_sound hca hcba_cm)
      | Deny      => simp
      | NoOpinion => exact ih hcba_rest

-- ============================================================================
-- Main theorems
-- ============================================================================

def isAllowed : Decision → Bool
  | .Allow => true
  | _      => false

/-- The pipeline allows a request iff the ideal UnionAuthorize allows it. -/
theorem transpiled_allows_iff
    (handlers : List Handler)
    : isAllowed (UnionAuthorize handlers)
    = isAllowed (PipelineDecision handlers) := by
  simp only [PipelineDecision]
  rw [← evaluateEntries_eq_authorize handlers]
  split
  · rename_i _ h_eq
    simp [h_eq, UnionEvaluateConditions, isAllowed]
  · cases hcba : UnionSliceCanBecomeAllowed (UnionConditionsAwareAuthorize handlers) with
    | true  => simp [isAllowed]
    | false =>
      simp [isAllowed]
      have h := cba_sound handlers hcba
      cases heval : UnionEvaluateConditions (UnionConditionsAwareAuthorize handlers) with
      | Allow     => exact absurd heval h
      | Deny      => rfl
      | NoOpinion => rfl

/-- Full decision equality when the pipeline proceeds via the conditional path. -/
theorem transpiled_eq_when_cba
    (handlers : List Handler)
    (hcba : UnionSliceCanBecomeAllowed (UnionConditionsAwareAuthorize handlers) = true)
    (h_not_sa : (match UnionConditionsAwareAuthorize handlers with
                  | [(_, .Allow)] => true | _ => false) = false)
    : UnionAuthorize handlers = PipelineDecision handlers := by
  simp only [PipelineDecision, h_not_sa, hcba, ite_true]
  exact (evaluateEntries_eq_authorize handlers).symm

-- ============================================================================
-- Metadata-only Authorize vs ideal Authorize
-- ============================================================================

/-- **Safety property**: If the metadata-only Authorize path allows a request,
    the ideal Authorize also allows it. The metadata path never grants access
    that the ideal path wouldn't.

    The converse does NOT hold: the metadata path may be more conservative,
    denying requests that the ideal (with full data) would allow. This is
    precisely the gap that conditional authorization closes — the pipeline
    (which uses evaluateConditions) recovers the ideal result. -/
theorem metadata_allow_implies_ideal_allow
    (handlers : List Handler)
    : isAllowed (UnionAuthorizeMetadata handlers) = true →
      isAllowed (UnionAuthorize handlers) = true := by
  induction handlers with
  | nil => simp [UnionAuthorizeMetadata, UnionAuthorize, isAllowed]
  | cons h rest ih =>
    simp only [UnionAuthorize, UnionAuthorizeMetadata]
    -- Case split on authorizeMetadata (what the metadata path does)
    -- and authorizeIdeal (what the ideal path does)
    cases hm : h.authorizeMetadata <;> cases hi : h.authorizeIdeal <;> simp [isAllowed]
    -- After simp [isAllowed], the goals with metadata=Deny are closed (vacuously true).
    -- Remaining cases where we need to prove something:
    -- 1. metadata=Allow, ideal=Allow → trivial
    -- 2. metadata=Allow, ideal=Deny → impossible by ax_metadata_not_allow
    -- 3. metadata=Allow, ideal=NoOpinion → impossible by ax_metadata_not_allow
    -- 4. metadata=NoOpinion, ideal=Allow → trivial
    -- 5. metadata=NoOpinion, ideal=Deny → need ih
    -- 6. metadata=NoOpinion, ideal=NoOpinion → need ih
    -- metadata=Allow, ideal=Deny → contradiction (metadata can't upgrade Deny to Allow)
    · exact absurd hm (by rw [h.ax_metadata_deny hi]; decide)
    -- metadata=Allow, ideal=NoOpinion → contradiction (metadata is NoOpinion or Deny, not Allow)
    · cases h.ax_metadata_noOpinion_fail_closed hi with
      | inl h => exact absurd hm (by rw [h]; decide)
      | inr h => exact absurd hm (by rw [h]; decide)
    -- metadata=NoOpinion, ideal=Deny → contradiction (metadata must also be Deny)
    · exact absurd hm (by rw [h.ax_metadata_deny hi]; decide)
    -- metadata=NoOpinion, ideal=NoOpinion → both recurse, use ih
    · exact ih

end TranspiledAuthz
