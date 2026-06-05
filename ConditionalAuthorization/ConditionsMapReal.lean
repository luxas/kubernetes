import ConditionalAuthorization.Authorizer

/-!
# Faithful Go → Lean transliteration of `ConditionsMap` and its `Evaluate` function

Standalone namespace `ConditionalAuthorization.ConditionsMapReal`. Reuses `Decision` and
`ConditionsData` from `Authorizer.lean` but defines its own `ConditionsMap`, `Condition`,
`ConditionEffect`, `ConditionEvaluationResult`, and `EvaluateResult`.

The `Evaluate` function mirrors Go's three-phase loop in
`staging/src/k8s.io/apiserver/pkg/authorization/authorizer/conditions.go:700-870`
line-by-line. Soundness theorems below state, for each possible `Evaluate` result, the
per-condition witness that must have been present to produce that result.
-/

namespace ConditionalAuthorization.ConditionsMapReal

open ConditionalAuthorization.Authorizer (Decision ConditionsData)

-- ============================================================================
-- Types (faithful to Go)
-- ============================================================================

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
  | Error           -- IsError (the Go variant carries a Go `error` value; collapsed here)
  | Unevaluatable   -- IsUnevaluatable (zero value)
  deriving DecidableEq, Repr

/-- Mirrors Go's `Condition` interface (conditions.go:418-455). Optional Go fields
    (`GetType`, `GetDescription`, `GetCondition`, `DeepCopy`) are collapsed; what
    matters for `Evaluate`'s semantics is `id`, `effect`, and the per-data evaluator. -/
structure Condition where
  id       : String
  effect   : ConditionEffect
  evaluate : ConditionsData → ConditionEvaluationResult

/-- Mirrors Go's `ConditionsMap` (conditions.go:348-358). Three lists, one per effect. -/
structure ConditionsMap where
  denyConditions      : List Condition
  noOpinionConditions : List Condition
  allowConditions     : List Condition

/-- The four possible outcomes of `Evaluate`: a final `Decision`, or a partially-evaluated
    `ConditionsMap` (Go returns this as a `ConditionsAwareDecision` carrying a refined
    `ConditionsMap`). -/
inductive EvaluateResult where
  | Allow
  | Deny
  | NoOpinion
  | Refined (refined : ConditionsMap)

-- ============================================================================
-- Methods (faithful to Go)
-- ============================================================================

/-- Mirrors Go `ConditionsMap.Length` (conditions.go:458-460). -/
def ConditionsMap.Length (c : ConditionsMap) : Nat :=
  c.denyConditions.length + c.noOpinionConditions.length + c.allowConditions.length

/-- Mirrors Go `ConditionsMap.Conditions` (conditions.go:471-489). Order: deny, then
    noOpinion, then allow. -/
def ConditionsMap.Conditions (c : ConditionsMap) : List Condition :=
  c.denyConditions ++ c.noOpinionConditions ++ c.allowConditions

def ConditionsMap.DenyConditions      (c : ConditionsMap) : List Condition := c.denyConditions
def ConditionsMap.NoOpinionConditions (c : ConditionsMap) : List Condition := c.noOpinionConditions
def ConditionsMap.AllowConditions     (c : ConditionsMap) : List Condition := c.allowConditions

/-- Mirrors Go `ConditionsMap.FailClosedDecision` (conditions.go:364-371): scans
    `c.Conditions()` for a Deny-effect condition. Equivalent to checking the deny list. -/
def ConditionsMap.FailClosedDecision (c : ConditionsMap) : Decision :=
  if c.denyConditions.isEmpty then .NoOpinion else .Deny

/-- Mirrors Go `ConditionsMap.CanBecomeAllowed` (conditions.go:465-467). -/
def ConditionsMap.CanBecomeAllowed (c : ConditionsMap) : Bool :=
  !c.allowConditions.isEmpty

-- ============================================================================
-- evalPhase: split a condition list into True / Error / Unevaluatable buckets
-- ============================================================================

/-- Per-iteration outcome of evaluating one effect-class list, exposing the three buckets
    Go's phase loops track (`appliedXReasons`, `xErrors`, `unevaluatedXConditions`). The
    "False" bucket is implicit — those conditions are dropped because they don't affect
    the phase decision. -/
structure PhaseResult where
  trues       : List Condition
  errors      : List Condition
  unevaluated : List Condition

/-- Split `conds` into True/Error/Unevaluatable buckets per `evalCond`. Mirrors Go's
    inner loop body in each phase of `Evaluate`. -/
def evalPhase (conds : List Condition) (evalCond : Condition → ConditionEvaluationResult)
    : PhaseResult :=
  match conds with
  | [] => ⟨[], [], []⟩
  | c :: rest =>
    let restResult := evalPhase rest evalCond
    match evalCond c with
    | .True          => { restResult with trues       := c :: restResult.trues }
    | .Error         => { restResult with errors      := c :: restResult.errors }
    | .Unevaluatable => { restResult with unevaluated := c :: restResult.unevaluated }
    | .False         => restResult

-- ── evalPhase correctness lemmas ──────────────────────────────────────────────

/-- Every condition in the `trues` bucket has `evalCond` evaluating to `.True`. -/
theorem evalPhase_trues_mem
    (conds : List Condition) (evalCond : Condition → ConditionEvaluationResult)
    (c : Condition) (h : c ∈ (evalPhase conds evalCond).trues)
    : evalCond c = .True := by
  induction conds with
  | nil => simp [evalPhase] at h
  | cons hd rest ih =>
    unfold evalPhase at h
    cases hev : evalCond hd with
    | True =>
      simp [hev] at h
      rcases h with hc | hrest
      · subst hc; exact hev
      · exact ih hrest
    | False => simp [hev] at h; exact ih h
    | Error => simp [hev] at h; exact ih h
    | Unevaluatable => simp [hev] at h; exact ih h

/-- Every condition in the `errors` bucket has `evalCond` evaluating to `.Error`. -/
theorem evalPhase_errors_mem
    (conds : List Condition) (evalCond : Condition → ConditionEvaluationResult)
    (c : Condition) (h : c ∈ (evalPhase conds evalCond).errors)
    : evalCond c = .Error := by
  induction conds with
  | nil => simp [evalPhase] at h
  | cons hd rest ih =>
    unfold evalPhase at h
    cases hev : evalCond hd with
    | True => simp [hev] at h; exact ih h
    | False => simp [hev] at h; exact ih h
    | Error =>
      simp [hev] at h
      rcases h with hc | hrest
      · subst hc; exact hev
      · exact ih hrest
    | Unevaluatable => simp [hev] at h; exact ih h

/-- Every condition in the `unevaluated` bucket has `evalCond` evaluating to `.Unevaluatable`. -/
theorem evalPhase_unevaluated_mem
    (conds : List Condition) (evalCond : Condition → ConditionEvaluationResult)
    (c : Condition) (h : c ∈ (evalPhase conds evalCond).unevaluated)
    : evalCond c = .Unevaluatable := by
  induction conds with
  | nil => simp [evalPhase] at h
  | cons hd rest ih =>
    unfold evalPhase at h
    cases hev : evalCond hd with
    | True => simp [hev] at h; exact ih h
    | False => simp [hev] at h; exact ih h
    | Error => simp [hev] at h; exact ih h
    | Unevaluatable =>
      simp [hev] at h
      rcases h with hc | hrest
      · subst hc; exact hev
      · exact ih hrest

/-- The buckets only contain elements from the original list (`trues`). -/
theorem evalPhase_trues_subset
    (conds : List Condition) (evalCond : Condition → ConditionEvaluationResult)
    (c : Condition) (h : c ∈ (evalPhase conds evalCond).trues)
    : c ∈ conds := by
  induction conds with
  | nil => simp [evalPhase] at h
  | cons hd rest ih =>
    unfold evalPhase at h
    cases hev : evalCond hd with
    | True =>
      simp [hev] at h
      rcases h with hc | hrest
      · subst hc; exact List.mem_cons_self
      · exact List.mem_cons_of_mem hd (ih hrest)
    | False => simp [hev] at h; exact List.mem_cons_of_mem hd (ih h)
    | Error => simp [hev] at h; exact List.mem_cons_of_mem hd (ih h)
    | Unevaluatable => simp [hev] at h; exact List.mem_cons_of_mem hd (ih h)

/-- Analogue for `errors`. -/
theorem evalPhase_errors_subset
    (conds : List Condition) (evalCond : Condition → ConditionEvaluationResult)
    (c : Condition) (h : c ∈ (evalPhase conds evalCond).errors)
    : c ∈ conds := by
  induction conds with
  | nil => simp [evalPhase] at h
  | cons hd rest ih =>
    unfold evalPhase at h
    cases hev : evalCond hd with
    | True => simp [hev] at h; exact List.mem_cons_of_mem hd (ih h)
    | False => simp [hev] at h; exact List.mem_cons_of_mem hd (ih h)
    | Error =>
      simp [hev] at h
      rcases h with hc | hrest
      · subst hc; exact List.mem_cons_self
      · exact List.mem_cons_of_mem hd (ih hrest)
    | Unevaluatable => simp [hev] at h; exact List.mem_cons_of_mem hd (ih h)

/-- Analogue for `unevaluated`. -/
theorem evalPhase_unevaluated_subset
    (conds : List Condition) (evalCond : Condition → ConditionEvaluationResult)
    (c : Condition) (h : c ∈ (evalPhase conds evalCond).unevaluated)
    : c ∈ conds := by
  induction conds with
  | nil => simp [evalPhase] at h
  | cons hd rest ih =>
    unfold evalPhase at h
    cases hev : evalCond hd with
    | True => simp [hev] at h; exact List.mem_cons_of_mem hd (ih h)
    | False => simp [hev] at h; exact List.mem_cons_of_mem hd (ih h)
    | Error => simp [hev] at h; exact List.mem_cons_of_mem hd (ih h)
    | Unevaluatable =>
      simp [hev] at h
      rcases h with hc | hrest
      · subst hc; exact List.mem_cons_self
      · exact List.mem_cons_of_mem hd (ih hrest)

-- ============================================================================
-- Evaluate: faithful three-phase loop (Go conditions.go:700-870)
-- ============================================================================

/-- The `evalCond` closure Go's `Evaluate` constructs: try the condition's own evaluator
    first; if Unevaluatable and a fallback `evaluateFunc` was provided, defer to it. -/
def evalCondOf (cond : Condition) (data : ConditionsData)
    (evaluateFunc : Option (Condition → ConditionsData → ConditionEvaluationResult)) :
    ConditionEvaluationResult :=
  let primary := cond.evaluate data
  match evaluateFunc with
  | none => primary
  | some f =>
    match primary with
    | .Unevaluatable => f cond data
    | _              => primary

/-- Faithful transliteration of Go's `ConditionsMap.Evaluate` (conditions.go:700-870).
    Three nested phases: Deny → NoOpinion → Allow. Each phase splits its condition list
    into True / Error / Unevaluatable buckets and applies Go's branch order:

    1. **Deny phase**: any True ⇒ Deny; any Error (no True) ⇒ Deny (fail-closed); any
       Unevaluated (no True, no Error) ⇒ Refined (with unevaluated denies + full
       noOpinion + full allow); all False ⇒ continue.
    2. **NoOpinion phase**: any True ⇒ NoOpinion; any Error (no True) ⇒ NoOpinion; any
       Unevaluated (no True, no Error) ⇒ Refined if allows exist else NoOpinion;
       all False ⇒ continue.
    3. **Allow phase**: any True ⇒ Allow; any Error (no True) ⇒ NoOpinion; any
       Unevaluated (no True, no Error) ⇒ Refined (only unevaluated allows); all False ⇒
       NoOpinion (default).
-/
def ConditionsMap.Evaluate (c : ConditionsMap) (data : ConditionsData)
    (evaluateFunc : Option (Condition → ConditionsData → ConditionEvaluationResult) := none)
    : EvaluateResult :=
  let evalCond := fun cond => evalCondOf cond data evaluateFunc
  -- Phase 1: Deny
  if !c.denyConditions.isEmpty then
    let phase := evalPhase c.denyConditions evalCond
    if !phase.trues.isEmpty then .Deny
    else if !phase.errors.isEmpty then .Deny  -- fail-closed on error
    else if !phase.unevaluated.isEmpty then
      .Refined { denyConditions := phase.unevaluated
                 noOpinionConditions := c.noOpinionConditions
                 allowConditions := c.allowConditions }
    else noOpinionPhase evalCond
  else noOpinionPhase evalCond
where
  noOpinionPhase (evalCond : Condition → ConditionEvaluationResult) : EvaluateResult :=
    -- Phase 2: NoOpinion
    if !c.noOpinionConditions.isEmpty then
      let phase := evalPhase c.noOpinionConditions evalCond
      if !phase.trues.isEmpty then .NoOpinion
      else if !phase.errors.isEmpty then .NoOpinion
      else if !phase.unevaluated.isEmpty then
        if c.allowConditions.isEmpty then .NoOpinion
        else .Refined { denyConditions := []
                        noOpinionConditions := phase.unevaluated
                        allowConditions := c.allowConditions }
      else allowPhase evalCond
    else allowPhase evalCond
  allowPhase (evalCond : Condition → ConditionEvaluationResult) : EvaluateResult :=
    -- Phase 3: Allow
    if !c.allowConditions.isEmpty then
      let phase := evalPhase c.allowConditions evalCond
      if !phase.trues.isEmpty then .Allow
      else if !phase.errors.isEmpty then .NoOpinion  -- errors with no match ⇒ NoOpinion
      else if !phase.unevaluated.isEmpty then
        .Refined { denyConditions := []
                   noOpinionConditions := []
                   allowConditions := phase.unevaluated }
      else .NoOpinion  -- default: all conditions evaluated False
    else .NoOpinion  -- no allow conditions and got past Deny/NoOpinion ⇒ NoOpinion

-- ============================================================================
-- Soundness theorems
-- ============================================================================

/-- If `evalPhase`'s `trues` bucket is non-empty (Bool form, matching `split`'s output),
    then `conds` contains a condition that `evalCond` mapped to `.True`. -/
theorem evalPhase_trues_nonempty_witness
    (conds : List Condition) (evalCond : Condition → ConditionEvaluationResult)
    (h : (!(evalPhase conds evalCond).trues.isEmpty) = true)
    : ∃ c ∈ conds, evalCond c = .True := by
  match h_trues : (evalPhase conds evalCond).trues with
  | [] => rw [h_trues] at h; simp [List.isEmpty] at h
  | head :: _ =>
    have hmem : head ∈ (evalPhase conds evalCond).trues := by
      rw [h_trues]; exact List.mem_cons_self
    exact ⟨head, evalPhase_trues_subset conds evalCond head hmem,
                 evalPhase_trues_mem conds evalCond head hmem⟩

theorem evalPhase_errors_nonempty_witness
    (conds : List Condition) (evalCond : Condition → ConditionEvaluationResult)
    (h : (!(evalPhase conds evalCond).errors.isEmpty) = true)
    : ∃ c ∈ conds, evalCond c = .Error := by
  match h_errs : (evalPhase conds evalCond).errors with
  | [] => rw [h_errs] at h; simp [List.isEmpty] at h
  | head :: _ =>
    have hmem : head ∈ (evalPhase conds evalCond).errors := by
      rw [h_errs]; exact List.mem_cons_self
    exact ⟨head, evalPhase_errors_subset conds evalCond head hmem,
                 evalPhase_errors_mem conds evalCond head hmem⟩

theorem evalPhase_unevaluated_nonempty_witness
    (conds : List Condition) (evalCond : Condition → ConditionEvaluationResult)
    (h : (!(evalPhase conds evalCond).unevaluated.isEmpty) = true)
    : ∃ c ∈ conds, evalCond c = .Unevaluatable := by
  match h_un : (evalPhase conds evalCond).unevaluated with
  | [] => rw [h_un] at h; simp [List.isEmpty] at h
  | head :: _ =>
    have hmem : head ∈ (evalPhase conds evalCond).unevaluated := by
      rw [h_un]; exact List.mem_cons_self
    exact ⟨head, evalPhase_unevaluated_subset conds evalCond head hmem,
                 evalPhase_unevaluated_mem conds evalCond head hmem⟩

/-- **Allow soundness**: `Evaluate` returns `.Allow` only if some allow condition
    evaluated to `.True` for the given data (via `evalCondOf`). -/
theorem evaluate_Allow_implies_some_allow_True
    (c : ConditionsMap) (data : ConditionsData)
    (ef : Option (Condition → ConditionsData → ConditionEvaluationResult))
    (h : c.Evaluate data ef = .Allow)
    : ∃ cond ∈ c.allowConditions, evalCondOf cond data ef = .True := by
  -- Unfold Evaluate and chase through the phases; Allow can only be produced by
  -- the allow-phase True branch.
  unfold ConditionsMap.Evaluate at h
  simp only at h
  -- Phase 1 result feeds into NoOpinion phase
  split at h
  case isTrue hdenyNE =>
    -- The deny phase only produces Deny / Refined / fall-through to NoOpinionPhase.
    -- It never produces Allow, so the Allow must come from the fall-through.
    split at h
    · -- denyPhase.trues non-empty ⇒ .Deny ≠ .Allow
      exact absurd h ((by intro e; cases e))
    · split at h
      · exact absurd h ((by intro e; cases e))  -- .Deny ≠ .Allow
      · split at h
        · -- .Refined ≠ .Allow
          exact absurd h ((by intro e; cases e))
        · -- fall-through to noOpinionPhase
          exact noOpinionPhase_Allow_witness c data ef h
  case isFalse hdenyE =>
    -- No deny conditions ⇒ go directly to noOpinionPhase
    exact noOpinionPhase_Allow_witness c data ef h
where
  /-- Helper: if `noOpinionPhase` produced `.Allow`, then some allow condition was True. -/
  noOpinionPhase_Allow_witness
      (c : ConditionsMap) (data : ConditionsData)
      (ef : Option (Condition → ConditionsData → ConditionEvaluationResult))
      (h : ConditionsMap.Evaluate.noOpinionPhase c
            (fun cond => evalCondOf cond data ef) = .Allow)
      : ∃ cond ∈ c.allowConditions, evalCondOf cond data ef = .True := by
    unfold ConditionsMap.Evaluate.noOpinionPhase at h
    simp only at h
    split at h
    case isTrue hnoNE =>
      split at h
      · exact absurd h ((by intro e; cases e))  -- .NoOpinion ≠ .Allow
      · split at h
        · exact absurd h ((by intro e; cases e))
        · split at h
          · split at h
            · exact absurd h ((by intro e; cases e))
            · exact absurd h ((by intro e; cases e))
          · exact allowPhase_Allow_witness c data ef h
    case isFalse hnoE =>
      exact allowPhase_Allow_witness c data ef h
  /-- Helper: if `allowPhase` produced `.Allow`, then some allow condition was True. -/
  allowPhase_Allow_witness
      (c : ConditionsMap) (data : ConditionsData)
      (ef : Option (Condition → ConditionsData → ConditionEvaluationResult))
      (h : ConditionsMap.Evaluate.allowPhase c
            (fun cond => evalCondOf cond data ef) = .Allow)
      : ∃ cond ∈ c.allowConditions, evalCondOf cond data ef = .True := by
    unfold ConditionsMap.Evaluate.allowPhase at h
    simp only at h
    split at h
    case isTrue hallowNE =>
      split at h
      case isTrue hphaseTrues =>
        -- Allow phase emitted .Allow via the trues bucket ⇒ extract witness
        exact evalPhase_trues_nonempty_witness c.allowConditions
                (fun cond => evalCondOf cond data ef) hphaseTrues
      case isFalse _ =>
        split at h
        · exact absurd h ((by intro e; cases e))  -- .NoOpinion ≠ .Allow
        · split at h
          · exact absurd h ((by intro e; cases e))
          · exact absurd h ((by intro e; cases e))
    case isFalse _ =>
      exact absurd h ((by intro e; cases e))

/-- **Deny soundness**: `Evaluate` returns `.Deny` only if some deny condition evaluated
    to `.True` or `.Error` (fail-closed on error). -/
theorem evaluate_Deny_implies_some_deny_True_or_Error
    (c : ConditionsMap) (data : ConditionsData)
    (ef : Option (Condition → ConditionsData → ConditionEvaluationResult))
    (h : c.Evaluate data ef = .Deny)
    : ∃ cond ∈ c.denyConditions,
        evalCondOf cond data ef = .True ∨ evalCondOf cond data ef = .Error := by
  unfold ConditionsMap.Evaluate at h
  simp only at h
  split at h
  case isTrue hdenyNE =>
    split at h
    case isTrue hphaseTrues =>
      -- Deny via True in deny phase
      obtain ⟨cond, hmem, heval⟩ :=
        evalPhase_trues_nonempty_witness c.denyConditions
          (fun cond => evalCondOf cond data ef) hphaseTrues
      exact ⟨cond, hmem, .inl heval⟩
    case isFalse _ =>
      split at h
      case isTrue hphaseErrs =>
        obtain ⟨cond, hmem, heval⟩ :=
          evalPhase_errors_nonempty_witness c.denyConditions
            (fun cond => evalCondOf cond data ef) hphaseErrs
        exact ⟨cond, hmem, .inr heval⟩
      case isFalse _ =>
        split at h
        · -- .Refined ≠ .Deny
          exact absurd h ((by intro e; cases e))
        · exact (noOpinionPhase_not_Deny c data ef h).elim
  case isFalse hdenyE =>
    -- No deny conditions ⇒ noOpinionPhase. NoOpinionPhase doesn't produce Deny.
    exact (noOpinionPhase_not_Deny c data ef h).elim
where
  noOpinionPhase_not_Deny
      (c : ConditionsMap) (data : ConditionsData)
      (ef : Option (Condition → ConditionsData → ConditionEvaluationResult))
      (h : ConditionsMap.Evaluate.noOpinionPhase c
            (fun cond => evalCondOf cond data ef) = .Deny)
      : False := by
    unfold ConditionsMap.Evaluate.noOpinionPhase at h
    simp only at h
    split at h
    case isTrue hnoNE =>
      split at h
      · exact absurd h ((by intro e; cases e))  -- .NoOpinion ≠ .Deny
      · split at h
        · exact absurd h ((by intro e; cases e))
        · split at h
          · split at h
            · exact absurd h ((by intro e; cases e))
            · exact absurd h ((by intro e; cases e))
          · exact allowPhase_not_Deny c data ef h
    case isFalse _ =>
      exact allowPhase_not_Deny c data ef h
  allowPhase_not_Deny
      (c : ConditionsMap) (data : ConditionsData)
      (ef : Option (Condition → ConditionsData → ConditionEvaluationResult))
      (h : ConditionsMap.Evaluate.allowPhase c
            (fun cond => evalCondOf cond data ef) = .Deny)
      : False := by
    unfold ConditionsMap.Evaluate.allowPhase at h
    simp only at h
    split at h
    case isTrue _ =>
      split at h
      · exact absurd h ((by intro e; cases e))  -- .Allow ≠ .Deny
      · split at h
        · exact absurd h ((by intro e; cases e))  -- .NoOpinion ≠ .Deny
        · split at h
          · exact absurd h ((by intro e; cases e))
          · exact absurd h ((by intro e; cases e))
    case isFalse _ =>
      exact absurd h ((by intro e; cases e))

/-- **Refined soundness**: `Evaluate` returns `.Refined r` only if some condition in
    the original map was `.Unevaluatable` (via `evalCondOf`). -/
theorem evaluate_Refined_implies_some_unevaluated
    (c : ConditionsMap) (data : ConditionsData)
    (ef : Option (Condition → ConditionsData → ConditionEvaluationResult))
    (r : ConditionsMap) (h : c.Evaluate data ef = .Refined r)
    : ∃ cond ∈ c.Conditions, evalCondOf cond data ef = .Unevaluatable := by
  unfold ConditionsMap.Evaluate at h
  simp only at h
  split at h
  case isTrue hdenyNE =>
    split at h
    · exact absurd h ((by intro e; cases e))
    · split at h
      · exact absurd h ((by intro e; cases e))
      · split at h
        case isTrue hphaseUneval =>
          obtain ⟨cond, hmem, heval⟩ :=
            evalPhase_unevaluated_nonempty_witness c.denyConditions
              (fun cond => evalCondOf cond data ef) hphaseUneval
          refine ⟨cond, ?_, heval⟩
          simp [ConditionsMap.Conditions]
          exact .inl hmem
        case isFalse _ =>
          exact noOpinionPhase_Refined_witness c data ef r h
  case isFalse _ =>
    exact noOpinionPhase_Refined_witness c data ef r h
where
  noOpinionPhase_Refined_witness
      (c : ConditionsMap) (data : ConditionsData)
      (ef : Option (Condition → ConditionsData → ConditionEvaluationResult))
      (r : ConditionsMap)
      (h : ConditionsMap.Evaluate.noOpinionPhase c
            (fun cond => evalCondOf cond data ef) = .Refined r)
      : ∃ cond ∈ c.Conditions, evalCondOf cond data ef = .Unevaluatable := by
    unfold ConditionsMap.Evaluate.noOpinionPhase at h
    simp only at h
    split at h
    case isTrue _ =>
      split at h
      · exact absurd h ((by intro e; cases e))  -- .NoOpinion
      · split at h
        · exact absurd h ((by intro e; cases e))
        · split at h
          case isTrue hphaseUneval =>
            split at h
            · exact absurd h ((by intro e; cases e))
            · obtain ⟨cond, hmem, heval⟩ :=
                evalPhase_unevaluated_nonempty_witness c.noOpinionConditions
                  (fun cond => evalCondOf cond data ef) hphaseUneval
              refine ⟨cond, ?_, heval⟩
              simp [ConditionsMap.Conditions]
              exact .inr (.inl hmem)
          case isFalse _ =>
            exact allowPhase_Refined_witness c data ef r h
    case isFalse _ =>
      exact allowPhase_Refined_witness c data ef r h
  allowPhase_Refined_witness
      (c : ConditionsMap) (data : ConditionsData)
      (ef : Option (Condition → ConditionsData → ConditionEvaluationResult))
      (r : ConditionsMap)
      (h : ConditionsMap.Evaluate.allowPhase c
            (fun cond => evalCondOf cond data ef) = .Refined r)
      : ∃ cond ∈ c.Conditions, evalCondOf cond data ef = .Unevaluatable := by
    unfold ConditionsMap.Evaluate.allowPhase at h
    simp only at h
    split at h
    case isTrue _ =>
      split at h
      · exact absurd h ((by intro e; cases e))  -- .Allow
      · split at h
        · exact absurd h ((by intro e; cases e))  -- .NoOpinion
        · split at h
          case isTrue hphaseUneval =>
            obtain ⟨cond, hmem, heval⟩ :=
              evalPhase_unevaluated_nonempty_witness c.allowConditions
                (fun cond => evalCondOf cond data ef) hphaseUneval
            refine ⟨cond, ?_, heval⟩
            simp [ConditionsMap.Conditions]
            exact .inr (.inr hmem)
          case isFalse _ =>
            exact absurd h ((by intro e; cases e))
    case isFalse _ =>
      exact absurd h ((by intro e; cases e))

-- ============================================================================
-- Bonus invariants: lifted axioms from the abstracted ConditionsMap
-- ============================================================================

/-- If there are no allow conditions, `Evaluate` cannot return `.Allow`. (Matches the
    spirit of `ax_no_allow_cond_implies_never_allow` in `Authorizer.lean`, but here a
    *theorem*, not an axiom.) -/
theorem allowConditions_empty_implies_never_Allow
    (c : ConditionsMap) (h_empty : c.allowConditions = [])
    : ∀ (data : ConditionsData)
        (ef : Option (Condition → ConditionsData → ConditionEvaluationResult)),
      c.Evaluate data ef ≠ .Allow := by
  intro data ef hAllow
  obtain ⟨cond, hmem, _⟩ := evaluate_Allow_implies_some_allow_True c data ef hAllow
  rw [h_empty] at hmem
  exact List.not_mem_nil hmem

/-- If there are no deny conditions, `Evaluate` cannot return `.Deny`. -/
theorem denyConditions_empty_implies_never_Deny
    (c : ConditionsMap) (h_empty : c.denyConditions = [])
    : ∀ (data : ConditionsData)
        (ef : Option (Condition → ConditionsData → ConditionEvaluationResult)),
      c.Evaluate data ef ≠ .Deny := by
  intro data ef hDeny
  obtain ⟨cond, hmem, _⟩ := evaluate_Deny_implies_some_deny_True_or_Error c data ef hDeny
  rw [h_empty] at hmem
  exact List.not_mem_nil hmem

/-- `FailClosedDecision` is `.Deny` iff there is at least one deny condition. -/
theorem FailClosedDecision_eq_Deny_iff (c : ConditionsMap) :
    c.FailClosedDecision = .Deny ↔ c.denyConditions ≠ [] := by
  unfold ConditionsMap.FailClosedDecision
  constructor
  · intro h
    intro hempty
    rw [hempty] at h
    simp at h
  · intro hne
    have : ¬ c.denyConditions.isEmpty := by
      intro hempty
      apply hne
      exact List.isEmpty_iff.mp hempty
    simp [this]

/-- `FailClosedDecision` always yields `.Deny` or `.NoOpinion` — never `.Allow`. -/
theorem FailClosedDecision_AllowOrNoOpinion (c : ConditionsMap) :
    c.FailClosedDecision = .Deny ∨ c.FailClosedDecision = .NoOpinion := by
  unfold ConditionsMap.FailClosedDecision
  by_cases h : c.denyConditions.isEmpty
  · right; simp [h]
  · left; simp [h]

-- ============================================================================
-- Constructor: ConditionsAwareDecisionConditionsMap (conditions.go:533-635)
-- ============================================================================
--
-- Faithful to Go's constructor: validates IDs (uniqueness + non-empty for label-key
-- validity), enforces a maximum count (`MaxConditionsPerMap = 128`), dispatches by
-- effect, fails closed on errors (Deny if any deny effect was seen, otherwise NoOpinion),
-- handles the feature gate, and yields NoOpinion for an empty result.

/-- Maximum conditions per `ConditionsMap` (Go conditions.go:528-530). -/
def MaxConditionsPerMap : Nat := 128

/-- Possible outcomes of `ConditionsAwareDecisionConditionsMap`. Mirrors what Go's
    constructor can return: a final `Decision` (Deny/NoOpinion from fail-closed or
    feature gate paths) or a `Built` ConditionsMap. -/
inductive ConstructorResult where
  | Deny
  | NoOpinion
  | Built (cm : ConditionsMap)

/-- Builder state threaded through the constructor's loop. Mirrors Go's per-effect
    accumulator slices plus the `seenIDs` set and the error list. `hasDenyEffect` is
    *not* tracked inline here — it's computed in one pass at the call site. -/
structure BuilderState where
  denyConds      : List Condition
  noOpinionConds : List Condition
  allowConds     : List Condition
  seenIds        : List String
  errors         : List String   -- non-empty ⇒ fail-closed at the end

def BuilderState.empty : BuilderState :=
  ⟨[], [], [], [], []⟩

/-- Simplified label-key validation (Go uses `content.IsLabelKey`). We require non-empty;
    any further character-class restrictions are orthogonal to the constructor's logic. -/
def isValidLabelKey (s : String) : Bool := !s.isEmpty

/-- Process one condition, updating builder state per Go's loop body (conditions.go:552-598).
    Duplicate ID or invalid ID ⇒ record an error and skip dispatch. Otherwise dispatch
    by effect into the matching bucket. -/
def processCondition (state : BuilderState) (cond : Condition) : BuilderState :=
  if cond.id ∈ state.seenIds then
    { state with errors := s!"duplicate condition ID \"{cond.id}\"" :: state.errors }
  else if !isValidLabelKey cond.id then
    { state with errors := s!"invalid condition ID \"{cond.id}\"" :: state.errors,
                 seenIds := cond.id :: state.seenIds }
  else
    let state := { state with seenIds := cond.id :: state.seenIds }
    match cond.effect with
    | .Deny      => { state with denyConds      := state.denyConds      ++ [cond] }
    | .NoOpinion => { state with noOpinionConds := state.noOpinionConds ++ [cond] }
    | .Allow     => { state with allowConds     := state.allowConds     ++ [cond] }

/-- True iff some condition in the input has `effect = .Deny`. Mirrors Go's
    `hasDenyEffect` flag, computed in a single linear scan. -/
def listHasDenyEffect (conditions : List Condition) : Bool :=
  conditions.any (fun c => match c.effect with | .Deny => true | _ => false)

/-- Constructor mirroring Go's `ConditionsAwareDecisionConditionsMap` (conditions.go:533-635).

    Steps:
    1. If `conditions.length > MaxConditionsPerMap` ⇒ `.Deny` (fail-closed, too many).
    2. Process each condition via `processCondition`: dispatch by effect, accumulate
       error messages for duplicate or invalid IDs.
    3. If any errors: fail-closed (`.Deny` if any deny effect was seen, else `.NoOpinion`).
    4. If the resulting map would be empty: `.NoOpinion`.
    5. If `featureGateOn = false`: fail-closed as in step 3.
    6. Otherwise: `.Built` the ConditionsMap.
-/
def ConditionsAwareDecisionConditionsMap
    (conditions : List Condition) (featureGateOn : Bool := true) : ConstructorResult :=
  if conditions.length > MaxConditionsPerMap then .Deny
  else if !(conditions.foldl processCondition BuilderState.empty).errors.isEmpty then
    (if listHasDenyEffect conditions then .Deny else .NoOpinion)
  else if (conditions.foldl processCondition BuilderState.empty).denyConds.length +
          (conditions.foldl processCondition BuilderState.empty).noOpinionConds.length +
          (conditions.foldl processCondition BuilderState.empty).allowConds.length = 0 then
    .NoOpinion
  else if !featureGateOn then
    (if listHasDenyEffect conditions then .Deny else .NoOpinion)
  else
    .Built
      { denyConditions      := (conditions.foldl processCondition BuilderState.empty).denyConds
        noOpinionConditions :=
          (conditions.foldl processCondition BuilderState.empty).noOpinionConds
        allowConditions     :=
          (conditions.foldl processCondition BuilderState.empty).allowConds }

-- ============================================================================
-- Constructor invariants
-- ============================================================================

/-- The condition lists are built up monotonically — `processCondition` only *appends*
    to whichever bucket it touches, never removes. Useful for the per-bucket
    "every element has the right effect" theorems. -/
theorem processCondition_denyConds_mono (s : BuilderState) (cond : Condition) :
    ∃ extra, (processCondition s cond).denyConds = s.denyConds ++ extra ∧
             ∀ c ∈ extra, c.effect = .Deny := by
  unfold processCondition
  split
  · -- duplicate ID branch — no append
    exact ⟨[], by simp, by simp⟩
  · split
    · -- invalid ID branch — no append
      exact ⟨[], by simp, by simp⟩
    · -- valid ID, dispatch by effect
      cases hef : cond.effect with
      | Deny =>
        refine ⟨[cond], ?_, ?_⟩
        · simp [hef]
        · intro c hc
          simp at hc; rw [hc]; exact hef
      | NoOpinion =>
        exact ⟨[], by simp [hef], by simp⟩
      | Allow =>
        exact ⟨[], by simp [hef], by simp⟩

theorem processCondition_noOpinionConds_mono (s : BuilderState) (cond : Condition) :
    ∃ extra, (processCondition s cond).noOpinionConds = s.noOpinionConds ++ extra ∧
             ∀ c ∈ extra, c.effect = .NoOpinion := by
  unfold processCondition
  split
  · exact ⟨[], by simp, by simp⟩
  · split
    · exact ⟨[], by simp, by simp⟩
    · cases hef : cond.effect with
      | Deny => exact ⟨[], by simp [hef], by simp⟩
      | NoOpinion =>
        refine ⟨[cond], ?_, ?_⟩
        · simp [hef]
        · intro c hc; simp at hc; rw [hc]; exact hef
      | Allow => exact ⟨[], by simp [hef], by simp⟩

theorem processCondition_allowConds_mono (s : BuilderState) (cond : Condition) :
    ∃ extra, (processCondition s cond).allowConds = s.allowConds ++ extra ∧
             ∀ c ∈ extra, c.effect = .Allow := by
  unfold processCondition
  split
  · exact ⟨[], by simp, by simp⟩
  · split
    · exact ⟨[], by simp, by simp⟩
    · cases hef : cond.effect with
      | Deny => exact ⟨[], by simp [hef], by simp⟩
      | NoOpinion => exact ⟨[], by simp [hef], by simp⟩
      | Allow =>
        refine ⟨[cond], ?_, ?_⟩
        · simp [hef]
        · intro c hc; simp at hc; rw [hc]; exact hef

/-- Folding `processCondition` over a list preserves the per-bucket effect invariant:
    every condition in `denyConds` has effect `.Deny`. -/
theorem foldl_processCondition_deny_effect (conditions : List Condition)
    (s : BuilderState) (h_s : ∀ c ∈ s.denyConds, c.effect = .Deny) :
    ∀ c ∈ (conditions.foldl processCondition s).denyConds, c.effect = .Deny := by
  induction conditions generalizing s with
  | nil => simpa using h_s
  | cons hd rest ih =>
    apply ih
    intro c hc
    obtain ⟨extra, hext, hef⟩ := processCondition_denyConds_mono s hd
    rw [hext] at hc
    rcases List.mem_append.mp hc with hl | hr
    · exact h_s c hl
    · exact hef c hr

theorem foldl_processCondition_noOpinion_effect (conditions : List Condition)
    (s : BuilderState) (h_s : ∀ c ∈ s.noOpinionConds, c.effect = .NoOpinion) :
    ∀ c ∈ (conditions.foldl processCondition s).noOpinionConds, c.effect = .NoOpinion := by
  induction conditions generalizing s with
  | nil => simpa using h_s
  | cons hd rest ih =>
    apply ih
    intro c hc
    obtain ⟨extra, hext, hef⟩ := processCondition_noOpinionConds_mono s hd
    rw [hext] at hc
    rcases List.mem_append.mp hc with hl | hr
    · exact h_s c hl
    · exact hef c hr

theorem foldl_processCondition_allow_effect (conditions : List Condition)
    (s : BuilderState) (h_s : ∀ c ∈ s.allowConds, c.effect = .Allow) :
    ∀ c ∈ (conditions.foldl processCondition s).allowConds, c.effect = .Allow := by
  induction conditions generalizing s with
  | nil => simpa using h_s
  | cons hd rest ih =>
    apply ih
    intro c hc
    obtain ⟨extra, hext, hef⟩ := processCondition_allowConds_mono s hd
    rw [hext] at hc
    rcases List.mem_append.mp hc with hl | hr
    · exact h_s c hl
    · exact hef c hr

/-- Internal lemma: only the success branch of the constructor returns `.Built`. Returns
    the folded builder state's bucket lists matching `cm`'s, plus `length > 0`. -/
private theorem built_iff_success
    (conditions : List Condition) (featureGateOn : Bool) (cm : ConditionsMap)
    (h : ConditionsAwareDecisionConditionsMap conditions featureGateOn = .Built cm) :
    conditions.length ≤ MaxConditionsPerMap ∧
    cm.denyConditions = (conditions.foldl processCondition BuilderState.empty).denyConds ∧
    cm.noOpinionConditions =
      (conditions.foldl processCondition BuilderState.empty).noOpinionConds ∧
    cm.allowConditions = (conditions.foldl processCondition BuilderState.empty).allowConds ∧
    (conditions.foldl processCondition BuilderState.empty).denyConds.length +
      (conditions.foldl processCondition BuilderState.empty).noOpinionConds.length +
      (conditions.foldl processCondition BuilderState.empty).allowConds.length > 0 := by
  unfold ConditionsAwareDecisionConditionsMap at h
  -- Outer: if conditions.length > MaxConditionsPerMap
  split at h
  · cases h  -- .Deny
  -- !s.errors.isEmpty branch
  split at h
  · -- failClosed = if hasDeny then .Deny else .NoOpinion
    split at h <;> cases h
  -- total = 0 branch
  split at h
  · cases h  -- .NoOpinion
  -- !featureGateOn branch
  split at h
  · split at h <;> cases h  -- failClosed
  -- success branch
  rename_i hlen _ htotal _
  injection h with hcm
  refine ⟨Nat.le_of_not_gt hlen, ?_, ?_, ?_, Nat.pos_of_ne_zero htotal⟩
  · rw [← hcm]
  · rw [← hcm]
  · rw [← hcm]

/-- **Property 1**: every condition in the `denyConditions` bucket of a `Built` map has
    effect `.Deny`. -/
theorem built_deny_have_deny_effect
    (conditions : List Condition) (featureGateOn : Bool) (cm : ConditionsMap)
    (h : ConditionsAwareDecisionConditionsMap conditions featureGateOn = .Built cm) :
    ∀ c ∈ cm.denyConditions, c.effect = .Deny := by
  obtain ⟨_, hdeny, _, _, _⟩ := built_iff_success conditions featureGateOn cm h
  rw [hdeny]
  exact foldl_processCondition_deny_effect conditions BuilderState.empty
          (by simp [BuilderState.empty])

theorem built_noOpinion_have_noOpinion_effect
    (conditions : List Condition) (featureGateOn : Bool) (cm : ConditionsMap)
    (h : ConditionsAwareDecisionConditionsMap conditions featureGateOn = .Built cm) :
    ∀ c ∈ cm.noOpinionConditions, c.effect = .NoOpinion := by
  obtain ⟨_, _, hno, _, _⟩ := built_iff_success conditions featureGateOn cm h
  rw [hno]
  exact foldl_processCondition_noOpinion_effect conditions BuilderState.empty
          (by simp [BuilderState.empty])

theorem built_allow_have_allow_effect
    (conditions : List Condition) (featureGateOn : Bool) (cm : ConditionsMap)
    (h : ConditionsAwareDecisionConditionsMap conditions featureGateOn = .Built cm) :
    ∀ c ∈ cm.allowConditions, c.effect = .Allow := by
  obtain ⟨_, _, _, hallow, _⟩ := built_iff_success conditions featureGateOn cm h
  rw [hallow]
  exact foldl_processCondition_allow_effect conditions BuilderState.empty
          (by simp [BuilderState.empty])

/-- **Property 2 (non-empty)**: a `Built` ConditionsMap is non-empty (`Length > 0`).
    This is the Go invariant on conditions.go:349 ("when the decision is of type
    ConditionsMap, Length() != 0"). -/
theorem built_implies_length_positive
    (conditions : List Condition) (featureGateOn : Bool) (cm : ConditionsMap)
    (h : ConditionsAwareDecisionConditionsMap conditions featureGateOn = .Built cm) :
    cm.Length > 0 := by
  obtain ⟨_, hd, hno, ha, hpos⟩ := built_iff_success conditions featureGateOn cm h
  simp [ConditionsMap.Length, hd, hno, ha]
  omega

/-- Helper: each `processCondition` step grows the total bucket-length by at most 1. -/
private theorem foldl_processCondition_total_length_le
    (conditions : List Condition) (s : BuilderState) :
    (conditions.foldl processCondition s).denyConds.length +
    (conditions.foldl processCondition s).noOpinionConds.length +
    (conditions.foldl processCondition s).allowConds.length
    ≤ s.denyConds.length + s.noOpinionConds.length + s.allowConds.length
      + conditions.length := by
  induction conditions generalizing s with
  | nil => simp
  | cons hd rest ih =>
    simp only [List.foldl_cons, List.length_cons]
    have step :
        (processCondition s hd).denyConds.length +
        (processCondition s hd).noOpinionConds.length +
        (processCondition s hd).allowConds.length
        ≤ s.denyConds.length + s.noOpinionConds.length + s.allowConds.length + 1 := by
      unfold processCondition
      split
      · simp
      · split
        · simp
        · cases cond_eff : hd.effect <;> simp [cond_eff] <;> omega
    have := ih (processCondition s hd)
    omega

/-- **Property 3 (bounded)**: a `Built` ConditionsMap's `Length` is at most
    `MaxConditionsPerMap`. -/
theorem built_implies_length_bounded
    (conditions : List Condition) (featureGateOn : Bool) (cm : ConditionsMap)
    (h : ConditionsAwareDecisionConditionsMap conditions featureGateOn = .Built cm) :
    cm.Length ≤ MaxConditionsPerMap := by
  obtain ⟨hLen, hd, hno, ha, _⟩ := built_iff_success conditions featureGateOn cm h
  have hbound :
      (conditions.foldl processCondition BuilderState.empty).denyConds.length +
      (conditions.foldl processCondition BuilderState.empty).noOpinionConds.length +
      (conditions.foldl processCondition BuilderState.empty).allowConds.length ≤
      conditions.length := by
    have hb := foldl_processCondition_total_length_le conditions BuilderState.empty
    simp [BuilderState.empty] at hb
    exact hb
  simp [ConditionsMap.Length, hd, hno, ha]
  omega

-- ============================================================================
-- Property-based equivalence
-- ============================================================================

/-- If *every* condition in the map is evaluable (its `evalCondOf` never returns
    `.Unevaluatable`), then `Evaluate` cannot return `.Refined` — it must commit to one
    of `.Allow`, `.Deny`, or `.NoOpinion`. (Contrapositive of
    `evaluate_Refined_implies_some_unevaluated`.) -/
theorem all_evaluable_implies_no_Refined
    (c : ConditionsMap) (data : ConditionsData)
    (ef : Option (Condition → ConditionsData → ConditionEvaluationResult))
    (h : ∀ cond ∈ c.Conditions, evalCondOf cond data ef ≠ .Unevaluatable)
    : ∀ r, c.Evaluate data ef ≠ .Refined r := by
  intro r hRefined
  obtain ⟨cond, hmem, hUneval⟩ :=
    evaluate_Refined_implies_some_unevaluated c data ef r hRefined
  exact h cond hmem hUneval

/-- Companion statement: under full evaluability, `Evaluate` lands in `{.Allow, .Deny, .NoOpinion}`. -/
theorem all_evaluable_implies_final_decision
    (c : ConditionsMap) (data : ConditionsData)
    (ef : Option (Condition → ConditionsData → ConditionEvaluationResult))
    (h : ∀ cond ∈ c.Conditions, evalCondOf cond data ef ≠ .Unevaluatable)
    : c.Evaluate data ef = .Allow
    ∨ c.Evaluate data ef = .Deny
    ∨ c.Evaluate data ef = .NoOpinion := by
  cases hev : c.Evaluate data ef with
  | Allow => exact .inl rfl
  | Deny => exact .inr (.inl rfl)
  | NoOpinion => exact .inr (.inr rfl)
  | Refined r => exact absurd hev (all_evaluable_implies_no_Refined c data ef h r)

-- ============================================================================
-- Signature confirmations
-- ============================================================================

#check @ConditionsMap.Evaluate
#check (@evaluate_Allow_implies_some_allow_True)
#check (@evaluate_Deny_implies_some_deny_True_or_Error)
#check (@evaluate_Refined_implies_some_unevaluated)
#check (@allowConditions_empty_implies_never_Allow)
#check (@denyConditions_empty_implies_never_Deny)
#check @ConditionsAwareDecisionConditionsMap
#check (@built_implies_length_positive)
#check (@built_implies_length_bounded)
#check (@built_deny_have_deny_effect)
#check (@built_noOpinion_have_noOpinion_effect)
#check (@built_allow_have_allow_effect)
#check (@all_evaluable_implies_no_Refined)
#check (@all_evaluable_implies_final_decision)

end ConditionalAuthorization.ConditionsMapReal
