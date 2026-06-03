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
-- Signature confirmations
-- ============================================================================

#check @ConditionsMap.Evaluate
#check (@evaluate_Allow_implies_some_allow_True)
#check (@evaluate_Deny_implies_some_deny_True_or_Error)
#check (@evaluate_Refined_implies_some_unevaluated)
#check (@allowConditions_empty_implies_never_Allow)
#check (@denyConditions_empty_implies_never_Deny)

end ConditionalAuthorization.ConditionsMapReal
