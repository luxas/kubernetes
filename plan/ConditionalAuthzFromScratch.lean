
namespace ConditionalAuthzFromScratch

-- ============================================================================
-- Types
-- ============================================================================

inductive Decision where
  | Deny | Allow | NoOpinion
  deriving Repr, DecidableEq, BEq

structure ConditionsMap where
  hasDenyCondition : Bool
  hasAllowCondition : Bool
  evaluate : Decision

  ax_at_least_one_allow_or_deny: hasDenyCondition = true ∨ hasAllowCondition = true
  ax_no_allow_cond_implies_never_allow : ¬hasAllowCondition → evaluate ≠ .Allow
  ax_no_deny_cond_implies_never_deny : ¬hasDenyCondition → evaluate ≠ .Deny
  deriving Repr, DecidableEq

def ConditionsMap.FailClosedDecision (c : ConditionsMap) : Decision :=
  if c.hasDenyCondition then .Deny else .NoOpinion

def ConditionsMap.CanBecomeAllowed (c : ConditionsMap) : Bool :=
  c.hasAllowCondition

def ConditionsMap.Ideal (c : ConditionsMap) : Decision :=
  c.evaluate

/-- A conditions-aware decision: either a leaf decision, or a union (chain) of decisions.
    Mirrors Go's `ConditionsAwareDecision`. -/
inductive ConditionsAwareDecision where
  | Allow
  | Deny
  | NoOpinion
  | ConditionsMap (cm: ConditionsMap)
  | Union (decisions : List ConditionsAwareDecision)
  deriving Repr

/-- Returns the decision to fail closed with when processing fails.
    If the decision contains any Deny (leaf or condition), we must fail closed with Deny —
    otherwise NoOpinion. -/
def ConditionsAwareDecision.FailClosedDecision : ConditionsAwareDecision → Decision
  | .Allow     => .NoOpinion
  | .NoOpinion => .NoOpinion
  | .Deny      => .Deny
  | .ConditionsMap c => c.FailClosedDecision
  | .Union authorizers => foldFailClosed authorizers
where
  foldFailClosed : List ConditionsAwareDecision → Decision
    | []      => .NoOpinion
    | d :: ds =>
      match d.FailClosedDecision with
      | .Deny => .Deny
      | _     => foldFailClosed ds

/-- Returns true if the decision tree contains at least one Allow or Deny leaf. -/
def ConditionsAwareDecision.ContainsAllowOrDeny : ConditionsAwareDecision → Bool
  | .Allow     => true
  | .Deny      => true
  | .NoOpinion => false
  | .ConditionsMap _ => false
  | .Union ds => anyContainsAllowOrDeny ds
where
  anyContainsAllowOrDeny : List ConditionsAwareDecision → Bool
    | []      => false
    | d :: ds => d.ContainsAllowOrDeny || anyContainsAllowOrDeny ds

/-- Returns true if there exists some ConditionsData for which the decision could evaluate to Allow. -/
def ConditionsAwareDecision.CanBecomeAllowed : ConditionsAwareDecision → Bool
  | .Allow     => true
  | .Deny      => false
  | .NoOpinion => false
  | .ConditionsMap c => c.CanBecomeAllowed
  | .Union ds => anyCanBecomeAllowed ds
where
  anyCanBecomeAllowed : List ConditionsAwareDecision → Bool
    | []      => false
    | d :: ds => d.CanBecomeAllowed || anyCanBecomeAllowed ds

def unionIdealAuthorize(decisions : List ConditionsAwareDecision) : Decision :=
  match decisions with
  | [] => .NoOpinion
  | d :: rest =>
    match d with
    | .Allow     => .Allow
    | .Deny      => .Deny
    | .NoOpinion => unionIdealAuthorize rest
    | .ConditionsMap cm => cm.Ideal
    | .Union subDecisions => unionIdealAuthorize subDecisions

/-- Returns the idealized unconditional decision from a Decision tree. -/
def ConditionsAwareDecision.Ideal : ConditionsAwareDecision → Decision
  | .Allow     => .Allow
  | .Deny      => .Deny
  | .NoOpinion => .NoOpinion
  | .ConditionsMap cm => cm.Ideal
  | .Union decisions => unionIdealAuthorize decisions

-- The axioms of the authorizer. The conditionsAwareAuthorize "controls" what authorize and evaluateConditions should return
def AuthorizerContract (conditionsAwareAuthorize : ConditionsAwareDecision)
    (authorize evaluateConditions : Decision) : Prop :=
  match conditionsAwareAuthorize with
  | .Allow     => authorize = .Allow ∧ evaluateConditions = .Deny
  | .Deny      => authorize = .Deny ∧ evaluateConditions = .Deny
  | .NoOpinion => authorize = .NoOpinion ∧ evaluateConditions = .Deny
  | .ConditionsMap _ | .Union _ =>
      evaluateConditions = conditionsAwareAuthorize.Ideal ∧
      match conditionsAwareAuthorize.FailClosedDecision with -- TODO: Theorem that says FailClosedDecision can never be false
      | .Deny => authorize = .Deny
      | _ => authorize = .NoOpinion

/-- An individual authorizer, with pre-bound attrs and data. -/
structure Authorizer where
  /-- The production Authorize(ctx, attrs) result — metadata-only, possibly fail-closed. -/
  authorize : Decision
  /-- The phase-1 result of ConditionsAwareAuthorize(ctx, attrs). -/
  conditionsAwareAuthorize : ConditionsAwareDecision
  /-- The phase-2 result of EvaluateConditions(ctx, decision, data). -/
  evaluateConditions : Decision

  /-- The per-authorizer coherence contract. -/
  ax_authorizer : AuthorizerContract conditionsAwareAuthorize authorize evaluateConditions

/-- The ideal result of an authorizer: what it would return with full information. -/
def Authorizer.idealAuthorize (a : Authorizer) : Decision :=
  a.conditionsAwareAuthorize.Ideal

-- ============================================================================
-- Transpiled: union.Authorize — metadata-only (union.go:46-70)
--
-- ```go
-- for _, curr := range authzHandler {
--     decision, _, _ := curr.Authorize(ctx, a)
--     switch decision {
--     case DecisionAllow, DecisionDeny: return decision, ...
--     case DecisionNoOpinion: // continue
--     }
-- }
-- return DecisionNoOpinion, ...
-- ```
-- ============================================================================

def unionAuthorize : List Authorizer → Decision
  | [] => .NoOpinion
  | h :: rest =>
    match h.authorize with
    | .Allow     => .Allow
    | .Deny      => .Deny
    | .NoOpinion => unionAuthorize rest

-- ============================================================================
-- Transpiled: union.ConditionsAwareAuthorize (union.go:73-96)
--
-- ```go
-- var decisions []ConditionsAwareDecision
-- for _, curr := range authzHandler {
--     decision := curr.ConditionsAwareAuthorize(ctx, a)
--     decisions = append(decisions, decision)
--     if decision.ContainsAllowOrDeny() { return DecisionUnion(decisions...) }
-- }
-- return DecisionUnion(decisions...)
-- ```
--
-- Returns the collected (authorizer, decision) entries. The decisions[i] ↔
-- authzHandler[i] index correlation is modelled as explicit pairing.
-- ============================================================================

def unionConditionsAwareAuthorize : List Authorizer → List (Authorizer × ConditionsAwareDecision)
  | [] => []
  | h :: rest =>
    let d := h.conditionsAwareAuthorize
    match d with
    | .Allow | .Deny => [(h, d)]  -- ContainsAllowOrDeny → short-circuit
    | .NoOpinion | .ConditionsMap _ => (h, d) :: unionConditionsAwareAuthorize rest
    | .Union _ => (h, d) :: unionConditionsAwareAuthorize rest  -- Union from individual authorizer treated like conditional

-- ============================================================================
-- Transpiled: union.EvaluateConditions (union.go:99-152)
--
-- ```go
-- for i, subD := range unionedDecisions {
--     if subD.IsAllowed() || subD.IsDenied() { return subD.UnconditionalParts() }
--     var decision Decision
--     if subD.IsNoOpinion() { decision = NoOpinion }
--     else { decision = authzHandler[i].EvaluateConditions(...) }
--     switch decision {
--     case Allow, Deny: return decision, ...
--     case NoOpinion: // continue
--     }
-- }
-- return NoOpinion, ...
-- ```
-- ============================================================================

def unionEvaluateConditions : List (Authorizer × ConditionsAwareDecision) → Decision
  | [] => .NoOpinion
  | (h, d) :: rest =>
    match d with
    | .Allow     => .Allow
    | .Deny      => .Deny
    | .NoOpinion => unionEvaluateConditions rest
    | .ConditionsMap _ | .Union _ =>
      -- decision = authzHandler[i].EvaluateConditions(ctx, subD, data)
      match h.evaluateConditions with
      | .Allow     => .Allow
      | .Deny      => .Deny
      | .NoOpinion => unionEvaluateConditions rest

-- ============================================================================
-- The ideal single-phase chain result
-- ============================================================================

def unionIdeal : List Authorizer → Decision
  | [] => .NoOpinion
  | h :: rest =>
    match h.idealAuthorize with
    | .Allow     => .Allow
    | .Deny      => .Deny
    | .NoOpinion => unionIdeal rest

-- ============================================================================
-- Proofs
-- ============================================================================

/-- Helper: extract the authorize and evaluateConditions from the contract
    for the ConditionsMap case. -/
private theorem contract_conditional (a : Authorizer) (cm : ConditionsMap)
    (hca : a.conditionsAwareAuthorize = .ConditionsMap cm)
    : a.evaluateConditions = cm.evaluate
    ∧ (cm.hasDenyCondition = true → a.authorize = .Deny)
    ∧ (cm.hasDenyCondition = false → a.authorize = .NoOpinion) := by
  have hc := a.ax_authorizer
  rw [hca] at hc
  simp [AuthorizerContract, ConditionsAwareDecision.Ideal, ConditionsMap.Ideal,
        ConditionsAwareDecision.FailClosedDecision, ConditionsMap.FailClosedDecision] at hc
  obtain ⟨heval, hmeta⟩ := hc
  constructor
  · exact heval
  · split at hmeta
    · exact ⟨fun _ => hmeta, fun h => by rename_i h'; simp_all⟩
    · exact ⟨fun h => by rename_i h'; simp_all, fun _ => hmeta⟩

/-- **Core lemma**: evaluating the union entries equals the ideal chain.
    union.go:111: "This logic directly maps 1:1 with Authorize()" -/
theorem evaluate_eq_ideal
    (handlers : List Authorizer)
    : unionEvaluateConditions (unionConditionsAwareAuthorize handlers)
    = unionIdeal handlers := by
  induction handlers with
  | nil => rfl
  | cons h rest ih =>
    simp only [unionIdeal, Authorizer.idealAuthorize]
    -- Show LHS = match h.conditionsAwareAuthorize.Ideal with ...
    show unionEvaluateConditions (unionConditionsAwareAuthorize (h :: rest))
       = match h.conditionsAwareAuthorize.Ideal with
         | .Allow => .Allow | .Deny => .Deny | .NoOpinion => unionIdeal rest
    cases hca : h.conditionsAwareAuthorize with
    | Allow =>
      simp [unionConditionsAwareAuthorize, hca, unionEvaluateConditions, ConditionsAwareDecision.Ideal]
    | Deny =>
      simp [unionConditionsAwareAuthorize, hca, unionEvaluateConditions, ConditionsAwareDecision.Ideal]
    | NoOpinion =>
      simp [unionConditionsAwareAuthorize, hca, unionEvaluateConditions, ConditionsAwareDecision.Ideal]
      exact ih
    | ConditionsMap cm =>
      have ⟨heval, _, _⟩ := contract_conditional h cm hca
      simp [unionConditionsAwareAuthorize, hca, unionEvaluateConditions,
            ConditionsAwareDecision.Ideal, ConditionsMap.Ideal, heval]
      cases cm.evaluate with
      | Allow     => rfl
      | Deny      => rfl
      | NoOpinion => exact ih
    | Union ds =>
      -- Individual authorizers returning Union is uncommon but handled for totality.
      -- The contract says evaluateConditions = Ideal(Union ds).
      have hc := h.ax_authorizer
      rw [hca] at hc
      simp [AuthorizerContract, ConditionsAwareDecision.Ideal] at hc
      obtain ⟨heval, _⟩ := hc
      simp [unionConditionsAwareAuthorize, hca, unionEvaluateConditions, ConditionsAwareDecision.Ideal, heval]
      cases unionIdealAuthorize ds with
      | Allow     => rfl
      | Deny      => rfl
      | NoOpinion => exact ih

mutual
/-- When `FailClosedDecision` does not produce Deny, `Ideal` also cannot produce Deny.
    Proved mutually with the list version (for Union's sub-decisions). -/
theorem failClosed_not_deny_implies_ideal_not_deny
    (d : ConditionsAwareDecision)
    (h : d.FailClosedDecision ≠ .Deny)
    : d.Ideal ≠ .Deny := by
  cases d with
  | Allow     => simp [ConditionsAwareDecision.Ideal]
  | Deny      => simp [ConditionsAwareDecision.FailClosedDecision] at h
  | NoOpinion => simp [ConditionsAwareDecision.Ideal]
  | ConditionsMap cm =>
    simp [ConditionsAwareDecision.FailClosedDecision, ConditionsMap.FailClosedDecision,
          ConditionsAwareDecision.Ideal, ConditionsMap.Ideal] at h ⊢
    cases hdeny : cm.hasDenyCondition with
    | true => simp [hdeny] at h
    | false => exact cm.ax_no_deny_cond_implies_never_deny (by simp [hdeny])
  | Union ds =>
    simp [ConditionsAwareDecision.FailClosedDecision, ConditionsAwareDecision.Ideal] at h ⊢
    exact foldFailClosed_not_deny_implies_ideal_not_deny ds h

theorem foldFailClosed_not_deny_implies_ideal_not_deny
    (ds : List ConditionsAwareDecision)
    (h : ConditionsAwareDecision.FailClosedDecision.foldFailClosed ds ≠ .Deny)
    : unionIdealAuthorize ds ≠ .Deny := by
  match ds with
  | [] => simp [unionIdealAuthorize]
  | d :: rest =>
    unfold unionIdealAuthorize
    unfold ConditionsAwareDecision.FailClosedDecision.foldFailClosed at h
    match hd : d with
    | .Allow => simp
    | .Deny => simp [ConditionsAwareDecision.FailClosedDecision] at h
    | .NoOpinion =>
      simp [ConditionsAwareDecision.FailClosedDecision] at h
      exact foldFailClosed_not_deny_implies_ideal_not_deny rest h
    | .ConditionsMap cm =>
      simp only [ConditionsMap.Ideal]
      cases hdeny : cm.hasDenyCondition with
      | true =>
        simp [ConditionsAwareDecision.FailClosedDecision, ConditionsMap.FailClosedDecision, hdeny] at h
      | false =>
        exact cm.ax_no_deny_cond_implies_never_deny (by simp [hdeny])
    | .Union subDs =>
      have h_fc : (ConditionsAwareDecision.Union subDs).FailClosedDecision ≠ .Deny := by
        simp [ConditionsAwareDecision.FailClosedDecision] at h ⊢
        intro hfold; simp [hfold] at h
      have := failClosed_not_deny_implies_ideal_not_deny (.Union subDs) h_fc
      simp [ConditionsAwareDecision.Ideal] at this
      exact this
end

/-- **Safety**: if metadata-only Authorize allows, ideal also allows.
    The metadata path never grants unauthorized access. -/
theorem metadata_allow_implies_ideal_allow
    (handlers : List Authorizer)
    : unionAuthorize handlers = .Allow →
      unionIdeal handlers = .Allow := by
  induction handlers with
  | nil => simp [unionAuthorize]
  | cons h rest ih =>
    simp only [unionAuthorize, unionIdeal, Authorizer.idealAuthorize]
    cases hca : h.conditionsAwareAuthorize with
    | Allow =>
      have hc := h.ax_authorizer; rw [hca] at hc
      simp [AuthorizerContract] at hc
      simp [hc.1, ConditionsAwareDecision.Ideal]
    | Deny =>
      have hc := h.ax_authorizer; rw [hca] at hc
      simp [AuthorizerContract] at hc
      simp [hc.1]
    | NoOpinion =>
      have hc := h.ax_authorizer; rw [hca] at hc
      simp [AuthorizerContract] at hc
      simp [hc.1, ConditionsAwareDecision.Ideal]
      exact ih
    | ConditionsMap cm =>
      have ⟨_, h_deny, h_nodeny⟩ := contract_conditional h cm hca
      simp [ConditionsAwareDecision.Ideal, ConditionsMap.Ideal]
      cases hdeny : cm.hasDenyCondition with
      | true =>
        -- authorize = Deny → metadata path returns Deny, can't be Allow
        simp [h_deny hdeny]
      | false =>
        -- authorize = NoOpinion → metadata path recurses
        simp [h_nodeny hdeny]
        -- Goal: unionAuthorize rest = Allow → match cm.evaluate with ... = Allow
        intro hrest_allow
        have hrest_ideal := ih hrest_allow
        cases heval : cm.evaluate with
        | Allow     => rfl
        | Deny      => exact absurd heval (cm.ax_no_deny_cond_implies_never_deny (by simp [hdeny]))
        | NoOpinion => exact hrest_ideal
    | Union ds =>
      have hc := h.ax_authorizer; rw [hca] at hc
      simp [AuthorizerContract, ConditionsAwareDecision.FailClosedDecision, ConditionsAwareDecision.Ideal] at hc
      obtain ⟨_, hmeta⟩ := hc
      simp [ConditionsAwareDecision.Ideal]
      -- metadata is either Deny or NoOpinion (from FailClosedDecision)
      split at hmeta
      · -- FailClosed = Deny → authorize = Deny → can't be Allow
        simp [hmeta]
      · -- FailClosed ≠ Deny → authorize = NoOpinion → recurse
        simp [hmeta]
        intro hrest_allow
        have hrest_ideal := ih hrest_allow
        -- h_not_deny is in scope from `split at hmeta` (the non-Deny branch).
        -- We need to find it among the renamed hypotheses.
        cases heval : unionIdealAuthorize ds with
        | Allow     => rfl
        | Deny      =>
          -- FailClosedDecision(Union ds) ≠ Deny → Ideal(Union ds) ≠ Deny → contradiction with heval
          exfalso
          have h_fc : (ConditionsAwareDecision.Union ds).FailClosedDecision ≠ .Deny := by
            simp [ConditionsAwareDecision.FailClosedDecision]
            -- The split at hmeta gave us the non-Deny branch hypothesis
            assumption
          have := failClosed_not_deny_implies_ideal_not_deny (.Union ds) h_fc
          simp [ConditionsAwareDecision.Ideal, heval] at this
        | NoOpinion => exact hrest_ideal
