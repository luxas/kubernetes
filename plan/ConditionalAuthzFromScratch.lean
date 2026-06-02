
namespace ConditionalAuthzFromScratch

-- ============================================================================
-- Types
-- ============================================================================

inductive Decision where
  | Deny | Allow | NoOpinion
  deriving Repr, DecidableEq, BEq

structure ConditionsData where
  object: String
  oldObject: String

structure ConditionsMap where
  hasDenyCondition : Bool
  hasAllowCondition : Bool
  evaluate : Decision -- Data -> Allow/Deny/NoOpinion

  -- condition: Data -> bool
  -- allowConditions: List Condition
  -- denyConditions: List Condition
  -- noOpinionConditions: List Condition

  -- TODO: externalize this
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
    | .ConditionsMap cm =>
      match cm.Ideal with
      | .Allow => .Allow
      | .Deny => .Deny
      | .NoOpinion => unionIdealAuthorize rest
    | .Union subDecisions =>
      match unionIdealAuthorize subDecisions with
      | .Allow => .Allow
      | .Deny => .Deny
      | .NoOpinion => unionIdealAuthorize rest

/-- Returns the idealized unconditional decision from a Decision tree.
  Ideal:
  Authorize : InternalState x Attributes x ConditionsData -> Decision

  Practical:
  ConditionalAuthorize : InternalState x Attributes -> ConditionsAwareDecision
  EvaluateConditions : ConditionsAwareDecision x ConditionsData -> Decision
-/
def ConditionsAwareDecision.Ideal : ConditionsAwareDecision → Decision
  | .Allow     => .Allow
  | .Deny      => .Deny
  | .NoOpinion => .NoOpinion
  | .ConditionsMap cm => cm.Ideal
  | .Union decisions => unionIdealAuthorize decisions

-- The axioms of the authorizer. The conditionsAwareAuthorize "controls" what authorize and evaluateConditions should return
-- inductive definition instead? hypothesis and split the cases
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
  /-- The production Authorize(ctx, attrs) result — metadata-only, possibly fail-closed.
    AuthorizeMetadata: InternalState x Attributes -> Decision
  -/
  authorize : Decision
  /-- The phase-1 result of ConditionsAwareAuthorize(ctx, attrs).
    ConditionsAwareAuthorize: InternalState x Attributes -> ConditionsAwareDecision
  -/
  conditionsAwareAuthorize : ConditionsAwareDecision
  /-- The phase-2 result of EvaluateConditions(ctx, decision, data).
    EvaluateConditions: ConditionsAwareDecision x ConditionsData -> Decision
  -/
  evaluateConditions : Decision

  /-- The per-authorizer coherence contract. -/
  ax_authorizer : AuthorizerContract conditionsAwareAuthorize authorize evaluateConditions

/-- The ideal result of an authorizer: what it would return with full information. -/
def Authorizer.idealAuthorize (a : Authorizer) : Decision :=
  a.conditionsAwareAuthorize.Ideal

-- theorem: all authorizers in a List are authorizers -> AuthorizerContract mkUnionAuthorizer
-- allows ignoring local errors when properties are not needed
-- e.g. ignore well-formed set behaviors

-- def mkUnionAuthorizer (authorizers: List Authorizer): Authorizer :=
--   TODO

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
    have h_d : d.FailClosedDecision ≠ .Deny := by
      intro hd; apply h; simp [ConditionsAwareDecision.FailClosedDecision.foldFailClosed, hd]
    have h_rest : ConditionsAwareDecision.FailClosedDecision.foldFailClosed rest ≠ .Deny := by
      intro hr; apply h
      unfold ConditionsAwareDecision.FailClosedDecision.foldFailClosed
      split
      · rfl
      · exact hr
    match d with
    | .Allow => simp [unionIdealAuthorize]
    | .Deny =>
      exfalso; exact h_d (by simp [ConditionsAwareDecision.FailClosedDecision])
    | .NoOpinion =>
      simp only [unionIdealAuthorize]
      exact foldFailClosed_not_deny_implies_ideal_not_deny rest h_rest
    | .ConditionsMap cm =>
      simp only [unionIdealAuthorize, ConditionsMap.Ideal]
      have h_not_deny : cm.evaluate ≠ .Deny := by
        apply cm.ax_no_deny_cond_implies_never_deny
        intro h_deny
        exact h_d (by simp [ConditionsAwareDecision.FailClosedDecision, ConditionsMap.FailClosedDecision, h_deny])
      split
      next => simp
      next h_eq => exact absurd h_eq h_not_deny
      next => exact foldFailClosed_not_deny_implies_ideal_not_deny rest h_rest
    | .Union subDs =>
      simp only [unionIdealAuthorize]
      have h_ideal := failClosed_not_deny_implies_ideal_not_deny (.Union subDs) h_d
      simp [ConditionsAwareDecision.Ideal] at h_ideal
      split
      next => simp
      next h_eq => exact absurd h_eq h_ideal
      next => exact foldFailClosed_not_deny_implies_ideal_not_deny rest h_rest
end

/-- **Invariant**: `ConditionsMap.FailClosedDecision` is always `Deny` or `NoOpinion`. -/
theorem conditionsMap_failClosed_deny_or_noOpinion (c : ConditionsMap)
    : c.FailClosedDecision = .Deny ∨ c.FailClosedDecision = .NoOpinion := by
  unfold ConditionsMap.FailClosedDecision
  cases c.hasDenyCondition <;> simp

mutual
/-- **Invariant**: `ConditionsAwareDecision.FailClosedDecision` is always `Deny` or `NoOpinion`,
    never `Allow`. The metadata-only / fail-closed path can deny or abstain but never grants access. -/
theorem failClosed_deny_or_noOpinion (d : ConditionsAwareDecision)
    : d.FailClosedDecision = .Deny ∨ d.FailClosedDecision = .NoOpinion := by
  cases d with
  | Allow => right; rfl
  | Deny => left; rfl
  | NoOpinion => right; rfl
  | ConditionsMap c =>
    simp only [ConditionsAwareDecision.FailClosedDecision]
    exact conditionsMap_failClosed_deny_or_noOpinion c
  | Union ds =>
    simp only [ConditionsAwareDecision.FailClosedDecision]
    exact foldFailClosed_deny_or_noOpinion ds

theorem foldFailClosed_deny_or_noOpinion (ds : List ConditionsAwareDecision)
    : ConditionsAwareDecision.FailClosedDecision.foldFailClosed ds = .Deny
    ∨ ConditionsAwareDecision.FailClosedDecision.foldFailClosed ds = .NoOpinion := by
  match ds with
  | [] => right; rfl
  | d :: rest =>
    unfold ConditionsAwareDecision.FailClosedDecision.foldFailClosed
    split
    · left; rfl
    · exact foldFailClosed_deny_or_noOpinion rest
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

-- add theorems for the intermediate result as well
-- make sure that can become allowed stuff is sound

-- ============================================================================
-- Constructing the union as an Authorizer instance
-- ============================================================================

/-- When no sub-handler's conditionsAwareAuthorize is Allow or Deny,
    unionAuthorize can only return Deny or NoOpinion (never Allow).
    This is because each sub-handler's `authorize` is Deny or NoOpinion
    by their individual contracts. -/
theorem unionAuthorize_no_allow_when_no_unconditional
    (handlers : List Authorizer)
    (h : ∀ a ∈ handlers,
      a.conditionsAwareAuthorize ≠ .Allow ∧ a.conditionsAwareAuthorize ≠ .Deny)
    : unionAuthorize handlers ≠ .Allow := by
  induction handlers with
  | nil => simp [unionAuthorize]
  | cons a rest ih =>
    simp only [unionAuthorize]
    have hab := h a (by simp)
    have ih' := ih (fun a' ha' => h a' (by simp [ha']))
    have hc := a.ax_authorizer
    -- a.conditionsAwareAuthorize is not Allow or Deny, so by contract
    -- a.authorize is Deny or NoOpinion
    cases hca : a.conditionsAwareAuthorize with
    | Allow => exact absurd hca hab.1
    | Deny => exact absurd hca hab.2
    | NoOpinion =>
      rw [hca] at hc; simp [AuthorizerContract] at hc
      simp [hc.1]; exact ih'
    | ConditionsMap cm =>
      rw [hca] at hc
      simp [AuthorizerContract, ConditionsAwareDecision.FailClosedDecision,
            ConditionsMap.FailClosedDecision] at hc
      obtain ⟨_, hmeta⟩ := hc
      split at hmeta
      · simp [hmeta]
      · simp [hmeta]; exact ih'
    | Union ds =>
      rw [hca] at hc
      simp [AuthorizerContract, ConditionsAwareDecision.FailClosedDecision] at hc
      obtain ⟨_, hmeta⟩ := hc
      split at hmeta
      · simp [hmeta]
      · simp [hmeta]; exact ih'

end ConditionalAuthzFromScratch
