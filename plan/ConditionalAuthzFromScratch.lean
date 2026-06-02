
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
      (authorize = .Allow → conditionsAwareAuthorize.Ideal = .Allow) ∧
      (conditionsAwareAuthorize.Ideal = .Deny → authorize = .Deny)

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

-- ============================================================================
-- Proofs
-- ============================================================================

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

-- ============================================================================
-- Go-transliterated standalone functions
-- ============================================================================

/-- Transliteration of Go's `unionAuthzHandler.Authorize` (union.go:46-70).
    Short-circuits on Allow or Deny. -/
def unionAuthorize : List Authorizer → Decision
  | [] => .NoOpinion
  | h :: rest =>
    match h.authorize with
    | .Allow => .Allow
    | .Deny => .Deny
    | .NoOpinion => unionAuthorize rest

/-- Transliteration of Go's `ConditionsAwareAuthorize` loop body (union.go:73-96).
    Collects (authorizer, decision) pairs, short-circuiting when a decision
    contains an unconditional Allow or Deny. -/
def collectEntries : List Authorizer → List (Authorizer × ConditionsAwareDecision)
  | [] => []
  | h :: rest =>
    let d := h.conditionsAwareAuthorize
    match d with
    | .Allow | .Deny => [(h, d)]
    | _ => (h, d) :: collectEntries rest

/-- Transliteration of Go's `unionAuthzHandler.EvaluateConditions` (union.go:98-152).
    Walks paired entries: leaf Allow/Deny short-circuit, NoOpinion skips,
    conditional delegates to the sub-authorizer's evaluateConditions. -/
def unionEvaluateConditions : List (Authorizer × ConditionsAwareDecision) → Decision
  | [] => .NoOpinion
  | (h, d) :: rest =>
    match d with
    | .Allow => .Allow
    | .Deny => .Deny
    | .NoOpinion => unionEvaluateConditions rest
    | .ConditionsMap _ | .Union _ =>
      match h.evaluateConditions with
      | .Allow => .Allow
      | .Deny => .Deny
      | .NoOpinion => unionEvaluateConditions rest

/-- The ideal (specification) chain: what each authorizer would return
    with full information. This is the claim, not part of any implementation. -/
def unionIdeal : List Authorizer → Decision
  | [] => .NoOpinion
  | h :: rest =>
    match h.idealAuthorize with
    | .Allow => .Allow
    | .Deny => .Deny
    | .NoOpinion => unionIdeal rest

-- ============================================================================
-- UnionAuthorizer structure (Go-transliterated)
-- ============================================================================

structure UnionAuthorizer where
  handlers : List Authorizer

namespace UnionAuthorizer

def entries (u : UnionAuthorizer) := collectEntries u.handlers

def authorize (u : UnionAuthorizer) : Decision :=
  unionAuthorize u.handlers

def conditionsAwareAuthorize (u : UnionAuthorizer) : ConditionsAwareDecision :=
  .Union (u.entries.map Prod.snd)

def evaluateConditions (u : UnionAuthorizer) : Decision :=
  unionEvaluateConditions u.entries

end UnionAuthorizer

-- ============================================================================
-- Per-authorizer lemmas from contract
-- ============================================================================

theorem Authorizer.authorize_allow_implies_ideal_allow (a : Authorizer)
    (h : a.authorize = .Allow) : a.idealAuthorize = .Allow := by
  have hax := a.ax_authorizer
  unfold AuthorizerContract at hax
  cases hca : a.conditionsAwareAuthorize with
  | Allow => simp [Authorizer.idealAuthorize, hca, ConditionsAwareDecision.Ideal]
  | Deny => rw [hca] at hax; rw [hax.1] at h; contradiction
  | NoOpinion => rw [hca] at hax; rw [hax.1] at h; contradiction
  | ConditionsMap _ =>
    rw [hca] at hax; simp only [Authorizer.idealAuthorize, hca]; exact hax.2.1 h
  | Union _ =>
    rw [hca] at hax; simp only [Authorizer.idealAuthorize, hca]; exact hax.2.1 h

theorem Authorizer.ideal_deny_implies_authorize_deny (a : Authorizer)
    (h : a.idealAuthorize = .Deny) : a.authorize = .Deny := by
  have hax := a.ax_authorizer
  unfold AuthorizerContract at hax
  cases hca : a.conditionsAwareAuthorize with
  | Allow => simp [Authorizer.idealAuthorize, hca, ConditionsAwareDecision.Ideal] at h
  | Deny => rw [hca] at hax; exact hax.1
  | NoOpinion => simp [Authorizer.idealAuthorize, hca, ConditionsAwareDecision.Ideal] at h
  | ConditionsMap _ =>
    rw [hca] at hax; simp only [Authorizer.idealAuthorize, hca] at h; exact hax.2.2 h
  | Union _ =>
    rw [hca] at hax; simp only [Authorizer.idealAuthorize, hca] at h; exact hax.2.2 h

theorem Authorizer.contract_eval_eq_ideal (a : Authorizer)
    (hc : (∃ cm, a.conditionsAwareAuthorize = .ConditionsMap cm) ∨
          (∃ ds, a.conditionsAwareAuthorize = .Union ds))
    : a.evaluateConditions = a.conditionsAwareAuthorize.Ideal := by
  have hax := a.ax_authorizer
  unfold AuthorizerContract at hax
  rcases hc with ⟨cm, h⟩ | ⟨ds, h⟩ <;> { rw [h] at hax ⊢; exact hax.1 }

-- ============================================================================
-- Key lemmas
-- ============================================================================

/-- The core equivalence: unionEvaluateConditions on collected entries
    equals unionIdeal on the original handlers. -/
theorem evaluate_eq_ideal (handlers : List Authorizer)
    : unionEvaluateConditions (collectEntries handlers) = unionIdeal handlers := by
  induction handlers with
  | nil => rfl
  | cons h rest ih =>
    cases hca : h.conditionsAwareAuthorize with
    | Allow =>
      simp [collectEntries, hca, unionEvaluateConditions, unionIdeal,
            Authorizer.idealAuthorize, ConditionsAwareDecision.Ideal]
    | Deny =>
      simp [collectEntries, hca, unionEvaluateConditions, unionIdeal,
            Authorizer.idealAuthorize, ConditionsAwareDecision.Ideal]
    | NoOpinion =>
      simp only [collectEntries, hca, unionEvaluateConditions, unionIdeal,
                 Authorizer.idealAuthorize, ConditionsAwareDecision.Ideal]
      exact ih
    | ConditionsMap cm =>
      have heval := h.contract_eval_eq_ideal (Or.inl ⟨cm, hca⟩)
      rw [hca] at heval
      simp only [ConditionsAwareDecision.Ideal, ConditionsMap.Ideal] at heval
      simp only [collectEntries, hca, unionEvaluateConditions, unionIdeal,
                 Authorizer.idealAuthorize, ConditionsAwareDecision.Ideal,
                 ConditionsMap.Ideal, heval]
      split <;> first | rfl | exact ih
    | Union ds =>
      have heval := h.contract_eval_eq_ideal (Or.inr ⟨ds, hca⟩)
      rw [hca] at heval
      simp only [ConditionsAwareDecision.Ideal] at heval
      simp only [collectEntries, hca, unionEvaluateConditions, unionIdeal,
                 Authorizer.idealAuthorize, ConditionsAwareDecision.Ideal, heval]
      split <;> first | rfl | exact ih

/-- If unionAuthorize returns Allow, then unionIdeal also returns Allow. -/
theorem metadata_allow_implies_ideal_allow (handlers : List Authorizer)
    (h : unionAuthorize handlers = .Allow)
    : unionIdeal handlers = .Allow := by
  induction handlers with
  | nil => simp [unionAuthorize] at h
  | cons hd rest ih =>
    cases hauth : hd.authorize with
    | Allow =>
      have hideal := hd.authorize_allow_implies_ideal_allow hauth
      simp [unionIdeal, hideal]
    | Deny => simp [unionAuthorize, hauth] at h
    | NoOpinion =>
      simp [unionAuthorize, hauth] at h
      cases hid : hd.idealAuthorize with
      | Allow => simp [unionIdeal, hid]
      | Deny =>
        have := hd.ideal_deny_implies_authorize_deny hid
        rw [hauth] at this; exact absurd this (by decide)
      | NoOpinion => simp only [unionIdeal, hid]; exact ih h

/-- If unionIdeal returns Deny, then unionAuthorize also returns Deny. -/
theorem ideal_deny_implies_authorize_deny (handlers : List Authorizer)
    (h : unionIdeal handlers = .Deny)
    : unionAuthorize handlers = .Deny := by
  induction handlers with
  | nil => simp [unionIdeal] at h
  | cons hd rest ih =>
    cases hid : hd.idealAuthorize with
    | Allow => simp [unionIdeal, hid] at h
    | Deny =>
      simp [unionAuthorize, hd.ideal_deny_implies_authorize_deny hid]
    | NoOpinion =>
      simp [unionIdeal, hid] at h
      cases hauth : hd.authorize with
      | Allow =>
        have := hd.authorize_allow_implies_ideal_allow hauth
        rw [this] at hid; exact absurd hid (by decide)
      | Deny => simp [unionAuthorize, hauth]
      | NoOpinion => simp only [unionAuthorize, hauth]; exact ih h

-- ============================================================================
-- Union ideal relates to existing unionIdealAuthorize
-- ============================================================================

theorem unionIdeal_eq_unionIdealAuthorize_entries (handlers : List Authorizer)
    : unionIdeal handlers =
      unionIdealAuthorize (collectEntries handlers |>.map Prod.snd) := by
  induction handlers with
  | nil => simp [unionIdeal, collectEntries, unionIdealAuthorize]
  | cons h rest ih =>
    cases hca : h.conditionsAwareAuthorize with
    | Allow =>
      simp [collectEntries, hca, unionIdeal, Authorizer.idealAuthorize,
            ConditionsAwareDecision.Ideal, List.map, unionIdealAuthorize]
    | Deny =>
      simp [collectEntries, hca, unionIdeal, Authorizer.idealAuthorize,
            ConditionsAwareDecision.Ideal, List.map, unionIdealAuthorize]
    | NoOpinion =>
      simp only [collectEntries, hca, unionIdeal, Authorizer.idealAuthorize,
                 ConditionsAwareDecision.Ideal, List.map, unionIdealAuthorize]
      exact ih
    | ConditionsMap cm =>
      simp only [collectEntries, hca, unionIdeal, Authorizer.idealAuthorize,
                 ConditionsAwareDecision.Ideal, ConditionsMap.Ideal,
                 List.map, unionIdealAuthorize]
      split <;> first | rfl | exact ih
    | Union ds =>
      simp only [collectEntries, hca, unionIdeal, Authorizer.idealAuthorize,
                 ConditionsAwareDecision.Ideal, List.map, unionIdealAuthorize]
      split <;> first | rfl | exact ih

-- ============================================================================
-- Main contract theorem
-- ============================================================================

theorem UnionAuthorizer.satisfies_contract (u : UnionAuthorizer)
    : AuthorizerContract u.conditionsAwareAuthorize u.authorize u.evaluateConditions := by
  simp only [UnionAuthorizer.conditionsAwareAuthorize, UnionAuthorizer.authorize,
             UnionAuthorizer.evaluateConditions, UnionAuthorizer.entries,
             AuthorizerContract]
  constructor
  · -- evaluateConditions = Ideal(Union entries)
    simp only [ConditionsAwareDecision.Ideal]
    rw [← unionIdeal_eq_unionIdealAuthorize_entries]
    exact evaluate_eq_ideal u.handlers
  constructor
  · -- authorize = Allow → Ideal = Allow
    intro h
    simp only [ConditionsAwareDecision.Ideal]
    rw [← unionIdeal_eq_unionIdealAuthorize_entries]
    exact metadata_allow_implies_ideal_allow u.handlers h
  · -- Ideal = Deny → authorize = Deny
    intro h
    simp only [ConditionsAwareDecision.Ideal] at h
    rw [← unionIdeal_eq_unionIdealAuthorize_entries] at h
    exact ideal_deny_implies_authorize_deny u.handlers h

def UnionAuthorizer.toAuthorizer (u : UnionAuthorizer) : Authorizer := {
  authorize := u.authorize,
  conditionsAwareAuthorize := u.conditionsAwareAuthorize,
  evaluateConditions := u.evaluateConditions,
  ax_authorizer := u.satisfies_contract
}

end ConditionalAuthzFromScratch
