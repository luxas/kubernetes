import ConditionalAuthorization.Authorizer
open ConditionalAuthorization.Authorizer

namespace ConditionalAuthorization.Spec

-- ============================================================================
-- Types
-- ============================================================================

-- The axioms of the authorizer. The conditionsAwareAuthorize "controls" what authorize and evaluateConditions should return
-- inductive definition instead? hypothesis and split the cases
def AuthorizerContract (conditionsAwareAuthorize : ConditionsAwareDecision)
    (authorize : Decision) (evaluateConditions : ConditionsData → Decision) : Prop :=
  match conditionsAwareAuthorize with
  | .Allow     => authorize = .Allow ∧ ∀ d, evaluateConditions d = .Deny
  | .Deny      => authorize = .Deny ∧ ∀ d, evaluateConditions d = .Deny
  | .NoOpinion => authorize = .NoOpinion ∧ ∀ d, evaluateConditions d = .Deny
  | .ConditionsMap _ | .Union _ =>
      -- TODO: Might be clearer here to inline the attributes quantification
      (∀ d, evaluateConditions d = conditionsAwareAuthorize.Ideal d) ∧
      (authorize = .Allow → ∀ d, conditionsAwareAuthorize.Ideal d = .Allow) ∧
      (∀ d, conditionsAwareAuthorize.Ideal d = .Deny → authorize = .Deny)

/-- An individual authorizer. Signatures mirror Go's `authorizer.Authorizer` interface
    (interfaces.go:89-108): `Authorize(ctx, attrs)`, `ConditionsAwareAuthorize(ctx, attrs)`,
    `EvaluateConditions(ctx, decision, data)`. -/
structure Authorizer where
  /-- Go's `Authorize(ctx, attrs)`: metadata-only authorization decision. -/
  authorize : Attributes → Decision
  /-- Go's `ConditionsAwareAuthorize(ctx, attrs)`: phase-1 conditions-aware decision. -/
  conditionsAwareAuthorize : Attributes → ConditionsAwareDecision
  /-- Go's `EvaluateConditions(ctx, decision, data)`: phase-2 condition evaluation. -/
  evaluateConditions : ConditionsAwareDecision → ConditionsData → Decision

  /-- The per-authorizer coherence contract, universally quantified over attributes. -/
  ax_authorizer : ∀ attrs,
    AuthorizerContract
      (conditionsAwareAuthorize attrs)
      (authorize attrs)
      (fun d => evaluateConditions (conditionsAwareAuthorize attrs) d)

/-- The ideal result of an authorizer: what it would return with full information. -/
def Authorizer.idealAuthorize (a : Authorizer) (attrs : Attributes) (d : ConditionsData) : Decision :=
  (a.conditionsAwareAuthorize attrs).Ideal d

-- ============================================================================
-- Proofs
-- ============================================================================

mutual
/-- When `FailClosedDecision` does not produce Deny, `Ideal data` also cannot produce Deny
    for any `data`. Proved mutually with the list version (for Union's sub-decisions). -/
theorem failClosed_not_deny_implies_ideal_not_deny
    (d : ConditionsAwareDecision) (data : ConditionsData)
    (h : d.FailClosedDecision ≠ .Deny)
    : d.Ideal data ≠ .Deny := by
  cases d with
  | Allow     => simp [ConditionsAwareDecision.Ideal]
  | Deny      => simp [ConditionsAwareDecision.FailClosedDecision] at h
  | NoOpinion => simp [ConditionsAwareDecision.Ideal]
  | ConditionsMap cm =>
    simp [ConditionsAwareDecision.FailClosedDecision, ConditionsMap.FailClosedDecision,
          ConditionsAwareDecision.Ideal, ConditionsMap.Ideal] at h ⊢
    cases hdeny : cm.hasDenyCondition with
    | true => simp [hdeny] at h
    | false => exact cm.ax_no_deny_cond_implies_never_deny (by simp [hdeny]) data
  | Union ds =>
    simp [ConditionsAwareDecision.FailClosedDecision, ConditionsAwareDecision.Ideal] at h ⊢
    exact foldFailClosed_not_deny_implies_ideal_not_deny ds data h

theorem foldFailClosed_not_deny_implies_ideal_not_deny
    (ds : List ConditionsAwareDecision) (data : ConditionsData)
    (h : ConditionsAwareDecision.FailClosedDecision.foldFailClosed ds ≠ .Deny)
    : unionIdealAuthorize ds data ≠ .Deny := by
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
      exact foldFailClosed_not_deny_implies_ideal_not_deny rest data h_rest
    | .ConditionsMap cm =>
      simp only [unionIdealAuthorize, ConditionsMap.Ideal]
      have h_not_deny : cm.evaluate data ≠ .Deny := by
        apply cm.ax_no_deny_cond_implies_never_deny
        intro h_deny
        exact h_d (by simp [ConditionsAwareDecision.FailClosedDecision, ConditionsMap.FailClosedDecision, h_deny])
      split
      next => simp
      next h_eq => exact absurd h_eq h_not_deny
      next => exact foldFailClosed_not_deny_implies_ideal_not_deny rest data h_rest
    | .Union subDs =>
      simp only [unionIdealAuthorize]
      have h_ideal := failClosed_not_deny_implies_ideal_not_deny (.Union subDs) data h_d
      simp [ConditionsAwareDecision.Ideal] at h_ideal
      split
      next => simp
      next h_eq => exact absurd h_eq h_ideal
      next => exact foldFailClosed_not_deny_implies_ideal_not_deny rest data h_rest
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
-- Per-authorizer lemmas from contract
-- ============================================================================

theorem Authorizer.authorize_allow_implies_ideal_allow (a : Authorizer) (attrs : Attributes)
    (h : a.authorize attrs = .Allow) : ∀ d, a.idealAuthorize attrs d = .Allow := by
  have hax := a.ax_authorizer attrs
  unfold AuthorizerContract at hax
  cases hca : a.conditionsAwareAuthorize attrs with
  | Allow => intro d; simp [Authorizer.idealAuthorize, hca, ConditionsAwareDecision.Ideal]
  | Deny => rw [hca] at hax; rw [hax.1] at h; contradiction
  | NoOpinion => rw [hca] at hax; rw [hax.1] at h; contradiction
  | ConditionsMap _ =>
    rw [hca] at hax; simp only [Authorizer.idealAuthorize, hca]; exact hax.2.1 h
  | Union _ =>
    rw [hca] at hax; simp only [Authorizer.idealAuthorize, hca]; exact hax.2.1 h

theorem Authorizer.ideal_deny_implies_authorize_deny (a : Authorizer) (attrs : Attributes)
    (d : ConditionsData) (h : a.idealAuthorize attrs d = .Deny) : a.authorize attrs = .Deny := by
  have hax := a.ax_authorizer attrs
  unfold AuthorizerContract at hax
  cases hca : a.conditionsAwareAuthorize attrs with
  | Allow => simp [Authorizer.idealAuthorize, hca, ConditionsAwareDecision.Ideal] at h
  | Deny => rw [hca] at hax; exact hax.1
  | NoOpinion => simp [Authorizer.idealAuthorize, hca, ConditionsAwareDecision.Ideal] at h
  | ConditionsMap _ =>
    rw [hca] at hax; simp only [Authorizer.idealAuthorize, hca] at h; exact hax.2.2 d h
  | Union _ =>
    rw [hca] at hax; simp only [Authorizer.idealAuthorize, hca] at h; exact hax.2.2 d h

theorem Authorizer.contract_eval_eq_ideal (a : Authorizer) (attrs : Attributes)
    (hc : (∃ cm, a.conditionsAwareAuthorize attrs = .ConditionsMap cm) ∨
          (∃ ds, a.conditionsAwareAuthorize attrs = .Union ds))
    : ∀ d, a.evaluateConditions (a.conditionsAwareAuthorize attrs) d
         = (a.conditionsAwareAuthorize attrs).Ideal d := by
  have hax := a.ax_authorizer attrs
  unfold AuthorizerContract at hax
  rcases hc with ⟨cm, h⟩ | ⟨ds, h⟩ <;> { rw [h] at hax ⊢; exact hax.1 }


-- ============================================================================
-- Signature verification: pin the new shapes that mirror Go's interfaces
-- ============================================================================

#check (Authorizer.authorize : Authorizer → Attributes → Decision)
#check (Authorizer.conditionsAwareAuthorize : Authorizer → Attributes → ConditionsAwareDecision)
#check (Authorizer.evaluateConditions :
          Authorizer → ConditionsAwareDecision → ConditionsData → Decision)


end ConditionalAuthorization.Spec
