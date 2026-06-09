import ConditionalAuthorization.Authorizer
open ConditionalAuthorization.Authorizer

namespace ConditionalAuthorization.Spec

-- ============================================================================
-- Types
-- ============================================================================

def AuthorizerContract (conditionsAwareAuthorize : ConditionsAwareDecision)
    (authorize : Decision) (evaluateConditions : ConditionsData → Decision) : Prop :=
  match conditionsAwareAuthorize with
  | .Allow     => authorize = .Allow ∧ ∀ d, evaluateConditions d = .Deny
  | .Deny      => authorize = .Deny ∧ ∀ d, evaluateConditions d = .Deny
  | .NoOpinion => authorize = .NoOpinion ∧ ∀ d, evaluateConditions d = .Deny
  | .ConditionsMap _ | .Union _ =>
      (∀ d, evaluateConditions d = conditionsAwareAuthorize.Ideal d) ∧
      (authorize = .Allow → ∀ d, conditionsAwareAuthorize.Ideal d = .Allow) ∧
      (∀ d, conditionsAwareAuthorize.Ideal d = .Deny → authorize = .Deny)

/-- An individual authorizer. Mirrors Go's `authorizer.Authorizer` interface
    (interfaces.go:103-127). Now includes `name` matching Go's `AuthorizerName()`. -/
structure Authorizer where
  /-- Go's `AuthorizerName()`: unique identifier for correlating decisions in unions. -/
  name : String
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

/-- **Invariant**: `ConditionsMap.FailureDecision` is always `Deny` or `NoOpinion`. -/
theorem conditionsMap_failureDecision_deny_or_noOpinion (c : ConditionsMap)
    : c.FailureDecision = .Deny ∨ c.FailureDecision = .NoOpinion := by
  unfold ConditionsMap.FailureDecision
  split <;> simp

/-- **Invariant**: `ConditionsAwareDecision.FailureDecision` is always `Deny` or `NoOpinion`,
    never `Allow`. -/
theorem failureDecision_deny_or_noOpinion (d : ConditionsAwareDecision)
    : d.FailureDecision = .Deny ∨ d.FailureDecision = .NoOpinion := by
  unfold ConditionsAwareDecision.FailureDecision
  split <;> simp

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
-- Signature verification
-- ============================================================================

#check (Authorizer.name : Authorizer → String)
#check (Authorizer.authorize : Authorizer → Attributes → Decision)
#check (Authorizer.conditionsAwareAuthorize : Authorizer → Attributes → ConditionsAwareDecision)
#check (Authorizer.evaluateConditions :
          Authorizer → ConditionsAwareDecision → ConditionsData → Decision)


end ConditionalAuthorization.Spec
