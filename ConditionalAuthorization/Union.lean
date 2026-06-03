import ConditionalAuthorization.Authorizer
import ConditionalAuthorization.Spec

open ConditionalAuthorization.Authorizer
open ConditionalAuthorization.Spec

namespace ConditionalAuthorization.Union

-- ============================================================================
-- UnionAuthorizer structure (Go-transliterated)
-- ============================================================================

/-- Transliteration of Go's `unionAuthzHandler.EvaluateConditions` (union.go:98-152).
    Walks paired entries: leaf Allow/Deny short-circuit, NoOpinion skips,
    conditional delegates to the sub-authorizer's `evaluateConditions decision data`.
    Kept as a free function because it operates on a pre-paired entry list, not on
    `UnionAuthorizer.handlers` directly. -/
def unionEvaluateConditions : List (Authorizer × ConditionsAwareDecision) → ConditionsData → Decision
  | [], _ => .NoOpinion
  | (h, d) :: rest, data =>
    match d with
    | .Allow => .Allow
    | .Deny => .Deny
    | .NoOpinion => unionEvaluateConditions rest data
    | .ConditionsMap _ | .Union _ =>
      match h.evaluateConditions d data with
      | .Allow => .Allow
      | .Deny => .Deny
      | .NoOpinion => unionEvaluateConditions rest data

structure UnionAuthorizer where
  handlers : List Authorizer

/-- Mirrors Go's `unionAuthzHandler.Authorize` (union.go:46-70) as a method on `UnionAuthorizer`.
    Short-circuits on Allow or Deny. -/
def UnionAuthorizer.authorize : UnionAuthorizer → Attributes → Decision
  | ⟨[]⟩, _ => .NoOpinion
  | ⟨h :: rest⟩, attrs =>
    match h.authorize attrs with
    | .Allow => .Allow
    | .Deny => .Deny
    | .NoOpinion => UnionAuthorizer.authorize ⟨rest⟩ attrs

/-- The ideal (specification) chain: what each authorizer would return with full information.
    Short-circuits on Allow/Deny, like `authorize`. This is the claim, not an implementation. -/
def UnionAuthorizer.idealAuthorize : UnionAuthorizer → Attributes → ConditionsData → Decision
  | ⟨[]⟩, _, _ => .NoOpinion
  | ⟨h :: rest⟩, attrs, data =>
    match h.idealAuthorize attrs data with
    | .Allow => .Allow
    | .Deny => .Deny
    | .NoOpinion => UnionAuthorizer.idealAuthorize ⟨rest⟩ attrs data

/-- Mirrors Go's `unionAuthzHandler.ConditionsAwareAuthorize` (union.go:73-96): produces a
    `.Union` of each handler's `conditionsAwareAuthorize attrs` result, short-circuiting
    on the first unconditional `.Allow | .Deny`. The helper `subDecisions` is `where`-scoped
    so the public surface is just this method — no separate `entries` pair-list ever exposed.

    **Surfaced discrepancy** (not fixed here): Go short-circuits on any decision with
    `ContainsAllowOrDeny()` (including nested Union sub-decisions); the Lean helper below
    only short-circuits on top-level `.Allow | .Deny` leaves. They coincide when individual
    authorizers don't return nested `.Union` decisions. -/
def UnionAuthorizer.conditionsAwareAuthorize (u : UnionAuthorizer) (attrs : Attributes)
    : ConditionsAwareDecision :=
  .Union (subDecisions u.handlers)
where
  subDecisions : List Authorizer → List ConditionsAwareDecision
    | [] => []
    | h :: rest =>
      let d := h.conditionsAwareAuthorize attrs
      match d with
      | .Allow | .Deny => [d]
      | _ => d :: subDecisions rest

/-- Mirrors Go's `union.EvaluateConditions` (union.go:99-152). For the `.Union ds` case,
    walks the sub-decisions paired positionally with `u.handlers` — matching Go's
    `authzHandler[i]` index correlation. Unconditional/ConditionsMap legs match Go's
    fail-closed / passthrough behavior. -/
def UnionAuthorizer.evaluateConditions (u : UnionAuthorizer) :
    ConditionsAwareDecision → ConditionsData → Decision :=
  fun decision data =>
    match decision with
    | .Allow => .Allow
    | .Deny => .Deny
    | .NoOpinion => .NoOpinion
    | .ConditionsMap _ => decision.FailClosedDecision  -- matches Go: fail-closed via union.EvaluateConditions
    | .Union ds => unionEvaluateConditions (List.zip u.handlers ds) data

-- ============================================================================
-- Key lemmas
-- ============================================================================

/-- The core equivalence: `unionEvaluateConditions` on the union's handlers zipped with
    its sub-decisions equals the union's idealAuthorize, at any `data`. -/
theorem UnionAuthorizer.evaluate_eq_ideal (u : UnionAuthorizer)
    (attrs : Attributes) (data : ConditionsData)
    : unionEvaluateConditions
        (List.zip u.handlers
          (UnionAuthorizer.conditionsAwareAuthorize.subDecisions attrs u.handlers))
        data
    = u.idealAuthorize attrs data := by
  obtain ⟨handlers⟩ := u
  induction handlers with
  | nil =>
    simp [UnionAuthorizer.conditionsAwareAuthorize.subDecisions,
          UnionAuthorizer.idealAuthorize, unionEvaluateConditions, List.zip]
  | cons h rest ih =>
    cases hca : h.conditionsAwareAuthorize attrs with
    | Allow =>
      simp [UnionAuthorizer.conditionsAwareAuthorize.subDecisions, hca,
            unionEvaluateConditions, UnionAuthorizer.idealAuthorize,
            Authorizer.idealAuthorize, ConditionsAwareDecision.Ideal, List.zip]
    | Deny =>
      simp [UnionAuthorizer.conditionsAwareAuthorize.subDecisions, hca,
            unionEvaluateConditions, UnionAuthorizer.idealAuthorize,
            Authorizer.idealAuthorize, ConditionsAwareDecision.Ideal, List.zip]
    | NoOpinion =>
      simp only [UnionAuthorizer.conditionsAwareAuthorize.subDecisions, hca,
                 unionEvaluateConditions, UnionAuthorizer.idealAuthorize,
                 Authorizer.idealAuthorize, ConditionsAwareDecision.Ideal,
                 List.zip, List.zipWith]
      exact ih
    | ConditionsMap cm =>
      have heval := h.contract_eval_eq_ideal attrs (Or.inl ⟨cm, hca⟩) data
      rw [hca] at heval
      simp only [ConditionsAwareDecision.Ideal, ConditionsMap.Ideal] at heval
      simp only [UnionAuthorizer.conditionsAwareAuthorize.subDecisions, hca,
                 unionEvaluateConditions, UnionAuthorizer.idealAuthorize,
                 Authorizer.idealAuthorize, ConditionsAwareDecision.Ideal,
                 ConditionsMap.Ideal, heval, List.zip, List.zipWith]
      split <;> first | rfl | exact ih
    | Union ds =>
      have heval := h.contract_eval_eq_ideal attrs (Or.inr ⟨ds, hca⟩) data
      rw [hca] at heval
      simp only [ConditionsAwareDecision.Ideal] at heval
      simp only [UnionAuthorizer.conditionsAwareAuthorize.subDecisions, hca,
                 unionEvaluateConditions, UnionAuthorizer.idealAuthorize,
                 Authorizer.idealAuthorize, ConditionsAwareDecision.Ideal, heval,
                 List.zip, List.zipWith]
      split <;> first | rfl | exact ih

/-- If `u.authorize attrs = .Allow`, then `u.idealAuthorize attrs data = .Allow` at any data. -/
theorem UnionAuthorizer.metadata_allow_implies_ideal_allow (u : UnionAuthorizer)
    (attrs : Attributes) (data : ConditionsData)
    (h : u.authorize attrs = .Allow)
    : u.idealAuthorize attrs data = .Allow := by
  obtain ⟨handlers⟩ := u
  induction handlers with
  | nil => simp [UnionAuthorizer.authorize] at h
  | cons hd rest ih =>
    cases hauth : hd.authorize attrs with
    | Allow =>
      have hideal := hd.authorize_allow_implies_ideal_allow attrs hauth data
      simp [UnionAuthorizer.idealAuthorize, hideal]
    | Deny => simp [UnionAuthorizer.authorize, hauth] at h
    | NoOpinion =>
      simp [UnionAuthorizer.authorize, hauth] at h
      cases hid : hd.idealAuthorize attrs data with
      | Allow => simp [UnionAuthorizer.idealAuthorize, hid]
      | Deny =>
        have := hd.ideal_deny_implies_authorize_deny attrs data hid
        rw [hauth] at this; exact absurd this (by decide)
      | NoOpinion => simp only [UnionAuthorizer.idealAuthorize, hid]; exact ih h

/-- If `u.idealAuthorize attrs data = .Deny` at some data, then `u.authorize attrs = .Deny`. -/
theorem UnionAuthorizer.ideal_deny_implies_authorize_deny (u : UnionAuthorizer)
    (attrs : Attributes) (data : ConditionsData)
    (h : u.idealAuthorize attrs data = .Deny)
    : u.authorize attrs = .Deny := by
  obtain ⟨handlers⟩ := u
  induction handlers with
  | nil => simp [UnionAuthorizer.idealAuthorize] at h
  | cons hd rest ih =>
    cases hid : hd.idealAuthorize attrs data with
    | Allow => simp [UnionAuthorizer.idealAuthorize, hid] at h
    | Deny =>
      simp [UnionAuthorizer.authorize, hd.ideal_deny_implies_authorize_deny attrs data hid]
    | NoOpinion =>
      simp [UnionAuthorizer.idealAuthorize, hid] at h
      cases hauth : hd.authorize attrs with
      | Allow =>
        have := hd.authorize_allow_implies_ideal_allow attrs hauth data
        rw [this] at hid; exact absurd hid (by decide)
      | Deny => simp [UnionAuthorizer.authorize, hauth]
      | NoOpinion => simp only [UnionAuthorizer.authorize, hauth]; exact ih h


-- ============================================================================
-- Union ideal relates to unionIdealAuthorize over the sub-decisions
-- ============================================================================

theorem UnionAuthorizer.idealAuthorize_eq_unionIdealAuthorize_subDecisions
    (u : UnionAuthorizer) (attrs : Attributes) (data : ConditionsData)
    : u.idealAuthorize attrs data =
      unionIdealAuthorize
        (UnionAuthorizer.conditionsAwareAuthorize.subDecisions attrs u.handlers) data := by
  obtain ⟨handlers⟩ := u
  induction handlers with
  | nil =>
    simp [UnionAuthorizer.idealAuthorize,
          UnionAuthorizer.conditionsAwareAuthorize.subDecisions, unionIdealAuthorize]
  | cons h rest ih =>
    cases hca : h.conditionsAwareAuthorize attrs with
    | Allow =>
      simp [UnionAuthorizer.conditionsAwareAuthorize.subDecisions, hca,
            UnionAuthorizer.idealAuthorize, Authorizer.idealAuthorize,
            ConditionsAwareDecision.Ideal, unionIdealAuthorize]
    | Deny =>
      simp [UnionAuthorizer.conditionsAwareAuthorize.subDecisions, hca,
            UnionAuthorizer.idealAuthorize, Authorizer.idealAuthorize,
            ConditionsAwareDecision.Ideal, unionIdealAuthorize]
    | NoOpinion =>
      simp only [UnionAuthorizer.conditionsAwareAuthorize.subDecisions, hca,
                 UnionAuthorizer.idealAuthorize, Authorizer.idealAuthorize,
                 ConditionsAwareDecision.Ideal, unionIdealAuthorize]
      exact ih
    | ConditionsMap cm =>
      simp only [UnionAuthorizer.conditionsAwareAuthorize.subDecisions, hca,
                 UnionAuthorizer.idealAuthorize, Authorizer.idealAuthorize,
                 ConditionsAwareDecision.Ideal, ConditionsMap.Ideal, unionIdealAuthorize]
      cases cm.evaluate data with
      | Allow => rfl
      | Deny => rfl
      | NoOpinion => exact ih
    | Union ds =>
      simp only [UnionAuthorizer.conditionsAwareAuthorize.subDecisions, hca,
                 UnionAuthorizer.idealAuthorize, Authorizer.idealAuthorize,
                 ConditionsAwareDecision.Ideal, unionIdealAuthorize]
      cases unionIdealAuthorize ds data with
      | Allow => rfl
      | Deny => rfl
      | NoOpinion => exact ih

-- ============================================================================
-- Main contract theorem
-- ============================================================================

theorem UnionAuthorizer.satisfies_contract (u : UnionAuthorizer) : ∀ attrs,
    AuthorizerContract
      (u.conditionsAwareAuthorize attrs)
      (u.authorize attrs)
      (fun d => u.evaluateConditions (u.conditionsAwareAuthorize attrs) d) := by
  intro attrs
  simp only [UnionAuthorizer.conditionsAwareAuthorize,
             UnionAuthorizer.evaluateConditions,
             AuthorizerContract]
  refine ⟨?_, ?_, ?_⟩
  · -- ∀ d, evaluateConditions (.Union subDecisions) d = .Union subDecisions .Ideal d
    intro d
    simp only [ConditionsAwareDecision.Ideal]
    rw [← u.idealAuthorize_eq_unionIdealAuthorize_subDecisions (attrs := attrs)]
    exact u.evaluate_eq_ideal attrs d
  · -- authorize = Allow → ∀ d, Ideal d = Allow
    intro h d
    simp only [ConditionsAwareDecision.Ideal]
    rw [← u.idealAuthorize_eq_unionIdealAuthorize_subDecisions]
    exact u.metadata_allow_implies_ideal_allow attrs d h
  · -- ∀ d, Ideal d = Deny → authorize = Deny
    intro d h
    simp only [ConditionsAwareDecision.Ideal] at h
    rw [← u.idealAuthorize_eq_unionIdealAuthorize_subDecisions] at h
    exact u.ideal_deny_implies_authorize_deny attrs d h

def UnionAuthorizer.toAuthorizer (u : UnionAuthorizer) : Authorizer := {
  authorize := u.authorize,
  conditionsAwareAuthorize := u.conditionsAwareAuthorize,
  evaluateConditions := u.evaluateConditions,
  ax_authorizer := u.satisfies_contract
}

#check (UnionAuthorizer.authorize : UnionAuthorizer → Attributes → Decision)
#check (UnionAuthorizer.idealAuthorize :
          UnionAuthorizer → Attributes → ConditionsData → Decision)
#check (unionEvaluateConditions :
          List (Authorizer × ConditionsAwareDecision) → ConditionsData → Decision)

end ConditionalAuthorization.Union
