import ConditionalAuthorization.Authorizer
import ConditionalAuthorization.Spec

open ConditionalAuthorization.Authorizer
open ConditionalAuthorization.Spec

namespace ConditionalAuthorization.Union

-- ============================================================================
-- UnionAuthorizer structure (Go-transliterated)
-- ============================================================================

structure UnionAuthorizer where
  handlers : List Authorizer

/-- Mirrors Go's `unionAuthzHandler.Authorize` (union.go:49-73). -/
def UnionAuthorizer.authorize : UnionAuthorizer → Attributes → Decision
  | ⟨[]⟩, _ => .NoOpinion
  | ⟨h :: rest⟩, attrs =>
    match h.authorize attrs with
    | .Allow => .Allow
    | .Deny => .Deny
    | .NoOpinion => UnionAuthorizer.authorize ⟨rest⟩ attrs

/-- The ideal (specification) chain. -/
def UnionAuthorizer.idealAuthorize : UnionAuthorizer → Attributes → ConditionsData → Decision
  | ⟨[]⟩, _, _ => .NoOpinion
  | ⟨h :: rest⟩, attrs, data =>
    match h.idealAuthorize attrs data with
    | .Allow => .Allow
    | .Deny => .Deny
    | .NoOpinion => UnionAuthorizer.idealAuthorize ⟨rest⟩ attrs data

-- ============================================================================
-- Name-based authorizer lookup (Go union.go:165-179)
-- ============================================================================

def getAuthorizerWithName (handlers : List Authorizer) (name : String) : Option Authorizer :=
  match handlers.filter (fun a => a.name == name) with
  | [a] => some a
  | _ => none

-- ============================================================================
-- ConditionsAwareAuthorize: builds named sub-decisions list
-- ============================================================================

/-- The sub-decisions list built by conditionsAwareAuthorize. Each entry pairs the
    authorizer's name with its conditionsAwareAuthorize result. Short-circuits when
    the head result ContainsAllowOrDeny, matching Go's loop + Add + ContainsAllowOrDeny. -/
def UnionAuthorizer.conditionsAwareAuthorize.subDecisions
    (attrs : Attributes) : List Authorizer → List (String × ConditionsAwareDecision)
  | [] => []
  | h :: rest =>
    let d := h.conditionsAwareAuthorize attrs
    match d with
    | .Allow | .Deny => [(h.name, d)]
    | _ => (h.name, d) :: subDecisions attrs rest

/-- Mirrors Go's `unionAuthzHandler.ConditionsAwareAuthorize` (union.go:76-98):
    produces a `.Union` wrapping each handler's named decision, short-circuiting
    on the first unconditional `.Allow | .Deny`. -/
def UnionAuthorizer.conditionsAwareAuthorize (u : UnionAuthorizer) (attrs : Attributes)
    : ConditionsAwareDecision :=
  .Union (UnionAuthorizer.conditionsAwareAuthorize.subDecisions attrs u.handlers)

-- ============================================================================
-- EvaluateConditions: name-based dispatch (Go union.go:102-163)
-- ============================================================================

/-- Mirrors Go's `union.EvaluateConditions` (union.go:102-155).
    For `.Union ds`, iterates named sub-decisions and looks up the authorizer by name. -/
def UnionAuthorizer.evaluateConditions (u : UnionAuthorizer)
    (decision : ConditionsAwareDecision) (data : ConditionsData) : Decision :=
  match decision with
  | .Allow => .Allow
  | .Deny => .Deny
  | .NoOpinion => .NoOpinion
  | .ConditionsMap _ => decision.FailureDecision
  | .Union ds => walk u.handlers ds data
where
  walk : List Authorizer → List (String × ConditionsAwareDecision) → ConditionsData → Decision
    | _, [], _ => .NoOpinion
    | handlers, (name, d) :: rest, data =>
      match d with
      | .Allow => .Allow
      | .Deny => .Deny
      | .NoOpinion => walk handlers rest data
      | .ConditionsMap _ | .Union _ =>
        match getAuthorizerWithName handlers name with
        | some a =>
          match a.evaluateConditions d data with
          | .Allow => .Allow
          | .Deny => .Deny
          | .NoOpinion => walk handlers rest data
        | none => d.FailureDecision

-- ============================================================================
-- Key lemmas
-- ============================================================================

private theorem walk_subDecisions_eq_idealAuthorize
    (allHandlers suffix : List Authorizer) (attrs : Attributes) (data : ConditionsData)
    (h_lookup : ∀ a, a ∈ suffix → getAuthorizerWithName allHandlers a.name = some a)
    : UnionAuthorizer.evaluateConditions.walk allHandlers
        (UnionAuthorizer.conditionsAwareAuthorize.subDecisions attrs suffix) data
    = UnionAuthorizer.idealAuthorize ⟨suffix⟩ attrs data := by
  induction suffix with
  | nil =>
    simp [UnionAuthorizer.conditionsAwareAuthorize.subDecisions,
          UnionAuthorizer.idealAuthorize, UnionAuthorizer.evaluateConditions.walk]
  | cons h rest ih =>
    have h_head := h_lookup h (by simp)
    have h_tail : ∀ a, a ∈ rest → getAuthorizerWithName allHandlers a.name = some a :=
      fun a ha => h_lookup a (by simp [ha])
    cases hca : h.conditionsAwareAuthorize attrs with
    | Allow =>
      simp [UnionAuthorizer.conditionsAwareAuthorize.subDecisions, hca,
            UnionAuthorizer.evaluateConditions.walk, UnionAuthorizer.idealAuthorize,
            Authorizer.idealAuthorize, ConditionsAwareDecision.Ideal]
    | Deny =>
      simp [UnionAuthorizer.conditionsAwareAuthorize.subDecisions, hca,
            UnionAuthorizer.evaluateConditions.walk, UnionAuthorizer.idealAuthorize,
            Authorizer.idealAuthorize, ConditionsAwareDecision.Ideal]
    | NoOpinion =>
      simp only [UnionAuthorizer.conditionsAwareAuthorize.subDecisions, hca,
                 UnionAuthorizer.evaluateConditions.walk, UnionAuthorizer.idealAuthorize,
                 Authorizer.idealAuthorize, ConditionsAwareDecision.Ideal]
      exact ih h_tail
    | ConditionsMap cm =>
      have heval := h.contract_eval_eq_ideal attrs (Or.inl ⟨cm, hca⟩) data
      rw [hca] at heval
      simp only [ConditionsAwareDecision.Ideal, ConditionsMap.Ideal] at heval
      simp only [UnionAuthorizer.conditionsAwareAuthorize.subDecisions, hca,
                 UnionAuthorizer.evaluateConditions.walk, h_head,
                 UnionAuthorizer.idealAuthorize, Authorizer.idealAuthorize,
                 ConditionsAwareDecision.Ideal, ConditionsMap.Ideal, heval]
      split <;> first | rfl | exact ih h_tail
    | Union ds =>
      have heval := h.contract_eval_eq_ideal attrs (Or.inr ⟨ds, hca⟩) data
      rw [hca] at heval
      simp only [ConditionsAwareDecision.Ideal] at heval
      simp only [UnionAuthorizer.conditionsAwareAuthorize.subDecisions, hca,
                 UnionAuthorizer.evaluateConditions.walk, h_head,
                 UnionAuthorizer.idealAuthorize, Authorizer.idealAuthorize,
                 ConditionsAwareDecision.Ideal, heval]
      split <;> first | rfl | exact ih h_tail

/-- The core equivalence: walking the named sub-decisions with name-based lookup
    equals the union's idealAuthorize. Requires unique name lookup. -/
theorem UnionAuthorizer.evaluate_eq_ideal (u : UnionAuthorizer)
    (attrs : Attributes) (data : ConditionsData)
    (h_unique : ∀ h, h ∈ u.handlers → getAuthorizerWithName u.handlers h.name = some h)
    : UnionAuthorizer.evaluateConditions.walk u.handlers
        (UnionAuthorizer.conditionsAwareAuthorize.subDecisions attrs u.handlers) data
    = u.idealAuthorize attrs data :=
  walk_subDecisions_eq_idealAuthorize u.handlers u.handlers attrs data h_unique

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

theorem UnionAuthorizer.satisfies_contract (u : UnionAuthorizer)
    (h_unique : ∀ h, h ∈ u.handlers → getAuthorizerWithName u.handlers h.name = some h)
    : ∀ attrs,
    AuthorizerContract
      (u.conditionsAwareAuthorize attrs)
      (u.authorize attrs)
      (fun d => u.evaluateConditions (u.conditionsAwareAuthorize attrs) d) := by
  intro attrs
  simp only [UnionAuthorizer.conditionsAwareAuthorize,
             UnionAuthorizer.evaluateConditions,
             AuthorizerContract]
  refine ⟨?_, ?_, ?_⟩
  · intro d
    simp only [ConditionsAwareDecision.Ideal]
    rw [← u.idealAuthorize_eq_unionIdealAuthorize_subDecisions (attrs := attrs)]
    exact u.evaluate_eq_ideal attrs d h_unique
  · intro h d
    simp only [ConditionsAwareDecision.Ideal]
    rw [← u.idealAuthorize_eq_unionIdealAuthorize_subDecisions]
    exact u.metadata_allow_implies_ideal_allow attrs d h
  · intro d h
    simp only [ConditionsAwareDecision.Ideal] at h
    rw [← u.idealAuthorize_eq_unionIdealAuthorize_subDecisions] at h
    exact u.ideal_deny_implies_authorize_deny attrs d h

def UnionAuthorizer.toAuthorizer (u : UnionAuthorizer)
    (h_unique : ∀ h, h ∈ u.handlers → getAuthorizerWithName u.handlers h.name = some h)
    : Authorizer := {
  name := s!"authorizer.k8s.io/Union[{", ".intercalate (u.handlers.map (·.name))}]",
  authorize := u.authorize,
  conditionsAwareAuthorize := u.conditionsAwareAuthorize,
  evaluateConditions := u.evaluateConditions,
  ax_authorizer := u.satisfies_contract h_unique
}

#check (UnionAuthorizer.authorize : UnionAuthorizer → Attributes → Decision)
#check (UnionAuthorizer.conditionsAwareAuthorize :
          UnionAuthorizer → Attributes → ConditionsAwareDecision)
#check (UnionAuthorizer.evaluateConditions :
          UnionAuthorizer → ConditionsAwareDecision → ConditionsData → Decision)
#check (UnionAuthorizer.idealAuthorize :
          UnionAuthorizer → Attributes → ConditionsData → Decision)

end ConditionalAuthorization.Union
