import ConditionalAuthorization.Authorizer
import ConditionalAuthorization.Spec

open ConditionalAuthorization.Authorizer
open ConditionalAuthorization.Spec

namespace ConditionalAuthorization.Union

-- ============================================================================
-- Go-transliterated standalone functions
-- ============================================================================

/-- Transliteration of Go's `unionAuthzHandler.Authorize` (union.go:46-70).
    Short-circuits on Allow or Deny. -/
def unionAuthorize : List Authorizer → Attributes → Decision
  | [], _ => .NoOpinion
  | h :: rest, attrs =>
    match h.authorize attrs with
    | .Allow => .Allow
    | .Deny => .Deny
    | .NoOpinion => unionAuthorize rest attrs

/-- Transliteration of Go's `ConditionsAwareAuthorize` loop body (union.go:73-96).
    Collects (authorizer, decision) pairs, short-circuiting when a decision
    contains an unconditional Allow or Deny. -/
def collectEntries : List Authorizer → Attributes → List (Authorizer × ConditionsAwareDecision)
  | [], _ => []
  | h :: rest, attrs =>
    let d := h.conditionsAwareAuthorize attrs
    match d with
    | .Allow | .Deny => [(h, d)]
    | _ => (h, d) :: collectEntries rest attrs

/-- Transliteration of Go's `unionAuthzHandler.EvaluateConditions` (union.go:98-152).
    Walks paired entries: leaf Allow/Deny short-circuit, NoOpinion skips,
    conditional delegates to the sub-authorizer's `evaluateConditions decision data`. -/
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

/-- The ideal (specification) chain: what each authorizer would return
    with full information. This is the claim, not part of any implementation. -/
def unionIdeal : List Authorizer → Attributes → ConditionsData → Decision
  | [], _, _ => .NoOpinion
  | h :: rest, attrs, data =>
    match h.idealAuthorize attrs data with
    | .Allow => .Allow
    | .Deny => .Deny
    | .NoOpinion => unionIdeal rest attrs data

-- ============================================================================
-- UnionAuthorizer structure (Go-transliterated)
-- ============================================================================

structure UnionAuthorizer where
  handlers : List Authorizer

def UnionAuthorizer.entries (u : UnionAuthorizer) (attrs : Attributes) :=
  collectEntries u.handlers attrs

def UnionAuthorizer.authorize (u : UnionAuthorizer) (attrs : Attributes) : Decision :=
  unionAuthorize u.handlers attrs

def UnionAuthorizer.conditionsAwareAuthorize (u : UnionAuthorizer) (attrs : Attributes) : ConditionsAwareDecision :=
  .Union ((u.entries attrs).map Prod.snd)

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
    | .ConditionsMap _ => .Deny
    | .Union ds => unionEvaluateConditions (List.zip u.handlers ds) data

-- ============================================================================
-- Key lemmas
-- ============================================================================

/-- The core equivalence: unionEvaluateConditions on collected entries
    equals unionIdeal on the original handlers, evaluated at any `data`. -/
theorem evaluate_eq_ideal (handlers : List Authorizer) (attrs : Attributes) (data : ConditionsData)
    : unionEvaluateConditions (collectEntries handlers attrs) data
    = unionIdeal handlers attrs data := by
  induction handlers with
  | nil => rfl
  | cons h rest ih =>
    cases hca : h.conditionsAwareAuthorize attrs with
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
      have heval := h.contract_eval_eq_ideal attrs (Or.inl ⟨cm, hca⟩) data
      rw [hca] at heval
      simp only [ConditionsAwareDecision.Ideal, ConditionsMap.Ideal] at heval
      simp only [collectEntries, hca, unionEvaluateConditions, unionIdeal,
                 Authorizer.idealAuthorize, ConditionsAwareDecision.Ideal,
                 ConditionsMap.Ideal, heval]
      split <;> first | rfl | exact ih
    | Union ds =>
      have heval := h.contract_eval_eq_ideal attrs (Or.inr ⟨ds, hca⟩) data
      rw [hca] at heval
      simp only [ConditionsAwareDecision.Ideal] at heval
      simp only [collectEntries, hca, unionEvaluateConditions, unionIdeal,
                 Authorizer.idealAuthorize, ConditionsAwareDecision.Ideal, heval]
      split <;> first | rfl | exact ih

/-- If unionAuthorize returns Allow at `attrs`, then unionIdeal also returns Allow there at any data. -/
theorem metadata_allow_implies_ideal_allow (handlers : List Authorizer)
    (attrs : Attributes) (data : ConditionsData)
    (h : unionAuthorize handlers attrs = .Allow)
    : unionIdeal handlers attrs data = .Allow := by
  induction handlers with
  | nil => simp [unionAuthorize] at h
  | cons hd rest ih =>
    cases hauth : hd.authorize attrs with
    | Allow =>
      have hideal := hd.authorize_allow_implies_ideal_allow attrs hauth data
      simp [unionIdeal, hideal]
    | Deny => simp [unionAuthorize, hauth] at h
    | NoOpinion =>
      simp [unionAuthorize, hauth] at h
      cases hid : hd.idealAuthorize attrs data with
      | Allow => simp [unionIdeal, hid]
      | Deny =>
        have := hd.ideal_deny_implies_authorize_deny attrs data hid
        rw [hauth] at this; exact absurd this (by decide)
      | NoOpinion => simp only [unionIdeal, hid]; exact ih h

/-- If unionIdeal returns Deny at some `data`, then unionAuthorize also returns Deny. -/
theorem ideal_deny_implies_authorize_deny (handlers : List Authorizer)
    (attrs : Attributes) (data : ConditionsData)
    (h : unionIdeal handlers attrs data = .Deny)
    : unionAuthorize handlers attrs = .Deny := by
  induction handlers with
  | nil => simp [unionIdeal] at h
  | cons hd rest ih =>
    cases hid : hd.idealAuthorize attrs data with
    | Allow => simp [unionIdeal, hid] at h
    | Deny =>
      simp [unionAuthorize, hd.ideal_deny_implies_authorize_deny attrs data hid]
    | NoOpinion =>
      simp [unionIdeal, hid] at h
      cases hauth : hd.authorize attrs with
      | Allow =>
        have := hd.authorize_allow_implies_ideal_allow attrs hauth data
        rw [this] at hid; exact absurd hid (by decide)
      | Deny => simp [unionAuthorize, hauth]
      | NoOpinion => simp only [unionAuthorize, hauth]; exact ih h


-- ============================================================================
-- Union ideal relates to existing unionIdealAuthorize
-- ============================================================================

theorem unionIdeal_eq_unionIdealAuthorize_entries (handlers : List Authorizer)
    (attrs : Attributes) (data : ConditionsData)
    : unionIdeal handlers attrs data =
      unionIdealAuthorize (collectEntries handlers attrs |>.map Prod.snd) data := by
  induction handlers with
  | nil => simp [unionIdeal, collectEntries, unionIdealAuthorize]
  | cons h rest ih =>
    cases hca : h.conditionsAwareAuthorize attrs with
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
      cases cm.evaluate data with
      | Allow => rfl
      | Deny => rfl
      | NoOpinion => exact ih
    | Union ds =>
      simp only [collectEntries, hca, unionIdeal, Authorizer.idealAuthorize,
                 ConditionsAwareDecision.Ideal, List.map, unionIdealAuthorize]
      cases unionIdealAuthorize ds data with
      | Allow => rfl
      | Deny => rfl
      | NoOpinion => exact ih

/-- Re-zipping the original handler list with the decisions extracted from
    `collectEntries` recovers the original `collectEntries` pairing — because
    `collectEntries` consumes handlers in order and at most truncates the tail. -/
theorem zip_handlers_collectEntries_snd (handlers : List Authorizer) (attrs : Attributes)
    : List.zip handlers ((collectEntries handlers attrs).map Prod.snd)
    = collectEntries handlers attrs := by
  induction handlers with
  | nil => rfl
  | cons h rest ih =>
    cases hca : h.conditionsAwareAuthorize attrs with
    | Allow => simp [collectEntries, hca, List.map, List.zip]
    | Deny => simp [collectEntries, hca, List.map, List.zip]
    | NoOpinion =>
      simp only [collectEntries, hca, List.map, List.zip, List.zipWith, List.cons.injEq, true_and]
      exact ih
    | ConditionsMap _ =>
      simp only [collectEntries, hca, List.map, List.zip, List.zipWith, List.cons.injEq, true_and]
      exact ih
    | Union _ =>
      simp only [collectEntries, hca, List.map, List.zip, List.zipWith, List.cons.injEq, true_and]
      exact ih

-- ============================================================================
-- Main contract theorem
-- ============================================================================

theorem UnionAuthorizer.satisfies_contract (u : UnionAuthorizer) : ∀ attrs,
    AuthorizerContract
      (u.conditionsAwareAuthorize attrs)
      (u.authorize attrs)
      (fun d => u.evaluateConditions (u.conditionsAwareAuthorize attrs) d) := by
  intro attrs
  simp only [UnionAuthorizer.conditionsAwareAuthorize, UnionAuthorizer.authorize,
             UnionAuthorizer.evaluateConditions, UnionAuthorizer.entries,
             AuthorizerContract]
  refine ⟨?_, ?_, ?_⟩
  · -- ∀ d, evaluateConditions (.Union entriesSnd) d = .Union entriesSnd .Ideal d
    intro d
    simp only [ConditionsAwareDecision.Ideal]
    rw [← unionIdeal_eq_unionIdealAuthorize_entries (attrs := attrs)]
    rw [zip_handlers_collectEntries_snd]
    exact evaluate_eq_ideal u.handlers attrs d
  · -- authorize = Allow → ∀ d, Ideal d = Allow
    intro h d
    simp only [ConditionsAwareDecision.Ideal]
    rw [← unionIdeal_eq_unionIdealAuthorize_entries]
    exact metadata_allow_implies_ideal_allow u.handlers attrs d h
  · -- ∀ d, Ideal d = Deny → authorize = Deny
    intro d h
    simp only [ConditionsAwareDecision.Ideal] at h
    rw [← unionIdeal_eq_unionIdealAuthorize_entries] at h
    exact ideal_deny_implies_authorize_deny u.handlers attrs d h

def UnionAuthorizer.toAuthorizer (u : UnionAuthorizer) : Authorizer := {
  authorize := u.authorize,
  conditionsAwareAuthorize := u.conditionsAwareAuthorize,
  evaluateConditions := u.evaluateConditions,
  ax_authorizer := u.satisfies_contract
}

#check (unionAuthorize : List Authorizer → Attributes → Decision)
#check (unionEvaluateConditions :
          List (Authorizer × ConditionsAwareDecision) → ConditionsData → Decision)
#check (unionIdeal : List Authorizer → Attributes → ConditionsData → Decision)

end ConditionalAuthorization.Union
