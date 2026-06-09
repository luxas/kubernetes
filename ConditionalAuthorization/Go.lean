import ConditionalAuthorization.Authorizer
import ConditionalAuthorization.Spec
import ConditionalAuthorization.Union
import Mathlib.Data.List.Basic
import Mathlib.Control.Basic

/-!
# Line-by-line Go → Lean transliterations

Each `XxxDo` is proven equal to its proof-friendly counterpart (`XxxDo_eq`).
-/

namespace ConditionalAuthorization.Authorizer

-- ============================================================================
-- Trivial transliterations
-- ============================================================================

def Attributes.isReadOnlyDo (a : Attributes) : Bool :=
  a.verb = "get" || a.verb = "list" || a.verb = "watch"

-- ============================================================================
-- ContainsAllowOrDeny Do-transliteration (updated for named pairs)
-- ============================================================================

mutual

def ConditionsAwareDecision.ContainsAllowOrDenyDo : ConditionsAwareDecision → Bool
  | .Allow => true
  | .Deny => true
  | .NoOpinion => false
  | .ConditionsMap _ => false
  | .Union ds => unionSliceContainsAllowOrDenyDo ds

def unionSliceContainsAllowOrDenyDo :
    List (String × ConditionsAwareDecision) → Bool
  | [] => false
  | (_, subDecision) :: rest =>
    if subDecision.ContainsAllowOrDenyDo then true
    else unionSliceContainsAllowOrDenyDo rest

end

end ConditionalAuthorization.Authorizer

-- ============================================================================
-- union.go — UnionAuthorizer methods (updated for name-based lookup)
-- ============================================================================

namespace ConditionalAuthorization.Union

open ConditionalAuthorization.Authorizer
open ConditionalAuthorization.Spec

def UnionAuthorizer.authorizeDo (u : UnionAuthorizer) (attrs : Attributes) : Decision :=
  Id.run do
    for curr in u.handlers do
      match curr.authorize attrs with
      | .Allow => return .Allow
      | .Deny  => return .Deny
      | .NoOpinion => pure ()
    return .NoOpinion

def UnionAuthorizer.conditionsAwareAuthorizeDo (u : UnionAuthorizer) (attrs : Attributes)
    : ConditionsAwareDecision := Id.run do
  let mut decisions : List (String × ConditionsAwareDecision) := []
  for currAuthzHandler in u.handlers do
    let decision := currAuthzHandler.conditionsAwareAuthorize attrs
    decisions := decisions ++ [(currAuthzHandler.name, decision)]
    if decision.ContainsAllowOrDenyDo then
      return .Union decisions
  return .Union decisions

def evaluateConditionsLoopDo (handlers : List Authorizer)
    (ds : List (String × ConditionsAwareDecision)) (data : ConditionsData) : Decision :=
  Id.run do
    for (name, unevaluatedSubDecision) in ds do
      match unevaluatedSubDecision with
      | .Allow => return .Allow
      | .Deny  => return .Deny
      | .NoOpinion => pure ()
      | .ConditionsMap _ | .Union _ =>
        match getAuthorizerWithName handlers name with
        | some a =>
          match a.evaluateConditions unevaluatedSubDecision data with
          | .Allow => return .Allow
          | .Deny  => return .Deny
          | .NoOpinion => pure ()
        | none => return unevaluatedSubDecision.FailureDecision
    return .NoOpinion

def UnionAuthorizer.evaluateConditionsDo (u : UnionAuthorizer)
    (unevaluatedDecision : ConditionsAwareDecision) (data : ConditionsData) : Decision :=
  match unevaluatedDecision with
  | .Allow     => .Allow
  | .Deny      => .Deny
  | .NoOpinion => .NoOpinion
  | .ConditionsMap _ => unevaluatedDecision.FailureDecision
  | .Union ds => evaluateConditionsLoopDo u.handlers ds data

end ConditionalAuthorization.Union

-- ============================================================================
-- Equivalence proofs
-- ============================================================================

namespace ConditionalAuthorization.Authorizer

theorem Attributes.isReadOnlyDo_eq (a : Attributes) :
    a.isReadOnlyDo = a.isReadOnly := rfl

-- ── ContainsAllowOrDenyDo_eq ────────────────────────────────────────────────

mutual

theorem ConditionsAwareDecision.ContainsAllowOrDenyDo_eq (d : ConditionsAwareDecision) :
    d.ContainsAllowOrDenyDo = d.ContainsAllowOrDeny := by
  cases d with
  | Allow | Deny | NoOpinion | ConditionsMap _ => rfl
  | Union ds =>
    show unionSliceContainsAllowOrDenyDo ds
       = ConditionsAwareDecision.ContainsAllowOrDeny.anyContainsAllowOrDeny ds
    exact unionSliceContainsAllowOrDenyDo_eq ds

theorem unionSliceContainsAllowOrDenyDo_eq
    (xs : List (String × ConditionsAwareDecision)) :
    unionSliceContainsAllowOrDenyDo xs
    = ConditionsAwareDecision.ContainsAllowOrDeny.anyContainsAllowOrDeny xs := by
  match xs with
  | [] => rfl
  | (_, sub) :: rest =>
    have ih_sub := sub.ContainsAllowOrDenyDo_eq
    have ih_rest := unionSliceContainsAllowOrDenyDo_eq rest
    show (if sub.ContainsAllowOrDenyDo then true else unionSliceContainsAllowOrDenyDo rest)
       = (sub.ContainsAllowOrDeny || ConditionsAwareDecision.ContainsAllowOrDeny.anyContainsAllowOrDeny rest)
    rw [ih_sub, ih_rest]
    cases sub.ContainsAllowOrDeny <;> simp

end

-- ── ContainsAllowOrDeny forces Ideal to Allow or Deny ───────────────────────

mutual

theorem containsAllowOrDeny_implies_ideal_AllowOrDeny
    (d : ConditionsAwareDecision) (data : ConditionsData)
    (h : d.ContainsAllowOrDeny = true)
    : d.Ideal data = .Allow ∨ d.Ideal data = .Deny := by
  cases d with
  | Allow => left; rfl
  | Deny => right; rfl
  | NoOpinion =>
    simp [ConditionsAwareDecision.ContainsAllowOrDeny] at h
  | ConditionsMap _ =>
    simp [ConditionsAwareDecision.ContainsAllowOrDeny] at h
  | Union ds =>
    simp only [ConditionsAwareDecision.ContainsAllowOrDeny] at h
    simp only [ConditionsAwareDecision.Ideal]
    exact anyContainsAllowOrDeny_implies_unionIdealAuthorize_AllowOrDeny ds data h

theorem anyContainsAllowOrDeny_implies_unionIdealAuthorize_AllowOrDeny
    (ds : List (String × ConditionsAwareDecision)) (data : ConditionsData)
    (h : ConditionsAwareDecision.ContainsAllowOrDeny.anyContainsAllowOrDeny ds = true)
    : unionIdealAuthorize ds data = .Allow ∨ unionIdealAuthorize ds data = .Deny := by
  match ds with
  | [] =>
    simp [ConditionsAwareDecision.ContainsAllowOrDeny.anyContainsAllowOrDeny] at h
  | (_, sub) :: rest =>
    simp only [ConditionsAwareDecision.ContainsAllowOrDeny.anyContainsAllowOrDeny,
               Bool.or_eq_true] at h
    unfold unionIdealAuthorize
    cases sub with
    | Allow => left; rfl
    | Deny => right; rfl
    | NoOpinion =>
      simp only [ConditionsAwareDecision.ContainsAllowOrDeny,
                 Bool.false_eq_true, false_or] at h
      exact anyContainsAllowOrDeny_implies_unionIdealAuthorize_AllowOrDeny rest data h
    | ConditionsMap c =>
      simp only [ConditionsAwareDecision.ContainsAllowOrDeny,
                 Bool.false_eq_true, false_or] at h
      simp only [ConditionsMap.Ideal]
      cases c.evaluate data with
      | Allow => left; rfl
      | Deny => right; rfl
      | NoOpinion =>
        exact anyContainsAllowOrDeny_implies_unionIdealAuthorize_AllowOrDeny rest data h
    | Union ds' =>
      dsimp only []
      cases hds : unionIdealAuthorize ds' data with
      | Allow => left; rfl
      | Deny => right; rfl
      | NoOpinion =>
        have h_rest :
            ConditionsAwareDecision.ContainsAllowOrDeny.anyContainsAllowOrDeny rest = true := by
          rcases h with hd' | hr
          · simp only [ConditionsAwareDecision.ContainsAllowOrDeny] at hd'
            have := anyContainsAllowOrDeny_implies_unionIdealAuthorize_AllowOrDeny ds' data hd'
            cases this with
            | inl hl => rw [hl] at hds; exact absurd hds (by decide)
            | inr hr' => rw [hr'] at hds; exact absurd hds (by decide)
          · exact hr
        exact anyContainsAllowOrDeny_implies_unionIdealAuthorize_AllowOrDeny rest data h_rest

end

end ConditionalAuthorization.Authorizer

-- ── UnionAuthorizer.* equivalences ────────────────────────────────────────────

namespace ConditionalAuthorization.Union

open ConditionalAuthorization.Authorizer
open ConditionalAuthorization.Spec

theorem UnionAuthorizer.authorizeDo_eq (u : UnionAuthorizer) (attrs : Attributes) :
    u.authorizeDo attrs = u.authorize attrs := by
  obtain ⟨handlers⟩ := u
  induction handlers with
  | nil => simp [UnionAuthorizer.authorizeDo, UnionAuthorizer.authorize]
  | cons h rest ih =>
    simp only [UnionAuthorizer.authorizeDo, List.forIn_cons, bind_pure_comp]
    cases ha : h.authorize attrs with
    | Allow => simp [ha, UnionAuthorizer.authorize]
    | Deny => simp [ha, UnionAuthorizer.authorize]
    | NoOpinion =>
      simp only [ha, UnionAuthorizer.authorize]
      simpa [UnionAuthorizer.authorizeDo] using ih

-- ── Recursive equivalent of conditionsAwareAuthorizeDo ──────────────────────

def subDecisionsDo : List Authorizer → Attributes
    → List (String × ConditionsAwareDecision)
  | [], _ => []
  | h :: rest, attrs =>
    let d := h.conditionsAwareAuthorize attrs
    if d.ContainsAllowOrDenyDo then [(h.name, d)]
    else (h.name, d) :: subDecisionsDo rest attrs

theorem UnionAuthorizer.conditionsAwareAuthorizeDo_eq_union_subDecisionsDo
    (u : UnionAuthorizer) (attrs : Attributes) :
    u.conditionsAwareAuthorizeDo attrs = .Union (subDecisionsDo u.handlers attrs) := by
  obtain ⟨handlers⟩ := u
  suffices h : ∀ (acc : List (String × ConditionsAwareDecision)),
      (Id.run do
        let mut decisions : List (String × ConditionsAwareDecision) := acc
        for currAuthzHandler in handlers do
          let decision := currAuthzHandler.conditionsAwareAuthorize attrs
          decisions := decisions ++ [(currAuthzHandler.name, decision)]
          if decision.ContainsAllowOrDenyDo then
            return (ConditionsAwareDecision.Union decisions)
        return (ConditionsAwareDecision.Union decisions))
      = ConditionsAwareDecision.Union (acc ++ subDecisionsDo handlers attrs) by
    have := h []
    simpa [UnionAuthorizer.conditionsAwareAuthorizeDo] using this
  intro acc
  induction handlers generalizing acc with
  | nil => simp [subDecisionsDo]
  | cons hd rest ih =>
    by_cases hc : (hd.conditionsAwareAuthorize attrs).ContainsAllowOrDenyDo
    · simp [hc, subDecisionsDo, List.forIn_cons]
    · simp only [subDecisionsDo, hc, List.forIn_cons, bind_pure_comp]
      have ih' := ih (acc ++ [(hd.name, hd.conditionsAwareAuthorize attrs)])
      simp only [List.append_assoc, List.cons_append] at ih' ⊢
      convert ih' using 2

-- ── evaluateConditionsLoopDo equals walk ─────────────────────────────────────

theorem evaluateConditionsLoopDo_eq_walk
    (handlers : List Authorizer) (ds : List (String × ConditionsAwareDecision))
    (data : ConditionsData) :
    evaluateConditionsLoopDo handlers ds data
    = UnionAuthorizer.evaluateConditions.walk handlers ds data := by
  simp only [evaluateConditionsLoopDo]
  induction ds with
  | nil =>
    simp [UnionAuthorizer.evaluateConditions.walk]
  | cons nd rest ih =>
    obtain ⟨name, sub⟩ := nd
    simp only [List.forIn_cons, bind_pure_comp]
    simp only [UnionAuthorizer.evaluateConditions.walk]
    cases sub with
    | Allow => simp
    | Deny => simp
    | NoOpinion =>
      simp only []
      convert ih using 2
    | ConditionsMap cm =>
      cases hget : getAuthorizerWithName handlers name with
      | none => simp
      | some a =>
        simp only []
        cases hec : a.evaluateConditions (.ConditionsMap cm) data with
        | Allow => simp
        | Deny => simp
        | NoOpinion =>
          simp only []
          convert ih using 2
    | Union ds' =>
      cases hget : getAuthorizerWithName handlers name with
      | none => simp
      | some a =>
        simp only []
        cases hec : a.evaluateConditions (.Union ds') data with
        | Allow => simp
        | Deny => simp
        | NoOpinion =>
          simp only []
          convert ih using 2

theorem UnionAuthorizer.evaluateConditionsDo_eq (u : UnionAuthorizer)
    (decision : ConditionsAwareDecision) (data : ConditionsData) :
    u.evaluateConditionsDo decision data = u.evaluateConditions decision data := by
  cases decision with
  | Allow | Deny | NoOpinion =>
    simp [UnionAuthorizer.evaluateConditionsDo, UnionAuthorizer.evaluateConditions]
  | ConditionsMap _ =>
    simp [UnionAuthorizer.evaluateConditionsDo, UnionAuthorizer.evaluateConditions]
  | Union ds =>
    show evaluateConditionsLoopDo u.handlers ds data
       = UnionAuthorizer.evaluateConditions.walk u.handlers ds data
    exact evaluateConditionsLoopDo_eq_walk u.handlers ds data

-- ── walk on subDecisionsDo equals idealAuthorize ────────────────────────────

private theorem walk_subDecisionsDo_eq_idealAuthorize_aux
    (allHandlers suffix : List Authorizer) (attrs : Attributes) (data : ConditionsData)
    (h_lookup : ∀ a, a ∈ suffix → getAuthorizerWithName allHandlers a.name = some a)
    : UnionAuthorizer.evaluateConditions.walk allHandlers
        (subDecisionsDo suffix attrs) data
    = UnionAuthorizer.idealAuthorize ⟨suffix⟩ attrs data := by
  induction suffix with
  | nil =>
    simp [subDecisionsDo, UnionAuthorizer.evaluateConditions.walk,
          UnionAuthorizer.idealAuthorize]
  | cons h rest ih =>
    have h_head := h_lookup h (by simp)
    have h_tail : ∀ a, a ∈ rest → getAuthorizerWithName allHandlers a.name = some a :=
      fun a ha => h_lookup a (by simp [ha])
    cases hca : h.conditionsAwareAuthorize attrs with
    | Allow =>
      have : ConditionsAwareDecision.Allow.ContainsAllowOrDenyDo = true := rfl
      simp [subDecisionsDo, hca, this,
            UnionAuthorizer.evaluateConditions.walk,
            UnionAuthorizer.idealAuthorize, Authorizer.idealAuthorize,
            ConditionsAwareDecision.Ideal]
    | Deny =>
      have : ConditionsAwareDecision.Deny.ContainsAllowOrDenyDo = true := rfl
      simp [subDecisionsDo, hca, this,
            UnionAuthorizer.evaluateConditions.walk,
            UnionAuthorizer.idealAuthorize, Authorizer.idealAuthorize,
            ConditionsAwareDecision.Ideal]
    | NoOpinion =>
      simp only [subDecisionsDo, hca,
                 UnionAuthorizer.idealAuthorize, Authorizer.idealAuthorize,
                 ConditionsAwareDecision.Ideal]
      exact ih h_tail
    | ConditionsMap c =>
      have hcad : (ConditionsAwareDecision.ConditionsMap c).ContainsAllowOrDenyDo = false := rfl
      have h_sub : subDecisionsDo (h :: rest) attrs
          = (h.name, ConditionsAwareDecision.ConditionsMap c) :: subDecisionsDo rest attrs := by
        simp [subDecisionsDo, hca, hcad]
      have heval := h.contract_eval_eq_ideal attrs (Or.inl ⟨c, hca⟩) data
      rw [hca] at heval
      simp only [ConditionsAwareDecision.Ideal, ConditionsMap.Ideal] at heval
      rw [h_sub]
      simp only [UnionAuthorizer.evaluateConditions.walk, h_head, heval,
                 UnionAuthorizer.idealAuthorize, Authorizer.idealAuthorize, hca,
                 ConditionsAwareDecision.Ideal, ConditionsMap.Ideal]
      cases c.evaluate data <;> first | rfl | exact ih h_tail
    | Union ds =>
      have heval := h.contract_eval_eq_ideal attrs (Or.inr ⟨ds, hca⟩) data
      rw [hca] at heval
      simp only [ConditionsAwareDecision.Ideal] at heval
      by_cases hcd : (ConditionsAwareDecision.Union ds).ContainsAllowOrDenyDo
      · have h_sub : subDecisionsDo (h :: rest) attrs
            = [(h.name, ConditionsAwareDecision.Union ds)] := by
          simp [subDecisionsDo, hca, hcd]
        have hcd_pf : (ConditionsAwareDecision.Union ds).ContainsAllowOrDeny = true := by
          rw [← ConditionsAwareDecision.ContainsAllowOrDenyDo_eq]; exact hcd
        rw [h_sub]
        simp only [UnionAuthorizer.evaluateConditions.walk, h_head, heval,
                   UnionAuthorizer.idealAuthorize, Authorizer.idealAuthorize, hca,
                   ConditionsAwareDecision.Ideal]
        have hAD := containsAllowOrDeny_implies_ideal_AllowOrDeny
            (ConditionsAwareDecision.Union ds) data hcd_pf
        simp only [ConditionsAwareDecision.Ideal] at hAD
        cases hunion : unionIdealAuthorize ds data with
        | Allow => rfl
        | Deny => rfl
        | NoOpinion =>
          cases hAD with
          | inl hl => rw [hunion] at hl; exact absurd hl (by decide)
          | inr hr => rw [hunion] at hr; exact absurd hr (by decide)
      · have hcd_f : (ConditionsAwareDecision.Union ds).ContainsAllowOrDenyDo = false :=
          Bool.eq_false_iff.mpr hcd
        have h_sub : subDecisionsDo (h :: rest) attrs
            = (h.name, ConditionsAwareDecision.Union ds) :: subDecisionsDo rest attrs := by
          simp [subDecisionsDo, hca, hcd_f]
        rw [h_sub]
        simp only [UnionAuthorizer.evaluateConditions.walk, h_head, heval,
                   UnionAuthorizer.idealAuthorize, Authorizer.idealAuthorize, hca,
                   ConditionsAwareDecision.Ideal]
        cases unionIdealAuthorize ds data <;> first | rfl | exact ih h_tail

-- ── Headline: Go-Do composition equals idealAuthorize ───────────────────────

theorem UnionAuthorizer.composition_do_eq_ideal (u : UnionAuthorizer)
    (attrs : Attributes) (data : ConditionsData)
    (h_unique : ∀ h, h ∈ u.handlers → getAuthorizerWithName u.handlers h.name = some h)
    : u.evaluateConditionsDo (u.conditionsAwareAuthorizeDo attrs) data
    = u.idealAuthorize attrs data := by
  rw [u.conditionsAwareAuthorizeDo_eq_union_subDecisionsDo attrs]
  show evaluateConditionsLoopDo u.handlers (subDecisionsDo u.handlers attrs) data
     = u.idealAuthorize attrs data
  rw [evaluateConditionsLoopDo_eq_walk]
  exact walk_subDecisionsDo_eq_idealAuthorize_aux u.handlers u.handlers attrs data h_unique

-- ── Do spec theorems ────────────────────────────────────────────────────────

theorem UnionAuthorizer.metadata_allow_implies_ideal_allow_Do (u : UnionAuthorizer)
    (attrs : Attributes) (data : ConditionsData)
    (h : u.authorizeDo attrs = .Allow)
    : u.idealAuthorize attrs data = .Allow := by
  rw [u.authorizeDo_eq] at h
  exact u.metadata_allow_implies_ideal_allow attrs data h

theorem UnionAuthorizer.ideal_deny_implies_authorize_deny_Do (u : UnionAuthorizer)
    (attrs : Attributes) (data : ConditionsData)
    (h : u.idealAuthorize attrs data = .Deny)
    : u.authorizeDo attrs = .Deny := by
  rw [u.authorizeDo_eq]
  exact u.ideal_deny_implies_authorize_deny attrs data h

end ConditionalAuthorization.Union

-- ============================================================================
-- #check lines verifying Go-Do signatures
-- ============================================================================

namespace ConditionalAuthorization.Go

open ConditionalAuthorization.Authorizer
open ConditionalAuthorization.Union

#check (Attributes.isReadOnlyDo : Attributes → Bool)
#check (ConditionsAwareDecision.ContainsAllowOrDenyDo : ConditionsAwareDecision → Bool)
#check (UnionAuthorizer.authorizeDo : UnionAuthorizer → Attributes → Decision)
#check (UnionAuthorizer.conditionsAwareAuthorizeDo :
          UnionAuthorizer → Attributes → ConditionsAwareDecision)
#check (UnionAuthorizer.evaluateConditionsDo :
          UnionAuthorizer → ConditionsAwareDecision → ConditionsData → Decision)
#check (UnionAuthorizer.evaluateConditionsDo_eq :
          ∀ (u : UnionAuthorizer) (d : ConditionsAwareDecision) (data : ConditionsData),
            u.evaluateConditionsDo d data = u.evaluateConditions d data)

end ConditionalAuthorization.Go
