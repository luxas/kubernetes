
namespace ConditionalAuthzFromScratch

-- ============================================================================
-- Types
-- ============================================================================

inductive Decision where
  | Deny | Allow | NoOpinion
  deriving Repr, DecidableEq, BEq

/-- Mirrors Go's `authorizer.AttributesRecord` (interfaces.go:138-154).
    Complex Go types (user.Info, fields.Requirements, labels.Requirements) collapse to
    plain strings — authorization correctness doesn't depend on their internal structure. -/
structure Attributes where
  user             : String
  verb             : String
  «namespace»      : String
  apiGroup         : String
  apiVersion       : String
  resource         : String
  subresource      : String
  name             : String
  resourceRequest  : Bool
  path             : String
  fieldSelector    : String
  labelSelector    : String
  deriving Repr, DecidableEq

/-- Derived from `verb` to match Go's `AttributesRecord.IsReadOnly` (interfaces.go:164-166). -/
def Attributes.isReadOnly (a : Attributes) : Bool :=
  a.verb = "get" || a.verb = "list" || a.verb = "watch"

/-- Mirrors Go's `authorizer.ConditionsDataAdmissionControl` interface (conditions.go:1008-1040).
    Complex Go types (runtime.Object, GroupVersionResource, GroupVersionKind, user.Info)
    collapse to plain strings. -/
structure ConditionsDataAdmissionControl where
  name             : String
  «namespace»      : String
  resource         : String
  subresource      : String
  operation        : String
  operationOptions : String
  isDryRun         : Bool
  object           : String
  oldObject        : String
  kind             : String
  userInfo         : String
  deriving Repr, DecidableEq

/-- Mirrors Go's `authorizer.ConditionsData` (conditions.go:993-999).
    The `admissionControl` field is `Option` because Go's comment says callers must
    verify non-nil before use. -/
structure ConditionsData where
  admissionControl : Option ConditionsDataAdmissionControl

structure ConditionsMap where
  hasDenyCondition : Bool
  hasAllowCondition : Bool
  evaluate : ConditionsData → Decision

  ax_at_least_one_allow_or_deny: hasDenyCondition = true ∨ hasAllowCondition = true
  ax_no_allow_cond_implies_never_allow : ¬hasAllowCondition → ∀ d, evaluate d ≠ .Allow
  ax_no_deny_cond_implies_never_deny : ¬hasDenyCondition → ∀ d, evaluate d ≠ .Deny

def ConditionsMap.FailClosedDecision (c : ConditionsMap) : Decision :=
  if c.hasDenyCondition then .Deny else .NoOpinion

def ConditionsMap.CanBecomeAllowed (c : ConditionsMap) : Bool :=
  c.hasAllowCondition

def ConditionsMap.Ideal (c : ConditionsMap) (d : ConditionsData) : Decision :=
  c.evaluate d

/-- A conditions-aware decision: either a leaf decision, or a union (chain) of decisions.
    Mirrors Go's `ConditionsAwareDecision`. -/
inductive ConditionsAwareDecision where
  | Allow
  | Deny
  | NoOpinion
  | ConditionsMap (cm: ConditionsMap)
  | Union (decisions : List ConditionsAwareDecision)

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

def unionIdealAuthorize (decisions : List ConditionsAwareDecision) (data : ConditionsData) : Decision :=
  match decisions with
  | [] => .NoOpinion
  | d :: rest =>
    match d with
    | .Allow     => .Allow
    | .Deny      => .Deny
    | .NoOpinion => unionIdealAuthorize rest data
    | .ConditionsMap cm =>
      match cm.Ideal data with
      | .Allow => .Allow
      | .Deny => .Deny
      | .NoOpinion => unionIdealAuthorize rest data
    | .Union subDecisions =>
      match unionIdealAuthorize subDecisions data with
      | .Allow => .Allow
      | .Deny => .Deny
      | .NoOpinion => unionIdealAuthorize rest data

/-- Returns the idealized unconditional decision from a Decision tree.
  Ideal:
  Authorize : InternalState x Attributes x ConditionsData -> Decision

  Practical:
  ConditionalAuthorize : InternalState x Attributes -> ConditionsAwareDecision
  EvaluateConditions : ConditionsAwareDecision x ConditionsData -> Decision
-/
def ConditionsAwareDecision.Ideal : ConditionsAwareDecision → ConditionsData → Decision
  | .Allow,     _ => .Allow
  | .Deny,      _ => .Deny
  | .NoOpinion, _ => .NoOpinion
  | .ConditionsMap cm, d => cm.Ideal d
  | .Union decisions, d => unionIdealAuthorize decisions d

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

namespace UnionAuthorizer

def entries (u : UnionAuthorizer) (attrs : Attributes) :=
  collectEntries u.handlers attrs

def authorize (u : UnionAuthorizer) (attrs : Attributes) : Decision :=
  unionAuthorize u.handlers attrs

def conditionsAwareAuthorize (u : UnionAuthorizer) (attrs : Attributes) : ConditionsAwareDecision :=
  .Union ((u.entries attrs).map Prod.snd)

/-- Mirrors Go's `union.EvaluateConditions` (union.go:99-152). For the `.Union ds` case,
    walks the sub-decisions paired positionally with `u.handlers` — matching Go's
    `authzHandler[i]` index correlation. Unconditional/ConditionsMap legs match Go's
    fail-closed / passthrough behavior. -/
def evaluateConditions (u : UnionAuthorizer) :
    ConditionsAwareDecision → ConditionsData → Decision :=
  fun decision data =>
    match decision with
    | .Allow => .Allow
    | .Deny => .Deny
    | .NoOpinion => .NoOpinion
    | .ConditionsMap _ => .Deny
    | .Union ds => unionEvaluateConditions (List.zip u.handlers ds) data

end UnionAuthorizer

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
      split <;> first | rfl | exact ih
    | Union ds =>
      simp only [collectEntries, hca, unionIdeal, Authorizer.idealAuthorize,
                 ConditionsAwareDecision.Ideal, List.map, unionIdealAuthorize]
      split <;> first | rfl | exact ih

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

-- ============================================================================
-- Signature verification: pin the new shapes that mirror Go's interfaces
-- ============================================================================

#check (Authorizer.authorize : Authorizer → Attributes → Decision)
#check (Authorizer.conditionsAwareAuthorize : Authorizer → Attributes → ConditionsAwareDecision)
#check (Authorizer.evaluateConditions :
          Authorizer → ConditionsAwareDecision → ConditionsData → Decision)
#check (unionAuthorize : List Authorizer → Attributes → Decision)
#check (unionEvaluateConditions :
          List (Authorizer × ConditionsAwareDecision) → ConditionsData → Decision)
#check (unionIdeal : List Authorizer → Attributes → ConditionsData → Decision)

end ConditionalAuthzFromScratch
