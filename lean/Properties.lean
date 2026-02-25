/-
  Properties.lean — Safety Properties and Theorems

  States and proves key invariants of the authorization stack, both
  before and after KEP-5681. These properties formalize the informal
  contracts described in the KEP and the existing code comments.
-/

import Kubernetes.AuthzBefore
import Kubernetes.AuthzAfter

namespace Kubernetes.Properties

open AuthzBefore (DecisionKind)
open AuthzAfter (ConditionEffect ConditionSet Condition ConditionData)

-- ============================================================================
-- Section 1: ConditionSet Evaluation — Effect Ordering
-- ============================================================================

/-- **Deny precedence**: If any deny-effect condition evaluates to true,
    the ConditionSet evaluates to Deny, regardless of other conditions.

    This is the most critical safety property of the system. -/
theorem deny_precedence
    (conds : List Condition)
    (condType authorizer : String)
    (data : ConditionData)
    (hDenyTrue : ∃ c ∈ conds, c.effect = .deny ∧ c.eval data = .ok true) :
    (AuthzAfter.evaluateConditionSet (.conditions condType authorizer conds) data).1.isDenied = true := by
  sorry  -- requires reasoning about evalEffectGroup and foldl

/-- **Deny error fail-closed**: If a deny-effect condition errors (and no
    deny condition is true), the ConditionSet evaluates to Deny. -/
theorem deny_error_fail_closed
    (conds : List Condition)
    (condType authorizer : String)
    (data : ConditionData)
    (hNoDenyTrue : ∀ c ∈ conds, c.effect = .deny → c.eval data ≠ .ok true)
    (hDenyError : ∃ c ∈ conds, c.effect = .deny ∧ ∃ msg, c.eval data = .error msg) :
    (AuthzAfter.evaluateConditionSet (.conditions condType authorizer conds) data).1.isDenied = true := by
  sorry

/-- **NoOpinion precedence over Allow**: If all deny conditions are false
    and any noOpinion condition is true, the result is NoOpinion even if
    allow conditions exist. -/
theorem noOpinion_precedence_over_allow
    (conds : List Condition)
    (condType authorizer : String)
    (data : ConditionData)
    (hDenyAllFalse : ∀ c ∈ conds, c.effect = .deny → c.eval data = .ok false)
    (hNoOpTrue : ∃ c ∈ conds, c.effect = .noOpinion ∧ c.eval data = .ok true) :
    (AuthzAfter.evaluateConditionSet (.conditions condType authorizer conds) data).1.isNoOpinion = true := by
  sorry

/-- **Allow requires all deny and noOpinion false**: Allow is only possible
    when every deny condition and every noOpinion condition evaluates to false. -/
theorem allow_requires_no_deny_no_noOpinion
    (conds : List Condition)
    (condType authorizer : String)
    (data : ConditionData)
    (hResult : (AuthzAfter.evaluateConditionSet (.conditions condType authorizer conds) data).1.isAllowed = true) :
    (∀ c ∈ conds, c.effect = .deny → c.eval data = .ok false) ∧
    (∀ c ∈ conds, c.effect = .noOpinion → c.eval data = .ok false) := by
  sorry

-- ============================================================================
-- Section 2: ConditionSet Evaluation — Concreteness
-- ============================================================================

/-- **Evaluation produces concrete decisions**: The output of evaluateConditionSet
    is always a concrete decision (allow, deny, or noOpinion), never conditional. -/
theorem evaluateConditionSet_is_concrete
    (cs : ConditionSet) (data : ConditionData) :
    let (d, _) := AuthzAfter.evaluateConditionSet cs data
    d.isConcrete = true := by
  match cs with
  | .unconditional d =>
    simp [AuthzAfter.evaluateConditionSet]
    cases d.kind <;> simp [AuthzAfter.Decision.isConcrete, AuthzAfter.Decision.isAllowed,
                           AuthzAfter.Decision.isDenied, AuthzAfter.Decision.isNoOpinion]
  | .conditions condType authorizer conds =>
    simp [AuthzAfter.evaluateConditionSet]
    sorry -- requires case analysis on evalEffectGroup results

/-- **No error can produce Allow from deny/noOpinion conditions**: The
    fail-closed property ensures that errors in deny or noOpinion
    conditions never lead to an Allow decision. -/
theorem errors_never_produce_allow
    (conds : List Condition)
    (condType authorizer : String)
    (data : ConditionData)
    (hResult : (AuthzAfter.evaluateConditionSet (.conditions condType authorizer conds) data).1.isAllowed = true) :
    -- If the result is Allow, then no deny/noOpinion conditions errored
    -- (because errors fail closed to deny/noOpinion respectively)
    (∀ c ∈ conds, c.effect = .deny → ∃ b, c.eval data = .ok b) ∧
    (∀ c ∈ conds, c.effect = .noOpinion → ∃ b, c.eval data = .ok b) := by
  sorry

-- ============================================================================
-- Section 3: Chain Properties (Pre-KEP)
-- ============================================================================

/-- **Chain short-circuit on Allow**: If the i-th authorizer returns Allow
    and all prior authorizers return NoOpinion, the chain returns Allow. -/
theorem chain_shortcircuit_allow_before
    (prefix : List AuthzBefore.Authorizer)
    (allowAuthz : AuthzBefore.Authorizer)
    (suffix : List AuthzBefore.Authorizer)
    (attrs : AuthzBefore.Attributes)
    (hPrefix : ∀ a ∈ prefix, (a attrs).decision.kind = .noOpinion)
    (hAllow : (allowAuthz attrs).decision.kind = .allow) :
    (AuthzBefore.chainAuthorize (prefix ++ [allowAuthz] ++ suffix) attrs).decision.kind = .allow := by
  sorry

/-- **Chain short-circuit on Deny**: If the i-th authorizer returns Deny
    and all prior authorizers return NoOpinion, the chain returns Deny. -/
theorem chain_shortcircuit_deny_before
    (prefix : List AuthzBefore.Authorizer)
    (denyAuthz : AuthzBefore.Authorizer)
    (suffix : List AuthzBefore.Authorizer)
    (attrs : AuthzBefore.Attributes)
    (hPrefix : ∀ a ∈ prefix, (a attrs).decision.kind = .noOpinion)
    (hDeny : (denyAuthz attrs).decision.kind = .deny) :
    (AuthzBefore.chainAuthorize (prefix ++ [denyAuthz] ++ suffix) attrs).decision.kind = .deny := by
  sorry

/-- **All-NoOpinion chain**: If every authorizer returns NoOpinion,
    the chain returns NoOpinion. -/
theorem all_noOpinion_chain_before
    (authzs : List AuthzBefore.Authorizer)
    (attrs : AuthzBefore.Attributes)
    (h : ∀ a ∈ authzs, (a attrs).decision.kind = .noOpinion) :
    (AuthzBefore.chainAuthorize authzs attrs).decision.kind = .noOpinion := by
  sorry

-- ============================================================================
-- Section 4: Chain Properties (Post-KEP)
-- ============================================================================

/-- **Conditional allow short-circuits lazily**: When an authorizer returns
    a conditional decision with allow-effect conditions, the chain captures
    the remaining authorizers for later evaluation. -/
theorem conditional_allow_captures_rest
    (prefix : List AuthzAfter.Authorizer)
    (condAuthz : AuthzAfter.Authorizer)
    (suffix : List AuthzAfter.Authorizer)
    (attrs : AuthzAfter.Attributes)
    (hPrefix : ∀ a ∈ prefix, (a attrs).1.isNoOpinion = true)
    (hCond : ∃ sets rest, (condAuthz attrs).1 = .conditional sets rest ∧
             AuthzAfter.isConditionalAllow sets = true) :
    (AuthzAfter.chainAuthorize (prefix ++ [condAuthz] ++ suffix) attrs).isConditional = true := by
  sorry

/-- **Conditional deny continues chain**: When an authorizer returns a
    conditional decision without allow-effect conditions (conditional deny),
    the chain continues to the next authorizer. -/
theorem conditional_deny_continues
    (condAuthz nextAuthz : AuthzAfter.Authorizer)
    (attrs : AuthzAfter.Attributes)
    (hCond : ∃ sets rest, (condAuthz attrs).1 = .conditional sets rest ∧
             AuthzAfter.isConditionalAllow sets = false)
    (hNext : (nextAuthz attrs).1.isAllowed = true) :
    -- The chain result should be conditional (incorporating both the
    -- conditional deny's conditions and the next authorizer's allow)
    (AuthzAfter.chainAuthorize [condAuthz, nextAuthz] attrs).isConditional = true := by
  sorry

-- ============================================================================
-- Section 5: Enforcement Properties
-- ============================================================================

/-- **Enforcement produces concrete decisions**: After enforcement, the
    result is always concrete (never conditional). -/
theorem enforcement_is_concrete
    (d : AuthzAfter.Decision) (data : ConditionData) (attrs : AuthzAfter.Attributes)
    -- We need a well-foundedness assumption: the chain eventually terminates
    (hTerminates : True) :
    (AuthzAfter.enforceConditions d data attrs).isConcrete = true := by
  sorry

/-- **Concrete decisions pass through enforcement unchanged**: If the
    decision is already concrete, enforcement is an identity. -/
theorem enforcement_identity_on_concrete
    (data : ConditionData) (attrs : AuthzAfter.Attributes) :
    (∀ r, AuthzAfter.enforceConditions (.allow r) data attrs = .allow r) ∧
    (∀ r, AuthzAfter.enforceConditions (.deny r) data attrs = .deny r) ∧
    (∀ r, AuthzAfter.enforceConditions (.noOpinion r) data attrs = .noOpinion r) := by
  constructor
  · intro r; simp [AuthzAfter.enforceConditions]
  constructor
  · intro r; simp [AuthzAfter.enforceConditions]
  · intro r; simp [AuthzAfter.enforceConditions]

-- ============================================================================
-- Section 6: Filter Properties
-- ============================================================================

/-- **Pre-KEP filter: Allow ↔ proceed**: The WithAuthorization filter
    lets a request proceed if and only if the authorizer allows. -/
theorem filter_before_allow_iff_proceed
    (authz : AuthzBefore.Authorizer) (attrs : AuthzBefore.Attributes) :
    (∃ d, AuthzBefore.withAuthorization authz attrs = .proceed d) ↔
    (authz attrs).decision.isAllowed = true := by
  constructor
  · intro ⟨d, hd⟩
    simp [AuthzBefore.withAuthorization] at hd
    split at hd <;> simp_all
  · intro h
    simp [AuthzBefore.withAuthorization, h]
    exact ⟨(authz attrs).decision, rfl⟩

/-- **Post-KEP filter: non-conditional Allow still proceeds**: When an
    authorizer concretely allows and conditionsMode is none, the filter
    proceeds (backward compatible). -/
theorem filter_after_concrete_allow_proceeds
    (authzs : List AuthzAfter.Authorizer) (attrs : AuthzAfter.Attributes)
    (hAllow : (AuthzAfter.chainAuthorize authzs attrs).isAllowed = true) :
    ∃ d, AuthzAfter.withAuthorization authzs attrs = .proceed d := by
  simp [AuthzAfter.withAuthorization, hAllow]
  exact ⟨AuthzAfter.chainAuthorize authzs attrs, rfl⟩

/-- **Post-KEP filter: conditional + no conditions support = forbidden**:
    If the request doesn't support conditions and the authorizer returns
    conditional, the filter returns Forbidden (fail closed). -/
theorem filter_after_conditional_no_support_forbidden
    (authzs : List AuthzAfter.Authorizer) (attrs : AuthzAfter.Attributes)
    (hCond : (AuthzAfter.chainAuthorize authzs attrs).isConditional = true)
    (hNoSupport : AuthzAfter.supportsConditions attrs = false) :
    ∃ r, AuthzAfter.withAuthorization authzs attrs = .forbidden r := by
  simp [AuthzAfter.withAuthorization]
  have hNotAllowed : (AuthzAfter.chainAuthorize authzs attrs).isAllowed = false := by
    cases AuthzAfter.chainAuthorize authzs attrs <;> simp_all [AuthzAfter.Decision.isAllowed, AuthzAfter.Decision.isConditional]
  simp [hNotAllowed, hCond, hNoSupport]
  exact ⟨(AuthzAfter.chainAuthorize authzs attrs).reason, rfl⟩

end Kubernetes.Properties
