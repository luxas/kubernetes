/-
  AuthzAfter.lean — Post-KEP 5681 Kubernetes Authorization Model

  Extends the pre-KEP model with conditional authorization. The key additions:
  - Conditions: residual expressions that depend on request/object data
  - ConditionSet: a set of conditions from a single authorizer
  - Conditional decisions: decisions that carry condition sets + remaining chain
  - ConditionSet evaluation algorithm (deny > noOpinion > allow)
  - Lazy chain evaluation with conditional short-circuiting
  - Condition enforcement at admission time
-/

import Kubernetes.AuthzBefore

namespace Kubernetes.AuthzAfter

-- ============================================================================
-- Condition Data (available at admission time, not at authorization time)
-- ============================================================================

/-- Opaque request/object data available during condition evaluation.
    In Go, this is the ConditionData interface providing GetObject(),
    GetOldObject(), GetOperation(), GetOperationOptions(). -/
structure ConditionData where
  operation : String
  /-- We model objects as opaque identifiers; real impl uses runtime.Object -/
  object : Option String
  oldObject : Option String
  deriving Repr

-- ============================================================================
-- Conditions
-- ============================================================================

/-- How a condition evaluating to `true` should affect the decision.
    Models the Go ConditionEffect type.

    Priority ordering: deny > noOpinion > allow
    This ordering is critical to the evaluation algorithm. -/
inductive ConditionEffect where
  /-- If true → Deny. Errors → Deny (fail closed). -/
  | deny
  /-- If true → NoOpinion. Errors → NoOpinion (fail closed). -/
  | noOpinion
  /-- If true → Allow. Errors → ignored. -/
  | allow
  deriving Repr, DecidableEq, BEq

/-- A condition is a named, typed predicate on ConditionData.

    In the real system, `eval` would be a CEL expression string that gets
    compiled and run. Here we model it directly as a function that can
    either succeed with a Bool or fail with an error. -/
structure Condition where
  id : String
  effect : ConditionEffect
  description : String := ""
  /-- The evaluation function. Returns `Except error bool`. -/
  eval : ConditionData → Except String Bool
  deriving Repr

/-- A ConditionSet groups conditions from a single authorizer.

    All conditions in a set share the same type (e.g., "k8s.io/cel").
    The set may alternatively represent an unconditional decision from
    a later authorizer in the chain (captured during eager evaluation). -/
inductive ConditionSet where
  /-- A set of conditions to be evaluated. -/
  | conditions (conditionType : String) (authorizer : String) (conds : List Condition)
  /-- An unconditional decision from a later authorizer (used in eager mode). -/
  | unconditional (decision : AuthzBefore.Decision)
  deriving Repr

-- ============================================================================
-- Extended Decision Type
-- ============================================================================

/-- ConditionsMode: how the caller wants conditions returned.
    Models the Go ConditionsMode type. -/
inductive ConditionsMode where
  | none       -- don't return conditions (default, backward compatible)
  | humanReadable
  | optimized
  deriving Repr, DecidableEq, BEq

/-- Extended attributes with conditions support. -/
structure Attributes extends AuthzBefore.Attributes where
  conditionsMode : ConditionsMode := .none
  deriving Repr

/-- The extended decision type with conditional authorization support.
    Models the Go Decision struct after KEP-5681. -/
inductive Decision where
  /-- Concrete allow with reason. -/
  | allow (reason : String := "")
  /-- Concrete deny with reason. -/
  | deny (reason : String := "")
  /-- Concrete no-opinion with reason. -/
  | noOpinion (reason : String := "")
  /-- Conditional: carries condition sets already computed, plus a
      (possibly empty) list of remaining authorizers to lazily evaluate. -/
  | conditional (conditionSets : List ConditionSet) (remainingChain : List Authorizer)
  deriving Repr

/-- An authorizer in the post-KEP model. Takes extended attributes. -/
def Authorizer := Attributes → Decision × Option AuthzBefore.AuthzError

-- ============================================================================
-- Decision Predicates
-- ============================================================================

def Decision.isAllowed : Decision → Bool
  | .allow _ => true
  | _ => false

def Decision.isDenied : Decision → Bool
  | .deny _ => true
  | _ => false

def Decision.isNoOpinion : Decision → Bool
  | .noOpinion _ => true
  | _ => false

def Decision.isConditional : Decision → Bool
  | .conditional _ _ => true
  | _ => false

def Decision.isConcrete (d : Decision) : Bool :=
  d.isAllowed || d.isDenied || d.isNoOpinion

/-- Can this decision become an Allow after condition evaluation?
    True for concrete Allow and for conditional decisions that contain
    at least one effect=allow condition. -/
def Decision.canBecomeAllowed : Decision → Bool
  | .allow _ => true
  | .conditional sets _ =>
    sets.any fun
      | .conditions _ _ conds => conds.any (·.effect == .allow)
      | .unconditional d => d.isAllowed
  | _ => false

def Decision.reason : Decision → String
  | .allow r | .deny r | .noOpinion r => r
  | .conditional _ _ => ""

-- ============================================================================
-- ConditionSet Evaluation Algorithm
-- ============================================================================

/-- Evaluate a single condition against condition data.
    Returns `Except errorMessage boolResult`. -/
def evalCondition (c : Condition) (data : ConditionData) : Except String Bool :=
  c.eval data

/-- Result of evaluating a group of conditions with the same effect. -/
inductive EffectGroupResult where
  | allFalse           -- all conditions in the group evaluated to false
  | someTrue           -- at least one condition evaluated to true
  | someError (msg : String)  -- at least one condition produced an error (and none was true)
  deriving Repr

/-- Evaluate all conditions with a given effect. -/
def evalEffectGroup (conds : List Condition) (targetEffect : ConditionEffect)
    (data : ConditionData) : EffectGroupResult :=
  let relevant := conds.filter (·.effect == targetEffect)
  relevant.foldl (fun acc c =>
    match acc with
    | .someTrue => .someTrue  -- short-circuit: already found true
    | _ =>
      match evalCondition c data with
      | .ok true => .someTrue
      | .ok false => acc
      | .error msg =>
        match acc with
        | .someError _ => acc  -- keep first error
        | _ => .someError msg
  ) .allFalse

/-- The canonical ConditionSet evaluation algorithm from the KEP.

    Priority: Deny > NoOpinion > Allow

    Step 1: Evaluate deny-effect conditions.
      - If any is true → Deny
      - If any errors (and none true) → Deny (fail closed)

    Step 2: Evaluate noOpinion-effect conditions (all deny conditions were false).
      - If any is true → NoOpinion
      - If any errors (and none true) → NoOpinion (fail closed)

    Step 3: Evaluate allow-effect conditions (all deny and noOpinion conditions were false).
      - If any is true → Allow
      - Errors are ignored
      - If none true → NoOpinion

    Returns (Decision, Option errorMessage). -/
def evaluateConditionSet (cs : ConditionSet) (data : ConditionData)
    : Decision × Option String :=
  match cs with
  | .unconditional d =>
    -- An unconditional decision from a later authorizer
    match d.kind with
    | .allow => (.allow d.reason, none)
    | .deny => (.deny d.reason, none)
    | .noOpinion => (.noOpinion d.reason, none)
  | .conditions _ _ conds =>
    -- Step 1: Deny conditions
    match evalEffectGroup conds .deny data with
    | .someTrue => (.deny "deny condition matched", none)
    | .someError msg => (.deny s!"deny condition error (fail closed): {msg}", some msg)
    | .allFalse =>
      -- Step 2: NoOpinion conditions
      match evalEffectGroup conds .noOpinion data with
      | .someTrue => (.noOpinion "noOpinion condition matched", none)
      | .someError msg => (.noOpinion s!"noOpinion condition error (fail closed): {msg}", some msg)
      | .allFalse =>
        -- Step 3: Allow conditions
        match evalEffectGroup conds .allow data with
        | .someTrue => (.allow "allow condition matched", none)
        | .someError _ => (.noOpinion "no allow condition matched (errors ignored)", none)
        | .allFalse => (.noOpinion "no allow condition matched", none)

-- ============================================================================
-- Chain Authorizer (with conditional support)
-- ============================================================================

/-- Does a ConditionSet contain at least one allow-effect condition?
    Used to distinguish "conditional allow" from "conditional deny". -/
def ConditionSet.hasAllowEffect : ConditionSet → Bool
  | .conditions _ _ conds => conds.any (·.effect == .allow)
  | .unconditional d => d.isAllowed

/-- Does a list of condition sets represent a "conditional allow"?
    A conditional allow has at least one set with an allow-effect condition. -/
def isConditionalAllow (sets : List ConditionSet) : Bool :=
  sets.any ConditionSet.hasAllowEffect

/-- Run a chain of authorizers with conditional support.

    The chain implements lazy evaluation:
    - Concrete Allow or Deny: short-circuit immediately
    - NoOpinion: skip, continue to next authorizer
    - Conditional with allow-effect ("conditional allow"):
        Short-circuit lazily — save the remaining chain for later evaluation
    - Conditional without allow-effect ("conditional deny"):
        Continue to next authorizer. If a later authorizer concretely Allows,
        the conditional deny's conditions still need evaluation.

    This models the Go union authorizer after KEP-5681. -/
def chainAuthorize (authorizers : List Authorizer) (attrs : Attributes) : Decision :=
  go authorizers [] []
where
  go : List Authorizer → List ConditionSet → List String → Decision
  | [], accSets, reasons =>
    if accSets.isEmpty then
      .noOpinion (String.intercalate "\n" reasons)
    else
      -- End of chain with accumulated conditional sets but no concrete decision.
      -- Return conditional with empty remaining chain.
      .conditional accSets []
  | authz :: rest, accSets, reasons =>
    let (decision, _err) := authz attrs
    match decision with
    | .allow r =>
      if accSets.isEmpty then
        -- No prior conditional decisions; concrete allow
        .allow r
      else
        -- Prior conditional decisions exist. The allow is unconditional
        -- relative to the later authorizer, but conditions from earlier
        -- authorizers still need evaluation.
        .conditional (accSets ++ [.unconditional (AuthzBefore.Decision.allow r)]) rest
    | .deny r =>
      if accSets.isEmpty then
        -- No prior conditional decisions; concrete deny
        .deny r
      else
        -- Prior conditional deny + later concrete deny = still need to
        -- check if the conditional deny's conditions evaluate to false
        -- (which would make it noOpinion, and then the concrete deny applies)
        .conditional (accSets ++ [.unconditional (AuthzBefore.Decision.deny r)]) rest
    | .noOpinion r =>
      -- Skip, continue to next authorizer
      let reasons' := if r.isEmpty then reasons else reasons ++ [r]
      go rest accSets reasons'
    | .conditional sets remainingInner =>
      if isConditionalAllow sets then
        -- Conditional allow: short-circuit lazily.
        -- Save the remaining outer chain (rest) for later evaluation.
        -- Also include any inner remaining chain.
        .conditional (accSets ++ sets) (remainingInner ++ rest)
      else
        -- Conditional deny: accumulate the condition sets and continue
        -- to look for a possible allow from later authorizers.
        go rest (accSets ++ sets) reasons

-- ============================================================================
-- Condition Enforcement (at admission time)
-- ============================================================================

/-- Enforce conditions from a conditional decision.

    This is called during the validating admission phase. It evaluates
    condition sets in order, short-circuiting on Allow or Deny.
    If NoOpinion, it continues to the next set. After exhausting
    precomputed sets, it lazily evaluates the remaining authorizer chain.

    Returns a concrete decision. -/
def enforceConditions (d : Decision) (data : ConditionData) (attrs : Attributes)
    : Decision :=
  match d with
  | .allow r => .allow r
  | .deny r => .deny r
  | .noOpinion r => .noOpinion r
  | .conditional sets remainingChain =>
    evaluateSets sets remainingChain data attrs
where
  evaluateSets : List ConditionSet → List Authorizer → ConditionData → Attributes → Decision
  | [], [], _, _ => .noOpinion "all condition sets evaluated to noOpinion"
  | [], remaining, data, attrs =>
    -- Lazily evaluate remaining authorizers
    let lazyDecision := chainAuthorize remaining attrs
    match lazyDecision with
    | .conditional sets' remaining' =>
      -- Recursive: the lazy chain itself returned conditional
      evaluateSets sets' remaining' data attrs
    | other => other
  | cs :: rest, remaining, data, attrs =>
    let (setDecision, _err) := evaluateConditionSet cs data
    match setDecision with
    | .allow r => .allow r
    | .deny r => .deny r
    | .noOpinion _ => evaluateSets rest remaining data attrs
    | .conditional _ _ => evaluateSets rest remaining data attrs  -- shouldn't happen

-- ============================================================================
-- WithAuthorization HTTP Filter (post-KEP)
-- ============================================================================

/-- Whether a request supports conditional authorization.
    In the real system, this checks verb, GVR, connect handlers, etc. -/
def supportsConditions (attrs : Attributes) : Bool :=
  attrs.conditionsMode != .none &&
  (attrs.verb == "create" || attrs.verb == "update" || attrs.verb == "delete" ||
   attrs.verb == "deletecollection" || attrs.verb == "connect")

/-- The outcome of the post-KEP WithAuthorization filter. -/
inductive FilterOutcome where
  /-- Request proceeds with no conditions (concrete allow). -/
  | proceed (decision : Decision)
  /-- Request proceeds with conditions to enforce at admission. -/
  | proceedConditional (decision : Decision)
  /-- Request is forbidden (403). -/
  | forbidden (reason : String)
  deriving Repr

/-- The WithAuthorization HTTP filter, extended for conditional authorization.

    If the authorizer allows concretely, proceed.
    If the authorizer returns conditional and the request supports conditions
    and the decision can become allowed, proceed conditionally.
    Otherwise, 403 Forbidden.

    The conditional decision is propagated to admission via the request
    context for enforcement by AuthorizationConditionsEnforcer. -/
def withAuthorization (authz : List Authorizer) (attrs : Attributes) : FilterOutcome :=
  let decision := chainAuthorize authz attrs
  if decision.isAllowed then
    .proceed decision
  else if decision.isConditional && supportsConditions attrs && decision.canBecomeAllowed then
    .proceedConditional decision
  else
    .forbidden decision.reason

-- ============================================================================
-- Injection from pre-KEP types (for refinement proofs)
-- ============================================================================

/-- Lift a pre-KEP decision into the post-KEP model. -/
def liftDecision (d : AuthzBefore.Decision) : Decision :=
  match d.kind with
  | .allow => .allow d.reason
  | .deny => .deny d.reason
  | .noOpinion => .noOpinion d.reason

/-- Lift pre-KEP attributes into post-KEP attributes.
    The conditionsMode defaults to .none (backward compatible). -/
def liftAttributes (a : AuthzBefore.Attributes) : Attributes :=
  { user := a.user
    verb := a.verb
    apiGroup := a.apiGroup
    resource := a.resource
    namespace := a.namespace
    name := a.name
    isResourceRequest := a.isResourceRequest
    path := a.path
    conditionsMode := .none }

/-- Lift a pre-KEP authorizer into the post-KEP model.
    The lifted authorizer never returns conditional decisions. -/
def liftAuthorizer (authz : AuthzBefore.Authorizer) : Authorizer :=
  fun attrs =>
    let result := authz attrs.toAttributes
    (liftDecision result.decision, result.error)

-- ============================================================================
-- Common Authorizer Implementations
-- ============================================================================

def alwaysAllow : Authorizer :=
  fun _ => (.allow "always allow", none)

def alwaysDeny : Authorizer :=
  fun _ => (.deny "always deny", none)

def alwaysNoOpinion : Authorizer :=
  fun _ => (.noOpinion "", none)

end Kubernetes.AuthzAfter
