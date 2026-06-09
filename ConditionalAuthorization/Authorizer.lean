import Mathlib.Data.Finset.Basic

namespace ConditionalAuthorization.Authorizer

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

/-- Mirrors Go's `ConditionsMap.PossibleDecisions` (conditionsmap.go:97-106).
    Returns the set of decisions this ConditionsMap can possibly evaluate to. -/
def ConditionsMap.PossibleDecisions (c : ConditionsMap) : Finset Decision :=
  {.NoOpinion} ∪ (if c.hasDenyCondition then {.Deny} else ∅)
               ∪ (if c.hasAllowCondition then {.Allow} else ∅)

/-- Mirrors Go's `ConditionsMap.FailureDecision` (conditionsmap.go:49-54).
    Fails closed with Deny if Deny is a possible outcome, otherwise NoOpinion. -/
def ConditionsMap.FailureDecision (c : ConditionsMap) : Decision :=
  if .Deny ∈ c.PossibleDecisions then .Deny else .NoOpinion

def ConditionsMap.Ideal (c : ConditionsMap) (d : ConditionsData) : Decision :=
  c.evaluate d

/-- A conditions-aware decision: either a leaf decision, a conditional ConditionsMap,
    or a union (chain) of named decisions. Mirrors Go's `ConditionsAwareDecision`.
    The `Union` variant carries `List (String × ConditionsAwareDecision)` matching
    Go's `ConditionsAwareDecisionUnion.inner : []namedConditionsAwareDecision`. -/
inductive ConditionsAwareDecision where
  | Allow
  | Deny
  | NoOpinion
  | ConditionsMap (cm: ConditionsMap)
  | Union (decisions : List (String × ConditionsAwareDecision))

/-- Mirrors Go's `ConditionsAwareDecision.ContainsAllowOrDeny` (conditionsawaredecision.go:196-204)
    and `ConditionsAwareDecisionUnion.ContainsAllowOrDeny` (union.go:67-74). -/
def ConditionsAwareDecision.ContainsAllowOrDeny : ConditionsAwareDecision → Bool
  | .Allow     => true
  | .Deny      => true
  | .NoOpinion => false
  | .ConditionsMap _ => false
  | .Union ds => anyContainsAllowOrDeny ds
where
  anyContainsAllowOrDeny : List (String × ConditionsAwareDecision) → Bool
    | []         => false
    | (_, d) :: ds => d.ContainsAllowOrDeny || anyContainsAllowOrDeny ds

/-- Mirrors Go's `ConditionsAwareDecision.PossibleDecisions` (conditionsawaredecision.go:307-320)
    and `ConditionsAwareDecisionUnion.PossibleDecisions` (union.go:76-88).
    The union version starts with {NoOpinion}, unions each sub-decision's PossibleDecisions,
    and erases NoOpinion if any sub-decision ContainsAllowOrDeny (short-circuit). -/
def ConditionsAwareDecision.PossibleDecisions : ConditionsAwareDecision → Finset Decision
  | .Allow => {.Allow}
  | .Deny => {.Deny}
  | .NoOpinion => {.NoOpinion}
  | .ConditionsMap cm => cm.PossibleDecisions
  | .Union ds =>
      let collected := collectUnionPossibleDecisions ds
      if ConditionsAwareDecision.ContainsAllowOrDeny.anyContainsAllowOrDeny ds
      then collected.erase .NoOpinion
      else {.NoOpinion} ∪ collected
where
  collectUnionPossibleDecisions : List (String × ConditionsAwareDecision) → Finset Decision
    | [] => ∅
    | (_, d) :: rest =>
        if d.ContainsAllowOrDeny then d.PossibleDecisions
        else d.PossibleDecisions ∪ collectUnionPossibleDecisions rest

/-- Mirrors Go's `ConditionsAwareDecision.FailureDecision` (conditionsawaredecision.go:187-192).
    Fails closed: Deny if PossibleDecisions includes Deny, otherwise NoOpinion. -/
def ConditionsAwareDecision.FailureDecision (d : ConditionsAwareDecision) : Decision :=
  if .Deny ∈ d.PossibleDecisions then .Deny else .NoOpinion

/-- The ideal evaluation of a union chain of named decisions. Iterates through the
    (name, decision) pairs, short-circuiting on Allow/Deny, recursing on NoOpinion,
    and evaluating ConditionsMap/Union sub-decisions. -/
def unionIdealAuthorize (decisions : List (String × ConditionsAwareDecision)) (data : ConditionsData) : Decision :=
  match decisions with
  | [] => .NoOpinion
  | (_, d) :: rest =>
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



end ConditionalAuthorization.Authorizer
