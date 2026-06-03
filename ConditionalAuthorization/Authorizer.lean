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



end ConditionalAuthorization.Authorizer
