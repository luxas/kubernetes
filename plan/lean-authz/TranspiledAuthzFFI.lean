import TranspiledAuthz
import Lean.Data.Json

/-!
# FFI exports for the transpiled authorization model.

Exposes the core transpiled functions via `@[export]` so they can be called
from Go (or any language) through Lean's C FFI. Uses JSON as the serialization
format for inputs and outputs.

- `lean_authz_evaluate(ByteArray) → String`: Given a JSON-encoded list of
  handler descriptions, computes UnionAuthorize, Pipeline, UnionEvaluateConditions,
  and SliceCBA, returning all results as a JSON string.
-/

open TranspiledAuthz Lean

-- ============================================================================
-- JSON-serializable types
-- ============================================================================

structure HandlerJson where
  authorizeIdeal         : String
  authorizeMetadata      : String
  conditionsAwareAuthorize : String
  cmCanBecomeAllowed     : Bool
  evaluateConditions     : String
  deriving FromJson, ToJson

structure AuthzInput where
  handlers : Option (List HandlerJson) := none
  deriving FromJson, ToJson

structure AuthzOutput where
  unionAuthorize         : String
  unionAuthorizeMetadata : String
  pipeline               : String
  evaluateEntries        : String
  sliceCBA               : Bool
  deriving FromJson, ToJson

structure ErrorOutput where
  error : String
  deriving ToJson

-- ============================================================================
-- Conversion helpers
-- ============================================================================

def parseDecision (s : String) : Decision :=
  match s with
  | "Allow"     => .Allow
  | "Deny"      => .Deny
  | _           => .NoOpinion

def parseLeafDecision (s : String) : LeafDecision :=
  match s with
  | "Allow"          => .Allow
  | "Deny"           => .Deny
  | "NoOpinion"      => .NoOpinion
  | "ConditionsMap"  => .ConditionsMap
  | _                => .NoOpinion

def decisionToString : Decision → String
  | .Allow     => "Allow"
  | .Deny      => "Deny"
  | .NoOpinion => "NoOpinion"

/-- Validate and construct a Handler from JSON. Rejects incoherent inputs
    so that all axioms hold by construction. -/
def toHandler (h : HandlerJson) : Except String Handler :=
  let ideal := parseDecision h.authorizeIdeal
  let md := parseDecision h.authorizeMetadata
  let ca := parseLeafDecision h.conditionsAwareAuthorize
  let cba := h.cmCanBecomeAllowed
  let eval := parseDecision h.evaluateConditions
  match ca with
  | .Allow =>
    -- ax_allow: ideal = Allow; ax_metadata_unconditional: meta = ideal
    match ideal, md with
    | .Allow, .Allow =>
      .ok { authorizeIdeal := .Allow, authorizeMetadata := .Allow,
            conditionsAwareAuthorize := .Allow,
            cmCanBecomeAllowed := cba, evaluateConditions := eval,
            ax_allow := fun _ => rfl, ax_deny := fun h => absurd h (by decide),
            ax_noOpinion := fun h => absurd h (by decide),
            ax_conditional := fun h => absurd h (by decide),
            ax_cba_sound := fun h => absurd h (by decide),
            ax_metadata_unconditional := fun _ => rfl,
            ax_metadata_allow := fun _ => rfl,
            ax_metadata_deny := fun h => absurd h (by decide),
            ax_metadata_noOpinion_fail_closed := fun h => absurd h (by decide) }
    | _, _ => .error s!"incoherent: ca=Allow requires ideal=Allow, meta=Allow"
  | .Deny =>
    match ideal, md with
    | .Deny, .Deny =>
      .ok { authorizeIdeal := .Deny, authorizeMetadata := .Deny,
            conditionsAwareAuthorize := .Deny,
            cmCanBecomeAllowed := cba, evaluateConditions := eval,
            ax_allow := fun h => absurd h (by decide), ax_deny := fun _ => rfl,
            ax_noOpinion := fun h => absurd h (by decide),
            ax_conditional := fun h => absurd h (by decide),
            ax_cba_sound := fun h => absurd h (by decide),
            ax_metadata_unconditional := fun _ => rfl,
            ax_metadata_allow := fun h => absurd h (by decide),
            ax_metadata_deny := fun _ => rfl,
            ax_metadata_noOpinion_fail_closed := fun h => absurd h (by decide) }
    | _, _ => .error s!"incoherent: ca=Deny requires ideal=Deny, meta=Deny"
  | .NoOpinion =>
    match ideal, md with
    | .NoOpinion, .NoOpinion =>
      .ok { authorizeIdeal := .NoOpinion, authorizeMetadata := .NoOpinion,
            conditionsAwareAuthorize := .NoOpinion,
            cmCanBecomeAllowed := cba, evaluateConditions := eval,
            ax_allow := fun h => absurd h (by decide),
            ax_deny := fun h => absurd h (by decide),
            ax_noOpinion := fun _ => rfl,
            ax_conditional := fun h => absurd h (by decide),
            ax_cba_sound := fun h => absurd h (by decide),
            ax_metadata_unconditional := fun _ => rfl,
            ax_metadata_allow := fun h => absurd h (by decide),
            ax_metadata_deny := fun h => absurd h (by decide),
            ax_metadata_noOpinion_fail_closed := fun _ => .inl rfl }
    | _, _ => .error s!"incoherent: ca=NoOpinion requires ideal=NoOpinion, meta=NoOpinion"
  | .ConditionsMap =>
    -- ax_conditional: ideal = eval
    -- ax_metadata_*: meta follows ideal with possible fail-closed
    -- ax_cba_sound: cba=false → eval ≠ Allow
    if ideal != eval then .error s!"incoherent: ca=ConditionsMap requires ideal=eval"
    else
    match eval, md with
    | .Allow, .Allow =>
      if hcba : cba = false
      then .error "incoherent: cba=false but eval=Allow"
      else .ok { authorizeIdeal := .Allow, authorizeMetadata := .Allow,
                 conditionsAwareAuthorize := .ConditionsMap,
                 cmCanBecomeAllowed := cba, evaluateConditions := .Allow,
                 ax_allow := fun h => absurd h (by decide),
                 ax_deny := fun h => absurd h (by decide),
                 ax_noOpinion := fun h => absurd h (by decide),
                 ax_conditional := fun _ => rfl,
                 ax_cba_sound := fun _ h => absurd h hcba,
                 ax_metadata_unconditional := fun h => absurd rfl h,
                 ax_metadata_allow := fun _ => rfl,
                 ax_metadata_deny := fun h => absurd h (by decide),
                 ax_metadata_noOpinion_fail_closed := fun h => absurd h (by decide) }
    | .Deny, .Deny =>
      .ok { authorizeIdeal := .Deny, authorizeMetadata := .Deny,
            conditionsAwareAuthorize := .ConditionsMap,
            cmCanBecomeAllowed := cba, evaluateConditions := .Deny,
            ax_allow := fun h => absurd h (by decide),
            ax_deny := fun h => absurd h (by decide),
            ax_noOpinion := fun h => absurd h (by decide),
            ax_conditional := fun _ => rfl,
            ax_cba_sound := fun _ _ h => absurd h (by decide),
            ax_metadata_unconditional := fun h => absurd rfl h,
            ax_metadata_allow := fun h => absurd h (by decide),
            ax_metadata_deny := fun _ => rfl,
            ax_metadata_noOpinion_fail_closed := fun h => absurd h (by decide) }
    | .NoOpinion, .NoOpinion =>
      .ok { authorizeIdeal := .NoOpinion, authorizeMetadata := .NoOpinion,
            conditionsAwareAuthorize := .ConditionsMap,
            cmCanBecomeAllowed := cba, evaluateConditions := .NoOpinion,
            ax_allow := fun h => absurd h (by decide),
            ax_deny := fun h => absurd h (by decide),
            ax_noOpinion := fun h => absurd h (by decide),
            ax_conditional := fun _ => rfl,
            ax_cba_sound := fun _ _ h => absurd h (by decide),
            ax_metadata_unconditional := fun h => absurd rfl h,
            ax_metadata_allow := fun h => absurd h (by decide),
            ax_metadata_deny := fun h => absurd h (by decide),
            ax_metadata_noOpinion_fail_closed := fun _ => .inl rfl }
    | .NoOpinion, .Deny =>
      -- Fail-closed: ideal=NoOpinion but metadata=Deny (allowed by ax_metadata_noOpinion_fail_closed)
      .ok { authorizeIdeal := .NoOpinion, authorizeMetadata := .Deny,
            conditionsAwareAuthorize := .ConditionsMap,
            cmCanBecomeAllowed := cba, evaluateConditions := .NoOpinion,
            ax_allow := fun h => absurd h (by decide),
            ax_deny := fun h => absurd h (by decide),
            ax_noOpinion := fun h => absurd h (by decide),
            ax_conditional := fun _ => rfl,
            ax_cba_sound := fun _ _ h => absurd h (by decide),
            ax_metadata_unconditional := fun h => absurd rfl h,
            ax_metadata_allow := fun h => absurd h (by decide),
            ax_metadata_deny := fun h => absurd h (by decide),
            ax_metadata_noOpinion_fail_closed := fun _ => .inr rfl }
    | _, _ => .error s!"incoherent: ca=ConditionsMap, eval={h.evaluateConditions}, meta={h.authorizeMetadata} not valid"

-- ============================================================================
-- Core FFI function
-- ============================================================================

@[export lean_authz_evaluate]
def leanAuthzEvaluate (input : @& ByteArray) : String :=
  let inputStr := String.fromUTF8! input
  match Json.parse inputStr >>= fromJson? (α := AuthzInput) with
  | .error e => toString (toJson (ErrorOutput.mk s!"parse error: {e}"))
  | .ok inp =>
    match (inp.handlers.getD []).mapM toHandler with
    | .error e => toString (toJson (ErrorOutput.mk e))
    | .ok handlers =>
      let entries := UnionConditionsAwareAuthorize handlers
      let result : AuthzOutput := {
        unionAuthorize := decisionToString (UnionAuthorize handlers)
        unionAuthorizeMetadata := decisionToString (UnionAuthorizeMetadata handlers)
        pipeline := decisionToString (PipelineDecision handlers)
        evaluateEntries := decisionToString (UnionEvaluateConditions entries)
        sliceCBA := UnionSliceCanBecomeAllowed entries
      }
      toString (toJson result)
