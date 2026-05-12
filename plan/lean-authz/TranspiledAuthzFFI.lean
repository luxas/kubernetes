import TranspiledAuthz
import Lean.Data.Json

/-!
# FFI exports for the transpiled authorization model.

Exposes the core transpiled functions via `@[export]` so they can be called
from Go (or any language) through Lean's C FFI. Uses JSON as the serialization
format for inputs and outputs.

## Exported C functions

- `lean_authz_evaluate(ByteArray) → String`: Given a JSON-encoded list of
  handler descriptions, computes UnionAuthorize, Pipeline, UnionEvaluateConditions,
  and SliceCBA, returning all results as a JSON string.
-/

open TranspiledAuthz Lean

-- ============================================================================
-- JSON-serializable types
-- ============================================================================

structure HandlerJson where
  authorize              : String
  conditionsAwareAuthorize : String
  cmCanBecomeAllowed     : Bool
  evaluateConditions     : String
  deriving FromJson, ToJson

structure AuthzInput where
  handlers : Option (List HandlerJson) := none
  deriving FromJson, ToJson

structure AuthzOutput where
  unionAuthorize        : String
  pipeline              : String
  evaluateEntries       : String
  sliceCBA              : Bool
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

def toHandler (h : HandlerJson) : Handler where
  authorize := parseDecision h.authorize
  conditionsAwareAuthorize := parseLeafDecision h.conditionsAwareAuthorize
  cmCanBecomeAllowed := h.cmCanBecomeAllowed
  evaluateConditions := parseDecision h.evaluateConditions

-- ============================================================================
-- Core FFI function
-- ============================================================================

/-- The main FFI entry point. Takes a JSON-encoded `AuthzInput` as a ByteArray,
    runs all four transpiled functions, and returns a JSON-encoded `AuthzOutput`.

    This is called from Go via cgo. -/
@[export lean_authz_evaluate]
unsafe def leanAuthzEvaluate (input : @& ByteArray) : String :=
  let inputStr := String.fromUTF8! input
  match Json.parse inputStr >>= fromJson? (α := AuthzInput) with
  | .error e => toString (toJson (ErrorOutput.mk s!"parse error: {e}"))
  | .ok inp =>
    let handlers := (inp.handlers.getD []).map toHandler
    let entries := UnionConditionsAwareAuthorize handlers
    let result : AuthzOutput := {
      unionAuthorize := decisionToString (UnionAuthorize handlers)
      pipeline := decisionToString (Pipeline handlers)
      evaluateEntries := decisionToString (UnionEvaluateConditions entries)
      sliceCBA := UnionSliceCanBecomeAllowed entries
    }
    toString (toJson result)
