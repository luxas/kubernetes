# Review: Add API serializations of the new authorizer types, including authorization.k8s.io/v1alpha1 (cce400c33ab)

- **SHA:** `cce400c33ab039277d52e510cae76508056f3d3e`
- **Author date:** 2026-07-20
- **Subject:** Add API serializations of the new authorizer types, including authorization.k8s.io/v1alpha1
- **Reachable on:** `impl-conditional-authz-3` (current branch).
- **Size:** 19+ files, +1400+/−

## What this commit does

The largest API-surface commit in the branch. Adds:

- **New v1alpha1 package**: `staging/src/k8s.io/api/authorization/v1alpha1/{doc,register,types}.go` — the `AuthorizationConditionsReview` API (`AuthorizationConditionsRequest{Decision, AdmissionRequest}`, `AuthorizationConditionsResponse{UID, Decision}`).
- **v1 additions**: `staging/src/k8s.io/api/authorization/v1/types.go` grows by 251 lines with `AuthorizationOptions`, `Condition`, `ConditionsMap`, `ConditionsAwareDecision`, `NamedConditionsAwareDecision`, `UnconditionalDecision`, `ConditionsAwareDecisionType`. Plus new `staging/src/k8s.io/api/authorization/v1/util.go` with the `HandledDecisionTypes` helpers.
- **Internal `pkg/apis/authorization/types.go`**: mirror types for internal-vs-external conversion (+250 lines).
- **Conversion functions**: `pkg/apis/{admission,authorization}/v1/conversion.go`, `pkg/apis/authorization/v1beta1/conversion.go` (+232 lines of conversion + tests).
- **v1alpha1 install/register**: `pkg/apis/authorization/{v1alpha1/{doc,register}.go,install/install.go,register.go}`.
- **Fuzzer**: `pkg/apis/authorization/fuzzer/fuzzer.go` grows to produce fuzzed values for the new types.
- **Testing hookup**: `pkg/api/testing/{fuzzer,validation_test}.go` extended.

Also touches `hack/lib/init.sh` (probably to add v1alpha1 to the list of API versions that codegen must process).

## Files touched

- Production
  - `staging/src/k8s.io/api/authorization/v1/{types,util}.go`
  - `staging/src/k8s.io/api/authorization/v1alpha1/{doc,register,types}.go`
  - `pkg/apis/authorization/{register,types}.go`, `pkg/apis/authorization/{v1,v1alpha1,v1beta1}/{doc,register,conversion}.go`
  - `pkg/apis/authorization/install/install.go`
  - `pkg/apis/admission/v1/conversion.go`
  - `hack/lib/init.sh`
- Tests
  - `staging/src/k8s.io/api/authorization/v1/util_test.go` (new, 209 lines)
  - `pkg/apis/authorization/fuzzer/fuzzer.go` (+/-)
  - `pkg/apis/authorization/v1beta1/conversion_test.go` (new, 232 lines)
  - `pkg/api/testing/validation_test.go` (+9)

## Findings

### Critical (must fix before merge)

1. **`AuthorizationOptions` is required on the wire but optional in Go (`*AuthorizationOptions`), and defaulting is not obvious.** From the review of the KEP → implementation deltas, the wire type has `HandledDecisionTypes` as `+required`, but the whole `AuthorizationOptions` block is optional (`omitempty`). When a client omits `authorizationOptions` entirely, the server must default to "unconditional-only" (`{Allow, Deny, NoOpinion}`) — this is done by `GetHandledDecisionTypes()` at line 63 of `util.go`. Verify that ALL server-side consumers hit `GetHandledDecisionTypes()` (nil-safe) rather than dereferencing `.HandledDecisionTypes` directly on a nil pointer. Grep will help; if any code path skips the nil-check, that's a nil-panic waiting to happen on legacy clients.

### Important (should fix)

1. **`Union` field type in `ConditionsAwareDecision` API type has `listType=map` on `authorizerName` — but doesn't enforce uniqueness at admission time?** The `+listType=map` marker is a schema-level assertion for controller managers; make sure declarative validation (`+k8s:listMapKey=authorizerName`) is emitted into the generated validation code. Otherwise a malicious webhook could return two entries with the same `authorizerName` and confuse `EvaluateConditions`.
2. **v1beta1 conversion — 232 lines of hand-written conversion.** `pkg/apis/authorization/v1beta1/conversion.go` and its test file. Because v1beta1 predates the new fields, `SubjectAccessReviewStatus.conditionalDecision` in v1 doesn't exist in v1beta1. Conversion must gracefully drop the field when going v1 → v1beta1. Check whether the conversion correctly does this (probably yes, since the field is `+optional`), and whether the round-trip test catches the case where a v1 client's response is converted to v1beta1 → back to v1.
3. **The `hack/lib/init.sh` change (+1) — need to verify it adds `v1alpha1` to whatever list drives codegen.** Skim to confirm.
4. **`pkg/apis/admission/v1/conversion.go` (+35 lines) is a surprising touch for an authorization-focused commit.** The v1alpha1 `AuthorizationConditionsRequest` embeds an `AdmissionRequest`; the conversion is presumably for a nested-conversion path. Verify this doesn't accidentally change admission's own conversion behaviour outside the conditional-authz path.
5. **`SupportsConditionalAuthorization` returns `true` if `ao.GetHandledDecisionTypes()` is a **superset** of the conditional set.** `util.go:44–47`. That's the right check — the client can declare more decision types than needed, and we still consider them conditions-aware. Ensure the reverse direction ("does the server-produced decision fit in the client's set") is checked at the wire boundary.

### Nits

- `util.go:69–72` — `ConditionalAuthorizationDecisionTypes` and `UnconditionalAuthorizationDecisionTypes` clone the underlying set on every call. Good; prevents accidental mutation of the package-level sets. The `.Clone()` calls have a comment "always return fresh copies, never expose the original data" — explicit and well-placed.
- The `omitted... field must be nil when Type != "X"` invariant across `ConditionsAwareDecision` union members should be enforced by validation. Verify with a round-trip fuzzer test.
- `UnconditionalDecision` is a two-string struct (`Reason`, `EvaluationError`). Consider whether these should live at the top level of `ConditionsAwareDecision` — they duplicate `SubjectAccessReviewStatus.Reason/EvaluationError`. Adding them here allows per-leaf reasons in a Union tree, which is what the KEP wants. OK.
- Doc typo in `util.go:73`: "the decision types that a client need to support" → "needs to support".
- `staging/src/k8s.io/api/authorization/v1alpha1/register.go` new file — verify GroupVersion is `authorization.k8s.io/v1alpha1` (from context, yes).

### Questions

- Was there consideration for putting `AuthorizationOptions` inside `ResourceAttributes` / `NonResourceAttributes` instead of `SubjectAccessReviewSpec`? Current placement is fine — options apply to the whole request, not per-attribute.
- Should the `HandledDecisionTypes` slice be validated for the specific known values (`Allow`, `Deny`, `NoOpinion`, `ConditionsMap`, `Union`)? Unknown values are treated as "not supported" by `IsSuperset`, so this is safe — but a validation error at request time would give better feedback.

## What's well done

- Union discriminator pattern applied consistently to `ConditionsAwareDecision`: `Type` field is the discriminator, five mutually-exclusive union members. The `+k8s:unionMember` markers on each variant field ensure declarative validation will enforce the invariant.
- `AuthorizationConditionsResponse.UID` copied from the request — the KEP's correlation mechanism landed as designed.
- Separate v1 helper file (`util.go`) with `SupportsConditionalAuthorization` / `SupportsUnconditionalAuthorization` — makes it easy for authorizers to check "does the client want conditions?" without repeating the set-superset logic.
- Fuzzer registration for the new types — good for round-trip testing.
- v1beta1 conversion tests (232 lines) — thorough coverage of the drop-fields cases.

## Tests

### Test files touched
- `staging/src/k8s.io/api/authorization/v1/util_test.go` new, +209 — `TestAuthorizationOptions_Supports` exercises `SupportsConditionalAuthorization`, `SupportsUnconditionalAuthorization`, `GetHandledDecisionTypes` across nil / empty / partial / full sets.
- `pkg/apis/authorization/v1beta1/conversion_test.go` new, +232 — v1beta1 ↔ internal conversion.
- `staging/src/k8s.io/apiserver/pkg/apis/authorization/v1beta1/conversion_test.go` new, +307 — v1beta1 ↔ internal conversion (moved copy).
- `staging/src/k8s.io/apiserver/pkg/apis/authorization/validation/validation_test.go` +444 — extends the validation tests with `AuthorizationOptions` / `ConditionalDecision` cases.
- Four `declarative_validation/authorization/*/declarative_validation_test.go` files — +332/+424/+332/+332 lines each. Auto-generated declarative validation harnesses that verify the `+k8s:*` markers on the new types.
- `staging/src/k8s.io/api/roundtrip_test.go` +2 — adds v1alpha1 to the round-trip test list.
- `pkg/api/testing/{fuzzer,validation_test}.go` +9 each.

### Coverage
- **Well covered:**
  - `AuthorizationOptions` nil-safety: `TestAuthorizationOptions_Supports` covers `nil` receiver on both `Supports*` methods, verifying the fallback to `unconditionalAuthorizationDecisionTypes`.
  - Empty `HandledDecisionTypes` (non-nil options with empty slice) — a subtle case: `SupportsUnconditionalAuthorization` returns `false` because the empty set is not a superset of `{Allow, Deny, NoOpinion}`. Verify this is the intended semantic (a client that opts in to `AuthorizationOptions` but doesn't specify types is *worse* than a client that omits `AuthorizationOptions` entirely).
  - v1beta1 conversion tests exercise: internal SAR with `ConditionalDecision` → v1beta1 (drops the field), v1beta1 → internal (leaves the field zero), and the round-trip identity.
- **Missing / thin:**
  - **Superset check with extra values**: `HandledDecisionTypes = [Allow, Deny, NoOpinion, ConditionsMap, Union, "Frobnicate"]` — extra unknown values should not break the superset check. Tests appear to cover the exact-match case; verify.
  - **`GetHandledDecisionTypes` returns a fresh set** — `util.go:66–68` builds a new set from the slice on every call. Verify no test relies on mutating the returned set and observing side effects (which would be a bug).
  - **Deep copy of `ConditionsAwareDecision`** — the deep-copy generated code is not explicitly asserted. The zz_generated file *should* handle recursive `Union` correctly, but a fuzzer round-trip catches this; verify via `TestRoundTripTypes` in `roundtrip_test.go`.
  - **Declarative validation** — the `+k8s:listType=map` on `Union[].authorizerName` enforces uniqueness. Verify the declarative validation test asserts an error for a duplicate `authorizerName`.
- **Feature-gate on/off:** partial — `SubjectAccessReviewSpec.AuthorizationOptions` is `+featureGate=ConditionalAuthorization`, `+k8s:ifDisabled("ConditionalAuthorization")=+k8s:forbidden`. The declarative validation tests presumably exercise both gate states via the `+k8s:ifDisabled` marker; verify.

### Structure
- Table-driven in `util_test.go` — straightforward.
- The four `declarative_validation_test.go` files are auto-generated and duplicated across LocalSAR/SelfSAR/SAR/AuthorizationConditionsReview — expected for codegen output; no simplification opportunity.
- `pkg/apis/authorization/v1beta1/conversion_test.go` and `staging/src/k8s.io/apiserver/pkg/apis/authorization/v1beta1/conversion_test.go` are nearly parallel copies of the same test surface — the "internal" location has 307 lines vs the "k8s.io" location's 232. Diff them to confirm the extra 75 lines are legitimate (perhaps additional coverage for the new types) and not accidental duplication.

### Stale comments
- Production `util.go:73` — docstring typo `"need to support"` → `"needs to support"`. (Already flagged in the main review's Nits.)
- Test file — no stale comments found.

## Verdict

**LGTM with nits.** Substantive API-shape commit. The one Critical item (nil-safety of `AuthorizationOptions`) is worth an explicit spot-check by grep before merge. Otherwise this is a well-structured commit for a large API landing.
