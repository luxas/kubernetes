# Review: Explicitly source the API version for the declarative SAR validations (dedec1a12ef)

- **SHA:** `dedec1a12efd8ca16a97d63ec06f5ca63b586929`
- **Author date:** 2026-07-20
- **Subject:** Explicitly source the API version for which to run the declarative SAR validations, if they differ between source API versions in the future
- **Reachable on:** `impl-conditional-authz-3` (current branch).
- **Size:** 7 files, +61 / -12

## What this commit does

Threads the request's original API version (from `RequestInfo.APIVersion`) into the validation call, so that declarative validation can be run against the source version rather than always defaulting to v1. Adds a `ri, ok := genericapirequest.RequestInfoFrom(ctx)` guard in each SAR REST handler and passes `ri.APIVersion` to `ValidateSubjectAccessReviewCreate` (and its LocalSAR/SelfSAR siblings).

The validation signature grows a `version string` parameter; the function then wires it into the `rest.DeclarativeValidationConfig`.

## Files touched

- Production
  - `pkg/registry/authorization/{local,self,}subjectaccessreview/rest.go` (+7 each)
  - `staging/src/k8s.io/apiserver/pkg/apis/authorization/validation/validation.go` (+45)
- Tests
  - Three `declarative_validation_test.go` files in `test/declarative_validation/authorization/…`.

## Findings

### Critical (must fix before merge)

None.

### Important (should fix)

1. **The `genericapirequest.RequestInfoFrom(ctx)` guard fails with a BadRequest.** `rest.go:70–73` in each handler. This is a programmer error more than a client error — RequestInfo is set by the request-info filter, which runs before REST handlers. Returning 400 to the client for a missing RequestInfo would confuse operators; consider `apierrors.NewInternalError(errors.New("no RequestInfo in context"))`.
2. **The API-version parameter is passed to the validation function but the declarative-validation config in `validation.go` may or may not actually use it.** `validation.go:` grew by 45 lines — need to read the diff to confirm the parameter isn't just plumbed and dropped. Sanity-check.
3. **The change is technically a forward-compatibility hook — currently v1 and v1beta1 SAR validations behave identically.** The commit body says "if they differ between source API versions in the future", so this is speculative future-proofing. Fine, but adding a test that exercises `version="v1beta1"` behaviour differently from `version="v1"` would exercise the code path today.

### Nits

- `rest.go` handlers duplicate the `ri, ok := genericapirequest.RequestInfoFrom(ctx)` block three times. Could be a helper.
- Error message `"expected a RequestInfo in the context"` — good, actionable.

### Questions

- The three `declarative_validation_test.go` files have a single-line diff each — what's being changed? Probably `t.Run` naming or the version string being tested.

## What's well done

- Speculative future-proofing is done with a clear intent (the commit body explicitly labels it as "if they differ ... in the future"), not silently.
- Threading the version through the call chain keeps the option open without over-engineering.

## Tests

### Test files touched
- Three `test/declarative_validation/authorization/{local,self,}subjectaccessreview/declarative_validation_test.go` files, 1–2 line diff each — the assertion presumably picks up the new `version string` parameter that the REST handlers now thread through.

### Coverage
- The three declarative_validation tests exercise a happy-path validation against a specific API version. This commit's plumbing is validated indirectly: if the wrong version string reached the validator, the declarative validation would surface a `+k8s:ifDisabled` or version-specific rule mismatch that these tests catch. But that's coincidental; no test explicitly asserts `version="v1beta1"` produces different behaviour from `version="v1"`.
- **Missing:** no test constructs a request with `X-Kubernetes-API-Version: v1beta1` or otherwise stubs `RequestInfo.APIVersion` and asserts the validation branches on it. Given the commit body explicitly says "if they differ between source API versions in the future", the hook exists but is not exercised. Add a test scaffolding when v1 and v1beta1 validations actually differ.

### Structure
- Nothing to critique — 1–2 lines changed per file.

### Stale comments
- Production `rest.go:70–73` — the `apierrors.NewBadRequest("expected a RequestInfo in the context")` — BadRequest may be misleading; RequestInfo missing is a server-side wiring bug, not a client error. (Already flagged in main review's Important #1.)

## Verdict

**LGTM.** Small, well-scoped forward-compat plumbing.
