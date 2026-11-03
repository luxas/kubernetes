# Comprehensive commit-by-commit review of the Conditional Authorization branch

## Context

The user's `changes.md` describes a 25-commit history for KEP-5681 (Conditional
Authorization). The task is to conduct a **commit-by-commit review** and emit
one Markdown review per commit under `review/<commit-sha>.md`.

Two important repo facts complicate the mechanics:

1. The current branch (`impl-conditional-authz-3`) has only 14 of the 25
   commits — the earlier 11 were squashed/rebased away. But all 25 commit
   SHAs are still reachable via git (either directly by SHA, or via the older
   `impl-conditional-authz-2` branch).
2. The full inventory can be reviewed against the SHAs listed below, so
   commit-by-commit granularity is preserved even for the earlier work.

The previous plan mode session (updating `kep.md`) has already produced a
deep mental model of the implementation. That knowledge (which files hold
what, which types and functions matter) is applied throughout this review.

## Review scope and output

- **What to produce:** one file per commit at
  `/Users/luxas/upbound/kubernetes-push/review/<commit-sha>.md` (12-char
  short SHA is fine — same as `git log --oneline` uses).
- **What NOT to produce:** any code changes. Reviews are read-only artefacts.
- **First step at execution time:** update
  `/Users/luxas/upbound/kubernetes-push/changes.md` to include this review
  plan (currently it only contains the terse task statement + commit list).
  This gives the user a persistent record of the review approach alongside
  the review artefacts.
- **Second step:** `mkdir -p review/` at repo root, then produce reviews
  in the order listed below.

## Review method (per commit)

For each commit:

1. `git show --stat <sha>` — file inventory + one-line summary of touch
   size.
2. `git show <sha>` — full diff. For very large commits (autogen, integration
   tests) read the diff in chunks with `git show <sha> -- <path>`.
3. Classify each changed file:
   - **Production code** — read the diff carefully; check invariants,
     error handling, thread-safety, comments.
   - **Tests** — verify what behaviours are covered; look for missing
     table entries, non-deterministic fixtures, hardcoded state.
   - **Generated / vendored / codegen output** — skim only; note any
     hand-modifications that shouldn't be in generated output.
4. Write `review/<sha>.md` from the template in the next section.

Aim for **substance over volume**. If a commit is truly routine (e.g. a pure
codegen refresh), the review can be short — flag it as "no substantive
review issues" rather than padding.

## Review template (per commit)

```markdown
# Review: <short subject> (<12-char-sha>)

- **SHA:** <full or 12-char sha>
- **Author date:** YYYY-MM-DD
- **Subject:** <exact commit subject line>
- **Reachable on:** <branch or "dangling; reachable by SHA only">
- **Size:** <N files, +A/-D lines>

## What this commit does
1–3 sentences in my own words: what changed, at what layer, and why (from
the commit body / surrounding context, not just the subject).

## Files touched
Grouped by category:
- Production (`pkg/…`, `staging/src/…` non-test, non-`zz_generated`)
- Tests (`_test.go`, `test/…`)
- Generated (`zz_generated*`, `openapi-spec/…`, `testdata/…`)
- Config / docs / other

## Findings

Use these buckets, in this order. Include specific file:line references.

### Critical (must fix before merge)
Bugs, security issues, backwards-compat breakage, missing feature-gate
guards, missing fail-closed behaviour, panics on unexpected input.

### Important (should fix)
API surface concerns, missing test coverage of a documented behaviour,
inconsistent naming, non-obvious invariant not documented, missing
error handling that could be a real problem in production.

### Nits (optional)
Wording, symmetry, style, minor doc improvements.

### Questions
Anything unclear that the author should confirm or clarify.

## What's well done
Positive observations — pattern reuse, thoughtful naming, good tests,
apt design decisions. Being specific here helps the author know what
not to un-do in follow-ups.

## Verdict
LGTM | LGTM with nits | Needs revision | Blocking issue
```

## Complete commit inventory (in recommended review order)

Reviewing in this order (roughly build-up-from-foundations) so each commit
is easier to reason about in the context of what came before. Author date
is provided for chronological reference; SHA is the source-of-truth.

### Phase A — Interface & data-model foundations (dangling SHAs, older impl history)

These 4 commits establish the `Authorizer` interface changes; SHAs are
directly reachable but not on any current branch.

| # | SHA | Date | Subject |
|---|---|---|---|
| 01 | `6d78dfd60cf` | 2026-03-15 | Extend the Authorizer interface with conditions-aware methods. |
| 02 | `7e3c7349470` | 2026-05-07 | Add the Unconditional prefix to Authorizer and WantsAuthorizer interfaces |
| 03 | `69a8b4dd7a9` | 2026-05-13 | Adapt the codebase to the Authorizer interface change |
| 04 | `27e0fa95ff9` | 2026-05-26 | Address liggitt's comments |

### Phase B — ConditionsAwareDecision + ConditionsMap types (on `impl-conditional-authz-2`)

The heart of the new data model.

| # | SHA | Date | Subject |
|---|---|---|---|
| 05 | `a42663cc26c` | 2026-07-07 | Move some definitions from conditions.go → interfaces.go and add or refine comments |
| 06 | `40d1ff2444b` | 2026-07-07 | Represent the ConditionsAwareDecision variants using an internal enum |
| 07 | `98eab691156` | 2026-07-03 | Add PossibleDecisions, FailureDecision, ContainsUnconditionalAllowOrDeny methods to ConditionsAwareDecision |
| 08 | `9d7f6593151` | 2026-07-07 | Add the ConditionsMap decision variant |
| 09 | `666dea045e8` | 2026-07-03 | Add a reference implementation for evaluating a ConditionsMap |
| 10 | `d725c326bcd` | 2026-07-03 | Implement conditions for the union authorizer |
| 11 | `7a6938b39f1` | 2026-07-07 | Add PartiallyEvaluateConditionsAwareDecision |

### Phase C — API validation, defaults & pre-factor (on `impl-conditional-authz-3`)

| # | SHA | Date | Subject |
|---|---|---|---|
| 12 | `5c9a3d7744d` | 2026-07-19 | Move authorization API validations, defaults and some conversions to k8s.io/apiserver so they are accessible to the webhook authorizer |
| 13 | `72400feff77` | 2026-07-19 | autogenerated |
| 14 | `3033213ea26` | 2026-07-18 | Pre-factor for conditional authz: AuthorizerNames are DNS 1123 subdomains, enforce length limits on conditions, require condition ID and type to be domain-qualified, and expose the UnconditionalParts convenience function. |
| 15 | `be2f64e38a9` | 2026-07-22 | Refine the UnconditionalParts method and add a test |
| 16 | `db947349618` | 2026-07-19 | Add ConditionalAuthorization feature gate |

### Phase D — New v1alpha1 API + CEL env + filter/plugin (on `impl-conditional-authz-3`)

| # | SHA | Date | Subject |
|---|---|---|---|
| 17 | `cce400c33ab` | 2026-07-20 | Add API serializations of the new authorizer types, including authorization.k8s.io/v1alpha1 |
| 18 | `dedec1a12ef` | 2026-07-20 | Explicitly source the API version for which to run the declarative SAR validations, if they differ between source API versions in the future |
| 19 | `f2982e77497` | 2026-07-19 | Add the conditionalAuthorization field to the CEL environment for the AuthorizationConfig usage |
| 20 | `67896e14ab4` | 2026-07-19 | Add a WithConditionsAwareAuthorization HTTP filter together with AuthorizationConditionsEnforcer admission plugin |

### Phase E — SAR + webhook + handler-chain wiring (on `impl-conditional-authz-3`)

| # | SHA | Date | Subject |
|---|---|---|---|
| 21 | `f0f9a3ed310` | 2026-07-20 | Make the SubjectAccessReview handlers conditions-aware |
| 22 | `f1e726ca22c` | 2026-07-20 | Implement conditions evaluation for the webhook authorizer, and add related API types. |
| 23 | `67711704058` | 2026-07-19 | Make the kube-apiserver handler chain support conditions for write requests covered by admission. |

### Phase F — Testing + codegen refresh (on `impl-conditional-authz-3`)

| # | SHA | Date | Subject |
|---|---|---|---|
| 24 | `6013eb05df2` | 2026-07-20 | Add conditional authorization integration test |
| 25 | `2f14e9c3e7d` | 2026-07-22 | hack/update-codegen.sh; UPDATE_COMPATIBILITY_FIXTURE_DATA=true go test k8s.io/api; go test k8s.io/api; hack/update-openapi-spec.sh |

## Cross-cutting themes to keep in mind while reviewing every commit

Apply this checklist mentally to each commit, not just the "obviously
relevant" ones:

1. **Backwards compatibility of the legacy `Decision int` enum.** Anywhere
   the code still uses `authorizer.Decision` (Allow/Deny/NoOpinion int
   constants) must preserve `Decision(0) == DecisionDeny` semantics. New
   struct types must not shadow these constants.
2. **Feature-gate discipline.** New public fields (e.g.
   `spec.authorizationOptions`, `status.conditionalDecision`) must be
   guarded by `+featureGate=ConditionalAuthorization` and forbidden when the
   gate is off. New code paths in `kube-apiserver`/`k8s.io/apiserver`
   should short-circuit to legacy behaviour when the gate is off.
3. **Fail-closed on unknown / unsupported conditions.** Any code that
   consumes a `ConditionsAwareDecision` in a legacy call site must fold
   through `UnconditionalParts(expectConditional=true)` →
   `FailureDecision()`. Authorizers that don't implement conditions must
   return `ErrorConditionEvaluationNotSupported` from `EvaluateConditions`.
4. **`UnconditionalAuthorizer` vs `Authorizer`.** Compound authz call
   sites (e.g. `ensureAuthorizedForVerb`) should take the downscoped
   interface; conditions-aware call sites (the enforcer, the new filter,
   SAR REST handlers) take the full interface.
5. **Immutability & thread safety of decisions.** `ConditionsAwareDecision`
   is passed by value and must be safe to share across goroutines.
   Constructors must copy any input slices they retain.
6. **API type validations.** Domain-qualified `id`/`type` (via
   `validateDomainPrefixSeparator`), 128-condition cap, 10240 / 1024 byte
   caps, DNS-1123-subdomain `authorizerName`.
7. **Union tree well-formedness.** The `Union` variant must always have at
   least one `ConditionsMap` leaf (else it collapses to unconditional);
   `authorizerName`s must be unique within a Union; ordering of leaves
   must be preserved.
8. **Correlation between SAR and ACR.** The ACR request carries the exact
   `ConditionsAwareDecision` from the earlier SAR, plus a fresh UUID; the
   ACR response must copy the UUID back verbatim.
9. **Audit annotations.** The new
   `authorization.k8s.io/is-conditional-decision=true` annotation must be
   set exactly when the filter lets a conditional-allow proceed.
10. **Silent misconfigurations.** The "feature gate on + plugin disabled"
    state currently silently falls back to `WithAuthorization`. Reviews of
    the plugin, filter, and options code should note this and flag it
    (either as a Nit or as an "Important — consider hardening").
11. **Ordering of the enforcer admission plugin.** After MutatingWebhook,
    before ValidatingAdmissionPolicy — check `RecommendedPluginOrder`
    matches.
12. **`ConditionsData` completeness.** The interface must expose enough
    to evaluate conditions against the fully-mutated request (object,
    oldObject, operation, options, dryRun, user info, kind + resource).
    Missing accessors are a real problem.
13. **Test coverage of "not-implemented" fallbacks.** E.g. legacy authorizer
    → `EvaluateConditions` returns `ErrorConditionEvaluationNotSupported`;
    tests should cover this path.
14. **Cross-commit consistency.** If commit N introduces a helper and
    commit N+3 uses it, the introduction should be complete (docs,
    signatures) without waiting until N+3. Watch for cases where an
    early commit is missing a doc that only makes sense later.
15. **CEL matcher env vs. CEL condition evaluator.** Reviewing commit 19,
    remember this only extends the *matcher* CEL env — not a condition
    evaluator. Anywhere the code implies otherwise is a comment/doc bug.
16. **Generated code sanity.** For commits like #13, #17, #25, verify the
    generated output matches the hand-written input (no hand edits inside
    `zz_generated*`; proto tags stable; openapi-spec deltas are consistent
    with API changes).

## Per-phase focus areas

**Phase A** (interface changes)
- Every call site correctly migrated to the new interface?
- Any leftover call sites still using the classic single-method interface
  that should be conditions-aware?
- Symmetry between `Authorize` and `ConditionsAwareAuthorize` (default
  implementations, embedded `UnconditionalAuthorizer`).

**Phase B** (decision + conditions types)
- Constructor validation. Correct handling of empty / all-noOpinion
  ConditionsMaps.
- Immutability of the exposed struct. Iterators return copies where
  appropriate.
- The internal-enum representation vs. exported `Type` on the wire.
- Union builder short-circuit / dedup logic.
- `PartiallyEvaluate` handling of unions, mixed evaluated/unevaluated
  leaves, and errors.

**Phase C** (API validation + pre-factor + feature gate)
- Domain-qualified label-key regex (accept `acme.io/x`, reject `x`,
  `k8s.io/x` if reserved, etc.).
- DNS-1123 subdomain acceptance / rejection for authorizer names.
- `UnconditionalParts(expectConditional=true|false)` behaviours match
  the test cases.
- Feature-gate lifecycle (alpha default off) and version metadata.
- Move commit (#12): does moving validation/defaults into
  `k8s.io/apiserver` change any semantics? Any place that imported the old
  location and now needs an update?

**Phase D** (v1alpha1 API + CEL env + filter/plugin)
- Wire types match the "in-process" types byte-for-byte semantically
  (serialisation round-trip is loss-less).
- CEL env extension for `AuthorizationConfig` matcher — only exposed
  when the feature gate is on; does not leak conditional-decision types
  as recognisable CEL variables (this is a matcher env, not evaluator).
- HTTP filter fallback path when the classifier returns false.
- Admission plugin's `Handles` / feature-gate check; behaviour when the
  context has no decision.

**Phase E** (SAR + webhook + handler-chain wiring)
- SAR REST handlers correctly propagate `handledDecisionTypes` down to
  the authorizer.
- Webhook authorizer's UUID correlation on ACR requests.
- Handler-chain classifier predicate matches the KEP description
  (verbs + concrete GVR + not-excluded).
- Aggregated-API-server / connect-verb TODOs left in the classifier are
  called out (they should be Nits or Important, not Critical).

**Phase F** (tests + codegen)
- Integration tests cover: unconditional Allow/Deny/NoOpinion,
  conditional Allow (evaluates to Allow / to NoOpinion / to Deny), deny
  precedence, operation-aware conditions, aggregated-API interop via CRD
  conversion, HPA v1/v2 old/new object.
- Feature-gate on and off exercised.
- Codegen commit: no hand-edits inside generated files;
  openapi-spec diff matches the API-type changes; compatibility fixture
  data plausible.

## Execution sequence at run time

1. Write this plan into `/Users/luxas/upbound/kubernetes-push/changes.md`
   (append after the existing "Comprehensive Review" heading so the plan
   sits alongside the commit list). Preserve the commit list.
2. `mkdir -p /Users/luxas/upbound/kubernetes-push/review`.
3. Loop through commits in the order in the tables above:
   - `git show --stat <sha>` → identify hotspots
   - `git show <sha>` → read the diff
   - Read any critical touched files at HEAD to sanity-check current state
   - Write `review/<sha>.md` using the template
4. After all 25 reviews are written, produce a **roll-up summary** at
   `review/00-summary.md` that:
   - Lists open questions and blocking issues (if any)
   - Highlights cross-cutting patterns and follow-ups
   - Suggests re-review of any commits after a specific critical fix

## Verification

Once execution finishes:

- `ls /Users/luxas/upbound/kubernetes-push/review/` should contain 25
  files named `<sha>.md` plus `00-summary.md`.
- `wc -l review/*.md` should show non-trivial content for every review
  (very short files should have a "verdict: LGTM, no substantive issues"
  explanation).
- Every file should reference at least one `file.go:line` from the diff.
- No git state has been mutated (no commits, no config edits, no branch
  changes) — the reviews are pure Markdown artefacts.

## Explicit non-goals

- **Not** producing code changes, fixes, or PR suggestions in the tree.
- **Not** rewriting the KEP again (that was the previous task; still
  useful as reference but not touched here).
- **Not** attempting to reconstruct the full pre-rebase history of the
  branch beyond the 25 commits explicitly listed.
