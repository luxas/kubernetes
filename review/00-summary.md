# Roll-up review of KEP-5681 Conditional Authorization

This is the cross-cutting summary of the commit-by-commit review of the
25-commit implementation of KEP-5681 (Conditional Authorization). Each
individual `review/<sha>.md` file has the per-commit deep dive; this file
distills the important patterns, blockers, and follow-ups.

## Structure of the change

The branch lands 25 commits across five architectural layers:

- **Phase A** (4 commits, `6d78dfd60cf` – `27e0fa95ff9`): grow the
  `authorizer.Authorizer` interface + `UnconditionalAuthorizer` split;
  adapt every in-tree implementation.
- **Phase B** (7 commits, `a42663cc26c` – `7a6938b39f1`): the
  `ConditionsAwareDecision` value type with five variants and the
  `ConditionsMap`/`Union` conditional variants; reference evaluator; the
  partial-evaluation entry point.
- **Phase C** (5 commits, `5c9a3d7744d` – `db947349618`): move validations
  into `k8s.io/apiserver`; validation constraints (domain-qualified IDs,
  length caps); pre-factor to expose `UnconditionalParts`; the
  `ConditionalAuthorization` feature gate.
- **Phase D** (4 commits, `cce400c33ab` – `67896e14ab4`): the v1 API
  additions (`AuthorizationOptions` etc.), v1alpha1 `AuthorizationConditionsReview`
  API, matcher-CEL extension, HTTP filter + admission plugin.
- **Phase E** (3 commits, `f0f9a3ed310` – `67711704058`): SAR REST handlers
  become conditions-aware; webhook authorizer gains full ACR support;
  kube-apiserver classifier and handler-chain wiring.
- **Phase F** (2 commits, `6013eb05df2` + `2f14e9c3e7d`): comprehensive
  integration test suite; final codegen refresh.

## Blocking issues (Critical severity, blockers before merge)

These items were flagged as Critical across the per-commit reviews. All are
correctable in-place; none are fundamental design flaws.

1. **`WantsAuthorizer` → `WantsUnconditionalAuthorizer` rename is a silent
   API break** (`7e3c7349470`). Third-party admission plugins implementing
   `SetAuthorizer(authorizer.Authorizer)` will silently stop being
   initialized (their type assertion no longer matches). The `authorizer`
   field becomes nil, and downstream plugin behaviour depends on how they
   handle nil — some may fail-open. Mitigation: keep both interfaces or
   preserve the original name with a widened type.
2. **Reserved-domain (`.k8s.io`, `.kubernetes.io`) authorizer names are
   only a warning, not a validation error** (`3033213ea26`). A malicious
   or careless operator could name their custom authorizer
   `evil.k8s.io` and shadow future Kubernetes-shipped authorizers. Fix
   before alpha ships, while the surface is still small.
3. **Silent fallback to legacy `WithAuthorization` when feature gate is
   on but the enforcer admission plugin is disabled** (`67896e14ab4`).
   Operators enabling the FG without the plugin see no conditional
   decisions and no error. `AdmissionOptions.Validate` should reject this
   configuration at startup.
4. **The `AuthorizationConditionsEnforcer` classifier flag is checked
   only in the HTTP filter, not in the classifier itself.** If someone
   disables the plugin explicitly via `--disable-admission-plugins=…`,
   the classifier still returns `true` for eligible requests and
   conditional decisions get attached to context with nothing to enforce
   them — fail-open (`67711704058`). Verify end-to-end that the plugin's
   `InspectFeatureGates` + admission wiring guarantees enforcement fires
   when the classifier says "yes".
5. **The classic `Authorize` path silently returns `NoOpinion` when a
   webhook returns a conditional decision to a non-conditions-aware
   caller** (`f1e726ca22c`). The webhook contract violation should be
   surfaced (Deny + audit annotation), not silently masked.
6. **Suspicious `new(metav1.GroupVersionKind(data.GetKind()))` in the
   ACR request construction** (`f1e726ca22c`). Verify this compiles as
   intended; the syntax looks broken.

## Important issues (should fix)

Grouped by theme:

**Interface / type ergonomics**
- Multiple docstrings on `ConditionsAwareDecision` overstate the state
  shipped at intermediate commits (five variants promised, three
  implemented until commit 08). Documentation debt across the Phase B
  commits.
- Boolean-flag `UnconditionalParts(expectConditional bool)` is a
  smell; two named methods would read better at call sites
  (`be2f64e38a9`).
- `newWithBackoff` and `New` on the webhook authorizer both take
  10+ parameters (`f1e726ca22c`). A config struct would help.

**Evaluation semantics**
- Short-circuit on first true Deny/NoOpinion condition drops accumulated
  errors from *previous* conditions (`666dea045e8`). Consider surfacing
  the swallowed errors via warnings or a separate `EvaluationError`
  field.
- `PartiallyEvaluateConditionsAwareDecision` is unbounded recursive
  (`7a6938b39f1`). Add an explicit depth cap or convert to iterative
  traversal.
- The `PossibleDecisions` default case for `ConditionsMap`/`Union`
  variants was buggy in the interim commit (`98eab691156`) and fixed by
  the follow-up (`9d7f6593151`). The interim state is a landmine.

**API-shape and validation**
- Nil-safety of `AuthorizationOptions.SupportsConditionalAuthorization()`
  when `AuthorizationOptions` is nil — the current chain of nil-safe
  methods works, but call sites don't make the nil-safety obvious
  (`f0f9a3ed310`). Explicit nil guards at call sites would help.
- Missing byte-length validation on `Condition.Condition`/`Description`
  in commit 08 (`9d7f6593151`); added in commit 14 (`3033213ea26`). The
  interim state is DoS-vulnerable.
- Nil-condition in a slice panics in the ConditionsMap constructor rather
  than fail-closing (`9d7f6593151`).
- `field.ErrorList` from `IsDomainPrefixedKey` is aggregated into a
  single error message, losing path information (`3033213ea26`).

**Metrics / observability**
- `"conditional"` metrics label coined in `instrumentedAuthorizer`
  (`69a8b4dd7a9`) — verify consistency with the audit annotation
  `authorization.k8s.io/is-conditional-decision`.
- Consider metrics for "authorizer returned Decision outside
  PossibleDecisions" — a signal for misbehaving authorizers.
- Log `klog.V(4)` when the enforcer plugin swallows errors from
  short-circuit evaluation.

**Test coverage gaps**
- Integration tests only exercise the `"using-webhook-only"` CEL
  evaluation variant; `"in-process-eval-only"` and
  `"if-in-process-fails-call-webhook"` are commented out awaiting the
  built-in CEL evaluator (`6013eb05df2`).
- No integration test proves the aggregated-API-server story — the
  classifier explicitly rejects aggregated-owned groups today
  (`67711704058`).
- Missing test that `EvaluateConditions` on a non-conditions-aware
  authorizer returns `ErrorConditionEvaluationNotSupported` — every
  in-tree authorizer implements this identically, but no test asserts it
  across the tree (`69a8b4dd7a9`).

**Security-adjacent**
- The webhook authorizer's `EvaluateConditions` return type-check uses
  `PossibleDecisions().Has(decision)` — good, but only enforces at the
  authorizer boundary; the enforcer plugin re-checks the same invariant
  as belt-and-suspenders. Belt-and-suspenders is intentional; document
  why.
- ACR UUID correlation is correct (`webhook.go` in `f1e726ca22c`); ACR
  responses are never cached — verify this is preserved in reload.

## Follow-ups (not blocking, but worth tracking)

1. **In-tree CEL condition evaluator** — the biggest deferred feature.
   Tests already have the shape to accept it (commented-out variants).
2. **Aggregated API server conditions-aware routing** — the classifier
   TODO in `67711704058`.
3. **Connect verb (`get pods/exec` etc.) conditions-aware routing** —
   the classifier TODO in `67711704058`.
4. **`ensureAuthorizedForVerb` conditions-aware** — the compound authz
   check on pod subresources still takes `UnconditionalAuthorizer`.
5. **`update.go` compound authz** — update→create secondary check not
   yet conditions-aware.
6. **Node authorizer / Constrained Impersonation** — design in the KEP,
   not implemented in this branch.
7. **Remove the `versionedAttributes` shim** once `admission.NewVersionedAttributes`
   is fixed to override `GetOldObject()` correctly (TODO in
   `67896e14ab4`).
8. **Consolidate the "convert internal → v1 SAR" boilerplate** across
   the three SAR REST handlers (`5c9a3d7744d`).

## OWASP-flavoured security notes

Applied to the branch as a whole:

- **A01 Broken Access Control**: fail-closed behaviour is consistently
  applied — every reviewer path routes unrecognised or errored decisions
  to `FailureDecision()` (Deny or NoOpinion depending on possible
  outcomes). The two silent-fallback cases flagged above (Critical #3,
  #4) are the exceptions to watch.
- **A02 Security Misconfiguration**: the "gate on + plugin off" state
  is exactly this — the operator misconfigures, and the server silently
  reverts to legacy auth without an error. Fix via
  `AdmissionOptions.Validate`.
- **A05 Injection**: `Condition.Condition` is a bounded string (10240
  bytes) evaluated by the authorizer that authored it — the API server
  never parses the body itself. No injection vector at the framework
  level; individual authorizers must guard their own evaluators.
- **A06 Insecure Design**: the reserved-domain warning-only check
  (Critical #2) is a design gap that could be tightened at low cost
  during alpha.
- **A08 Data Integrity**: `ConditionsAwareDecision` is passed by value
  and constructed with `slices.Clone` where slices are stored — good
  immutability discipline. The UUID correlation on ACR requests
  prevents cache-substitution attacks.
- **A09 Logging & Alerting Failures**: the short-circuit-drops-errors
  pattern (Important item above) and the silent-fallback modes are
  where observability could be improved. Suggest: emit klog.V(4)
  warnings when decisions get folded to fail-closed, and an audit
  annotation on webhook-contract violations.
- **A10 Mishandling of Exceptional Conditions**: consistent
  fail-closed via `FailureDecision()` handles most exception cases;
  the two silent-mask cases (Critical #3, #5) are the exceptions.

## Suggested rebase (optional)

The commit history has some churn worth cleaning up:

- Commits 01 (`6d78dfd60cf`, Mar 15) and 04 (`27e0fa95ff9`, May 26) both
  touch `conditions.go`. Squash the "Address liggitt's comments" commit
  into the interface-introduction commit for a cleaner story.
- Commits 07 (`98eab691156`), 06 (`40d1ff2444b`), 08 (`9d7f6593151`)
  are one logical unit (build the `ConditionsAwareDecision` +
  `ConditionsMap` type). Consider squashing.
- Commits 15 (`be2f64e38a9`) reintroduces `UnconditionalParts` that
  was removed in commit 04. Squash back into commit 14 (`3033213ea26`)
  where `UnconditionalParts` returns.
- Commit 13 (`72400feff77` "autogenerated") could be squashed into
  commit 12 (`5c9a3d7744d`).

Not blocking — the current history is reviewable — but a rebase would
compact the ~25 commits to ~14–16.

## Verdict by phase

| Phase | Verdict | Rationale |
|---|---|---|
| A — Interface split | Needs revision | `WantsAuthorizer` API break (Critical) |
| B — Types and evaluation | LGTM with nits | Landmine in `PossibleDecisions` interim state; drop-errors trade-off should be explicit |
| C — Validation, feature gate | Needs revision | Reserved-domain warning-only (Critical) |
| D — API + filter + plugin | Needs revision | Silent gate-on-plugin-off fallback (Critical) |
| E — SAR + webhook + wiring | Needs revision | Silent NoOpinion on webhook contract violation (Critical); `new(metav1.…)` construction (Critical) |
| F — Testing + codegen | LGTM with nits | Only webhook-only variant exercised |

## Overall

The branch is a substantive, well-designed implementation of KEP-5681. The
data-model choices (`ConditionsAwareDecision` as a value type with an
internal enum, `ConditionsMap` with structural effects via slice
membership, `Union` as a tree of named sub-decisions) are cleaner than
the KEP's original sketch (see the previously updated `kep.md`). Test
coverage is generous across the type-level tests and the integration
suite.

The critical items are all correctable in-place and do not require
redesign. Most are either "silently allowing a misconfiguration to leak
through" (fixable by rejecting at startup) or "documentation debt where
the code is stricter than the docstring suggests". The biggest deferred
feature — the built-in CEL condition evaluator — is a large but
well-scoped follow-up that the current framework accepts without further
refactoring.

**Recommend: revise the six Critical items, then merge as alpha.** The
deferred follow-ups (in-tree CEL evaluator, connect verbs, aggregated
API server routing, Node authorizer migration) are natural post-alpha
work.
