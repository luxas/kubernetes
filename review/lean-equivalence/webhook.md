# webhook

Scope: `lean/webhook/webhook.lean` (all definitions) and the theorem statements of
`lean/webhook/webhook_properties.lean`, against
`staging/src/k8s.io/apiserver/plugin/pkg/authorizer/webhook/webhook.go` (HEAD), with
`pkg/apis/authorization/v1/encoding.go:124-152`, `pkg/apis/authorization/validation/validation.go:90-133`,
`pkg/authorization/authorizer/evaluate.go:121-130` and `conditions.go:162-173` read where the
webhook calls into them.

Build: `lake build webhook.webhook webhook.webhook_properties` succeeds (one unused-variable
lint, `_hD` in `P_69_legacy_unrequested_conditional_errors`). No `sorry`, no `axiom` in
either file.

| Lean def | Go file:line | verdict | note |
|---|---|---|---|
| `SubjectAccessReviewStatus` | `api/authorization/v1/types.go` (status) | Abstraction | `ConditionalDecision` holds the decoded CAD (`ToAuthorizerConditionsAwareDecision(*cd, w.conditionsAwareFailureDecision)`). Both Go call sites (`:266`, `:341`) decode with the same `failClosed`, so one decoded value serves both paths. The constructor fail-closed for invalid maps (`encoding.go:134-142`) and the unknown-type `failClosed` (`:149-150`) are part of the decoded value, so no decision-relevant step is hidden (see "Decoding" below). |
| `WebhookAuthorizer` | `webhook.go:90-102,150-170` | Abstraction | `hasReviewer` is `authorizationConditionsReviewer != nil` (gate ∧ client, `:155-157`). `builtin` is the per-request evaluator, and `acr` is the ACR round trip. Both are per-call oracles, which is sound because every theorem quantifies over `w`. |
| `WebhookAuthorizer.WF` | apiserver config validation | Equivalent | `decisionOnError ≠ Allow`. Only used by `P_49_legacy_allowed_and_conditional_not_allow`, where it is needed (the error paths return `decisionOnError` raw, `:245,255`). |
| `ValidRejectsUnrequested` | `validation.go:98-103` | Equivalent | True of the real validator: `clientIsConditionsAware = SupportsConditionalAuthorization(spec.AuthorizationOptions)`, and options are set iff `handlesConditional` (`:287-293`). Hypothesis only, not an axiom. |
| `err*` constants | various | Abstraction | Text only. The nil/non-nil status of each error is what matters, and it is faithful. |
| `authorizeStatus` | `webhook.go:258-272` | Equivalent | Same order: both ⇒ (D, reason, err); denied ⇒ (D, reason, nil); cd ⇒ (FD(decoded), reason, err); allowed ⇒ (A, reason, nil); else (N, reason, nil). `r.Status.Reason` is threaded in every branch. `EvaluationError` is ignored in Go's legacy path and in the Lean, so these agree. |
| `Authorize` | `webhook.go:220-273` | Equivalent | A match error returns `(decisionOnError, "", err)` (`:244-246`). A FALSE match returns `(N, "", nil)` (`:249-251`). A transport error returns `(decisionOnError, "", err)` (`:254-256`). Line numbers in the doc comment are wrong (doc nit 1). |
| `conditionsAwareFailureDecision` | `webhook.go:349-354` | Equivalent | `NoOpinion` ⇒ `noOpinion("failed closed", err)`, else `deny("failed closed", err)` (this includes a non-WF `Allow`, as in Go). The error is threaded. Go always passes a non-nil error, and every Lean call site passes `some`. |
| `handlesConditional` | `webhook.go:287` | Equivalent | |
| `evaluationErrOf` | `webhook.go:331-334` | Equivalent | `len != 0` ⇒ `errors.New(s)`. |
| `conditionsAwareStatus` | `webhook.go:322-346` | Equivalent | The both-flags check comes before validation (`:323-325`) and returns `deny(reason, errBoth)` without the evaluation error, as in Go. Validation failure ⇒ `failPol(err)` (`:327-329`). Switch: denied ⇒ `deny(reason, evalErr)`; cd ⇒ decoded value as is, with no evalErr attached (as in Go `:340-341`); allowed ⇒ `allow(reason, evalErr)`; else `noOpinion(reason, evalErr)`. `valid` is a predicate on the decoded status, while Go validates the raw SAR, including spec and metadata. This is sound per call (Abstraction note A1). |
| `ConditionsAwareAuthorize` | `webhook.go:275-347` | Equivalent | Match error ⇒ failPol (`:308-310`); FALSE ⇒ `noOpinion("", nil)` (`:313-315`); transport error ⇒ failPol (`:318-320`). The SAR answer is a function of `handlesConditional`, which models the different spec and cache key. |
| `builtinOracle` | `webhook.go:963-972` | Equivalent | E ⇒ U; T/F/U unchanged. |
| `tryEvaluateUsingBuiltins` | `webhook.go:951-973` | Gap | A nil builder or an `EvaluatorForData` error returns the original decision (`none`), and the ctx authorizer (`:956`) is folded into `b`. Both are correct. However, Go's partial evaluation does not use `p_b` alone: `evaluate.go:121-130` first calls the condition's own `cond.Evaluate(data)` and falls back to `p_b` only on U. The Lean passes `builtinOracle b` as the whole oracle, which is right only when every condition has `EvaluateFunc == nil` (ev₀ ≡ U). That holds for conditions this webhook decoded itself (`encoding.go:154-163`), but it is an unstated precondition. See Gap G1. |
| `webhookEvaluateConditions` | `webhook.go:453-563` | Abstraction | Control flow is equivalent: reviewer nil ⇒ FD(d′) + err (`:455-457`). Every ACR failure ⇒ `acr = none` ⇒ FD(d′) + err; this covers the apiVersion/kind check `:467-481`, transport `:520-530`, `response == nil` `:532-534`, validation `:536-538`, UID `:541-543`, and `default` `:561-562` (unreachable after validation, P-59). On a clamp miss, the result is FD(d′) + err, where d′ is the refined argument and never `decisionOnError`. On a hit, the result is `(dec, UnconditionalReason, UnconditionalEvaluationError)` taken from the oracle, as in `:546-560`. The ACR is built from the argument d′ (`:459-463`), and `acr` receives d′. |
| `EvaluateConditions` | `webhook.go:429-449` | Equivalent | Unconditional input ⇒ (FD(d), "failed closed", err), checked first (`:430-432`). `data == nil` ⇒ (FD(d), …, err) (`:437-439`). Refined unconditional ⇒ `UnconditionalPartsOrError(d′)` (`:443-445`; Lean `conditions.lean:132` matches `conditions.go:162-173`). Otherwise the webhook is called with d′ (`:449`). A typed-nil `data` passes Go's `== nil` check; the Lean `Option` cannot express this, but it is irrelevant to every property. |

Counts: Equivalent 11, Divergence 0, Abstraction 4, Gap 1.

### Decoding (the specific question in the brief)

Representing `status.conditionalDecision` by its decoded value does not hide any
decision-relevant step:

- On the legacy path, Go decodes only to take `FailureDecision()` (`:266`). If the
  `ConditionsMap` constructor rejects the map (`encoding.go:134-142` → `conditionsmap.go`
  fail-closed), the result is `deny(err)` when deny conditions were present and
  `noOpinion(err)` otherwise. Its FD is D or N respectively. Lean's `d.FailureDecision`
  computes FD on that same value, and decoding is pure. An unknown type decodes to
  `failPol(err)`, whose FD is `decisionOnError` (D or N), and this is also captured.
- On the CAA path, decoding happens after validation and its result is returned unchanged
  (`:341`). A raw value that passes validation but then fails the constructor (if any
  exists) yields an unconditional fail-closed decision. The Lean returns the same `d`. The
  ordering "validate raw, then decode" matters only through `valid`, which is per-call
  (A1).

### Abstraction notes

- **A1 (`valid` on the decoded status).** The Go validator looks at the raw `type`, the spec
  and the metadata, so in general it does not factor through decoding. For example, raw
  `type=Allow` (rejected, `validation.go:107-110`) and a raw Union that folds to the same
  `allow` might be told apart. Every theorem takes `valid` per call and quantifies over it,
  and `ValidRejectsUnrequested` holds of any `valid` that agrees with the real validator on
  the one status of the call. So the abstraction is sound for every stated theorem. It
  would become unsound only for a theorem relating two calls with different raw statuses
  that decode equally; no such theorem exists.

## Divergences

None. Every branch of the six modelled Go functions produces the same decision, PD/FD,
reason threading and error nil-ness as the Lean, for all inputs inside the stated
abstractions.

### Gap G1: precompiled condition evaluators are dropped in `tryEvaluateUsingBuiltins`

- **Input:** `EvaluateConditions` is called with a `conditionsMap` whose deny condition `c`
  has a non-nil `GenericCondition.EvaluateFunc` returning E, and `p_b(c) = F`.
- **Go:** `evalCond(c) = cond.Evaluate = E`, so `deny("one or more … errors", err)` is
  unconditional and is returned as `(D, …, err≠nil)`.
- **Lean:** the oracle is `builtinOracle b`, so `c` evaluates to F and the deny condition is
  eliminated. The result depends on the remaining conditions, for example N or a webhook
  call.
- **Reachability:** none in production. The webhook only receives decisions it decoded
  itself, and their conditions have `EvaluateFunc == nil` (`encoding.go:154-163`). The
  union authorizer hands each child its own sub-decision. No catalogued property is wrong
  on HEAD because of this. However, the "never feeds errors into partial evaluation" half
  of P-32, and the P-27 premise for the production caller, implicitly rely on ev₀ ≡ U, and
  the model states this nowhere.
- **Proposed fix:** make the composition explicit and state the precondition:

```lean
/-- Effective oracle of `partiallyEvaluateConditionsMapInternal` (`evaluate.go:122-129`):
the condition's own evaluator first, the fallback only on `unevaluatable`. -/
def composeOracle (ev₀ fallback : MaybeEvaluateConditionFunc) : MaybeEvaluateConditionFunc :=
  fun c => match ev₀ c with
    | .unevaluatable => fallback c
    | r => r

def tryEvaluateUsingBuiltins (w : WebhookAuthorizer) (ev₀ : MaybeEvaluateConditionFunc)
    (unevaluatedDecision : ConditionsAwareDecision) : ConditionsAwareDecision :=
  match w.builtin with
  | none => unevaluatedDecision
  | some b => PartiallyEvaluateConditionsAwareDecision unevaluatedDecision (composeOracle ev₀ (builtinOracle b))

/-- Decoded conditions carry no evaluator (`encoding.go:154-163`). -/
theorem compose_decoded (b) : composeOracle (fun _ => .unevaluatable) (builtinOracle b) = builtinOracle b := rfl
```

A cheaper alternative is to keep the code and add to the module doc: "precondition: every
condition of `decisionToEvaluate` has ev₀ ≡ U (decoded by this webhook)".

### Doc nits (line numbers in `webhook.lean` / `webhook_properties.lean`)

1. `Authorize` doc: `:250-256`, `:257-260`, `:253-255`, `:257` should be: match error
   `:244-246`, FALSE match `:249-251`, SAR call `:253`, transport error `:254-256`.
2. Module doc: "`w.match`, `webhook.go:250,307`" should be `:240,304`.
3. Module doc: "`default` branch (`:560-561`)" should be `:561-562`. The `webhookEvaluateConditions`
   doc "clamped (`:546-559`)" should be `:545-560`.
4. `P_25_hyp` doc says "Proved (for WF decisions) by the wave-2 evaluate properties". No
   theorem stating `PD(peval d p) ⊆ PD d` exists anywhere in `lean/` (grep for `Subset` and
   `P_25` finds only the definition in `interfaces.lean`). Either the claim is stale or the
   theorem was not committed. Until then, P-26 rests on an undischarged hypothesis.
5. `properties.md` lists "Lean: no" for P-32, P-49, P-50, P-51 and P-52. These are now
   stated and proved in Lean.

## Theorem statement review

- `P_49_legacy_shape`: **matches, more precise than the catalogue.** The catalogue's
  "(D, _, nil) if denied" is wrong when `allowed ∧ denied`: Go returns `(D, reason, err)`
  (`:259-260`), and the Lean has a third disjunct for that case. The catalogue should add
  the both-flags case. The theorem is scoped to match=TRUE ∧ SAR answered, which is the
  only case where `cd` exists.
- `P_49_legacy_conditional_not_allow`: **matches** ("never becomes Allow" for an answered
  SAR).
- `P_49_legacy_allowed_and_conditional_not_allow`: **matches.** It covers every match and
  transport outcome, with a `WF` hypothesis that is necessary and justified. The catalogue
  leaves WF implicit.
- `P_49_caa_no_reviewer`: **weaker by `hboth`, and correctly so.** With `allowed ∧ denied`,
  Go returns `deny(reason, errBoth)`, not `failPol(err)`. The catalogue's "⇒ failPol(err)"
  is slightly wrong; its "∈ {deny, noOp}" part still holds. The theorem is stated on
  `conditionsAwareStatus`, but the match and transport branches of CAA are `failPol` anyway.
- `P_50_conditional_requires_reviewer`: **matches** (full `ConditionsAwareAuthorize`, every
  branch). The only premise is `ValidRejectsUnrequested`, which is true of the real
  validator.
- `P_51_invalid_follows_failurePolicy`: **matches** the catalogue with the both-flags
  exclusion. The catalogue needs that exclusion; see the next item.
- `P_51_denied_invalid_noOpinion`: **matches** the deny-intent case ("⇒ N under NoOpinion").
- `P_51_unrestricted_does_not_hold`: **correct negation** of the catalogue's literal claim.
  The counterexample (`failurePolicy=NoOpinion`, `allowed=denied=true`, `valid ≡ false`) is
  realizable (`validation.go:93-96` rejects it) and differs in the DECISION (D vs N), not
  just in reason text. The catalogue should add "unless allowed ∧ denied (then D)".
- `P_52_possible_or_failure`: **matches**: either `∈ PD(d′)` and the webhook's own answer, or
  `(FD d′, "failed closed", err≠nil)`.
- `P_52_allow_only_if_possible_and_said`: **matches.**
- `P_32_builtin_oracle_no_error`: **matches the catalogue literally** (`p_b(c) ∈ {T,F,U}`),
  but it is about `p_b` only, not the effective oracle (G1).
- `P_32_unconditional_refined_no_acr` / `_acr_irrelevant`: **match** ("no ACR is sent"; the
  extensional form makes the ACR oracle irrelevant).
- `P_32_conditional_refined_sent`: **matches** "the ACR carries peval(d, p_b)". The clamp
  against `PD(peval(d, p_b))` follows when this is combined with `P_52_*` applied to the
  refined decision. A one-line corollary stating the clamp directly on
  `EvaluateConditions` would close the catalogue text exactly. This is optional.
- `P_26_failure_decision_drops`: **weaker than the catalogue formal, but the catalogue is
  the one at fault.** The catalogue states `FD(peval(d,p)) ≤ FD(d)` with no WF premise, yet
  derives it from P-25, which requires WF. The Lean doc gives a non-WF counterexample to
  the unrestricted P-25. The hypothesis form
  `∀ b, w.builtin = some b → P_25_hyp d (builtinOracle b)` is the right shape: it is
  per-instance, so it cannot introduce inconsistency. However, it is not discharged
  anywhere (doc nit 4). Proposed: prove `P_25 : d.WF → P_25_hyp d p` in
  `authorizer/evaluate_properties.lean` and restate P-26 with `(hwf : d.WF)` in place of
  `hP25`.
- `P_69_legacy_unrequested_conditional_errors`: **matches** the documented divergence
  (`:264-267`, non-nil error ⇒ 500). Outside §G; checked for consistency only.
- Helpers (`FailureDecision_ne_Allow`, `FailureDecision_cases`,
  `conditionsAwareFailureDecision_unconditional`, `failLe`, `failLe_of_subset`): correct
  statements of `conditions.go:224-229` facts and of the `N < D` order of §1.1.

## Axioms

None in `webhook.lean` or `webhook_properties.lean`. The environment facts are hypotheses
on individual theorems (`ValidRejectsUnrequested`, `WF`, `P_25_hyp`), so none of them can
make the model inconsistent. `ValidRejectsUnrequested` and `WF` are true of HEAD. `P_25_hyp`
is false for some non-WF inputs, which is exactly why it is a per-instance hypothesis
rather than an axiom, and that is correct.

## Verdict

The webhook model is trustworthy for the properties it proves. Branch order and outcomes
match Go in all six modelled functions:

- the legacy switch, including the deny-before-conditional ordering and reason threading;
- the CAA both-flags check before `CombinedValidate`, and evaluation-error attachment on
  allow/deny/noOpinion only;
- the `failurePolicy` mapping;
- fail-closed to FD of the *original* decision before refinement, and of the *refined*
  decision after it, including every ACR failure and the PD clamp.

Folding decoding into the status loses nothing a theorem uses, and the per-call `valid` and
`acr` oracles are sound abstractions.

There are no divergences. The only substantive item is Gap G1: the model silently assumes
that conditions handed to `EvaluateConditions` carry no precompiled evaluator. This is true
in production but unstated, and it should be made explicit before P-27 is cited for the
webhook.

The catalogue itself needs two corrections that the Lean already gets right: the both-flags
case of P-49 and P-51, and the WF premise of P-26. In addition, P-26's supporting
hypothesis P-25 is claimed proved but no such theorem exists in the tree.
