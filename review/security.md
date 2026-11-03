# Stage 3a: blind end-to-end security review, KEP-5681 Conditional Authorization (gate ON)

HEAD `57a6904a21a` (= `origin/master` `c5bdf2219ee` + PR #143024 `f410163f598` + review docs).
Inputs read: `review/plan.md`, `review/shipped.md`, `review/shipped/*.md`, `review/kep.md`, source tree.
No `review/pr-*.md` file and no `pr-*-overview/review.json` export was read. Nothing was built or run;
every verdict below comes from reading code on HEAD. "Holds" means I found no path that breaks the
property; "does not hold" means I found one and cite it.

Severity: Critical / Important / Nit / Question. Kind: code / KEP / test. Findings are `S-n`.

## 0. Threat model

**Assets.** (a) Integrity of writes in kube-apiserver: a conditionally authorized write must persist
only if the conditions evaluate to Allow. (b) The Deny precedence of the authorizer chain. (c)
Confidentiality of objects, of authorization policy, and of other users' conditions. (d) Availability
of kube-apiserver CPU and memory. (e) Gate-off compatibility with 1.37.

**Trust boundaries.**

1. Requester → kube-apiserver. The requester controls the HTTP verb, path, query (field/label selectors,
   dryRun), the body (object, including subresource "action" objects such as Eviction), and timing.
2. kube-apiserver ↔ webhook authorizer (SAR + ACR). Configured by the admin and trusted for decisions,
   but its responses are *parsed*. Webhook bugs and partially user-derived content (reasons,
   condition text built from user data) are in scope.
3. kube-apiserver → aggregated API servers (proxy) and → peer apiservers (mixed-version proxy).
4. In-process: handler chain → admission → registry. A conditional decision travels only through the
   request `context` (`endpoints/request/context.go:92-106`).

**Enforcement architecture as built.** The filter `WithConditionsAwareAuthorization`
(`endpoints/filters/authorization.go:143-223`) is installed only when the gate is on, a classifier is set
(kube-apiserver only, `pkg/controlplane/apiserver/config.go:248-250`), and the enforcer plugin is in the
admission list (`server/config.go:1077`). If the classifier returns true (resource request, verb ∈
{create, update, patch, delete, deletecollection}, GR not admission-excluded,
`pkg/controlplane/apiserver/config.go:294-319`) and `PossibleDecisions ∋ Allow`, the request continues
with the decision in `ctx` (`authorization.go:170`, `:202-208`). The **only** enforcement point is the
validating admission plugin `AuthorizationConditionsEnforcer`
(`admission/plugin/authorizer/conditionsenforcer/conditionsenforcer.go:78-142`). **There is no
end-of-request check that the enforcer actually ran.** Every handler path that persists state or
returns data without calling validating admission is therefore a candidate bypass. That is the main
thing check 1 below looks for.

Attacker goals: (i) write completes without its conditions being enforced; (ii) Deny weakened to
Allow/NoOpinion; (iii) learn policy, objects or other users' conditions; (iv) exhaust resources;
(v) change behaviour with the gate off.

## 1. Required checks

### Check 1: enforcement points per request shape (`shipped/C-symbols-and-callsites.md` §2.2)

| Request shape (classifier = true) | Enforcer runs? | Verdict | Evidence (HEAD) |
|---|---|---|---|
| create (generic `Store`) | yes, `createValidation` before persist | holds | `registry/generic/registry/store.go:624-627` |
| create with `generateName` retry | yes, once per attempt | holds (multiple evaluations, S-7) | `store.go:585-590` |
| update / patch / apply (existing object) | yes, inside `GuaranteedUpdate` after `BeforeUpdate`, so post-mutation and post-strategy | holds (re-run on every conflict retry, S-7) | `store.go:898-916`; mutating admission in transformers `handlers/update.go:169-190` |
| update / patch / apply → create | yes, but evaluates the **update** decision against a Create admission op; secondary `create` check is unconditional-only | holds fail-closed; semantics questionable (S-17) | `handlers/update.go:212-215`, `:258-282`; `store.go:841-845` |
| delete (immediate / graceful / finalizers) | yes | holds for the write; **pending-graceful delete returns the object without running admission** (S-5) | `store.go:1194`, `:1351`; `:1300-1303` |
| deletecollection | yes, once per item | holds (partial deletion + audit, S-7) | `store.go:1426` |
| dry-run (all verbs) | yes, admission runs on dry-run | holds | `store.go:1351` (dryRun flag passed through) |
| subresource status / scale | yes (`StatusREST`/`ScaleREST` → `Store.Update`) | holds | e.g. `pkg/registry/apps/deployment/storage/storage.go:158,322`; CRD `apiextensions-apiserver/pkg/apiserver/customresource_handler.go:420-449` |
| pods/binding | yes | holds; condition sees Binding, not Pod (S-10) | `pkg/registry/core/pod/storage/storage.go:200-201` |
| pods/eviction | yes, on the Eviction object only; the pod delete uses `ValidateAllObjectFunc` | holds; condition sees requester-supplied Eviction (S-10) | `pkg/registry/core/pod/storage/eviction.go:152-153` |
| serviceaccounts/token | yes, after a `Get` of the SA and a UID-conflict check that both leak before validation (S-5) | holds | `pkg/registry/core/serviceaccount/storage/token.go:114,124,159-160` |
| exec / attach / portforward / proxy via POST/PUT/DELETE | yes (Connect admission) | holds; condition sees `*Options`, `oldObject` nil (S-10) | `endpoints/handlers/rest.go:199-210` |
| exec etc. via GET (websocket) | classifier false → unconditional; extra unconditional `create` check | holds fail-closed (conditional grants unusable, S-20) | `pkg/controlplane/apiserver/config.go:317-318`; `pkg/registry/core/pod/rest/authorize.go:38-62` |
| CRDs served in-process by apiextensions-apiserver | yes (same admission chain, copied config) | holds | `customresource_handler.go:391-409`; `pkg/controlplane/apiserver/apiextensions.go:45` |
| APIServices served by kube-aggregator itself | yes (copied config) | holds | `pkg/controlplane/apiserver/aggregator.go:64` |
| **aggregated APIs proxied by kube-aggregator** | **no**: proxy, no admission in kube-apiserver; classifier still true | **does not hold** (S-1) | `config.go:299-319` (TODO `:314-316`); `aggregator.go:64` copies the classifier into the aggregator's chain |
| peer-proxied (mixed-version) requests | not locally; the peer re-runs authz + admission | holds (assumes peer chain) | `aggregator.go:79-86` |
| **corrupt-object unsafe delete** | **no**: admission replaced by `ValidateAllObjectFunc`; only an unconditional `unsafe-delete-ignore-read-errors` check | **does not hold** (S-2) | `endpoints/handlers/delete.go:141-163`, `:413-423`; `registry/generic/registry/corrupt_obj_deleter.go:111-113,134` |
| admission-excluded resources (SAR/TokenReview family) | classifier false → unconditional | holds fail-closed | `pkg/kubeapiserver/admission/exclusion/resources.go:45-53`; `config.go:308-311` |
| namespace delete when already terminating with finalizers | no admission, returns the namespace | holds for writes; read leak (S-5) | `pkg/registry/core/namespace/storage/storage.go:140,252-254` |
| custom REST `Create/Update/Delete` impls in `pkg/registry` | all checked ones call the validation funcs (rollback, token, eviction, binding, legacy binding, namespace, priorityclass, job, RBAC policybased) | holds | `deployment/storage/storage.go:219-220`; `namespace/storage/storage.go:192`; others pass through to `Store` |

Also checked: the filter fails closed on everything that is neither Allow nor possibly-Allow
(`authorization.go:211-221`); the enforcer returns 500 on a missing decision
(`conditionsenforcer.go:85-88`) and on Deny/NoOpinion/impossible-Allow reaching admission (`:92-94`).

### Check 2: gate OFF identical to 1.37 for API clients — **does not hold, minor** (S-12)

- Filter: `WithAuthorization` only adds a ctx attach under the gate (`authorization.go:101-110`). Holds.
- SAR/SelfSAR/LocalSAR: `authorizationOptions` cleared when gate off (`selfsubjectaccessreview/rest.go:79-81`,
  `subjectaccessreview/rest.go:78`, `localsubjectaccessreview/rest.go:80`); status cleared first
  (`selfsubjectaccessreview/rest.go:74`); legacy `Authorize` path (`:114-122`); DV forbids the fields when
  off (`api/authorization/v1/types.go:237-238,305-306`). Holds.
- Webhook legacy `Authorize`: the unrequested-`conditionalDecision` branch is **ungated**
  (`plugin/pkg/authorizer/webhook/webhook.go:264-267`). With the gate off, a webhook that sends
  `allowed:true` plus any `conditionalDecision` used to get Allow; it now gets
  NoOpinion/Deny + error. That error becomes a 500 when nothing later allows (`authorization.go:115-118`). The JSON
  decoder populates the field regardless of the gate.
- Union reason text: aggregated NoOpinion reasons are prefixed with `<authorizerName>: `, ungated
  (`authorization/union/union.go:88-89`). This changes 403 bodies.
- `GetOldObject` (#142493): ungated override in `admission/conversion.go:62-68`. I found no in-tree
  non-test caller that relies on the old internal-version behaviour (grep over
  `admission/plugin/{webhook,policy,cel}`). Holds as far as checked.

### Check 3: unknown or unrequested decision types — **does not hold on the conditions-aware path** (S-3, S-4)

- Legacy `Authorize` (`webhook.go:258-272`): `denied` wins; an unrequested `conditionalDecision` →
  `FailureDecision()` of the parsed tree (Deny if any Deny conditions) + error; unknown types → `failClosed`
  (`apis/authorization/v1/encoding.go:149-150`). No validation runs on this path. This path fails closed.
- `ConditionsAwareAuthorize` (`webhook.go:275-347`): `CombinedValidateSubjectAccessReviewCreate` runs on
  the **whole SAR, including the server-built spec**, *before* the `Denied` check (`:327-329` vs `:338`).
  Any validation error is mapped to `failurePolicy` (`conditionsAwareFailureDecision`, `:349-354`), not
  to `FailureDecision()`. Consequences:
  - Without `conditionsReview` (`handlesConditional=false`, `:287`), an unrequested conditional decision is
    rejected by `validation.go:101-103` and turned into **NoOpinion** under `failurePolicy: NoOpinion`, even
    when it carries Deny conditions. The legacy path returns Deny for the same response. The API doc
    requires "Deny if any Deny conditions were present" (`api/authorization/v1/types.go:418-419`).
  - `denied:true` plus anything invalid (e.g. a `conditionalDecision`, which `validation.go:117-119` forbids)
    → NoOpinion. The comment at `webhook.go:261` states the opposite intent for the legacy path.
  - `conditionalDecision.type ∈ {Allow, Deny, NoOpinion}` (`validation.go:107-109`), or DV errors inside a
    map with Deny conditions (per-list `maxItems=128`, `maxBytes=10240`, ID format;
    `api/authorization/v1/zz_generated.validations.go:475-576`) → NoOpinion. The constructor would have
    produced Deny (`authorizer/conditionsmap.go:141-146`), but DV runs first.
  - Spec validation of server-built data: `validation.go:45-48` (empty user and groups),
    `:198-217` (field-selector requirement with empty key). A requester can reach the latter on
    `deletecollection` with `?fieldSelector==x` (`endpoints/request/requestinfo.go:261-266` →
    `filters/authorization.go:252-259` → `webhook.go:579-583,604-607` →
    `apimachinery/.../meta/v1/validation/validation.go:137-139`). The webhook's answer, including a Deny,
    is replaced by failurePolicy. Labels cannot trigger it (`labels.Parse` validates keys and values).
    Unusual verbs and Extra keys are not validated, so they cannot trigger it.
- `EvaluateConditions` ACR path: every malformed/unexpected answer → `FailureDecision()` of the refined
  decision; responses outside `PossibleDecisions` are rejected (`webhook.go:532-563`). This path fails closed.

### Check 4: every place an answer is replaced by failurePolicy / FailureDecision

| Site | Replacement | Can Deny be weakened? |
|---|---|---|
| `webhook.go:244-246` (legacy matchConditions error) | failurePolicy | pre-existing |
| `webhook.go:254-256` (legacy SAR transport error) | failurePolicy | pre-existing |
| `webhook.go:264-267` (legacy unrequested conditional) | `FailureDecision()` + err | no |
| `webhook.go:308-310`, `:318-320` (CA matchConditions / transport) | failurePolicy | pre-existing semantics |
| **`webhook.go:327-329` (CA validation error)** | **failurePolicy** | **yes**: explicit Deny and Deny conditions → NoOpinion (S-3, S-4) |
| `encoding.go:149-150` (unknown type) | failurePolicy (`failClosed` arg) | yes in principle; DV catches it first |
| `conditionsmap.go:150-174` (constructor) | Deny if any Deny conditions | no |
| `conditionsunion.go:138-141` (dup/invalid names) | union `FailureDecision()` | no |
| `webhook.go:430-457,479,529-562` (EvaluateConditions) | refined `FailureDecision()` | no. Refined Deny can drop to NoOpinion only after all Deny conditions evaluated false in-process (`:424-428`) |
| `union.go:134-136,162-167,189-192` | sub-/union `FailureDecision()` | no |
| `conditionsenforcer.go:148-150` | Deny | no |
| `pkg/registry/authorization/util/helpers.go:278-285` (SAR encoding) | `FailureDecision()` | no |

Note on the KEP: `kep.md:822-823` says a Deny-condition error "is controlled by FailureMode". In the code it is always
Deny + error (`authorizer/evaluate.go:144-146`), which is stricter. This is KEP-delta material.

### Check 5: condition-ID and authorizer-name collisions — holds

- Top-level union names come from the configured chain. They are unique and DNS-1123
  (`apis/apiserver/validation/validation.go:632-639`; `union.go:56-68`), and dispatch is by name
  (`union.go:188-193`). An authorizer only ever evaluates its own subtree. The ACR carries only the
  webhook's own sub-decision (`union.go:161` → `webhook.go:459-463`), so other authorizers' conditions
  are not leaked to a webhook.
- Webhook-returned nested `Union`: names must be unique and DNS-1123, else fail closed with
  `FailureDecision` (`conditionsunion.go:63-72,138-141`). They live under the webhook's own name and
  cannot shadow outer names.
- Condition IDs are unique per map across all three effects (`conditionsmap.go:164-174`). Duplicates across
  maps are allowed and harmless for evaluation. Deny/Allow reasons returned from the union are **not**
  prefixed with the authorizer name (`union.go:153,155,172` vs the NoOpinion prefix `:180`), so an audit
  reader cannot tell which authorizer's condition `x` decided (Nit, in S-15).
- Reserved `*.k8s.io`/`*.kubernetes.io` IDs/types are documented (`types.go:438-458`) but not enforced. Only
  authorizers author conditions, so this is not attacker-reachable.

### Check 6: the enforcer

- **Position.** Mutating phase (MAP, MutatingAdmissionWebhook) completes first. In the validating phase
  the enforcer is 37th of 40, after ImagePolicyWebhook, EventRateLimit, PodSecurity, NodeRestriction,
  OwnerReferencesPermissionEnforcement and ValidatingAdmissionPolicy (`pkg/kubeapiserver/options/plugins.go:73-118`,
  esp. `:84,90,111-114`). The KEP says "first validating admission plugin" (`kep.md:977-979`). Earlier
  plugins with side effects or external calls run for requests the conditions will deny (S-6).
- **Which `o`.** `admission.NewVersionedAttributes(a, a.GetKind(), o)` (`conditionsenforcer.go:106`) over
  the attributes of the validating call. Those hold the post-mutation, post-strategy object
  (`store.go:898-916`, `:836-845`). Nothing mutates between validating admission and persist except
  RV/TTL. Holds.
- **Exactly once: does not hold.** The enforcer runs once per validation invocation: per
  `GuaranteedUpdate` retry, per `deletecollection` item, per `generateName` retry. Each time can mean an
  ACR webhook call. Every evaluation must Allow, so integrity holds. Audit does not (next bullet).
- **Audit first-writer-wins.** `audit/context.go:351-354` drops a later differing value with a warning. The
  enforcer writes `decision=allow` on the first Allow (`conditionsenforcer.go:116-124`, TODO `:117-118`), so a
  later Forbid (`:137-139`) is lost. The audit log can say `allow` for a request that ended 403 (S-7).
- **Missing decision** → error → 500 (`conditionsenforcer.go:85-88`). Holds fail-closed. A generic server
  with the gate on and a nil authorizer gets no ctx decision (`authorization.go:67-70`), so every write
  is a 500 (S-19).
- **Gate source.** The filter reads `utilfeature.DefaultFeatureGate` (`server/config.go:1077`,
  `authorization.go:101,136`). The enforcer reads the gate injected via `InspectFeatureGates`
  (`conditionsenforcer.go:63-65,74-76`). kube-apiserver injects `utilfeature.DefaultFeatureGate`
  (`pkg/controlplane/apiserver/config.go:429-434`), so it holds there. An embedder that sets a classifier and passes a
  different gate to admission could get "filter on, enforcer off", which fails open (S-13).
- Disabling the plugin with the gate on: the code warns and installs the legacy filter
  (`server/config.go:1077-1091`). The KEP says startup fails (`kep.md:968-972`). The code's behaviour is
  the safe direction (KEP-delta, Nit, S-21).

### Check 7: reload — holds with a narrow caveat (S-11)

The filter stores the reloadable resolver (`authorization.go:170` with `a` = resolver). `EvaluateConditions`
dispatches to `r.current.Load()` at evaluation time (`pkg/kubeapiserver/authorizer/reload.go:96-99`), so
a decision authored by union generation N can be evaluated by generation N+1. If the name disappears →
`couldn't find authorizer` → fail closed (`union.go:189-192`). If the name now belongs to a non-webhook →
Deny + `ErrorConditionEvaluationNotSupported` (`authorizerfactory/builtin.go:45-47`) and the `PossibleDecisions`
guard (`union.go:162-165`). If a webhook keeps its name but changes endpoint or ACR config → the new
endpoint evaluates foreign conditions. This needs an admin reload mid-request. Window: filter → admission.

### Check 8: SAR / SelfSAR / LocalSAR returning trees — holds as designed; policy disclosure (S-14)

- Conditional trees are returned only if the gate is on and the client's `handledDecisionTypes` ⊇ all five
  (`pkg/registry/authorization/util/helpers.go:251-262`; `selfsubjectaccessreview/rest.go:105-126`).
- SelfSAR: any authenticated user gets the full condition text (CEL, descriptions) that every conditional
  authorizer would apply to *them*, for any verb/resource. LocalSAR: a holder of `create
  localsubjectaccessreviews` in namespace N gets any user's tree for N. Namespace pinning:
  `apis/authorization/validation/validation.go:176-178`. SAR: cluster-wide, privileged.
- Reasons in unconditional SAR answers now carry authorizer-name prefixes (`union.go:88-89`).

### Check 9: unconditional-only in-process `Authorize` callers — holds (fail closed)

All 29 `Authorize` call sites are unconditional (`shipped/C` §2.2). The webhook's legacy path fails
closed on conditional answers (`webhook.go:262-267`). So a user with only a conditional grant:
- RBAC escalate/bind (`pkg/registry/rbac/escalation_check.go:90,138`): Authorize → not Allow → falls back to
  rule coverage. No escalation.
- create-on-update (`handlers/update.go:268`): denied unless `create` is unconditional (S-17).
- Pod connect re-check (`pod/rest/authorize.go:55`), impersonation (`impersonation/impersonation.go:118`,
  `mode.go:560`), kubelet (`pkg/kubelet/server/server.go:408`), CEL `authorizer` (`cel/library/authz.go:671,726`),
  GC / NodeRestriction / cert plugins: all 403 for conditional-only grants. Integrity holds. Some
  features cannot be used with conditional grants (S-20).
- Unsafe delete (`delete.go:413`): the secondary check is unconditional, **but the primary conditional
  `delete` is never evaluated** (S-2).

### Check 10: CEL in #143024 — does not hold for resource bounds (S-8)

- Budget is per condition: `RuntimeCELCostBudget` is passed per `EvaluateCondition` and the remaining budget is
  discarded (`admission/plugin/cel/authorization_conditions.go:168`; TODO `:52`). There is no per-request total.
  VAP, by contrast, threads one remaining budget through a policy's expressions.
- Recompiled on every call: `CompileCELExpression` per condition per evaluation (`:163`), no cache, up to
  10 KiB source each (`conditionsmap.go:119`). There is no estimated-cost rejection at compile time.
- Env: `environment.MustBaseEnvSet(DefaultCompatibilityVersion())` with `StoredExpressions` (`:42-46,163`).
  That is the most permissive env, used for text that arrives fresh on every request (Nit).
- `authorizer` variable: `NewCachingAuthorizer(root)` per `EvaluatorForData`, so per evaluation (not per
  request), and the request user is taken from the activation (`:99-104`). The root authorizer comes from ctx
  (`webhook.go:956`). It calls `Authorize` only, so there is no recursion into conditions. Holds.
- Builtin errors (including cost-exceeded) become Unevaluatable and are retried by the webhook
  (`webhook.go:968-970`). Cost-exceeded work is paid twice. Fails closed only if the ACR webhook is
  correct.
- `namespaceObject` may trigger a live GET when it is not in the informer (`authorization_conditions.go:133`;
  `namespacematcher`), so one write can cost an extra apiserver read per evaluation.
- In-process CEL exists only with `conditionsReview` configured (`reload.go:188-212`).

### Check 11: decision-tree size — does not hold (S-9)

- Per-map cap 128 (constructor, total; DV, per list). Union width: no `maxItems` (`api/authorization/v1/types.go:586-593`).
  Depth: unbounded, limited only by the JSON decoder's nesting limit. The webhook response body has no
  size limit in the SAR/ACR clients (not found).
- Quadratic work: `ConditionsAwareDecisionUnion.Add` checks duplicates linearly (`conditionsunion.go:66,86-90`),
  so decode is O(width²). It runs on every request, **including cache hits**, because the cache stores the raw
  status and `ToAuthorizerConditionsAwareDecision` runs again (`webhook.go:363-364,341`).
  `collectReasonsAndErrors` copies the name prefix at every level (`conditionsunion.go:201`), O(depth²).
  DV, `FromAuthorizerConditionsAwareDecision`, `PartiallyEvaluateConditionsAwareDecision` and `String()`
  are all recursive (`encoding.go:70-81`, `evaluate.go:240-277`, `conditions.go:271-286`).
- SelfSAR echoes the whole tree to any user (size amplification is bounded by what the webhook returns).

### Check 12: webhook response cache — holds

Key = `json.Marshal(r.Spec)` and includes `authorizationOptions` (`webhook.go:359`). Conditional and legacy
entries never collide, and the conditional answer depends only on the spec. Conditional answers are cached
with `authorizedTTL` only when requested (`:413-418`). An unrequested conditional answer gets `unauthorizedTTL`. The cache is
per `WebhookAuthorizer` and rebuilt on reload. Costs per hit: S-9.

### Check 13: `GetOldObject` versioning — holds for create/update; untested for patch/delete (S-18)

`VersionedAttributes.GetOldObject` returns the converted old object (`admission/conversion.go:62-68,97-103`).
The enforcer converts to `a.GetKind()`, the request's external kind (`conditionsenforcer.go:106`).
`ConvertToGVK` returns the same pointer when the GVK already matches (CRs, `conversion.go:74-76`). The
evaluators only read it. Tests: `crd_conversion_test.go` and `hpa_conversion_test.go` exercise create and
update only (`crd_conversion_test.go:201-471`, `hpa_conversion_test.go:43-284`). There is no patch, delete,
deletecollection or subresource coverage. For delete the object is nil and `oldObject` is the stored object
(`handlers/delete.go:139,169`).

### Check 14: information leakage in 403/500 bodies — mostly pre-existing pattern (S-15, S-5, S-6)

- 403 reasons: condition ID + description (`evaluate.go:205-208`), authorizer-name prefixes (`union.go:88-89,180`).
- 500 bodies: `InternalError` prints the error (`responsewriters/errors.go:83-85`). The enforcer returns
  `NewInternalError(err)` for Deny/NoOpinion+error (`conditionsenforcer.go:126-128`), which carries ACR
  `evaluationError` text and aggregated errors of all authorizers in the union. Also
  `decision.String()` in impossible states (`:94,103`).
- New with this feature: conditionally allowed requests reach registry and admission code that returns
  object state or validation detail before the enforcer runs (S-5, S-6).

## 2. Findings

### S-1 Critical, code+KEP: conditional decisions for aggregated (proxied) APIs are not enforced by kube-apiserver

`conditionalRequestClassifier` returns true for any write verb on any non-excluded GR, including groups
served by a remote APIService (`pkg/controlplane/apiserver/config.go:299-319`; the TODO at `:314-316`
acknowledges aggregated groups but only to make them *more* conditional). The aggregator's chain uses the
copied config (`aggregator.go:64`), so the filter lets `PossibleDecisions ∋ Allow` through
(`authorization.go:202-208`). The proxy then forwards without running kube-apiserver admission. This
breaks the classifier contract "MUST guarantee that there is some conditions enforcement later in the request
handler chain" (`authorization.go:53-55`). Conditions end up enforced only if the aggregated server
re-authorizes. Shipped aggregated servers use the legacy filter (`server/config.go:1086`) and legacy
SAR, so for them a conditional grant becomes a 403 (safe but non-functional). Any aggregated server
that trusts kube-apiserver's authorization (AlwaysAllow, no authorizer, or a non-k8s.io/apiserver
implementation) gets an **unconditional Allow** for a conditionally authorized write. Before this
feature, kube-apiserver's 403 protected such servers. The KEP states the requirement
(`kep.md:907-913`) but nothing enforces it. Fix: the classifier returns false for GRs whose APIService has
a `service` (local APIServices only), until aggregated-server support exists.

### S-2 Important, code: corrupt-object unsafe delete skips the enforcer

With `AllowUnsafeMalformedObjectDeletion` (Beta, default on, `apiserver/pkg/features/kube_features.go:390-393`), a
delete with `ignoreStoreReadErrorWithClusterBreakingPotential=true` checks only an unconditional
`unsafe-delete-ignore-read-errors` (`handlers/delete.go:153-160,380-423`). It then deletes through
`corruptObjectDeleter` with `rest.ValidateAllObjectFunc` (`corrupt_obj_deleter.go:111-113,134`), so
validating admission never runs. A conditional primary `delete` decision is silently treated as Allow.
Fix: in that branch, require the ctx decision to be unconditional Allow (or call the enforcer with
`oldObject=nil`, which fails closed for object-scoped conditions).

### S-3 Important, code: conditions-aware webhook path lets validation errors weaken Deny to failurePolicy

`webhook.go:327-329` runs full SAR validation before the decision switch (`:336-346`) and maps any
error to `conditionsAwareFailureDecision` (`:349-354`). Under `failurePolicy: NoOpinion`, the following
become NoOpinion, so a later authorizer such as RBAC can Allow: an explicit `denied:true` with any invalid
companion field; an unrequested conditional decision (no `conditionsReview`, `:287` → `validation.go:101-103`)
with Deny conditions; `conditionalDecision.type=Deny` (`validation.go:107-109`); a map with Deny conditions
that fails DV limits (`zz_generated.validations.go:475-576`). The legacy path returns Deny for the first
three (`webhook.go:262-267`). The constructor would return Deny for the last (`conditionsmap.go:141-146`).
The API contract says to fail closed to Deny if Deny conditions exist (`types.go:418-419`). Fix: check
`Denied` first, and on status validation errors return the parsed tree's `FailureDecision()` (or Deny),
not failurePolicy.

### S-4 Nit, code: server-built SAR spec is validated as client input; requester can trigger failurePolicy

`?fieldSelector==x` on `deletecollection` yields a requirement with empty key that fails
`ValidateFieldSelectorRequirement` (path in Check 3). The webhook's answer, including Deny, is replaced
by failurePolicy. I did not run it. By reading, the deletecollection then fails field-label conversion
(`handlers/delete.go:253-255`), so the realistic impact is an oracle: the user learns whether later
authorizers would allow. Fix: validate only `status` at `webhook.go:327`.

### S-5 Important, code+KEP: conditionally allowed requests reach registry reads before the enforcer

The read happens between the filter and admission:
- Deleting an object already pending graceful deletion returns it without admission
  (`store.go:1300-1303` → `finalizeDelete` `:1535-1536`). Pods return the full object
  (`pkg/registry/core/pod/storage/storage.go:93`). A user with a conditional `delete` and no `get` can read any
  terminating pod (spec, env) in scope, whatever the conditions say.
- A namespace that is terminating with finalizers is returned without admission
  (`namespace/storage/storage.go:252-254`). Precondition errors print UID and RV (`:156-170`).
- `TokenRequest` reveals SA existence and UID before validation (`token.go:114,124`).
- 404/409/422 from `Get`/`BeforeUpdate` reveal existence and state before validation (`store.go:1282-1284`, `:898-900`).
Previously such users got a 403 at the filter. The KEP's model ("a conditional allow is as safe as
admission") covers writes only. Fix options: return nothing but status for unenforced paths; or
evaluate conditions with `oldObject` before returning on `pendingGraceful`; document it in the KEP.

### S-6 Important, code+KEP: enforcer runs after mutating admission and after 36 plugins

Order: `plugins.go:84` ImagePolicyWebhook, `:90` EventRateLimit, …, `:111-113` MAP/MutatingWebhook/VAP,
`:114` enforcer. Consequences for requests the conditions will deny: mutating webhooks (sideEffects
`NoneOnDryRun` may have real side effects) and ImagePolicyWebhook receive the full object and user
(confidentiality and DoS amplification); EventRateLimit buckets are spent; PodSecurity/VAP/plugin error messages
are returned instead of 403, which leaks policy. The KEP says "first validating plugin" (`kep.md:977-979`). The
code comment (`plugins.go:114`) chose to save ACR calls instead. The mutating phase cannot be avoided
(conditions need the final object). Moving the enforcer first among validators removes the validating-plugin
part.

### S-7 Important, code: "evaluated exactly once" does not hold; audit can record Allow for a 403

Re-evaluation happens per conflict retry, per deletecollection item and per generateName retry (Check 6). First-writer-wins
(`audit/context.go:351-354`) keeps the first `decision=allow` (`conditionsenforcer.go:119-121`) and drops a
later `forbid` (`:137-139`). Example: deletecollection where item 1 passes and item 2 fails. The audit event
says allow, the response is 403, and item 1 is deleted. Each re-evaluation can call the ACR webhook. Fix:
record per-evaluation annotations under distinct keys or write the final decision in the handler.

### S-8 Important, code: in-process CEL has no per-request bound

Per-condition full `RuntimeCELCostBudget` × up to 128 conditions per map × unbounded maps per union, plus
a full compile of up to 10 KiB source per condition per evaluation, with no cache and no estimated-cost check
(`authorization_conditions.go:52,163,168`). Multiply by S-7 re-evaluations. A webhook that emits many or heavy
conditions turns each write into seconds of CPU. Requesters control object size, which drives
runtime cost within the per-condition budget. Fix: a shared per-request budget, a compile cache keyed by expression
text + env, and compile-time cost estimation.

### S-9 Important, code: decision-tree width and depth are unbounded

Union has no `maxItems` (`types.go:586-593`). Decode is O(width²) (`conditionsunion.go:66,86-90`) and is
re-run on every cache hit (`webhook.go:363-364,341`). Several functions recurse over the tree (Check 11). A
misbehaving webhook can pin apiserver CPU for its whole cache TTL. Fix: cap union width (e.g. 32) and depth
(e.g. 4) in DV and the builder; cache the decoded decision.

### S-10 Important, KEP: for action subresources the condition's `object` is requester-supplied

For `pods/eviction`, `pods/binding`, `serviceaccounts/token`, `deployments/rollback` and Connect
(`*Options`), the object is the request body and `oldObject` is nil (`eviction.go:152-153`,
`pod/storage/storage.go:200-201`, `token.go:159-160`, `deployment/storage/storage.go:219-220`,
`handlers/rest.go:210`). A condition such as `object.metadata.labels.team == 'a'` on `create pods/eviction`
is satisfied by labelling the Eviction body. The policy author probably meant the target pod. The KEP
and docs should say so. Consider refusing conditional decisions for these subresources in the classifier.

### S-11 Nit, code: reload can evaluate conditions with a different authorizer generation

See Check 7 (`reload.go:96-99`). Fix: store the resolved `current` union in ctx instead of the resolver.

### S-12 Nit, code: gate-off differences visible to clients

`webhook.go:264-267` is not gated. `union.go:88-89` prefixes reasons with authorizer names regardless of the gate.

### S-13 Nit, code: filter and enforcer read the gate from different sources

`server/config.go:1077` and `authorization.go:101,136` vs `conditionsenforcer.go:63-65`. This is safe in
kube-apiserver (`controlplane/apiserver/config.go:434`). Library consumers could combine "filter on" with
"enforcer off", which fails open. Fix: derive `ConditionsEnforcerPluginEnabled` from the plugin's
effective `Handles` state, or have the filter refuse when the injected admission gate differs.

### S-14 Question, KEP: policy and data exposure by design

SelfSAR exposes full condition text to every user (Check 8). The ACR sends full `object`/`oldObject`,
Secrets included, to the authorization webhook for any resource where it returned conditions
(`webhook.go:494-516`). Previously authorization webhooks never saw object content. The KEP should state
both, and maybe offer a redaction or opt-in.

### S-15 Nit, code: reason and error text in 403/500 bodies

Check 14. Deny/Allow reasons are unprefixed while NoOpinion reasons are prefixed (`union.go:153,155,172` vs `:180`). Aggregated
errors from all authorizers reach clients in 500 bodies (`conditionsenforcer.go:126-128`). This follows the
pre-existing pattern, now with more sources.

### S-16 (no finding) cache key completeness: holds (Check 12).

### S-17 Question, code+KEP: create-on-update semantics

The `update` decision's conditions are evaluated against a Create admission op with `oldObject=nil`
(`update.go:212-215`), and the secondary `create` must be unconditional (`update.go:268`). This fails
closed, but conditions written for update run with unexpected inputs. The integration rows are disabled
(`test/integration/apiserver/conditionalauthorization/conditionalauthorization_test.go:653-659`).

### S-18 Important, test: security-relevant paths with no test that would fail if broken

Missing tests: DELETE, PATCH, apply, deletecollection (incl. partial failure + audit), status/scale/eviction/binding/exec,
`failurePolicy: Deny`, webhook-returned top-level Union, `denied:true` + invalid fields on the CA path,
unrequested conditional with no `conditionsReview`, corrupt-object delete with a conditional decision,
aggregated-API request with a conditional decision, reload between filter and enforcer, union width or
condition-count limits, CEL budget exhaustion. Existing: create/update rows plus
`crd_conversion_test`/`hpa_conversion_test` (create/update only, Check 13).

### S-19 Nit, code: gate on + nil authorizer in a generic server → every write 500

`authorization.go:67-70` attaches no decision. The enforcer is default-on and errors (`conditionsenforcer.go:85-88`).

### S-20 Nit, KEP: conditional grants cannot be used for websocket exec/attach/portforward or any GET-connect

`config.go:317-318`, `pod/rest/authorize.go:38-62`. This fails closed. The KEP says pod connect "would be conditions-aware".

### S-21 Nit, KEP: plugin disabled with gate on

The code warns and falls back (`server/config.go:1089-1091`). The KEP says startup fails (`kep.md:968-972`).

## 3. Top 10 risks (ranked)

1. **S-1** Aggregated APIs: kube-apiserver lets conditional writes through to proxied APIs with no local enforcement (Critical).
2. **S-3** The conditions-aware webhook path turns explicit Deny or Deny conditions into NoOpinion on any validation error under `failurePolicy: NoOpinion` (Important).
3. **S-2** Corrupt-object unsafe delete never evaluates the conditional `delete` (Important).
4. **S-5** Pending-graceful delete and other pre-admission paths return object data to users whose conditions would deny (Important).
5. **S-6** Enforcer after mutating webhooks, ImagePolicyWebhook, EventRateLimit and VAP: side effects and policy leaks for unauthorized requests (Important).
6. **S-8** CEL: per-condition budget, recompile per evaluation, no request-level bound (Important).
7. **S-9** Unbounded union width/depth with O(n²) decode on every cache hit (Important).
8. **S-7** Audit first-writer-wins can record `allow` for a forbidden request; multiple ACR calls per request (Important).
9. **S-10** Action-subresource conditions are evaluated against requester-supplied bodies (Important, KEP).
10. **S-18** No tests for delete/patch/deletecollection/subresources/failurePolicy/Union/aggregated paths, which are exactly where S-1..S-7 live (Important, test).

## 4. Overall assessment

The core decision algebra is careful and fails closed almost everywhere it is self-contained:
`PossibleDecisions` guards at union, webhook and enforcer level; `FailureDecision` in the constructors and
the ACR path; unconditional-only secondary checks that deny conditional grants; a gate-off path that is
nearly inert. The weak point is the architectural one the threat model predicts. Enforcement is a single
validating admission plugin, and nothing checks that it ran. Any handler path that persists or returns
data without validating admission becomes a bypass. The review found two write bypasses (aggregated
proxy, corrupt-object delete) and several read paths. The second weak point is the conditions-aware SAR
parsing path, which maps validation failures to failurePolicy instead of the tree's own fail-closed
decision. That reintroduces Deny→NoOpinion weakening that the legacy path explicitly avoids. Resource
bounds (CEL budget, compile cache, union size) are missing, which is tolerable for a trusted webhook but
not for beta. For an **alpha behind a default-off gate**, this is acceptable to ship only if S-1 is fixed
or documented as a hard operational precondition, and S-3 is fixed. Both changes are small. S-2, S-5..S-10
and S-18 should block beta.

## 5. Counts and limits

Findings: Critical 1 (S-1); Important 9 (S-2, S-3, S-5, S-6, S-7, S-8, S-9, S-10, S-18; S-3 groups four
response shapes); Nit 8 (S-4, S-11, S-12, S-13, S-15, S-19, S-20, S-21); Question 2 (S-14, S-17);
S-16 is a "holds" record.

Not checked / could not check:
- Nothing was executed. The S-4 downstream rejection and the S-9 CPU estimates come from reading code only.
- Out-of-tree aggregated servers and their authorizer setups (the real exposure of S-1).
- client-go REST client response-size limits for the webhook clients (I found none, but did not trace the transport).
- Byte-level parity of `k8s-prefixed-label-key` (DV) vs `IsDomainPrefixedKey` (constructor).
- The KEP and code comments contained no text addressed to the reviewer. No injection attempts were seen.
