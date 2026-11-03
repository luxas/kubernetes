# KEP-5681: Conditional Authorization

- Author: Lucas Käldström, Upbound
- Contributor: Micah Hausler, AWS

<!-- toc -->
- [Release Signoff Checklist](#release-signoff-checklist)
- [Abstract](#abstract)
  - [Example Use Cases](#example-use-cases)
  - [Goals](#goals)
  - [Non-goals](#non-goals)
- [Background and Major Considered Alternatives](#background-and-major-considered-alternatives)
  - [Why not just give authorizers access to request and stored objects?](#why-not-just-give-authorizers-access-to-request-and-stored-objects)
  - [Why not just use <code>ValidatingAdmissionPolicies</code>?](#why-not-just-use-validatingadmissionpolicies)
  - [What is partial evaluation?](#what-is-partial-evaluation)
  - [Why propagate the conditions with the request?](#why-propagate-the-conditions-with-the-request)
  - [Glossary](#glossary)
- [Proposal](#proposal)
  - [Technical Requirements](#technical-requirements)
  - [Core interface changes](#core-interface-changes)
  - [Condition and ConditionsMap data model](#condition-and-conditionsmap-data-model)
  - [Computing a concrete decision from a ConditionsMap](#computing-a-concrete-decision-from-a-conditionsmap)
  - [Computing a concrete decision from a conditional authorization chain](#computing-a-concrete-decision-from-a-conditional-authorization-chain)
  - [<code>AuthorizationConditionsEnforcer</code> admission controller](#authorizationconditionsenforcer-admission-controller)
  - [Changes to <code>(Self)SubjectAccessReview</code>](#changes-to-selfsubjectaccessreview)
  - [Supporting webhooks through the <code>AuthorizationConditionsReview</code> API](#supporting-webhooks-through-the-authorizationconditionsreview-api)
  - [Composite / Union Authorizer Support](#composite--union-authorizer-support)
  - [Built-in CEL conditions evaluator](#built-in-cel-conditions-evaluator)
  - [Feature availability and version skew](#feature-availability-and-version-skew)
- [Other Kubernetes authorization enforcement points, with and without conditions-awareness](#other-kubernetes-authorization-enforcement-points-with-and-without-conditions-awareness)
  - [Compound Authorization for Connectible Resources](#compound-authorization-for-connectible-resources)
  - [Compound Authorization for update/patch → create](#compound-authorization-for-updatepatch--create)
  - [Constrained Impersonation through Conditional Authorization](#constrained-impersonation-through-conditional-authorization)
  - [Node authorizer](#node-authorizer)
  - [ValidatingAdmissionPolicies](#validatingadmissionpolicies)
  - [<code>deletecollection</code> support](#deletecollection-support)
  - [Complete list of all <code>Authorize</code> calls in <code>kube-apiserver</code>](#complete-list-of-all-authorize-calls-in-kube-apiserver)
- [Authorizer requirements](#authorizer-requirements)
  - [Risks and Mitigations](#risks-and-mitigations)
  - [Test Plan](#test-plan)
    - [Prerequisite testing updates](#prerequisite-testing-updates)
    - [Unit tests](#unit-tests)
    - [Integration tests](#integration-tests)
    - [e2e tests](#e2e-tests)
  - [Graduation Criteria](#graduation-criteria)
    - [Alpha](#alpha)
    - [Beta](#beta)
    - [GA](#ga)
  - [Version Skew Strategy](#version-skew-strategy)
- [Production Readiness Review Questionnaire](#production-readiness-review-questionnaire)
  - [Feature Enablement and Rollback](#feature-enablement-and-rollback)
  - [Rollout, Upgrade and Rollback Planning](#rollout-upgrade-and-rollback-planning)
  - [Monitoring Requirements](#monitoring-requirements)
  - [Dependencies](#dependencies)
  - [Scalability](#scalability)
  - [Troubleshooting](#troubleshooting)
- [TODOs](#todos)
- [Alternatives Considered](#alternatives-considered)
  - [Expose all conditions in AdmissionReview, and have admission plugins “acknowledge” the conditions](#expose-all-conditions-in-admissionreview-and-have-admission-plugins-acknowledge-the-conditions)
  - [Propagate an API server-generated request UID to both authorization and admission](#propagate-an-api-server-generated-request-uid-to-both-authorization-and-admission)
  - [Only one ConditionSet exposed as part of SubjectAccessReview status](#only-one-conditionset-exposed-as-part-of-subjectaccessreview-status)
  - [Require the client to annotate its write request with field or label selectors](#require-the-client-to-annotate-its-write-request-with-field-or-label-selectors)
  - [Extract label and field selectors from the request and current object in etcd, and supply that to the authorization process](#extract-label-and-field-selectors-from-the-request-and-current-object-in-etcd-and-supply-that-to-the-authorization-process)
  - [Do nothing, force implementers to implement all of this out of tree](#do-nothing-force-implementers-to-implement-all-of-this-out-of-tree)
- [Drawbacks](#drawbacks)
- [Appendix A: Further resources](#appendix-a-further-resources)
- [Appendix B: Future addition sketch: Conditional Reads](#appendix-b-future-addition-sketch-conditional-reads)
<!-- /toc -->

## Release Signoff Checklist

- [x] Enhancement issue in release milestone, which links to KEP dir in [kubernetes/enhancements] (not the initial KEP PR)
- [x] KEP approvers have approved the KEP status as `implementable`
- [x] Design details are appropriately documented
- [ ] (R) Test plan is in place, giving consideration to SIG Architecture and SIG Testing input (including test refactors)
  - [ ] e2e Tests for all Beta API Operations (endpoints)
  - [ ] (R) Ensure GA e2e tests meet requirements for [Conformance Tests](https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/conformance-tests.md)
  - [ ] (R) Minimum Two Week Window for GA e2e tests to prove flake free. *Not yet applicable for this KEP*
- [ ] (R) Graduation criteria is in place
  - [ ] [all GA Endpoints](https://github.com/kubernetes/community/pull/1806) must be hit by [Conformance Tests](https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/conformance-tests.md) within one minor version of promotion to GA. *Not yet applicable for this KEP*
- [x] Production readiness review completed
- [x] Production readiness review approved
- [x] "Implementation History" section is up-to-date for milestone
- [ ] User-facing documentation has been created in [kubernetes/website], for publication to [kubernetes.io]
- [ ] Supporting documentation—e.g., additional design documents, links to mailing list discussions/SIG meetings, relevant PRs/issues, release notes

[kubernetes.io]: https://kubernetes.io/
[kubernetes/enhancements]: https://git.k8s.io/enhancements
[kubernetes/kubernetes]: https://git.k8s.io/kubernetes
[kubernetes/website]: https://git.k8s.io/website

## Abstract

This KEP proposes extending Kubernetes authorization to support **conditions**,
where an authorization decision depends on **resource data** (labels and fields
of object), rather than only metadata (apiGroup, resource, namespace, name).
This enables more fine-grained, and most importantly,
[**cohesive**](https://github.com/kubernetes/kubernetes/issues/118985) access
control policies that span both authorization and admission phases, while
maintaining backward compatibility with existing authorizers.

The goal of this proposal is to make authorizers able scope down their policies
*as if* the authorizer had access to the resource data directly, through the use
of two phases:

1. compute `Allow`, `Deny`, `NoOpinion` or `Conditional` response during the
   authorization phase. If `Conditional`, return the set of conditions to Kubernetes.
1. evaluate any conditions on the old/new object(s) during the validating admission
   phase, and enforce the concrete `Allow`, `Deny` or `NoOpinion` result.

Through this KEP, Kubernetes guarantees to the authorizer that its scoped-down
authorization policy will be enforced, without the authorizer having to rely on
existence of other specific admission plugins.

Concretely, all `SubjectAccessReview` (SAR) APIs are extended such that a client
can ask for conditions and the authorizer can respond with conditions. The end
user thus becomes aware of what restrictions they are subject to through
`kubectl auth can-i` self-lookups. In addition, a new
`AuthorizationConditionsReview` API is added to let out-of-tree authorizers
evaluate conditions.

This KEP aims to provide generalized framework for multiple previous features,
KEPs and issues:

- [DRA AdminAccess](https://github.com/kubernetes/enhancements/tree/master/keps/sig-auth/5018-dra-adminaccess):
  "Deny creates and updates to `ResourceClaim`s with
  `.spec.devices[*].adminAccess=true`, unless
  `namespaceObject.metadata.labels["resource.kubernetes.io/admin-access"] == "true"`"
- [Fine-grained Kubelet API Authorization](https://github.com/kubernetes/enhancements/blob/master/keps/sig-node/2862-fine-grained-kubelet-authz/README.md):
  "Allow a node agent to proxy requests to nodes through the API server, but
  only to scrape readonly information from a path starting with `/pods/`, not to
  exec into pods"
- [Constrained Impersonation](https://github.com/kubernetes/enhancements/tree/master/keps/sig-auth/5284-constrained-impersonation):
  "Allow node agent `csi-driver-foo` to only impersonate the node it is running
  on to `get pods`"
- Requiring presence of certain labels or fields: [#44703](https://github.com/kubernetes/kubernetes/issues/44703)
- Empowering authorizers to restrict the names of created objects: [#54080](https://github.com/kubernetes/kubernetes/issues/54080)
- The tight coupling between the `Node` authorizer and `NodeEnforcement`
  admission controller; with this KEP, the same logic could be modelled through
  only a conditional authorizer[^1].
- Provide an alternative to hard-coded compound authorization (e.g. the
  secondary
  [CSR SignerName](https://github.com/kubernetes/enhancements/tree/master/keps/sig-auth/1513-certificate-signing-request)
  authorization check) where needed (even though the two paradigms are
  complimentary)
- Hopefully, provide a feature that is helpful to unblocking the
  [Referential Authorization KEP](https://github.com/kubernetes/enhancements/pull/4387).
- "RBAC++" efforts, eventually.

[^1]: Note that this proposal does not directly propose any relation/graph-based
authorization mechanism, but that a request might be conditionally allowed on
relation-based conditions.

### Example Use Cases

A non-exhaustive list, in addition to the ones mentioned above:

- Allow user Alice to create, update, delete PersistentVolumes, but only
  whenever spec.storageClassName is "dev"
- Allow a principal to update an object, but only when a sensitive field is unchanged
- Allow a principal to create CertificateSigningRequests, but only when using a
  given signerName
- Allow a principal to update a resource, but only when a sensitive field is
  left unchanged
- Allow a principal to issue ServiceAccount tokens, but only with a given audience
- Allow a controller to update a resource, but only to add/remove its own
  finalizer name
- Allow a node agent to handle a resource, but only when `.spec.nodeName=<node-name>`
- Allow a user to `create subjectaccessreviews`, but only to check permissions
  of certain other users

### Goals

- Provide a way for an authorizer (and by extension, policy author) to only
  authorize certain write[^2] operations, when the payload or stored object
  satisfies some specific conditions
- Let users discover what conditions they are subject to through
  `(Self)SubjectAccessReview`
- Initially support enforcement of write and connect requests in the
  `k8s.io/apiserver` `WithAuthorization` HTTP filter, with options to expand
  coverage to read[^2] and impersonate verbs later.
  - However, conditions can be returned for any verb in `SubjectAccessReview`
    responses, so extensions can be built arbitrarily on top. For instance,
    aggregated API servers can choose to enforce conditions on whatever custom
    verbs it wants, and authorizer can return conditions for any verb it likes.
- Allow any authorizer's conditions to be expressed in both transparent,
  analyzable forms (like Cedar or CEL), or opaque ones (like just `policy16`).
- Support expressing conditions with either “Allow” and “Deny” effects.
- Provide the foundational framework on top of which we can build other
  authorization features, such as Constrained Impersonation, RBAC++ and
  Referential Authorization.
- Ensure that a request is evaluated against an atomic set of policies in the
  authorizer, even in presence of cached authorization decisions

[^2]: This KEP focuses on write requests, but another KEP that would add a
[generalized selector syntax](https://github.com/kubernetes/kubernetes/issues/128154)
is anticipated. That KEP would add a CEL-based, Kubernetes-specific, selector
syntax that form conditions for read requests. Thus could a generic,
conditions-aware "list me what I can see"-client be written that first issues a
SelfSAR, and then adds the returned (authorized) conditions to the list/watch
request, such that the request is by definition authorized.

### Non-goals

- Designing or mandating use of a specific policy authoring UX
- Designing or mandating use of a specific “official” condition syntax  
- Expose the conditions to admission controllers  

## Background and Major Considered Alternatives

To make the proposal easier to read, context and rationale for
commonly-asked-about alternatives is provided already at this stage. The reader
deeply familiar with Kubernetes authorization may proceed to the
[proposal chapter](#proposal).

### Why not just give authorizers access to request and stored objects?

Kubernetes Authorizers today do not have access to the resource data for good
reason:

1. Not all requests have resource data attached to it  
1. The API server must be sure that the request **can become authorized**
   according to all data known at the time (even though to reach a final
   decision, the object must be decoded to check). It would be wasteful, and a
   DoS vector to use API server CPU and RAM resources to decode a request
   payload in a request that anyways cannot become authorized.  
1. Authorization decisions must be stateless, i.e. the same authorization query
   must yield the exact same decision whenever the underlying policy store is
   the same. The authorizer should in other words be a deterministic function
   `a: Metadata x PolicyStore → Decision`. In other words, the initial
   authorization decision *must not*
   [depend on the state of objects in etcd](https://github.com/kubernetes/kubernetes/issues/44703#issuecomment-324826356).
1. The request payload might be mutated many times by admission controllers
   before it reaches the state that can be checked into etcd. In addition, the
   old object is only available very late in the request handling process, right
   before an update is actually about to go through in the storage layer (and
   thus admission is invoked).
1. Even if it was technically possible, providing the authorizer up-front with
   the objects could yield a significant hit, as some time would be spent on
   just propagating the objects to each authorizer, and the authorizer might
   spend more time examining the object earlier.

### Why not just use `ValidatingAdmissionPolicies`?

The observant reader might notice that some of the
[use cases](#example-use-cases) can already be achieved today with the
`ValidatingAdmissionPolicy` (VAP) API.

However, the solution is still in some regards sub-optimal:

1. In the authorization phase, the policy author must "over-grant", and then
   remember to (!) "remove" the permissions in the admission phase.
1. The user needs to understand two different paradigms at once, and coordinate
   the policies between them.
1. The principal-matching predicate needs to be duplicated between RBAC and VAP.
1. The policy author needs permission to both author RBAC rules and VAP objects.
   VAP objects do not have privilege escalation prevention, which means that
   anyone that can create a VAP can author a static `false` condition for
   `operation=*` and `resources=*`, which blocks all writes to the cluster, until
   an admin removes the offending VAP. Thus should not “create VAP” permissions
   be handed out to lower-privileged principals, e.g. namespaced administrators,
   who otherwise legitimately would need to write conditionally authorized
   policies.
1. Strict ordering of creates and deletes: In order to not at any point leak
   data, must the VAP deny rule be authored *and successfully activated* before
   the RBAC allow rules are, and vice versa for deletes.  
1. The conditions do not show up in a `(Self)SubjectAccessReview`, but are only
   noticed by a user subject to the policy upon performing a request.
1. Status quo with `ValidatingAdmissionPolicy` does not offer a tangible path
   forward for providing a unified experience for writing fine-grained
   authorization policies for reads.
1. The authorizer cannot let the policy author express conditional policies of
   the form "allow create persistentvolumes, only when storageClassName=='foo'",
   as the authorizer cannot mandate or control the admission plugins or cluster
   setup process of the cluster it serves authorization decisions to.
1. If the policy could not be modelled as a `ValidatingAdmissionPolicy`, but an
   admission webhook would be needed, that webhook might need to be sent for
   every request in the worst case, as opposed to only those requests that are
   conditionally authorized (as in this proposal).

![Over-grant in RBAC, deny in VAP](images/over-grant-rbac-deny-vap.png)

This proposal solves all of these mentioned issues through a two-phase model:

1. the authorizer **partially evaluates** its authorization policies into
   `Allow`, `Deny`, `NoOpinion`, or a set of conditions on the at the
   authorization-stage unknown data: the request and stored object.
1. Kubernetes or the authorizer evaluates the conditions into a concrete
   response, during the admission phase.

### What is partial evaluation?

Partial evaluation is the process of evaluating expressions as far as possible
with incomplete data. A crucial consequence of this is that some unknown data
might turn out to not be needed at all to assign a fixed value to the
expression! This effective form of pruning can take place if some sub-expression
is independent of the unknown data.

In the KEP context, the unknown data at authorization time is the request and
stored objects, and the request options.

Consider a ValidatingAdmissionPolicy/CEL-like expression syntax,
and how the following two policies would be partially evaluated for the two
example users Alice and Bob:

- Allow Policy 1: `request.apiGroup == "" && request.userInfo.username == "bob"`
- Allow Policy 2:

  ```cel
  request.apiGroup == ""
  && request.resource == "persistentvolumeclaims"
  && request.verb == "create"
  && request.userInfo.username == "alice"
  && object.spec.storageClassName == "dev"
  ```

Now, if Alice performs a `create persistentvolumeclaims`, what will the policies
partially evaluate to?

- Allow Policy 1: `true && false` => `false`
- Allow Policy 2:
  `true && true && true && true && object.spec.storageClassName == "dev"` =>
  `object.spec.storageClassName == "dev"`

In these examples, the result of each sub-expression is shown for clarity.
Policy 1 clearly evaluates to false, without knowing the value of `object`.
Policy 2 produces a *residual expression*. Without knowing the object, it is
impossible to assign a truth value to the residual, and thus is this our
condition in the authorizer response.

Next, let's consider what happens if Bob performs `create persistentvolumeclaims`
in the same setting:

- Allow Policy 1: `true && true` => `true`
- Allow Policy 2:
  `true && true && true && false && object.spec.storageClassName == "dev"` =>
  `false`

Now, Policy 1 returned an unconditional (concrete) allow, and Policy 2 can never
be true, no matter what the value of the object is. If the authorizer follows
"at least one matching Allow policy yields Allow", a concrete Allow can be
returned instantly.

The authorizer might also do positive pruning, that is, if one Allow policy
evaluates to `true`, and another Allow policy to a residual, the authorizer
concludes that no matter what the object is, their union will yield Allow.

Finally, what would happen if user Eve (who is assigned no permissions) tries to
`create persistentvolumeclaims`:

- Allow Policy 1: `true && false` => `false`
- Allow Policy 2:
  `true && true && true && false && object.spec.storageClassName == "dev"` =>
  `false`

This gives us both properties we want: Eve is denied access immediately in the
authorization stage (without ever decoding the body), while it being possible to
express a policy that spans both authorization and admission (policy 2).

Three adjacent systems support partial evaluation:
[Cedar](https://github.com/cedar-policy/rfcs/blob/main/text/0095-type-aware-partial-evaluation.md),
[CEL](https://pkg.go.dev/github.com/google/cel-go@v0.26.1/cel#Env.PartialVars)
and [OPA](https://blog.openpolicyagent.org/partial-evaluation-162750eaf422). In
particular the Cedar RFC has good argumentation on why partial evaluation only
works well in cases where all expressions have a concrete type.

Note that partial evaluation *should* substitute all known variables with
constants, even if the residual cannot be fully evaluated. For example, when a
sub-expression is initially `object.name == request.userInfo.username` and
`request.userInfo.username` is known to be `"lucas"`, but `object` is unknown,
the resulting residual is `object.name == "lucas"`. In other
words, the residual does not depend on any variables already known.

### Why propagate the conditions with the request?

It was already concluded that the authorizer needs to be able to
depend on the API server to “call the authorizer back” with the resource data,
whenever a conditional decision is returned. However, instead of the
authorizer returning the set of conditions to Kubernetes, one could
imagine two other methods, as follows:

1. The authorizer does not return a `ConditionsMap`, but relies on Kubernetes to
   send an `AdmissionReview` to the authorizer whenever a conditional decision
   was made. The authorizer then re-evaluates all policies against the
   AdmissionReview with complete data. This approach has many drawbacks:  
   1. **Two full evaluations needed:** During the authorization phase, the
      worst-case runtime is `O(nk)`, where n is the number of policies, and k is
      the maximum policy evaluation time. The admission-time evaluation would
      also be `O(nk)` in this case.
      1. With this proposal, only `O(k)` time would be required in admission,
         given that the amount of conditions is `O(1)` for a typical request.
   2. **Non-atomicity**: For a given authorizer, a request should be authorized
      from exactly one policy store snapshot. If two full re-evaluations were
      done, the latter (admission-time) policy store semantics would apply, if
      the policy store changed between the request performed authorization and
      admission.
      1. With this proposal, the conditions are computed at authorization time
         by partial evaluation and unmodified enforced at admission, exactly and
         only the authorization-time policy store semantics apply.
   3. **Tight coupling between conditions authoring and evaluation**: The
      authorizer would be the only entity which would be able to evaluate the
      conditional response in the admission stage, which forms a forced tight
      coupling. Two webhooks per authorizer per request is necessary.
      1. With this proposal, builtin conditions enforcers might evaluate and
         enforce the conditions in-process, without a need for another webhook
         in admission. One such builtin enforcer is proposed to be CEL-based.
         This is faster and more reliable.
   4. **Not observable through (Self)SubjectAccessReview**: As for admission
      today, a user subject to a policy would not know what policy they are
      subject to before they execute a request that violates it (hopefully with
      a nice error message).
      1. With this proposal, a user can see the conditions serialized in the
         `(Self)SubjectAccessReview`. Some of the conditions might be opaque (like
         `policy16`), yes, but at least the user might know where to look next.
2. The authorizer does not return a `ConditionsMap`, but instead caches the
   conditions in memory. The authorizer relies on Kubernetes to generate a
   random “request ID”, which is passed to both `SubjectAccessReview` and
   `AdmissionReview` webhooks, so the authorizer can know which conditions to
   apply to which request.  
   1. This approach does not have the “Two full evaluations needed” and
      “Non-atomicity” problems of the first alternative approach, as only the
      conditions need to be atomically evaluated against the resource data.
      However, this approach is subject to the “Tight coupling” and “Not
      observable through `(Self)SubjectAccessReview`” problems. In addition, the
      following problems arise:  
   2. **A stateful authorizer is complex and hard to scale:** The authorizer
      must be way more complex, as it needs to keep a lookup table of request ID
      to condition set internally. If the authorizer needs to be horizontally
      scaled, the load balancer in front of the horizontally scaled authorizers
      would somehow need to know which authorizer replica has what requests'
      conditions stored in memory.
      1. With this proposal, the authorizer is allowed to be stateless and thus
         simpler. Therefore, also the horizontal scaling can be done in a
         straightforward manner, from this perspective.
   3. **Unclear caching semantics**: The authorizer would need to cache the
      conditions in memory for at least as long as SubjectAccessReview requests
      can be cached, for the above atomicity invariant to hold. However, the
      authorizer does not (generally) know the API server configuration, and
      thus does not know how long to cache the conditions, or if at all.

### Glossary

- Concrete/Unconditional (authorization) decision: one of `Allow`, `Deny`,
  `NoOpinion`. Represented in Go as the pre-existing `authorizer.Decision` int
  enum (`DecisionDeny=0`, `DecisionAllow`, `DecisionNoOpinion`), or as a
  `ConditionsAwareDecision` whose `Type` is `Deny`, `Allow` or `NoOpinion`.
- Residual: Expression which is a deterministic function of data that was
  unknown during partial evaluation.
- `ConditionsAwareDecision`: The wire and in-process type that represents any
  decision variant an authorizer can produce. Discriminated by `Type`, with
  variants `Deny`, `Allow`, `NoOpinion`, `ConditionsMap`, and `Union`. Union
  nodes contain an ordered list of `NamedConditionsAwareDecision` (one per
  sub-authorizer). The zero value is `Deny`.
- `ConditionsMap`: The leaf conditional decision. Holds three ordered slices —
  `denyConditions`, `noOpinionConditions`, `allowConditions` — where the
  *effect* of a condition is determined structurally by which slice it lives
  in (there is no per-`Condition` `Effect` field). A valid `ConditionsMap` has
  at least one Allow condition *or* at least one Deny condition, and at most
  128 conditions in total.
- Conditional Allow: A `ConditionsAwareDecision` whose `PossibleDecisions()`
  includes `DecisionAllow`. In practice: a `ConditionsMap` with at least one
  Allow condition, or a `Union` that contains such a `ConditionsMap`
  reachable before any unconditional Deny.
- Conditional Deny: A `ConditionsAwareDecision` whose `PossibleDecisions()`
  is `{DecisionDeny, DecisionNoOpinion}` (no reachable Allow). Typically a
  `ConditionsMap` with only `denyConditions` and/or `noOpinionConditions`.

## Proposal

To achieve the above mentioned goals, at a high level, the following changes are
proposed:

- The `authorizer.Authorizer` interface is **split** into a downscoped
  `authorizer.UnconditionalAuthorizer` (the classic `Authorize` method,
  suitable for legacy callers) and the full `authorizer.Authorizer`
  interface that additionally exposes `ConditionsAwareAuthorize` and
  `EvaluateConditions`. Callers that don't need conditions accept
  `UnconditionalAuthorizer`; conditions-aware call sites (the enforcer plugin,
  the new HTTP filter, the SAR registry) take the full `Authorizer`.
- The `SubjectAccessReview` API is extended so:
  - The client opts in by populating
    `spec.authorizationOptions.handledDecisionTypes` with the decision types
    it can consume. Legacy clients pass only
    `{Allow, Deny, NoOpinion}`; conditions-aware clients also include
    `ConditionsMap` and `Union`.
  - The authorizer returns a conditional response in a new
    `status.conditionalDecision` field (a `*ConditionsAwareDecision`),
    mutually exclusive with `allowed=true` and `denied=true`. A conditional
    decision may itself be a `Union` of sub-authorizers' decisions.
- A new sibling HTTP filter
  `WithConditionsAwareAuthorization(handler, auth, s, conditionsEnforcerEnabled, classifier)`
  runs whenever the `ConditionalAuthorization` feature gate is on, the
  `AuthorizationConditionsEnforcer` admission plugin is enabled *and* a
  `ConditionalAuthorizationRequestClassifier` is installed. It attaches the
  authorizer's `ConditionsAwareDecision` to the request context via
  `request.WithConditionallyAuthorizedDecision`, and lets a conditional-allow
  request proceed only when the classifier confirms the request path is
  covered by the enforcer plugin later on. In all other cases it falls back
  to the legacy `WithAuthorization` filter.
- An `AuthorizationConditionsEnforcer` validating admission plugin (in
  `staging/src/k8s.io/apiserver/pkg/admission/plugin/authorizer/conditionsenforcer/`)
  reads the conditions-aware decision from the request context, calls
  `authz.EvaluateConditions(ctx, decision, data)` against a versioned
  admission attributes wrapper, and enforces the resulting `Decision`. It is
  positioned in the recommended plugin order *after* `MutatingAdmissionWebhook`
  and *before* `ValidatingAdmissionPolicy`, so it sees the fully-mutated
  object but runs before validating webhooks.
- To empower out-of-tree/webhook authorizers to evaluate their (opaque)
  conditions, a new `AuthorizationConditionsReview` API (v1alpha1) is added.
  Any conditional authorizer must serve this API — including `kube-apiserver`
  itself, because it acts as a webhook authorizer for aggregated API
  servers.[^3]
- The proposed `k8s.io/apiserver`-built-in CEL condition evaluator is
  **not yet implemented** in this branch and is tracked as future work; today
  all condition evaluation of webhook-authored conditions is delegated back
  to the authorizer via `AuthorizationConditionsReview`.

[^3]: As `kube-apiserver` serves as a webhook authorizer for aggregated API servers.

Notably, this design achieves its goal of unified authorization expressions
across authorization and admission, without the breaking the reasons why
authorizers do not have direct access to the request body in the authorization
stage:

1. Conditional Authorization is only supported for certain requests, namely
   whenever admission is invoked (verbs `create`, `update`, `patch`, `delete`,
   `deletecollection` and connect requests).
1. Any request that cannot become authorized, regardless of the value of the
   resource data, is rejected already at the authorization stage, thanks to
   partial evaluation.
1. The conditions are part of the returned authorization decision, and partial
   evaluation is a deterministic function, i.e. the same output (which includes
   the conditions) is guaranteed for the same inputs (metadata and policy store
   content).
1. The API server enforces the conditions in the validating admission stage,
   where access to the objects is available with the correct consistency
   guarantees.
1. Authorizers process the object data only when really needed, which minimizes
   the performance hit.

The following picture summarizes how, with this feature, a webhook authorizer
can expose a unified policy authoring experience (e.g. through Cedar or CEL) by
returning conditions that are propagated with the request chain until validating
admission, where the `AuthorizationConditionsEnforcer` plugin "calls the
authorizer back" with the conditions it gave, and the rest of the data.

![Conditional Authorization Overview](images/overview.png)

In function syntax, an authorizer is a deterministic function
`authorize: Metadata x PolicyStore → ConditionsAwareDecision`. A
`ConditionsMap`, returned by some authorizer, holds three ordered slices of
conditions grouped by effect (`denyConditions`, `noOpinionConditions`,
`allowConditions`), each keyed by an authorizer-scoped `id`. With this
proposal, the returned decision is modelled as an algebraic type
`ConditionsAwareDecision` with five variants: `Deny`, `Allow`, `NoOpinion`,
`ConditionsMap`, and `Union` (an ordered tree of named sub-decisions).

Let `ConditionsData` be the term for the data unknown at authorization time
(request, stored object, request options, and other admission-time context).
A condition is a deterministic function
`condition: ConditionsData → Boolean`. Note that the condition is only
a function of the unknown data; already-known data should be constants of the
condition (see the [partial evaluation section](#what-is-partial-evaluation) for
an example). A condition's *effect* — Allow, Deny, or NoOpinion — is expressed
structurally by which slice of the `ConditionsMap` it lives in (there is no
`Effect` field on the `Condition` interface itself); it controls whether
evaluation to `true` produces an Allow, Deny, or NoOpinion decision.

Note that even though the “full” new and old objects are given as inputs to the
condition in this model, the authorizer is free to choose how much of that API
surface is exposed to policy authors. Some authorizer might decide to e.g. only
expose field-selectable fields in the expression model given to the policy
author.

Evaluating a `ConditionsMap` is a deterministic function
`evaluate: ConditionsMap x ConditionsData → Decision`, where `Decision` is one
of `Allow`, `Deny`, or `NoOpinion`. Note that conditions evaluation *should
not* have access to the policy store; this is by design, as it makes this
two-stage mechanism *atomic*, just like it would have been if it could have
been evaluated directly.

### Technical Requirements

- The final decision must always be the same in this two-phase model as in a
  one-phase model (that is, if the request / stored object were given directly
  to the authorizer). This for example implies that the order of the authorizers
  must be preserved.
- Capabilities and decision logic must be exactly the same for both in-tree and
  out-of-tree authorizers.
- Only proceed to decode the object if the request *can become authorized*, to
  avoid Denial-of-Service attack vectors.
- Must work for connectible resources (see
  [this section](#compound-authorization-for-connectible-resources) for more
  details)
- Keep backwards compatibility within supported version skew, as always.
- Consider that a `patch` or `update` in authorization can turn into a `create`
  in admission, `patch` in authorization can turn into an `update` in admission,
  and `deletecollection` in authorization turns into a `delete` in admission.
- Must work with aggregated API servers.
- Must work with any authorizer chain that is formed as a DAG.

### Core interface changes

Rather than turning `authorizer.Decision` into a struct with attached data
(the KEP's original sketch), the implementation keeps the pre-existing
`Decision int` enum unchanged and introduces a new sibling type,
`ConditionsAwareDecision`, that carries the conditional variants. The
`authorizer.Authorizer` interface is split into a downscoped
`UnconditionalAuthorizer` (for legacy call sites) and the full `Authorizer`.
This preserves the invariant `Decision{} == DecisionDeny` (via
`Decision(0) == DecisionDeny`) and lets thousands of legacy call sites keep
compiling unchanged, while still expressing conditional decisions through
the new type.

```go
package authorizer // k8s.io/apiserver/pkg/authorization/authorizer

// Decision is the classic unconditional decision enum. Unchanged by this KEP.
// The zero value is DecisionDeny (see the const block below).
type Decision int

const (
    DecisionDeny Decision = iota
    DecisionAllow
    DecisionNoOpinion
)

// UnconditionalAuthorizer is a downscoped variant of Authorizer for callers
// that don't need conditions (e.g. compound authorization inside subresource
// registries). It only exposes the classic Authorize method.
type UnconditionalAuthorizer interface {
    Authorize(ctx context.Context, a Attributes) (authorized Decision, reason string, err error)
}

// Authorizer makes an authorization decision based on information gained by
// making zero or more calls to methods of the Attributes interface. It may
// return an error together with any decision; it is up to the caller to
// decide whether that error is critical or not.
type Authorizer interface {
    UnconditionalAuthorizer

    // ConditionsAwareAuthorize returns an unconditional, conditional, or unioned
    // decision, where the reason and error are part of the returned struct.
    //
    // An authorizer that is not conditions-aware MUST implement this method as:
    //     return authorizer.ConditionsAwareDecisionFromParts(self.Authorize(ctx, a))
    // Callers must call only one of Authorize or ConditionsAwareAuthorize per
    // request — never both.
    ConditionsAwareAuthorize(ctx context.Context, a Attributes) ConditionsAwareDecision

    // EvaluateConditions evaluates a previously-returned conditional decision
    // against the previously-unknown data available at admission time. It
    // must return a concrete Decision (Allow, Deny, or NoOpinion).
    //
    // An authorizer that does not support conditions MUST fail closed and
    // return authorizer.DecisionDeny, "", authorizer.ErrorConditionEvaluationNotSupported.
    // The context may only be used for timeouts, cancellation, and tracing;
    // it must not influence the outcome. Only `decision` and `data` may.
    EvaluateConditions(ctx context.Context, decision ConditionsAwareDecision, data ConditionsData) (authorized Decision, reason string, err error)
}

var ErrorConditionEvaluationNotSupported = errors.New("condition evaluation not supported")
```

`Attributes` is *not* extended with a `ConditionsMode()` method. Instead, the
client's opt-in signal travels along the request via
`SubjectAccessReviewSpec.authorizationOptions.handledDecisionTypes` — see
[Changes to (Self)SubjectAccessReview](#changes-to-selfsubjectaccessreview)
below. Helpers in
`staging/src/k8s.io/api/authorization/v1/util.go`
(`SupportsConditionalAuthorization`, `SupportsUnconditionalAuthorization`,
`ConditionalAuthorizationDecisionTypes`,
`UnconditionalAuthorizationDecisionTypes`) tell an authorizer whether the
client can handle `ConditionsMap`/`Union` responses.

`ConditionsAwareDecision` is the algebraic type that carries the return value:

```go
// ConditionsAwareDecision represents an authorization decision that may be
// unconditional (Allow/Deny/NoOpinion), a leaf conditional (ConditionsMap),
// or an ordered tree of sub-authorizer decisions (Union).
// Immutable after construction; the zero value is Deny.
type ConditionsAwareDecision struct { /* internal fields only */ }

// Constructors for unconditional variants:
func ConditionsAwareDecisionDeny(reason string, err error) ConditionsAwareDecision
func ConditionsAwareDecisionAllow(reason string, err error) ConditionsAwareDecision
func ConditionsAwareDecisionNoOpinion(reason string, err error) ConditionsAwareDecision

// Lift a legacy (Decision, reason, error) triple into the new type. This is
// what an authorizer that is not conditions-aware calls from its
// ConditionsAwareAuthorize implementation.
func ConditionsAwareDecisionFromParts(d Decision, reason string, err error) ConditionsAwareDecision

// Construct a leaf conditional decision (ConditionsMap):
func ConditionsAwareDecisionConditionsMap(deny, noOpinion, allow []Condition) ConditionsAwareDecision

// Union decisions are built stepwise via a ConditionsAwareDecisionUnion builder,
// see the "Computing a concrete decision from a conditional authorization
// chain" section below.

// Variant/predicate accessors:
func (d ConditionsAwareDecision) IsAllow() bool
func (d ConditionsAwareDecision) IsDeny() bool
func (d ConditionsAwareDecision) IsNoOpinion() bool
func (d ConditionsAwareDecision) IsUnconditional() bool
func (d ConditionsAwareDecision) IsConditionsMap() bool
func (d ConditionsAwareDecision) IsUnion() bool

// Content accessors:
func (d ConditionsAwareDecision) ConditionsMap() ConditionsMap
func (d ConditionsAwareDecision) UnionedDecisions() iter.Seq2[string, ConditionsAwareDecision]
func (d ConditionsAwareDecision) Reason() string
func (d ConditionsAwareDecision) Error() error

// Reasoning helpers:
//   PossibleDecisions returns the set of concrete Decisions this decision can
//   evaluate to, given some ConditionsData. For unconditional variants the
//   set has exactly one element. Never empty.
func (d ConditionsAwareDecision) PossibleDecisions() sets.Set[Decision]

//   FailureDecision returns the fail-closed unconditional decision to use in
//   contexts where the conditional decision cannot be honoured — Deny if
//   PossibleDecisions() contains Deny, else NoOpinion.
func (d ConditionsAwareDecision) FailureDecision() Decision

//   ContainsUnconditionalAllowOrDeny reports whether any leaf in this
//   decision tree is an unconditional Allow or Deny (used by the Union
//   builder to short-circuit further additions).
func (d ConditionsAwareDecision) ContainsUnconditionalAllowOrDeny() bool

//   UnconditionalParts is the primary bridge back to the classic
//   (Decision, reason, error) return.
//   - If expectConditional == true, a still-conditional decision is folded to
//     FailureDecision() with an explanatory reason (fail-closed).
//   - If expectConditional == false, a still-conditional decision produces an
//     error (programmer bug: conditional decision reached a non-conditional
//     call site).
func (d ConditionsAwareDecision) UnconditionalParts(expectConditional bool) (Decision, string, error)
```

Internally, `ConditionsAwareDecision` uses a five-variant enum
(`Deny`, `Allow`, `NoOpinion`, `ConditionsMap`, `Union`). Legacy callers do
not need to know about this — they interact through the classic `Decision`
enum via `Authorize()` and `UnconditionalParts()`.

Evaluating a conditional decision into a concrete one is done by supplying
the previously-unknown data. Any authorization policy may reference this
data; if partial evaluation was done correctly, each condition is a pure
function of it:

```go
package authorizer // k8s.io/apiserver/pkg/authorization/authorizer

// ConditionsData represents the data available at admission time against
// which conditions can be evaluated. By design a subset of admission.Attributes.
type ConditionsData interface {
    GetName() string
    GetNamespace() string
    GetResource() schema.GroupVersionResource
    GetSubresource() string
    GetKind() schema.GroupVersionKind
    GetOperation() AdmissionOperation
    GetOperationOptions() runtime.Object
    IsDryRun() bool
    // GetObject is the object from the incoming request; only populated for
    // CREATE and UPDATE requests.
    GetObject() runtime.Object
    // GetOldObject is the existing object in storage; only populated for
    // UPDATE and DELETE requests.
    GetOldObject() runtime.Object
    GetUserInfo() user.Info
}
```

The `AdmissionOperation` type is defined in this package (rather than
imported from `k8s.io/apiserver/pkg/admission`) to avoid an import cycle;
the string constants match the admission operations (`CREATE`, `UPDATE`,
`DELETE`, `CONNECT`).

### Condition and ConditionsMap data model

The KEP-original `ConditionSet` (a flat list of conditions each carrying an
`Effect` field) is replaced by `ConditionsMap`, a struct with three ordered
slices: `denyConditions`, `noOpinionConditions`, and `allowConditions`. The
effect of a condition is expressed *structurally* — by which slice a
`Condition` lives in — rather than through a per-condition `Effect` field.
This keeps each individual `Condition` smaller and makes the deny/noOpinion/
allow evaluation ladder trivial to walk.

The three effect meanings are unchanged from the KEP's original description:

- **Deny**: If any Deny condition evaluates to true, the `ConditionsMap`
  necessarily evaluates to Deny. No further authorizers are consulted.
- **NoOpinion**: If any NoOpinion condition evaluates to true (and no Deny
  condition did), the `ConditionsMap` evaluates to NoOpinion for this
  authorizer — later authorizers in the chain can still Allow or Deny. It is
  effectively a "soft deny" that overrides this authorizer's own Allow
  conditions but not the union.
- **Allow**: If any Allow condition evaluates to true (and no Deny/NoOpinion
  did), the `ConditionsMap` evaluates to Allow.

`Condition` is expressed as an interface, not a struct, so authorizers can
plug in pre-compiled representations without an extra serialize/parse round
trip:

```go
package authorizer // k8s.io/apiserver/pkg/authorization/authorizer

// Condition is one authorization condition inside a ConditionsMap. Its
// effect is determined by which slice of the ConditionsMap it lives in.
// A Condition must be immutable and thread-safe.
type Condition interface {
    // GetID uniquely identifies the condition within the ConditionsMap.
    // Validated as a domain-qualified Kubernetes label key
    // (e.g. "acme.io/no-pod-exec"). Any *.k8s.io or *.kubernetes.io domain
    // is reserved for Kubernetes.
    GetID() string

    // GetType describes the condition's encoding (e.g. "acme.io/opaque",
    // or a future built-in like "k8s.io/authorization-cel"). Validated as a
    // domain-qualified label key. Optional if the authorizer can identify
    // the condition by ID alone.
    GetType() string

    // GetCondition returns the condition body: a pure, deterministic function
    // from ConditionsData to a Boolean, encoded as a string. May be opaque
    // or human-readable; the API caps it at 10240 bytes (MaxConditionBytes).
    GetCondition() string

    // GetDescription is an optional human-friendly description shown in
    // errors and for debugging. The API caps it at 1024 bytes.
    GetDescription() string

    // Evaluate lets an authorizer with a pre-compiled representation evaluate
    // this Condition directly (avoiding a parse round trip). If evaluation
    // is not possible in this process — e.g. the Condition has been
    // deserialised as an opaque payload — Evaluate may return
    // ConditionsEvaluationResultUnevaluatable, in which case the caller
    // falls back to ConditionsMap.Evaluate's EvaluateConditionFunc.
    Evaluate(ctx context.Context, data ConditionsData) ConditionEvaluationResult
}

// GenericCondition is the reference struct implementation, used by
// authorizers that carry conditions as (id, type, string body, description)
// tuples and evaluate them from the string body.
type GenericCondition struct {
    ID          string
    Condition   string
    Type        string
    Description string
    // Optional; if nil, the condition is treated as Unevaluatable and the
    // caller's EvaluateConditionFunc is used instead.
    EvaluateFunc func(ctx context.Context, data ConditionsData) ConditionEvaluationResult
}
```

`ConditionEvaluationResult` (in `evaluate.go`) is a small algebraic type with
four states — True, False, Error, Unevaluatable — where the Unevaluatable
state is the addition that makes partial evaluation composable:

```go
type ConditionEvaluationResult struct { /* internal */ }

func ConditionEvaluationResultBoolean(v bool) ConditionEvaluationResult
func ConditionEvaluationResultError(err error) ConditionEvaluationResult
func ConditionsEvaluationResultUnevaluatable() ConditionEvaluationResult

func (r ConditionEvaluationResult) IsTrue() bool
func (r ConditionEvaluationResult) IsFalse() bool
func (r ConditionEvaluationResult) IsError() bool
func (r ConditionEvaluationResult) IsUnevaluatable() bool
func (r ConditionEvaluationResult) Error() error
```

`ConditionsMap` itself:

```go
// ConditionsMap is a conditional decision leaf. It must contain at least one
// Allow condition OR at least one Deny condition (a map that could only
// evaluate to NoOpinion is useless), and at most 128 conditions in total.
type ConditionsMap struct {
    // Private slices, populated only via ConditionsAwareDecisionConditionsMap.
    // Iterated in order via DenyConditions(), NoOpinionConditions(),
    // AllowConditions() (each returning iter.Seq[Condition]).
}

const (
    MaxConditionsPerMap          = 128
    MaxConditionBytes            = 10240 // GetCondition body upper bound
    MaxConditionDescriptionBytes = 1024
)

// PossibleDecisions returns the concrete outcomes this map can evaluate to,
// e.g. {Allow, NoOpinion} for a map with only Allow conditions, or
// {Deny, NoOpinion} for a map with only Deny/NoOpinion conditions.
func (c ConditionsMap) PossibleDecisions() sets.Set[Decision]

// FailureDecision returns Deny if this map's PossibleDecisions() contain
// Deny, else NoOpinion. Used as the fail-closed folding target.
func (c ConditionsMap) FailureDecision() Decision

// Evaluate walks the deny/noOpinion/allow ladder against `data`, using
// evaluateConditionFn for any Condition whose native Evaluate returned
// Unevaluatable. It always returns a concrete Decision.
func (c ConditionsMap) Evaluate(ctx context.Context, data ConditionsData, evaluateConditionFn EvaluateConditionFunc) (Decision, string, error)
```

**Validation.** The wire-level `Condition` and `ConditionsMap` types in
`staging/src/k8s.io/api/authorization/v1/types.go` are subject to the
following validation (from
`staging/src/k8s.io/apiserver/pkg/apis/authorization/validation/validation.go`):

- `Condition.ID` and `Condition.Type` must be **domain-qualified label keys**
  of the form `<domain>/<key>` (e.g. `acme.io/no-pod-exec`), enforced by
  `validateDomainPrefixSeparator`. Any `*.k8s.io` or `*.kubernetes.io` domain
  is reserved for Kubernetes.
- `Condition.Condition` is capped at 10240 bytes; `Condition.Description` at
  1024 bytes.
- Each of `ConditionsMap.denyConditions`, `noOpinionConditions`, and
  `allowConditions` is validated as `listType=map` on `id` with
  `maxItems=128`.
- Within a `Union` decision, each `NamedConditionsAwareDecision.authorizerName`
  must be a DNS-1123 subdomain and unique within that union.
- The SAR-level `spec.authorizationOptions` and `status.conditionalDecision`
  fields are behind `+featureGate=ConditionalAuthorization` and forbidden
  when the gate is off.

### Computing a concrete decision from a ConditionsMap

Evaluating a `ConditionsMap` is done by `ConditionsMap.Evaluate(ctx, data, evalFn)`
in `staging/src/k8s.io/apiserver/pkg/authorization/authorizer/evaluate.go`. It
takes an `EvaluateConditionFunc`, used to concretely evaluate any `Condition`
whose native `Evaluate` returned `Unevaluatable`:

```go
type EvaluateConditionFunc      func(ctx context.Context, condition Condition, data ConditionsData) (bool, error)
type MaybeEvaluateConditionFunc func(ctx context.Context, condition Condition, data ConditionsData) ConditionEvaluationResult
```

`ConditionsMap.Evaluate` always returns a concrete `Decision`. Its partial
sibling, `PartiallyEvaluateConditionsAwareDecision(ctx, decision, data, maybeEvalFn)`
(see the next section), takes a `MaybeEvaluateConditionFunc` and may leave
still-Unevaluatable conditions in place, returning a
`ConditionsAwareDecision` that is partially reduced. In practice:

- The admission-time enforcer uses `ConditionsMap.Evaluate` (via
  `authz.EvaluateConditions`) — it wants a final answer.
- A future built-in CEL evaluator, chained in front of the authorizer, would
  use `PartiallyEvaluateConditionsAwareDecision` to try to evaluate what it
  can in-process and only webhook back to the authorizer for the residue.

The deny/noOpinion/allow ladder itself is unchanged:

1. Evaluate each condition to True, False, Error, or Unevaluatable.
2. Aggregate:

If there is at least one Deny condition that evaluates to true, return `Deny`.

If there is at least one Deny condition that evaluates to an error, return
`Deny` and surface the error (fail closed).

Otherwise, all Deny conditions evaluate to false. If there is at least one
NoOpinion condition that evaluates to true, return `NoOpinion`.

If there is at least one NoOpinion condition that evaluates to an error,
return `NoOpinion` (as if the condition evaluated to true) along with the
error for logging/diagnostics.

Otherwise, all NoOpinion conditions evaluate to false. If there is at least
one Allow condition that evaluates to true, return `Allow`.

Any Allow condition that evaluates to an error is ignored (it merely fails to
contribute to the Allow disjunction). If no Allow condition evaluates to
true, return `NoOpinion`.

![How a decision is computed from an evaluated ConditionsMap](images/conditionset-evaluation.png)

One quite tricky technical detail about partial evaluation is the
short-circuiting of e.g. the common `&&` and `||` operators, especially with
regards to errors. Clearly, `false && <residual>` can be simplified to `false`.
However, `<residual> && false` can either be `false` or `<error>`, if evaluating
`<residual>` can produce an error. Thus are the `&&` and `||` operators **not**
commutative.

The authorizer contract is such that the authorizer *should* only return a
`ConditionsMap` that *could* evaluate to `Allow`. Returning a `ConditionsMap`
that can only evaluate to `NoOpinion` or `Deny` is a waste of resources.
Concretely, the authorizer should not put conditions of form
`<residual> && false` in `allowConditions`, as such conditions are either
`false` or `<error>` and thus never contribute to an `Allow` decision.
However, the same pruning cannot be done for `denyConditions` or
`noOpinionConditions`, as an evaluation error would trigger fail-closed
short-circuiting to `Deny` or `NoOpinion`.

### Computing a concrete decision from a conditional authorization chain

It is now known how to evaluate a *single* `ConditionsMap` together with the
`ConditionsData` into a single, aggregate concrete decision, the same decision
that the authorizer would have immediately returned, if it had direct access
to the `ConditionsData`. Next, we discuss the semantics of multiple
authorizers chained after each other (i.e. the
[union](https://pkg.go.dev/k8s.io/apiserver/pkg/authorization/union)
authorizer), in the light of conditional authorization.

To begin with, it is good to state that the semantics of the existing modes
`Allow`, `Deny` and `NoOpinion` do not change. Whenever a `NoOpinion` is
returned by an authorizer, that decision is ignored (even if an error is
returned), and the next authorizer in the chain is consulted. Thus must any
safety-critical errors be turned into `Deny` decisions if failing closed is
needed. A chain with the decision prefix `NoOpinion, …, NoOpinion, Allow` still
short-circuits and returns a concrete `Allow`. Vice versa for a chain with the
prefix `NoOpinion, …, NoOpinion, Deny` => `Deny`.

A `ConditionsMap` with at least one Allow condition is considered a
"conditional allow". The union authorizer short-circuits when seeing such a
decision — the request *can become allowed*. Crucially, however, the rest of
the authorizer chain (that was not yet considered) must be saved in the
returned decision for later, lazy evaluation, in case the conditional allow
would evaluate into a `NoOpinion`.

**The union authorizer.** Chain semantics are modelled as a tree rather than
a flat list: the `Union` variant of `ConditionsAwareDecision` holds an
ordered `[]NamedConditionsAwareDecision`, where each leaf is a `Deny`,
`Allow`, `NoOpinion`, or `ConditionsMap` decision. The tree is built
stepwise via the `ConditionsAwareDecisionUnion` builder in
`staging/src/k8s.io/apiserver/pkg/authorization/authorizer/conditionsunion.go`:

```go
type ConditionsAwareDecisionUnion struct { /* internal */ }

// Add appends a named sub-authorizer's decision to the union. Validates
// authorizerName (DNS-1123 subdomain, unique within the union). If any
// previously-added decision already contains an unconditional Allow or Deny
// leaf, further Add calls are ignored — the chain has already committed.
func (b *ConditionsAwareDecisionUnion) Add(authorizerName string, d ConditionsAwareDecision)

// ToDecision finalises the builder. If the tree collapses to a single
// unconditional outcome, returns that unconditional decision; otherwise
// returns a Union-variant ConditionsAwareDecision.
func (b *ConditionsAwareDecisionUnion) ToDecision() ConditionsAwareDecision
```

The union authorizer's Go implementation lives in
`staging/src/k8s.io/apiserver/pkg/authorization/union/union.go`; its
`ConditionsAwareAuthorize` walks the chain, feeding each sub-decision into a
`ConditionsAwareDecisionUnion`. `PossibleDecisions` on a Union is the union
of its sub-decisions' possible outcomes (removing `NoOpinion` if any leaf can
Allow or Deny unconditionally). `FailureDecision` returns `DecisionDeny` if
any leaf could Deny, else `DecisionNoOpinion`.

**Two HTTP filters.** Rather than augmenting the signature of
`WithAuthorization`, the implementation adds a *sibling* filter
`WithConditionsAwareAuthorization` in
`staging/src/k8s.io/apiserver/pkg/endpoints/filters/authorization.go`:

```go
// Legacy — unchanged.
func WithAuthorization(
    hhandler http.Handler,
    auth authorizer.UnconditionalAuthorizer,
    s runtime.NegotiatedSerializer,
) http.Handler

// New — engaged when the ConditionalAuthorization feature gate is on AND the
// AuthorizationConditionsEnforcer admission plugin is enabled AND a
// classifier is provided. Falls back to WithAuthorization otherwise.
func WithConditionsAwareAuthorization(
    hhandler http.Handler,
    auth authorizer.Authorizer,
    s runtime.NegotiatedSerializer,
    conditionsEnforcerEnabled bool,
    conditionalAuthzClassifier ConditionalAuthorizationRequestClassifier,
) http.Handler

// ConditionalAuthorizationRequestClassifier returns true if a request with
// the given attributes supports conditional authorization. It MUST guarantee
// that some conditions enforcement runs later in the request handler chain
// (in practice, that the AuthorizationConditionsEnforcer admission plugin
// will fire for this request).
type ConditionalAuthorizationRequestClassifier func(attrs authorizer.Attributes) bool
```

When engaged, `WithConditionsAwareAuthorization`:

1. Calls `auth.ConditionsAwareAuthorize(ctx, attrs)` if the classifier
   returned true; otherwise lifts the classic
   `Authorize` result via `ConditionsAwareDecisionFromParts`. Either way, a
   `ConditionsAwareDecision` is available.
2. Attaches the decision to the context along with the `Authorizer` that
   produced it, via
   `request.WithConditionallyAuthorizedDecision(ctx, authz, d)` (see
   `staging/src/k8s.io/apiserver/pkg/endpoints/request/context.go`). The
   admission enforcer plugin later reads this back with
   `request.ConditionallyAuthorizedDecisionFrom(ctx)`.
3. Lets the request proceed if the decision `IsAllow()` (unconditional Allow)
   or if `PossibleDecisions().Has(DecisionAllow)` (conditional allow). In the
   latter case it adds an audit annotation
   `authorization.k8s.io/is-conditional-decision=true`.
4. Otherwise returns 403 with the reason from the decision, or 500 if the
   decision carried an error.

Note: even when the classifier returns false, the filter still attaches the
(unconditional) decision to context. The enforcer plugin then observes the
decision and short-circuits (since it's already unconditional), keeping the
control flow uniform across classifier=true and classifier=false paths.

**The classifier's predicate in `kube-apiserver`.** The classifier is
provided by `pkg/controlplane/apiserver/config.go`
(`conditionalRequestClassifier`), and wired onto
`server.Config.Authorization.ConditionalAuthorizationRequestClassifier`
whenever the feature gate is on (see
`staging/src/k8s.io/apiserver/pkg/server/config.go`). The current predicate
accepts requests where:

- `verb ∈ {create, update, patch, delete, deletecollection}`;
- the resource, API group, and API version are all concrete (not `*` or empty);
- the GroupResource is not in the admission `exclusion.Excluded()` set.

TODO markers in the classifier note that connect requests (accessed via HTTP
`GET`) and requests for aggregated-API-server-owned groups are not yet
routed through the conditions-aware filter — they are follow-up items.

**Conditional deny vs conditional allow.** If no Allow condition is present
in a returned `ConditionsMap`, the decision is a "conditional deny": later
authorizers need to be consulted to find out if this request can become
authorized. If a later authorizer returns a concrete `Deny`, the request
cannot become allowed; it is either conditionally or concretely denied.[^5]
If a later authorizer returns a concrete `Allow`, the request is
conditionally allowed; if the deny conditions in the beginning all evaluate
to `false`, that first authorizer would have returned `NoOpinion`, and the
next authorizer's concrete `Allow` stands.

[^5]: Note: As we fold `ConditionalDeny + Deny` into Deny directly, the audit log just
tells that one of the authorizers (in this case, the latter) denied it, not
necessarily the first one.

The DRA AdminAccess feature is a good example of a feature that could be
modelled as an authorizer in the beginning of the chain that returns
`NoOpinion` for most requests, but conditional denies for some requests
(namely, creates and updates of `ResourceClaim(Template)s`). In contrast to
using `ValidatingAdmissionPolicy` for that purpose, an authorizer does not
need to allow for its policies to be deleted. In contrast to the existing
DRA AdminAccess implementation at the storage layer, the condition shows up
in `SubjectAccessReviews`.

**Lazy evaluation.** What is proposed in this KEP is thus **lazy
evaluation**, that allows a request to proceed to admission whenever a
conditional allow is seen at authorization time, and the rest of the chain
is lazily evaluated only if needed (if the previous authorizer evaluated to
a concrete `NoOpinion`). The union builder above enforces this: once a
conditional-allow leaf has been added, subsequent authorizers are only
consulted at evaluation time.

Another considered alternative is the eager variant, that would call each
authorizer in the chain already in the authorization stage, until a concrete
`Allow` or `Deny` is reached. However, this approach might be wasteful and
call later authorizers, whose response is never considered in the evaluation
phase in admission. Thus is the lazy approach proposed. Note that when
aggregated API servers ask `kube-apiserver` for a `SubjectAccessReview`, the
evaluation is necessarily eager (the whole chain must be walked once, so its
result can be serialised) — this is acceptable and only affects cross-process
evaluation.

**Partial evaluation.** The top-level
`PartiallyEvaluateConditionsAwareDecision(ctx, decision, data, maybeEvalFn)`
function (in `evaluate.go`) walks the decision DAG depth-first: unconditional
Allow/Deny leaves short-circuit, and the walk stops at the first
still-conditional leaf that `maybeEvalFn` can't reduce (later leaves are
left untouched). This is the intended entry point for a future in-process
CEL evaluator that reduces what it can and defers the rest to
`Authorizer.EvaluateConditions`.

![How conditions are propagated in the API server request chain](images/request-conditions-flow.png)

A high-level picture of the request flow with conditional authorization. The
chain of authorizer decisions can be lazily evaluated, such that the third
authorizer in the picture is not evaluated directly in the authorization
stage, as already the second one might yield an Allow. However, in admission,
if the second authorizer ends up evaluating to `NoOpinion`, the third
authorizer is evaluated (and in this example evaluates first to a conditional
allow, then concrete `Allow`).

A diagram to summarize what the request chain looks like:

![How various authorizer chain decisions are computed into one](images/authorizer-chain-computation.png)

### `AuthorizationConditionsEnforcer` admission controller

The `AuthorizationConditionsEnforcer` validating admission plugin
(`staging/src/k8s.io/apiserver/pkg/admission/plugin/authorizer/conditionsenforcer/`)
evaluates the conditions attached to the request at authorization time and
enforces the resulting concrete `Decision`. It operates on the
fully-mutated request object, and is positioned in the recommended plugin
order **after** `MutatingAdmissionWebhook` and **before**
`ValidatingAdmissionPolicy` (`RecommendedPluginOrder` in
`staging/src/k8s.io/apiserver/pkg/server/options/admission.go`). This gives
it the fully-mutated object while still allowing it to short-circuit before
any validating webhooks fire.

**Feature-gate + plugin-flag coupling.** The current implementation does
*not* hard-error on the "gate on, plugin off" configuration. Instead, the
enablement of the conditions-aware code path is *conjunctive*:

1. `pkg/kubeapiserver/options/plugins.go` registers
   `AuthorizationConditionsEnforcer` in `AllOrderedPlugins`, and in
   `DefaultOffAdmissionPlugins` (it only becomes active when the feature
   gate is enabled — see the plugin's `Handles` gate on
   `genericfeatures.ConditionalAuthorization`).
2. `AdmissionOptions.ApplyTo` records the fact of the plugin being enabled:
   ```go
   c.Authorization.ConditionsEnforcerPluginEnabled =
       slices.Contains(pluginNames, conditionsenforcer.PluginName)
   ```
3. `server.Config.DefaultBuildHandlerChain` chooses between the two filters:
   ```go
   if utilfeature.DefaultFeatureGate.Enabled(genericfeatures.ConditionalAuthorization)
       && c.Authorization.ConditionsEnforcerPluginEnabled {
       handler = genericapifilters.WithConditionsAwareAuthorization(handler,
           c.Authorization.Authorizer, c.Serializer,
           c.Authorization.ConditionsEnforcerPluginEnabled,
           c.Authorization.ConditionalAuthorizationRequestClassifier)
   } else {
       handler = genericapifilters.WithAuthorization(handler, /* ... */)
   }
   ```

The result: if the operator turns on the feature gate but does not enable
the plugin, the API server silently degrades to the legacy filter — no
conditional decisions are ever produced, so there is nothing to enforce.
This is safe but *silent*; a future hardening (proposed as a follow-up) is
to make `AdmissionOptions.Validate` error out on this misconfiguration so
the API server refuses to start.

**Plugin logic.** On `Validate`, the plugin:

1. Reads the request-scoped conditional decision via
   `request.ConditionallyAuthorizedDecisionFrom(ctx)`. If none is present or
   the decision is already unconditional, the plugin returns `nil`
   immediately.
2. Constructs a `ConditionsData`-shaped view of the admission attributes
   using `versioned_attrs.go`, converting `Object` and `OldObject` to the
   authorizer's requested GVK.
3. Calls `authz.EvaluateConditions(ctx, decision, data)` — where `authz` is
   the exact `Authorizer` that produced the decision, propagated via the
   context alongside the decision itself. This ensures that the *same*
   authorizer that authored the conditions is asked to evaluate them.
4. Validates that the returned concrete decision is within
   `decision.PossibleDecisions()`; enforces the outcome (`DecisionAllow` →
   pass; `DecisionDeny`/`DecisionNoOpinion` → return a `Forbidden` admission
   error carrying the reason).

### Changes to `(Self)SubjectAccessReview`

One of the core goals of this KEP is to make it easier for users subject to
authorization policies that span authorization and admission to understand
what policies they are subject to. This in practice means that the
conditional decision should be shown in `(Self)SubjectAccessReview` (SAR)
responses. Two details drive the shape:

- The same request might be subject to multiple conditional authorizers in
  the authorizer chain. Consider a chain of two authorizers both returning a
  conditional decision. The first authorizer's returned `ConditionsMap` has
  precedence over the second, so they cannot be merged; the response must
  retain their order.
- Consider a two-authorizer chain, where the first returns a conditional
  decision and the second returns `Allow`. Since the conditional response
  could evaluate to `Deny` (if there are Deny conditions), the response
  structure must be able to model both conditional and concrete decisions
  interleaved.

Both requirements are met by carrying a single `*ConditionsAwareDecision` on
`status`. Its `Union` variant covers the multi-authorizer chain case; leaf
variants cover the "just one authorizer's `ConditionsMap`" and unconditional
cases uniformly.

The `SubjectAccessReviewStatus` API is thus augmented as follows (the actual
Go types are in
`staging/src/k8s.io/api/authorization/v1/types.go`):

```go
type SubjectAccessReviewStatus struct {
    // Allowed is required. True if the action would be allowed, false otherwise.
    // Mutually exclusive with Denied=true and ConditionalDecision != nil.
    Allowed bool `json:"allowed"`

    // Denied is optional. True if the action would be denied, otherwise false.
    // If Allowed, Denied, and ConditionalDecision are all zero, the authorizer
    // returned NoOpinion. (Previously v1beta1-only; now promoted to v1.)
    // Mutually exclusive with Allowed=true and ConditionalDecision != nil.
    Denied bool `json:"denied,omitempty"`

    // Reason indicates why a request was allowed or denied.
    Reason string `json:"reason,omitempty"`
    // EvaluationError indicates that some error occurred during the
    // authorization check.
    EvaluationError string `json:"evaluationError,omitempty"`

    // ConditionalDecision carries the authorizer's conditional decision.
    // Mutually exclusive with Allowed=true and Denied=true. In practice the
    // top-level Type is expected to be ConditionsMap or Union; the
    // Allow/Deny/NoOpinion variants are representable but redundant with the
    // Allowed/Denied booleans above.
    //
    // Requires the ConditionalAuthorization feature gate to be enabled;
    // forbidden when the gate is off.
    //
    // +optional
    // +featureGate=ConditionalAuthorization
    ConditionalDecision *ConditionsAwareDecision `json:"conditionalDecision,omitempty"`
}

// ConditionsAwareDecisionType is the discriminator for ConditionsAwareDecision.
type ConditionsAwareDecisionType string

const (
    ConditionsAwareDecisionTypeDeny          ConditionsAwareDecisionType = "Deny"
    ConditionsAwareDecisionTypeAllow         ConditionsAwareDecisionType = "Allow"
    ConditionsAwareDecisionTypeNoOpinion     ConditionsAwareDecisionType = "NoOpinion"
    ConditionsAwareDecisionTypeConditionsMap ConditionsAwareDecisionType = "ConditionsMap"
    ConditionsAwareDecisionTypeUnion         ConditionsAwareDecisionType = "Union"
)

// ConditionsAwareDecision is a discriminated union: exactly the field named
// by Type is set. Union nodes form an ordered tree; all other Types are
// leaves. During evaluation, the tree is walked depth-first until an
// unconditional Allow/Deny is reached.
type ConditionsAwareDecision struct {
    // Discriminator.
    // +required
    Type ConditionsAwareDecisionType `json:"type"`

    Deny          *UnconditionalDecision           `json:"deny,omitempty"`
    NoOpinion     *UnconditionalDecision           `json:"noOpinion,omitempty"`
    Allow         *UnconditionalDecision           `json:"allow,omitempty"`
    ConditionsMap *ConditionsMap                   `json:"conditionsMap,omitempty"`

    // Union has at least one element when Type=="Union". listMap on authorizerName.
    Union []NamedConditionsAwareDecision `json:"union,omitempty"`
}

// NamedConditionsAwareDecision associates a sub-authorizer's decision with its
// stable name, so kube-apiserver can correlate conditions back to the
// authorizer that authored them.
type NamedConditionsAwareDecision struct {
    // AuthorizerName is the unique-within-the-union stable name of the
    // sub-authorizer. Validated as a k8s-long-name (DNS-1123 subdomain).
    // +required
    AuthorizerName string                  `json:"authorizerName"`
    // +required
    Decision       ConditionsAwareDecision `json:"decision"`
}

// UnconditionalDecision carries the (reason, evaluationError) tuple for the
// Deny / NoOpinion / Allow variants of ConditionsAwareDecision.
type UnconditionalDecision struct {
    Reason          string `json:"reason,omitempty"`
    EvaluationError string `json:"evaluationError,omitempty"`
}

// ConditionsMap is a conditional decision leaf.
// Must have at least one Allow condition OR one Deny condition. At most 128
// conditions total across the three slices. Each slice is a listMap on `id`.
type ConditionsMap struct {
    DenyConditions      []Condition `json:"denyConditions,omitempty"`
    NoOpinionConditions []Condition `json:"noOpinionConditions,omitempty"`
    AllowConditions     []Condition `json:"allowConditions,omitempty"`
}

// Condition is one authorization condition. Note the absence of an `Effect`
// field — the effect is determined by which slice of ConditionsMap the
// condition lives in.
type Condition struct {
    // ID is a domain-qualified label key (e.g. "acme.io/no-pod-exec"),
    // unique within the ConditionsMap.
    // +required
    ID          string `json:"id"`
    // Condition body, at most 10240 bytes. Encoding is described by Type.
    Condition   string `json:"condition,omitempty"`
    // Type is a domain-qualified label key describing the condition encoding.
    // Optional; can be omitted if the authorizer already knows how to
    // evaluate the condition by ID.
    Type        string `json:"type,omitempty"`
    // Description is a human-friendly, optional string, at most 1024 bytes.
    Description string `json:"description,omitempty"`
}
```

A conditional response is characterised by `Status.ConditionalDecision != nil`.
Old clients that do not recognise this field observe `Allowed=false` and
`Denied=false` and correctly treat the response as a `NoOpinion` — the
authorizer must fold back to `FailureDecision()` for these clients (see the
`HandledDecisionTypes` opt-in below).

The `spec` field is augmented with an `AuthorizationOptions` block that
lets the caller advertise which decision types it can consume:

```go
type SubjectAccessReviewSpec struct {
    // ... resourceAttributes / nonResourceAttributes / user / groups / extra / uid
    // as before, plus:

    // Requires the ConditionalAuthorization feature gate to be enabled;
    // forbidden when the gate is off.
    // +optional
    // +featureGate=ConditionalAuthorization
    AuthorizationOptions *AuthorizationOptions `json:"authorizationOptions,omitempty"`
}

type SelfSubjectAccessReviewSpec struct {
    // ... resourceAttributes / nonResourceAttributes as before, plus:
    // (same field, same semantics)
    // +optional
    // +featureGate=ConditionalAuthorization
    AuthorizationOptions *AuthorizationOptions `json:"authorizationOptions,omitempty"`
}

// AuthorizationOptions carries client-specified options about how the
// authorizer should respond.
type AuthorizationOptions struct {
    // HandledDecisionTypes specifies which ConditionsAwareDecisionType values
    // the caller can consume in this context. Currently valid combinations:
    //   - {Allow, Deny, NoOpinion}              (conditions-unaware caller)
    //   - {Allow, Deny, NoOpinion, ConditionsMap, Union} (conditions-aware)
    // If the authorizer would return a decision type the caller cannot
    // handle, it MUST fold to ConditionsAwareDecision.FailureDecision()
    // (Deny if any Deny conditions were present, else NoOpinion).
    // Set semantics; order does not matter. All clients must handle the
    // conditions-unaware subset.
    // +listType=set
    // +required
    HandledDecisionTypes []ConditionsAwareDecisionType `json:"handledDecisionTypes"`
}
```

Helpers in `staging/src/k8s.io/api/authorization/v1/util.go`
(`SupportsConditionalAuthorization`, `SupportsUnconditionalAuthorization`,
`ConditionalAuthorizationDecisionTypes`,
`UnconditionalAuthorizationDecisionTypes`) let authorizers cheaply check
what a caller supports.

Design note: the KEP originally proposed a `ConditionsMode`
(`""`/`HumanReadable`/`Optimized`) field that let the caller ask for a
particular encoding format. That was replaced by `HandledDecisionTypes`
during implementation — it turned out that the meaningful contract between
client and authorizer was "can you consume conditional decision types at
all?", not "which serialisation flavour do you prefer?". Presentation
formatting concerns (if any) can be added as separate `AuthorizationOptions`
fields later without changing the enum semantics.

### Supporting webhooks through the `AuthorizationConditionsReview` API

The webhook authorizer needs a way to be called back at admission time to
evaluate the conditions it previously returned in a `SubjectAccessReview`.
This is done through a new `AuthorizationConditionsReview` (ACR) API in
`authorization.k8s.io/v1alpha1`. Because `kube-apiserver` acts as a webhook
authorizer for aggregated API servers, `kube-apiserver` also serves this
API. ACR requests are not themselves subject to admission in
`kube-apiserver`.

The ACR API carries the exact `ConditionsAwareDecision` the authorizer
returned previously — no bespoke chain field. Correlation between the SAR
that produced the conditions and the ACR that evaluates them is done by
sending the very same `Decision` back to the authorizer:

```go
// staging/src/k8s.io/api/authorization/v1alpha1/types.go

// AuthorizationConditionsReview describes a request to evaluate authorization conditions.
type AuthorizationConditionsReview struct {
    metav1.TypeMeta   `json:",inline"`
    // ObjectMeta must be an empty struct.
    metav1.ObjectMeta `json:"metadata,omitempty"`
    // +optional
    Request  *AuthorizationConditionsRequest  `json:"request,omitempty"`
    // +optional
    Response *AuthorizationConditionsResponse `json:"response,omitempty"`
}

// AuthorizationConditionsRequest describes the authorization conditions request.
type AuthorizationConditionsRequest struct {
    // Decision is the exact ConditionsAwareDecision the authorizer previously
    // returned in SubjectAccessReviewStatus.ConditionalDecision. If it is a
    // Union, only sub-decisions relevant to this authorizer are included
    // (kube-apiserver, as a composite authorizer, filters the union to
    // sub-authorizers that use this ACR endpoint before forwarding).
    // +required
    Decision authorizationv1.ConditionsAwareDecision `json:"decision"`

    // AdmissionRequest carries the object, oldObject, operation, options,
    // dryRun flag, and userInfo the authorizer will evaluate its conditions
    // against — the ConditionsData subset needed at admission time. The
    // AdmissionRequest shape is reused from admission.k8s.io/v1 to avoid
    // duplicating well-tested types.
    // +optional
    AdmissionRequest *admissionv1.AdmissionRequest `json:"admissionRequest,omitempty"`
}

// AuthorizationConditionsResponse describes an authorization conditions response.
type AuthorizationConditionsResponse struct {
    // UID must be copied verbatim from the request. The server generates a
    // fresh UUID per outbound ACR request and verifies it on the response
    // before trusting the returned decision.
    // +required
    UID types.UID `json:"uid"`

    // Decision is the authorizer's decision after seeing the request data.
    // In practice this is expected to be unconditional (Allow/Deny/NoOpinion)
    // — the whole point of ACR is to reduce the previously-conditional
    // decision to a concrete one — but the type allows any variant. For
    // example, an object-scoped constrained-impersonation authorizer could
    // return a follow-up ConditionsMap (future work).
    // +required
    Decision authorizationv1.ConditionsAwareDecision `json:"decision"`
}
```

The webhook authorizer implementation in
`staging/src/k8s.io/apiserver/plugin/pkg/authorizer/webhook/webhook.go`
handles the client side: `ConditionsAwareAuthorize` sends a SAR that lists
its supported `handledDecisionTypes`; `EvaluateConditions` sends an ACR
carrying the returned `Decision` plus an `AdmissionRequest` synthesised
from the `ConditionsData`. It generates a fresh UUID per ACR request and
rejects responses whose `UID` doesn't match.

**Configuration.** Webhook authorizers opt into ACR support through an
optional `conditionsReview` block on `WebhookConfiguration` (in
`staging/src/k8s.io/apiserver/pkg/apis/apiserver/types.go`,
`WebhookConfiguration.ConditionsReview`):

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AuthorizationConfiguration
authorizers:
 - type: Webhook
   name: webhook
   webhook:
    # Existing SAR wiring
    subjectAccessReviewVersion: v1
    connectionInfo:
      type: KubeConfigFile
      kubeConfigFile: /kube-system-authz-webhook.yaml

    # New: Enables conditional authorization support for this webhook. If
    # unset, the webhook will only be called for classic (unconditional)
    # SubjectAccessReview requests.
    conditionsReview:
      # Required. The AuthorizationConditionsReview API version to send.
      version: v1alpha1
      # Optional. The kubeconfig context to use for ACR calls. If unset,
      # ACR calls reuse the same URL as SAR calls (the caller distinguishes
      # by TypeMeta).
      kubeConfigContextName: authorization-conditions
```

The reload/config plumbing lives in `pkg/kubeapiserver/authorizer/reload.go`,
which loads the `conditionsReview` context (if any) into an
`authorizationConditionsReviewer` REST client on the `WebhookAuthorizer`.

Finally, recall that the webhook authorizer by default caches responses.
Any authorizer that caches SAR responses must also cache the returned
`ConditionsAwareDecision`, so that a follow-up ACR at admission time sees
the same decision (and thus the same policy-store snapshot) that produced
it in the first place.

If Kubernetes supports evaluating some or all conditions in-process with a
built-in condition evaluator, the ACR webhook may become unnecessary. The
implementation currently ships **no** such built-in evaluator (see the
"Built-in CEL conditions evaluator" section) — every conditional decision
today round-trips to the authorizer via ACR. The intended future shape is
summarised by:

| Webhooks during phase: | Authorization response not cached | Authorization response cached |
| :---- | :---- | :---- |
| Condition Type Not Supported by Builtin Condition Evaluators | `ConditionsAwareAuthorize()` + `EvaluateConditions()` (ACR) | `EvaluateConditions()` (ACR) |
| Condition Type Supported by Builtin Evaluator | `ConditionsAwareAuthorize()` | Neither |
| **Today (no built-in evaluator)** | `ConditionsAwareAuthorize()` + `EvaluateConditions()` (ACR) | `EvaluateConditions()` (ACR) |

### Composite / Union Authorizer Support

Some authorizers, like kube-apiserver itself, do not perform authorization logic
themselves, but instead delegates actual authorization decisions to a set of
ordered sub-authorizers. As long as there are no clearly circular dependencies
in the authorizer call chain, this is supported. Consider the following example:

![Directed Acyclic Graph](images/composite-chain.png)

1. A user sends a conditionally-authorized request (e.g. `create`) to an
   aggregated API server.
1. The aggregated API server, as per our contract, must be configured with the
   `kube-apiserver` as its first webhook authorizer, and thus sends a
   `SubjectAccessReview` to it.
1. `kube-apiserver` in turn is configured with a webhook authorizer `foo`,
   to which it sends another `SubjectAccessReview`. `foo` is internally a
   composite authorizer over two sub-authorizers (`system` and `user`), so
   it responds with a `Union` decision whose two children are
   `ConditionsMap` decisions:

   ```yaml
   kind: SubjectAccessReview
   status:
     allowed: false
     conditionalDecision:
       type: Union
       union:
       - authorizerName: system
         decision:
           type: ConditionsMap
           conditionsMap:
             denyConditions:
             - id: foo/system-1
               # Supported by both the kube-apiserver and the aggregated API server
               type: k8s.io/authorization-cel
               condition: <something>
       - authorizerName: user
         decision:
           type: ConditionsMap
           conditionsMap:
             noOpinionConditions:
             - id: foo/user-1
               type: foo.example.com/opaque
               condition: <something>
             allowConditions:
             - id: foo/user-2
               type: foo.example.com/opaque
               condition: <something>
   ```

1. Although it is at this stage known that the request can be authorized (if
   the Deny and NoOpinion conditions evaluate to false and the Allow
   condition evaluates to true), evaluation of the authorizer chain proceeds
   eagerly until an unconditional response is found or the end of the chain
   is reached. Lazy evaluation is only available when the authorizer resides
   in the same process as the request; when a webhook returns a conditional
   decision, `kube-apiserver` must serialise the *entire* remaining chain
   into the outbound SAR response.
1. Thus, `kube-apiserver` performs a webhook to authorizer `bar`, which
   responds with a `ConditionsMap` with one Allow condition:

   ```yaml
   kind: SubjectAccessReview
   status:
     allowed: false
     conditionalDecision:
       type: ConditionsMap
       conditionsMap:
         allowConditions:
         - id: bar/1
           type: k8s.io/authorization-cel
           condition: <something>
   ```

1. As `bar` also responded with a conditional allow, `kube-apiserver`
   consults the Node authorizer next, which returns `NoOpinion`, and finally
   the RBAC authorizer, which also returns `NoOpinion`.
1. If an unconditional response would have been found, `kube-apiserver`
   would have been able to short-circuit the evaluation. Now it reached the
   end of the authorizer chain, and thus returned the following aggregated
   response to the aggregated API server:

   ```yaml
   kind: SubjectAccessReview
   status:
     allowed: false
     conditionalDecision:
       type: Union
       union:
       - authorizerName: foo
         decision:
           type: Union # nested composite authorizer
           union:
           - authorizerName: system
             decision:
               type: ConditionsMap
               conditionsMap:
                 denyConditions:
                 - id: foo/system-1
                   type: k8s.io/authorization-cel
                   condition: <something>
           - authorizerName: user
             decision:
               type: ConditionsMap
               conditionsMap:
                 noOpinionConditions:
                 - id: foo/user-1
                   type: foo.example.com/opaque
                   condition: <something>
                 allowConditions:
                 - id: foo/user-2
                   type: foo.example.com/opaque
                   condition: <something>
       - authorizerName: bar # authorizer name in kube-apiserver
         decision:
           type: ConditionsMap
           conditionsMap:
             allowConditions:
             - id: bar/1
               type: k8s.io/authorization-cel
               condition: <something>
       # node authorizer omitted, as it responded NoOpinion
       # rbac authorizer omitted, as it responded NoOpinion
       # if the node authorizer would have answered Allow, it would have been:
       # - authorizerName: node
       #   decision:
       #     type: Allow
       #     allow:
       #       reason: <something>
   ```

1. The aggregated API server sees that this aggregate conditional response
   from `kube-apiserver` means the request can become authorized if certain
   conditions are met, so it saves the decision on the request context and
   proceeds.
1. Next, the `AuthorizationConditionsEnforcer` admission controller enforces
   that the conditions hold. It walks the decision tree depth-first. First
   up is the `foo` authorizer's `system` `ConditionsMap`, which uses
   `type: k8s.io/authorization-cel`. **In the future**, when the built-in
   CEL evaluator lands, the aggregated API server evaluates the
   `foo/system-1` condition directly against the object, which yields
   `false`, so the Deny condition does not apply and evaluation proceeds.
   **In the current implementation** (no built-in evaluator), the aggregated
   API server issues an `AuthorizationConditionsReview` back to
   `kube-apiserver` for the whole decision tree.
1. The `foo` authorizer's `user` `ConditionsMap` uses the opaque condition
   type `foo.example.com/opaque` which cannot be evaluated by the
   aggregated API server, and so the aggregated API server sends the
   following ACR to `kube-apiserver`:

   ```yaml
   kind: AuthorizationConditionsReview
   request:
     decision:
       type: Union
       union:
       - authorizerName: foo
         decision:
           type: Union
           union:
           # The "system" ConditionsMap was already evaluated to NoOpinion,
           # and is thus omitted
           - authorizerName: user
             decision:
               type: ConditionsMap
               conditionsMap:
                 noOpinionConditions:
                 - id: foo/user-1
                   type: foo.example.com/opaque
                   condition: <something>
                 allowConditions:
                 - id: foo/user-2
                   type: foo.example.com/opaque
                   condition: <something>
       - authorizerName: bar
         decision:
           type: ConditionsMap
           conditionsMap:
             allowConditions:
             - id: bar/1
               type: k8s.io/authorization-cel
               condition: <something>
     admissionRequest:
       # object, oldObject, operation, options, dryRun, userInfo, etc.
       ...
   ```

1. `kube-apiserver` correlates each `NamedConditionsAwareDecision` through
   its `authorizerName` and calls the corresponding authorizer's
   `EvaluateConditions` method. For the `foo` sub-authorizer (a webhook), it
   issues a nested ACR:

   ```yaml
   kind: AuthorizationConditionsReview
   request:
     decision:
       type: ConditionsMap # "system" ConditionsMap already NoOpinion, omitted
       conditionsMap:
         noOpinionConditions:
         - id: foo/user-1
           type: foo.example.com/opaque
           condition: <something>
         allowConditions:
         - id: foo/user-2
           type: foo.example.com/opaque
           condition: <something>
     admissionRequest:
       ...
   ```

1. The `foo` authorizer responds with `NoOpinion`, as both `foo/user-1` and
   `foo/user-2` evaluated to `false`:

   ```yaml
   kind: AuthorizationConditionsReview
   response:
     uid: <copied from the request UID>
     decision:
       type: NoOpinion
       noOpinion:
         reason: no matching allow condition
   ```

1. Next, `kube-apiserver` evaluates the `bar` sub-decision. These conditions
   are of the (future) built-in CEL condition type, so `kube-apiserver`
   would try to evaluate them in-process. If in-process evaluation is not
   possible (e.g. the condition uses a CEL function introduced in a newer
   kube-apiserver than what is running), `kube-apiserver` falls back to
   an ACR back to `bar`. This "fast-path fails → webhook fallback"
   behaviour is described in the "Built-in CEL conditions evaluator"
   section; today all `bar`-owned conditions are evaluated via ACR.
1. The `bar` authorizer returns `NoOpinion`, in the same way as `foo`.
1. Since both `foo` and `bar` evaluated to `NoOpinion`, `kube-apiserver`
   returns `NoOpinion` to the aggregated API server.
1. As evaluation of the first authorizer's conditional allow turned out to
   be `NoOpinion`, evaluation of the other authorizers in the aggregated
   API server's chain is lazily resumed. `Authorize` on the RBAC
   authorizer is called; say it returns `NoOpinion`.
1. Finally, `Authorize` on webhook `baz` is called, which sends a SAR to
   `baz`. Suppose the response is:

   ```yaml
   kind: SubjectAccessReview
   status:
     allowed: false
     conditionalDecision:
       type: ConditionsMap
       conditionsMap:
         allowConditions:
         - id: baz/1
           type: k8s.io/authorization-cel
           condition: <something>
         - id: baz/3
           type: k8s.io/authorization-cel
           condition: <something>
         denyConditions:
         - id: baz/2
           type: k8s.io/authorization-cel
           condition: <something>
   ```

1. If the aggregated API server supports evaluating
   `k8s.io/authorization-cel` in-process (future work), it evaluates in
   the deny→noOpinion→allow order. `baz/2` returns `false`, then `baz/1`
   and `baz/3` are evaluated to `false` and `true` respectively. Since at
   least one Allow condition evaluated to `true` (order within a slice
   doesn't matter), the `ConditionsMap` evaluates to `Allow`. The request
   is thus allowed to proceed to the remaining validating admission
   controllers. In the current implementation, evaluation happens via an
   ACR back to `baz`.

### Built-in CEL conditions evaluator

> **Status: not implemented in this branch.** The current commit set ships
> only the framework (interfaces, decision types, HTTP filter, admission
> plugin, ACR API) and delegates all condition evaluation back to the
> authorizer via `AuthorizationConditionsReview`. No `k8s.io/authorization-cel`
> (or similar) built-in condition type exists yet. The integration test
> `test/integration/apiserver/conditionalauthorization/conditionalauthorization_test.go`
> has commented-out `in-process-eval-only` and
> `if-in-process-fails-call-webhook` variants that mark the intended future
> shape.

The most logical primitive for Kubernetes to add as a follow-up is a CEL
conditions evaluator. Such an evaluator could re-use most of the CEL
infrastructure that Kubernetes already has, and provide a unified model for
those already familiar with `ValidatingAdmissionPolicies`. A wide variety of
authorizers could then author CEL-typed conditions and let the API server
evaluate them without a second webhook. RBAC++ could use this as well. The
CEL evaluator could evolve with distinct maturity guarantees from the core
conditional authorization feature.

The plumbing point for such a future evaluator is the top-level
`PartiallyEvaluateConditionsAwareDecision(ctx, d, data, maybeEvalFn)`
function. The evaluator would be a `MaybeEvaluateConditionFunc` that
recognises specific condition types (e.g. `k8s.io/authorization-cel`) and
returns `ConditionEvaluationResultUnevaluatable` for others. The reduced
decision is then handed to `Authorizer.EvaluateConditions` for the residue.
The intended interface sketch:

```go
// Future work — not implemented today.
type BuiltinConditionsMapEvaluator interface {
    // SupportedConditionTypes defines the Condition.Type values this builtin
    // evaluator can assign truth values to in-process.
    SupportedConditionTypes() sets.Set[string]

    // Evaluate is used as a MaybeEvaluateConditionFunc; returns
    // ConditionsEvaluationResultUnevaluatable for unsupported types.
    Evaluate(ctx context.Context, condition Condition, data ConditionsData) ConditionEvaluationResult
}
```

To avoid parsing the AST from a string on every evaluation (which is
relatively expensive), the CEL evaluator can accept a binary-encoded AST
directly, to get performance on par with `ValidatingAdmissionPolicy`, which
also executes pre-compiled CEL programs.

The built-in CEL condition environment would be similar to that of
`ValidatingAdmissionPolicy`, including the ability to perform secondary
authorization checks through the built-in `authorizer` function. This allows
an authorizer at any point in the authorizer chain to respect other
authorizers in their configured order for secondary authorization checks.
It also makes the authorization layer aware of API-author-designated
secondary checks — e.g. the designer of the `CertificateSigningRequest` API
can require any writer of its objects to also have the `sign` permission on
some signer resource.

**Note on what *did* land in the CEL area.** The commit "Add the
`conditionalAuthorization` field to the CEL environment for the
AuthorizationConfig usage" extends the CEL environment used for
`AuthorizationConfiguration.Authorizers[].MatchConditions` to expose
`authorizationOptions.handledDecisionTypes` on the SAR spec — so operator-
written CEL match conditions can filter based on whether the client opts
into conditional authorization. This is a *matcher* CEL environment (which
authorizers see the request), not a *condition* CEL evaluator (which
evaluates authorizer-authored conditions against the object). The two must
not be conflated.

**Version-skew considerations for the future CEL evaluator.** The authorizer
returning conditions might not know what the caller's (enforcement point's)
CEL capabilities are. If there were two supported CEL condition types
`k8s.io/authorization-cel-v1` and `k8s.io/authorization-cel-v2`, the
authorizer would need to pick one. If the API server supports only `v1` but
the authorizer returned `v2`, the API server would not be able to evaluate
those conditions in-process — but the fallback path is exactly the
already-implemented ACR round-trip, so evaluation still succeeds (just
slower). Even within a single type, if a new CEL function was added in a
later minor version and a newer authorizer used it against an older API
server, the API server would fail in-process evaluation with "no such
function exists" and fall back to ACR, again producing the correct answer.

### Feature availability and version skew

Conditional authorization is available for a given request when all of the
following criteria are met:

- The authorizer implementation supports conditions:
  - In-tree authorizer: implements the full `authorizer.Authorizer`
    interface (including `ConditionsAwareAuthorize` and `EvaluateConditions`)
    and returns something other than a `ConditionsAwareDecisionFromParts`
    lift when appropriate.
  - Webhook authorizer: `WebhookConfiguration.ConditionsReview` is set with
    a valid ACR version, and the webhook responds with
    `.status.conditionalDecision` populated (along with
    `.status.allowed=false` and `.status.denied=false`).
- The `ConditionalAuthorization` feature gate is enabled **AND** the
  `AuthorizationConditionsEnforcer` admission plugin is enabled. When both
  are true, `server.Config.DefaultBuildHandlerChain` installs
  `WithConditionsAwareAuthorization`; if either is missing the API server
  silently falls back to the legacy filter and no conditional decisions
  ever leave the authorizer chain. Follow-up hardening: make
  `AdmissionOptions.Validate` error out on "gate on, plugin off" so a
  misconfigured server refuses to start.
- The request classifier
  (`server.Config.Authorization.ConditionalAuthorizationRequestClassifier`,
  provided by kube-apiserver via
  `pkg/controlplane/apiserver/config.go:conditionalRequestClassifier`)
  returns true. Currently: verb ∈ `{create, update, patch, delete,
  deletecollection}`, resource / APIGroup / APIVersion all concrete
  (no `*`), and the GroupResource is not on the admission
  `exclusion.Excluded()` list. Connect requests and aggregated-API-server-
  owned groups are flagged as TODOs in the classifier — they are
  follow-up items.
- The client opts in via
  `SubjectAccessReviewSpec.AuthorizationOptions.HandledDecisionTypes`
  containing all conditional variants. Kube-apiserver's built-in call
  sites opt in whenever the feature gate is on.

**Version-skew matrix.** Because opt-in is per-request via
`HandledDecisionTypes`, older callers never see conditional decisions and
newer callers negotiate down as needed:

| | Old API server | New API server |
| :---- | :---- | :---- |
| Old webhook | Conditions never returned (webhook doesn't know how). | Conditions never returned (webhook has no `conditionsReview` block, so kube-apiserver treats it as conditions-unaware). |
| New webhook | Webhook sees old SAR spec without `authorizationOptions` → treats the client as conditions-unaware → folds to `FailureDecision()`. | Full conditional flow: kube-apiserver sends `authorizationOptions.handledDecisionTypes`; new webhook returns `status.conditionalDecision` when useful. |

## Other Kubernetes authorization enforcement points, with and without conditions-awareness

In this section, existing and prospective applications of conditional
authorization are listed. Existing `Authorize` call sites *not* listed as
conditions-aware take `authorizer.UnconditionalAuthorizer` (the downscoped
interface) and thus fail closed if handed a conditional decision by folding
to `FailureDecision()`.

The **current status** of each enforcement point below reflects the commit
set that landed the framework. Only the primary `WithAuthorization` /
`WithConditionsAwareAuthorization` filter and the
`AuthorizationConditionsEnforcer` admission plugin are wired end-to-end.
The other integrations listed below remain follow-up work; they are
described here because the design is stable enough to serve as guidance.

One thing that needs to be taken into account for secondary authorization
checks: today some of the checks set `APIVersion="*"` (for unknown reason)
when there is no logical API version at hand. If such checks would need to
start supporting conditional authorization, a concrete API version needs to
be propagated instead, as the classifier rejects wildcard API versions.

### Compound Authorization for Connectible Resources

After the move to WebSockets
([KEP 4006](https://github.com/kubernetes/enhancements/tree/master/keps/sig-api-machinery/4006-transition-spdy-to-websockets#proposal-synthetic-rbac-create-authorization-check)),
connect requests are initially authorized as e.g. `get pods/exec`, which can
lead someone to think that giving `get *` gives only read-only access, and
not also write access. To mitigate this privilege-escalation vector, when
the `AuthorizePodWebsocketUpgradeCreatePermission` feature gate is enabled
(beta and on by default in 1.35), currently `pods/attach`, `pods/exec` and
`pods/portforward` are subject to compound authorization: it is made sure
that the requestor also is authorized to `create` the corresponding
connectible resource. This check is not added (yet at least) for
`pods/proxy`, `services/proxy` and `nodes/proxy`.

**Status: not yet conditions-aware.** The current compound authz call site,
`ensureAuthorizedForVerb` in
`pkg/registry/core/pod/rest/authorize.go`, takes an
`authorizer.UnconditionalAuthorizer`, so any conditional decision returned
by the authorizer folds to its `FailureDecision()` at this call site. Making
this call site conditions-aware — with `operation == CONNECT`,
`object == <connect-data>` (e.g. `PodExecOptions`), `oldobject == nil`, and
`options == nil`, just like connect admission today — remains follow-up
work. That change also requires the classifier to accept the connect
verb (currently a TODO in `conditionalRequestClassifier`).

Once conditions-aware, this check becomes a generalisation of
[KEP-2862: Fine-grained Kubelet API Authorization](https://github.com/kubernetes/enhancements/blob/master/keps/sig-node/2862-fine-grained-kubelet-authz/README.md),
as an authorizer can say "allow lucas to `create nodes/proxy`, but only when
`options.path == "/configz"`", or any other such policy the administrator
might fancy.

### Compound Authorization for update/patch → create

If an `update` or `patch` turns into a `create`, the API server performs
compound authorization to make sure the requestor also has the privilege to
create the resource.

**Status: not yet conditions-aware.**
`staging/src/k8s.io/apiserver/pkg/endpoints/handlers/update.go` does not
consume the conditional decision from the request context; it still uses
the classic `Authorizer.Authorize` path. Wiring `ConditionsAwareAuthorize`
here (and passing along the `ConditionsMap` for a follow-up ACR) is
follow-up work covered by the same design as the primary filter above.

### Constrained Impersonation through Conditional Authorization

[KEP-5284: Constrained Impersonation](https://github.com/kubernetes/enhancements/tree/master/keps/sig-auth/5284-constrained-impersonation)
proposes a way to restrict impersonation such that the requestor both needs
the permission to impersonate the specified user *and* the permission to
impersonate certain types of requests, e.g. `lucas can only impersonate
node foo, but only to get pods`. This is a perfect example of where
conditional authorization shines; the request that is being performed is
the initially-unknown data that an authorizer might want to specify
conditions on.

**Status: not implemented in this branch.** The framework supports the
design; wiring the impersonation filter to a conditions-aware code path
remains follow-up work.

Consider the example of
`lucas can only impersonate node foo, but only to get pods`. The authorizer
policy (in pseudo-code) is of form:

```cel
request.userInfo.username == "lucas" &&  
request.verb == "impersonate" &&  
request.resource == "nodes" &&  
request.apiGroup == "authentication.k8s.io" &&  
request.name == "foo" &&  
impersonatedRequest.apiGroup == "" &&  
impersonatedRequest.resource == "pods" &&  
impersonatedRequest.verb == "get"
```

The first five ANDed expressions can be evaluated to `true` directly, just based
on the data that is available in the normal impersonation `SubjectAccessReview`.
However, `impersonatedRequest` is unknown, and thus does the residual expression
yield conditions in the `SubjectAccessReview` response, e.g. as follows:

```yaml
apiVersion: authorization.k8s.io/v1
kind: SubjectAccessReview
status:
  allowed: false
  conditionalDecision:
    type: ConditionsMap
    conditionsMap:
      allowConditions:
      - id: acme.io/lucas-only-impersonate-node-get-pods
        type: k8s.io/authorization-cel
        condition: |
          impersonatedRequest.apiGroup == "" &&
          impersonatedRequest.resource == "pods" &&
          impersonatedRequest.verb == "get"
```

Now, the impersonation filter can evaluate the condition, either through the
builtin CEL evaluator (if applicable), or by calling the Authorizer's
`EvaluateConditions` endpoint with the missing data (the information about the
impersonated request).

This approach supports the use-cases of the existing Constrained Impersonation
KEP, but also other types of expressions, for instance:

- "A ServiceAccount `ai-agent-foo` can only impersonate user `lucas` if *it also
  at the same time impersonates group* `ai-agent-foo`"
  - This allows *attenuating* what an impersonator can do through generic deny
    rules for the given additional group.
- "ServiceAccount `ai-agent-foo` can impersonate `alice` only for read requests,
  but the same ServiceAccount can impersonate `bob` for any action"
  - The current Constrained Impersonation KEP does not allow distinguishing what
    the impersonator can do for what target user.

In the future, it would be possible to even restrict impersonation based on the
`object` and `oldObject`. For example, consider the following abstract policy
which allows lucas to impersonate any user for `create` and `update` requests,
but only if lucas annotates changed resources with the `lucas-impersonated=true`
label:

```cel
request.userInfo.username == "lucas" &&  
request.verb == "impersonate" && 
request.resource == "users" &&  
request.apiGroup == "" &&
impersonatedRequest.verb in ["create", "update"] &&
has(object.metadata.labels["lucas-impersonated"]) &&
object.metadata.labels["lucas-impersonated"] == "true"
```

For fully evaluating this request, three stages are needed.

1. First, in the normal `SubjectAccessReview`, only metadata about the
   requesting user, and the user to be impersonated can be populated in the SAR
   fields. The user to be impersonated is modelled as the "resource", and the
   verb is `impersonate`. In the CEL environment, this data corresponds to the
   `request` variable. For an applicable request for the policy above, the
   condition produced look like:

    ```cel
    impersonatedRequest.verb in ["create", "update"] &&
    has(object.metadata.labels["lucas-impersonated"]) &&
    object.metadata.labels["lucas-impersonated"] == "true"
    ```

1. The impersonation filter does know up front, however, the metadata of the
   request that is being performed, and if some authorizer returned a
   conditional response in the first stage, the impersonation filter could
   directly afterwards run `EvaluateConditions()` / `AdmissionConditionsReview`
   with more information: namely the `impersonatedRequest` metadata. After this
   step, the condition produced by partial evaluation with this additional
   information yields:

    ```cel
    has(object.metadata.labels["lucas-impersonated"]) &&
    object.metadata.labels["lucas-impersonated"] == "true"
    ```

1. As impersonation might happen in an authenticating front proxy (e.g.
   `kube-apiserver`), but object decoding and admission run in another process
   (e.g. an aggregated API server), the impersonation filter running in the
   former process does not have access to the request object. Thus, if we
   allowed impersonation expressing conditions on the request/stored object, the
   condition residual shown in 2. needs to be propagated from the front proxy to
   the aggregated API server.

   1. One backwards-compatible way to do this in practice, is to reserve one
      userinfo extra key (e.g. `k8s.io/impersonation-conditions`) to propagate
      the conditions. As we already require and assume that the aggregated API
      server uses the front proxy `kube-apiserver` as its first webhook
      authorizer, `kube-apiserver` can treat the conditions found in the
      userextra as the first deny-only conditional authorizer, and thus return
      these `object`-scoped conditions to the aggregated API server like usual.
   1. The conditions-aware impersonation authorizer would need to either cache
      the conditions internally using a context key, or pass the conditions
      transparently to the client, so that it can evaluate those later itself
      when passed back.

Initially, however, we do not need to go this far as to implement object-level
constraints during impersonation, but this design should be future-proof as
keeps the option open.

### Node authorizer

The Node authorizer was the first conditional authorizer in spirit: it had
both an authorization and admission part that were always designed and
evolved in tandem. This proposal generalises that pattern. The Node
authorizer could return conditional responses with, say,
`type: acme.io/node-authorizer` (or with transparent conditions written in
CEL once the built-in CEL evaluator lands), e.g.
`condition: '{"condition": "require-pod-node-name", "nodeName": "foo"}'`.

In the opaque condition case, the Node authorizer would implement
`EvaluateConditions` to, even in native code, enforce e.g. that a Pod's
`spec.nodeName` actually matches what it should be. All logic then lives in
the authorizer, instead of being split between the authorizer and the
`NodeEnforcement` admission controller, and `SubjectAccessReview` shows
what policies apply.

**Status: not implemented in this branch.** The Node authorizer still
follows the classic split; converting it is follow-up work.

### ValidatingAdmissionPolicies

`ValidatingAdmissionPolicies` support secondary authorization checks through the
`authorizer` function in the CEL environment. This could be used, for example, to
check that the requestor also has the
`sign certificates.k8s.io signers <signerName>` permission, for the signer
specified in the `CertificateSigningRequest` API.

Secondary checks in VAP *could* support conditionally-authorized requests too,
given that the secondary check using the authorizer also supplies the relevant
`object` and/or `oldobject` against which conditions could be written. However,
this does not seem to be a major use-case, as most secondary checks that have
been seen in the wild check permissions against some resource, subresource or
verb that is not served by the API server.

The loss of power of not supporting conditions in secondary VAP checks is minor.
The VAP authorizer can perform secondary permission checks for permissions
independently from each other, e.g. "this write request of the `VM` resource is
only allowed if the requestor also has the `backup` privilege on the referenced
storage bucket (when backups are enabled) and when the requestor can `use` the
referenced network". Without conditional authorization in this context, the
authorizer cannot express an intersection of the two, e.g. "the requestor can
only `backup` VM objects using this storage bucket when the VM is using this
given network".

If conditions were supported in VAP, it would be possible to decouple the
authorization policy (in the authorizer) from the enforcement code (in VAP), as
long as the data exchanged between them is consistent. Without conditions
supported in VAP, the enforcement code there needs to choose based on what
attributes to perform secondary checks.

To give users more information about what they can do (for debugging), the
`SelfSubjectAccessReview` endpoint could also show partially-evaluated CEL from
`ValidatingAdmissionPolicy` objects. However, if this is done, the user could
know better how to create an object that passes authorization and admission, for
better and worse.

### `deletecollection` support

Although not immediately obvious, conditional authorization also works for
`verb=deletecollection` requests. The condition is written just as it would
be for `verb=delete`; the same admission chain (which runs the
`AuthorizationConditionsEnforcer` plugin ahead of validating webhooks) is
executed once per object.

### Complete list of all `Authorize` calls in `kube-apiserver`

- `k8s.io/kubernetes/pkg/certauthorization.IsAuthorizedForSignerName`: Secondary
  authorization check for the `sign/approve/attest` virtual verbs on the
  `certificates.k8s.io signers` resource.
  - Does not support conditions (for now at least), for the same reasoning as VAP.
- `k8s.io/kubernetes/pkg/kubelet/server.InstallAuthFilter`: Primary
  authorization for the kubelet server.
  - Would support conditions, so that conditions can apply to the path called of
    the `nodes/proxy` resource. Not implemented yet.
- `k8s.io/kubernetes/pkg/registry/admissionregistration/{validating,mutating}admissionpolicy{,binding}`
  Performs secondary checks of the requestor being able to `get` the referenced
  parameter resource object or all objects.
  - Does not support conditions, verb is `get`
- `k8s.io/kubernetes/pkg/registry/authorization/{local,self,}subjectaccessreview`:
  Serving the SAR endpoints.
  - Conditions-aware in this branch: the SAR REST handlers propagate
    `spec.authorizationOptions.handledDecisionTypes` down to the authorizer
    and serialise the returned `ConditionsAwareDecision` into
    `status.conditionalDecision`. See the "Make the SubjectAccessReview
    handlers conditions-aware" commit.
- `k8s.io/kubernetes/pkg/registry/core/pod/rest.ensureAuthorizedForVerb`:
  Ensures that the requestor also has the `create` verb on certain connectible
  subresources for pods, as discussed above.
  - **Currently uses `UnconditionalAuthorizer`** — see
    [Compound Authorization for Connectible Resources](#compound-authorization-for-connectible-resources).
    Follow-up work.
- `k8s.io/kubernetes/pkg/registry/rbac`: Verifies that a user cannot
  privilege-escalate their permissions when creating roles and bindings. If the
  user indeed would try to privilege-escalate, allow them to do so if they have
  the `escalate` or `bind` verbs. This check would not support conditions.
- `k8s.io/kubernetes/plugin/pkg/admission/gc`: Verifies that ownerReferences are
  correctly set. Someone that updates an object's ownerReferences, need to be
  able to delete that object. In addition, if an owner reference of an create or
  update is blocking, the requestor either needs permission to `update
  */finalizers`, or on the owner resource. These checks would not support
  conditions.
- `k8s.io/kubernetes/plugin/pkg/admission/noderestriction`: Ensures that a node
  can only issue ServiceAccount tokens for allowed audiences. If the requested
  audiences are not found in the PodSpec, a secondary check to
  `request-serviceaccounts-token-audience <audience>` of the ServiceAccount's
  name/ns is issued. These checks would not support conditions.
- `k8s.io/apiserver/plugin/pkg/admission/plugin/authorizer/caching_authorizer.go`:
  This authorizer caches responses from SAR requests issued from e.g.
  `ValidatingAdmissionPolicy` secondary checks. This could eventually support
  caching conditional checks, but initially, it is not needed, as long as all
  such secondary checks do *not* support conditions.
- `k8s.io/apiserver/pkg/cel/library`: Implements the CEL functions for VAP
  secondary checks. These do not support conditions initially at least, but this
  could be expanded in the future as discussed above.
- `k8s.io/apiserver/pkg/endpoints/filters`: Home of both the legacy
  `WithAuthorization` (unchanged; takes `UnconditionalAuthorizer`) and the
  new `WithConditionsAwareAuthorization` (takes the full `Authorizer` plus
  a `ConditionalAuthorizationRequestClassifier`). Also contains the
  impersonation code, which is a candidate for future conditions-aware
  wiring.
- `k8s.io/apiserver/pkg/endpoints/handlers/delete.go`: Authorizes use of unsafe
  deletion without reading the object, as a special case. This would not support
  conditions.
- `k8s.io/apiserver/pkg/endpoints/handlers/update.go`: Secondary check for
  `update` requests turning into a `create` request. Currently not
  conditions-aware (follow-up work).

## Authorizer requirements

To recap, the authorizer must adhere to the following requirements to be
considered functional:

- Respect the caller's `spec.authorizationOptions.handledDecisionTypes`. If
  the caller has not opted into `ConditionsMap`/`Union` (or the field is
  absent), no conditional decision must be returned; the authorizer must
  fold to `ConditionsAwareDecision.FailureDecision()` (Deny if any Deny
  conditions were present, else NoOpinion). Use the helpers
  `authorizationv1.SupportsConditionalAuthorization` and
  `SupportsUnconditionalAuthorization` in `util.go` for the check.
- Only ever produce a conditional response if producing an unconditional
  response is not possible.
  - The effect of authorizer-internal policies determines this. If an
    authorizer has policies with Allow / NoOpinion (soft deny) / Deny
    (hard deny) effects, then the strength of policies is ordered as:
    `Deny` (unconditional) > `Deny` (conditional) > `NoOpinion`
    (unconditional) > `NoOpinion` (conditional) > `Allow` (unconditional) >
    `Allow` (conditional).
  - For example, if an unconditional `Deny` policy matches, the output is
    always an unconditional `Deny`, regardless of other matches.
  - If no `Deny` or `NoOpinion` policies match, and only a conditional and
    an unconditional `Allow` are candidates, the unconditional `Allow`
    takes precedence.
  - However, if a conditional `Deny` policy matches together with an
    unconditional `Allow`, the response needs to be conditional — before
    producing a final response, one needs to know whether the conditional
    `Deny` will override the unconditional `Allow`.
- The authorizer can only return a `ConditionsMap` with Allow conditions if
  there is a path for the request to become authorized. All pruning that is
  possible to do with the initial authorizer `Attributes` MUST be used.
  - For example, a policy of form `object.metadata.labels.foo == "bar" &&
    request.verb == "create"` MUST NOT yield a conditional response for a
    `verb="update"` request, as the LHS of `&&` is then always `false`.
- The `ConditionsMap` returned MUST fit within the enforced limits:
  - At most 128 conditions in total across `denyConditions`,
    `noOpinionConditions`, `allowConditions`.
  - Each `Condition.Condition` body ≤ 10240 bytes,
    `Condition.Description` ≤ 1024 bytes.
  - Each `Condition.ID` and `Condition.Type` MUST be a domain-qualified
    label key (e.g. `acme.io/foo`); reserved domains are `*.k8s.io` and
    `*.kubernetes.io`.
- An authorizer must be API-version aware, and should only let a policy
  author refer to a field in a version-dependent manner and/or validate
  that the policy applies successfully to all known versions.
  - The request object version might not equal the storage version, and
    the API server cannot necessarily convert between the versions (due to
    CRD conversion webhooks failing). For in-tree types, one can always
    convert without errors and reasonably fast. The new (request) object is
    always in the request API version. The authorizer could ask the API
    server to convert, if we want, but this is not necessarily error-free.
    - TODO(Lucas): See what happens for a CRD + VAP if the request version
      != storage version, or if the CRD schema changes.
  - For example, VAP policies today use the latter technique, which
    rejects expressions that do not compile under all possible API
    version-specific CEL environments.
  - Another technique could be to expose the object through a
    version-specific fieldpath, e.g. `v1.spec.foo` and `v2.spec.bar` refer
    to logically the same value of a field that was renamed from `foo` in
    `v1` to `bar` in `v2`.
- To fail closed when new API versions are added, the authorizer could
  automatically insert restrictions that only API versions referenced in
  the policy can yield an allowed response. In the following example,
  write requests fail closed for API version `v3` until the policy author
  has had time to add the restriction specific to that version:

  ```cel
  request.verb in ["create", "update"] &&
  if has(v1) then
    v1.spec.foo == "baz"
  else if has(v2) then
    v2.spec.bar == "baz"
  else
    false
  ```

- An authorizer must be able to evaluate any condition it authors, so that
  the API server can always call back through `EvaluateConditions`
  (regardless of in-process evaluation capabilities). An authorizer only
  ever evaluates its own conditions. An authorizer that does not implement
  condition evaluation MUST return
  `DecisionDeny, "", ErrorConditionEvaluationNotSupported` from
  `EvaluateConditions` (fail-closed).
- The authorizer must make sure their conditions are safe and performant to
  execute. In particular, any CEL condition that is returned to Kubernetes must
  be within reasonable CEL cost limits. The authorizer should reject policies
  that would be too costly to execute in the request path.
  - Towards this end, it is highly recommended that the authorizer uses a
    non-Turing complete language, to avoid e.g. the [Halting problem] and remote
    code execution.
  - As a worst-case example, if an authorizer accepted Python code as
    conditions, then any Kubernetes user with `create authorizationconditionsreview`
    would be able to send malicious conditions
    that remotely executes arbitrary code through a "condition" of form
    `import os; os.system("sudo nmap ...")`

[Halting problem](https://en.wikipedia.org/wiki/Halting_problem)

### Risks and Mitigations

Showing the users what authorization conditions that they are subject to through
`SelfSubjectAccessReview` means that badly-written access control policies which
follow the pattern of [Security Through Obscurity] would be "broken". For
example, if a user can only `create pods` conditioned on `metadata.labels.foo ==
"42"`, the latter condition would be returned in the SelfSAR, whereas without
this information the user would need to "blindly" guess the number. However,
these kind of practices are highly discouraged, as they rarely are effective in
practice. For example, if the user could `list pods` otherwise (which in that
case would be a reasonable permission to have), they could most likely
reverse-engineer the conditions they are subject to, by seeing data that "got
through".

This risk could be mitigated by the authorizer returning opaque conditions
(which could not be efficiently evaluated in the API server), instead of
transparent (e.g. CEL) ones. It is up to the authorizer's discretion to know
whether conditions are "secret" or can be shown to the user. For clarity to the
user, it is recommended that conditions are shown when possible and reasonable.

[Security Through Obscurity](https://en.wikipedia.org/wiki/Security_through_obscurity)

### Test Plan

[x] I/we understand the owners of the involved components may require updates to
existing tests to make this code solid enough prior to committing the changes necessary
to implement this enhancement.

#### Prerequisite testing updates

The update of the authorizer interface will need to update any test which uses
the authorizer, which could be quite many.

#### Unit tests

Existing code that will be affected by the change (along with existing unit test
coverage):

- `k8s.io/apiserver/pkg/authorization/union`: `2026-02-10` - `88`
- `k8s.io/apiserver/plugin/pkg/authorizer/webhook`: `2026-02-10` - `86`
- `k8s.io/apiserver/pkg/endpoints/filters/authorization.go`: `2026-02-10` - `91`

Testing will in addition be added as appropriate to new packages.

#### Integration tests

Integration tests for this feature live at
`k8s.io/kubernetes/test/integration/apiserver/conditionalauthorization/`.
The current landed set covers:

- `conditionalauthorization_test.go` — end-to-end SAR + ACR flow with the
  webhook authorizer configured against a test HTTP server that installs an
  in-test `testAuthorizer` (unconditional Allow/Deny/NoOpinion; CEL-based
  Allow/Deny/NoOpinion conditions; deny-overrides-allow priority;
  operation-aware conditions). Feature-gate on and off are both exercised
  via `TestConditionalAuthorizationEnabled` and
  `TestConditionalAuthorizationDisabled`.
- `hpa_conversion_test.go` — HPA v1/v2 CPU utilisation conditions across
  create and update, verifying condition evaluation against both the
  request and stored object shapes.
- `crd_conversion_test.go` — a CRD with two versions and a webhook
  conversion strategy, verifying conditional authz interop with CRD
  version conversion.
- `main_test.go` — feature-gate + kube-apiserver bootstrap.

**Caveat:** only the webhook-only condition-evaluation variant is
exercised. The commented-out `in-process-eval-only` and
`if-in-process-fails-call-webhook` variants at
`conditionalauthorization_test.go` (near `celConditionalAuthorizerVariants`)
mark the intended coverage once the built-in CEL condition evaluator
lands.

#### e2e tests

When the feature is enabled, tests will be added for user-facing functionality
such as the `SubjectAccessReview` API, and sending request objects which are
allowed and denied. In addition, one end to end test should make sure that the
feature also works as expected in a scenario with aggregated API servers.

### Graduation Criteria

#### Alpha

- Refactoring of the authorizer interface is completed
- Feature implemented behind a feature flag
- Initial integration tests completed and enabled

#### Beta

- There is in-core use of this feature, e.g. the node authorizer and/or
  constrained impersonation.
- Gather feedback from developers and surveys
- Additional tests are in Testgrid and linked in KEP
- More rigorous forms of testing—e.g., downgrade tests and scalability tests
- All functionality completed
- All security enforcement completed
- All monitoring requirements completed
- All testing requirements completed
- All known pre-release issues and gaps resolved

**Note:** Beta criteria must include all functional, security, monitoring, and
testing requirements along with resolving all issues and gaps identified

#### GA

- N (to be determined later) examples of real-world usage
- N installs
- Allowing time for feedback
- All issues and gaps identified as feedback during beta are resolved

**Note:** GA criteria must not include any functional, security, monitoring, or
testing requirements. Those must be beta requirements.

**Note:** Generally we also wait at least two releases between beta and
GA/stable, because there's no opportunity for user feedback, or even bug reports,
in back-to-back releases.

**For non-optional features moving to GA, the graduation criteria must include
[conformance tests].**

[conformance tests]: https://git.k8s.io/community/contributors/devel/sig-architecture/conformance-tests.md

### Version Skew Strategy

In general, old clients can safely talk to new conditional authorizers, as the
authorizer will notice that the old client did not explicitly opt into the new
behavior, and thus will the authorizer fold to `NoOpinion` or `Deny` as
appropriate.

However, rollouts of new `AuthorizationConfig` configurations in multi-API server
scenarios (or similar) such as shown in this picture might need some special care.

![Possible failure scenario of AuthorizationConfig rollout](images/rollout-of-authz-config.png)

For this reason, it is recommended that conditions-aware authorizers with a
loadbalancer in between itself and the client either:

- (preferred) configure the load balancer to perform a blue-green rollout of the
  API server configuration, initially only sending requests to old API servers
  (without the API server configured), and then, at once, sending requests to
  new API servers.
  - If the rollout is such that a conditional authorizer is removed in the new
    configuration, the authorizer should send only `NoOpinion` decisions before
    the blue-green rollout, to make sure there are no
    `AuthorizationConfigReview` requests pending to be sent to it.
- make the authorizer respond with `NoOpinion` until it is known that the
  rollout of all intermediate kube-apiservers to the new configuration has
  completed.

## Production Readiness Review Questionnaire

<!--

Production readiness reviews are intended to ensure that features merging into
Kubernetes are observable, scalable and supportable; can be safely operated in
production environments, and can be disabled or rolled back in the event they
cause increased failures in production. See more in the PRR KEP at
https://git.k8s.io/enhancements/keps/sig-architecture/1194-prod-readiness.

The production readiness review questionnaire must be completed and approved
for the KEP to move to `implementable` status and be included in the release.

In some cases, the questions below should also have answers in `kep.yaml`. This
is to enable automation to verify the presence of the review, and to reduce review
burden and latency.

The KEP must have a approver from the
[`prod-readiness-approvers`](http://git.k8s.io/enhancements/OWNERS_ALIASES)
team. Please reach out on the
[#prod-readiness](https://kubernetes.slack.com/archives/CPNHUMN74) channel if
you need any help or guidance.
-->

### Feature Enablement and Rollback

<!--
This section must be completed when targeting alpha to a release.
-->

###### How can this feature be enabled / disabled in a live cluster?

<!--
Pick one of these and delete the rest.

Documentation is available on [feature gate lifecycle] and expectations, as
well as the [existing list] of feature gates.

[feature gate lifecycle]: https://git.k8s.io/community/contributors/devel/sig-architecture/feature-gates.md
[existing list]: https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/
-->

- [x] Feature gate
  - Feature gate name: `ConditionalAuthorization`
  - Components depending on the feature gate: `kube-apiserver`
- [x] Opt-in on an authorizer basis for webhook authorizers in `StructuredAuthorizationConfig`
  - This can be done with no API server downtime.

###### Does enabling the feature change any default behavior?

<!--
Any change of default behavior may be surprising to users or break existing
automations, so be extremely careful here.
-->

No.

###### Can the feature be disabled once it has been enabled (i.e. can we roll back the enablement)?

<!--
Describe the consequences on existing workloads (e.g., if this is a runtime
feature, can it break the existing applications?).

Feature gates are typically disabled by setting the flag to `false` and
restarting the component. No other changes should be necessary to disable the
feature.

NOTE: Also set `disable-supported` to `true` or `false` in `kep.yaml`.
-->

Yes.

###### What happens if we reenable the feature if it was previously rolled back?

Nothing special, feature enablement is stateless.

###### Are there any tests for feature enablement/disablement?

<!--
The e2e framework does not currently support enabling or disabling feature
gates. However, unit tests in each component dealing with managing data, created
with and without the feature, are necessary. At the very least, think about
conversion tests if API types are being modified.

Additionally, for features that are introducing a new API field, unit tests that
are exercising the `switch` of feature gate itself (what happens if I disable a
feature gate after having objects written with the new field) are also critical.
You can take a look at one potential example of such test in:
https://github.com/kubernetes/kubernetes/pull/97058/files#diff-7826f7adbc1996a05ab52e3f5f02429e94b68ce6bce0dc534d1be636154fded3R246-R282
-->

Yes, there will be integration and/or end to end tests covering both the feature
when enabled and disabled.

### Rollout, Upgrade and Rollback Planning

<!--
This section must be completed when targeting beta to a release.
-->

###### How can a rollout or rollback fail? Can it impact already running workloads?

<!--
Try to be as paranoid as possible - e.g., what if some components will restart
mid-rollout?

Be sure to consider highly-available clusters, where, for example,
feature flags will be enabled on some API servers and not others during the
rollout. Similarly, consider large clusters and how enablement/disablement
will rollout across nodes.
-->

- If an administrator configures a webhook authorizer to support conditions on
  the endpoint `/conditions`, but the authorizer server for some reason does not
  serve this endpoint (correctly), this misconfiguration can fail conditionally
  authorized requests that otherwise could succeed. Before pointing the API
  server at a conditional endpoint, all replicas of the authorizer must support
  conditions.

###### What specific metrics should inform a rollback?

<!--
What signals should users be paying attention to when the feature is young
that might indicate a serious problem?
-->

- High p50 and p99 latency of authorizer-handled and in-process conditions evaluation
- We could add a counter for how many authorizer requests (out of a total count)
  that produced an error, and then users can make sure this metric is not
  growing at a higher pace

###### Were upgrade and rollback tested? Was the upgrade->downgrade->upgrade path tested?

<!--
Describe manual testing that was done and the outcomes.
Longer term, we may want to require automated upgrade/rollback tests, but we
are missing a bunch of machinery and tooling and can't do that now.
-->

This has not been tested yet, but should not be a problem as all code is feature-gated.

###### Is the rollout accompanied by any deprecations and/or removals of features, APIs, fields of API types, flags, etc.?

<!--
Even if applying deprecation policies, they may still surprise some users.
-->

No.

### Monitoring Requirements

<!--
This section must be completed when targeting beta to a release.

For GA, this section is required: approvers should be able to confirm the
previous answers based on experience in the field.
-->

###### How can an operator determine if the feature is in use by workloads?

<!--
Ideally, this should be a metric. Operations against the Kubernetes API (e.g.,
checking if there are objects with field X set) may be a last resort. Avoid
logs or events for this purpose.
-->

Audit annotations surface conditional authorization use. Specifically:

- `authorization.k8s.io/decision` — `allow`/`forbid`, as before.
- `authorization.k8s.io/reason` — reason string, as before.
- `authorization.k8s.io/is-conditional-decision` — set to `"true"` on
  requests that were let through the authorization filter as a
  conditional allow (the enforcer plugin later decided the final
  outcome). Absent for unconditional requests.

Operators can also observe the
`authorizationMetricsLabelForAuthorizeConditionsAware` result label on
the standard authorization latency metrics
(`staging/src/k8s.io/apiserver/pkg/endpoints/filters/metrics.go`) — this
label distinguishes conditions-aware decisions from classic ones.

###### How can someone using this feature know that it is working for their instance?

<!--
For instance, if this is a pod-related feature, it should be possible to determine if the feature is functioning properly
for each individual pod.
Pick one more of these and delete the rest.
Please describe all items visible to end users below with sufficient detail so that they can verify correct enablement
and operation of this feature.
Recall that end users cannot usually observe component logs or access metrics.
-->

Submit a `(Self)SubjectAccessReview` whose response is known to be conditional,
and check if conditions are returned.

###### What are the reasonable SLOs (Service Level Objectives) for the enhancement?

<!--
This is your opportunity to define what "normal" quality of service looks like
for a feature.

It's impossible to provide comprehensive guidance, but at the very
high level (needs more precise definitions) those may be things like:
  - per-day percentage of API calls finishing with 5XX errors <= 1%
  - 99% percentile over day of absolute value from (job creation time minus expected
    job creation time) for cron job <= 10%
  - 99.9% of /health requests per day finish with 200 code

These goals will help you determine what you need to measure (SLIs) in the next
question.
-->

Evaluation time of authorization builtin CEL conditions is of the same magnitude
as for `ValidatingAdmissionPolicy`.

###### What are the SLIs (Service Level Indicators) an operator can use to determine the health of the service?

<!--
Pick one more of these and delete the rest.
-->

- [x] Metrics
  - Metric name: Authorization latency and error rate (both should be low and steady)
  - Components exposing the metric: kube-apiserver
- [x] Instrumentation of conditional authorizer implementations external to Kubernetes

###### Are there any missing metrics that would be useful to have to improve observability of this feature?

<!--
Describe the metrics themselves and the reasons why they weren't added (e.g., cost,
implementation difficulties, etc.).
-->

N/A

### Dependencies

<!--
This section must be completed when targeting beta to a release.
-->

Existing CEL libraries of Kubernetes.

###### Does this feature depend on any specific services running in the cluster?

<!--
Think about both cluster-level services (e.g. metrics-server) as well
as node-level agents (e.g. specific version of CRI). Focus on external or
optional services that are needed. For example, if this feature depends on
a cloud provider API, or upon an external software-defined storage or network
control plane.

For each of these, fill in the following—thinking about running existing user workloads
and creating new ones, as well as about cluster-level services (e.g. DNS):
  - [Dependency name]
    - Usage description:
      - Impact of its outage on the feature:
      - Impact of its degraded performance or high-error rates on the feature:
-->

Not in particular, but until there is a built-in authorizer that is conditional,
the cluster administrator needs to make use of some webhook authorizer to enable
conditionally-authorized responses.

### Scalability

<!--
For alpha, this section is encouraged: reviewers should consider these questions
and attempt to answer them.

For beta, this section is required: reviewers must answer these questions.

For GA, this section is required: approvers should be able to confirm the
previous answers based on experience in the field.
-->

###### Will enabling / using this feature result in any new API calls?

<!--
Describe them, providing:
  - API call type (e.g. PATCH pods)
  - estimated throughput
  - originating component(s) (e.g. Kubelet, Feature-X-controller)
Focusing mostly on:
  - components listing and/or watching resources they didn't before
  - API calls that may be triggered by changes of some Kubernetes resources
    (e.g. update of object X triggers new updates of object Y)
  - periodic API calls to reconcile state (e.g. periodic fetching state,
    heartbeats, leader election, etc.)
-->

There might be a slight increase in traffic between aggregated API servers and
the kube-apiserver, due to aggregated API servers potentially asking the
kube-apiserver to resolve authorization conditions.

###### Will enabling / using this feature result in introducing new API types?

<!--
Describe them, providing:
  - API type
  - Supported number of objects per cluster
  - Supported number of objects per namespace (for namespace-scoped objects)
-->

A new API type `AuthorizationConditionsReview` is introduced, but it is not
stored in etcd.

###### Will enabling / using this feature result in any new calls to the cloud provider?

<!--
Describe them, providing:
  - Which API(s):
  - Estimated increase:
-->

No.

###### Will enabling / using this feature result in increasing size or count of the existing API objects?

<!--
Describe them, providing:
  - API type(s):
  - Estimated increase in size: (e.g., new annotation of size 32B)
  - Estimated amount of new objects: (e.g., new Object X for every existing Pod)
-->

No.

###### Will enabling / using this feature result in increasing time taken by any operations covered by existing SLIs/SLOs?

<!--
Look at the [existing SLIs/SLOs].

Think about adding additional work or introducing new steps in between
(e.g. need to do X to start a container), etc. Please describe the details.

[existing SLIs/SLOs]: https://git.k8s.io/community/sig-scalability/slos/slos.md#kubernetes-slisslos
-->

Authorization latency could increase.

###### Will enabling / using this feature result in non-negligible increase of resource usage (CPU, RAM, disk, IO, ...) in any components?

<!--
Things to keep in mind include: additional in-memory state, additional
non-trivial computations, excessive access to disks (including increased log
volume), significant amount of data sent and/or received over network, etc.
This through this both in small and large cases, again with respect to the
[supported limits].

[supported limits]: https://git.k8s.io/community//sig-scalability/configs-and-limits/thresholds.md
-->

No.

###### Can enabling / using this feature result in resource exhaustion of some node resources (PIDs, sockets, inodes, etc.)?

<!--
Focus not just on happy cases, but primarily on more pathological cases
(e.g. probes taking a minute instead of milliseconds, failed pods consuming resources, etc.).
If any of the resources can be exhausted, how this is mitigated with the existing limits
(e.g. pods per node) or new limits added by this KEP?

Are there any tests that were run/should be run to understand performance characteristics better
and validate the declared limits?
-->

No.

### Troubleshooting

<!--
This section must be completed when targeting beta to a release.

For GA, this section is required: approvers should be able to confirm the
previous answers based on experience in the field.

The Troubleshooting section currently serves the `Playbook` role. We may consider
splitting it into a dedicated `Playbook` document (potentially with some monitoring
details). For now, we leave it here.
-->

###### How does this feature react if the API server and/or etcd is unavailable?

Not applicable, the feature resides completely within the API server. However,
as before, if the kube-apiserver is down, so are all aggregated API servers
(unable to properly authorize requests).

###### What are other known failure modes?

<!--
For each of them, fill in the following information by copying the below template:
  - [Failure mode brief description]
    - Detection: How can it be detected via metrics? Stated another way:
      how can an operator troubleshoot without logging into a master or worker node?
    - Mitigations: What can be done to stop the bleeding, especially for already
      running user workloads?
    - Diagnostics: What are the useful log messages and their required logging
      levels that could help debug the issue?
      Not required until feature graduated to beta.
    - Testing: Are there any tests for failure mode? If not, describe why.
-->

Not known.

###### What steps should be taken if SLOs are not being met to determine the problem?

- Check the `AuthorizationConfiguration`
- Troubleshoot any webhook authorizers' responses
- Check audit logs and metrics

## TODOs

Framework-level TODOs still open at the time of writing:

- TODO: Expand on this point of conditional vs composite authorization.
- TODO: Add more wording on ReferenceGrants.
- TODO(Lucas): See what happens for a CRD + VAP if the request version !=
  storage version, or if the CRD schema changes.

Implementation follow-ups (the framework has landed; these are natural next
steps that the design already accommodates):

- Ship the built-in CEL condition evaluator
  (`k8s.io/authorization-cel` — or successor naming), plugged in via
  `PartiallyEvaluateConditionsAwareDecision`. Reactivate the
  `in-process-eval-only` and `if-in-process-fails-call-webhook` variants of
  the integration test.
- Wire conditional authz into `ensureAuthorizedForVerb`
  (`pkg/registry/core/pod/rest/authorize.go`) and the update→create
  compound check (`staging/src/k8s.io/apiserver/pkg/endpoints/handlers/update.go`).
- Extend the `ConditionalAuthorizationRequestClassifier` in
  `pkg/controlplane/apiserver/config.go` to accept connect requests and
  aggregated-API-server-owned groups (both are TODOs in the current
  predicate).
- Harden misconfiguration: make `AdmissionOptions.Validate` error out when
  `ConditionalAuthorization` is enabled but `AuthorizationConditionsEnforcer`
  is not, so the API server refuses to start in that state.
- Consider surfacing a set-level `Type` on `ConditionsMap` (in addition to
  the current per-`Condition` `Type`), if operational experience shows all
  conditions in a set typically share a type.

Resolved TODOs (kept here as historical anchors):

- ~~"One might be able to infer the admission-time operation…"~~ — resolved:
  `ConditionsData.GetOperation()` returns an explicit `AdmissionOperation`.
- ~~"ConditionData interface might need to change to something more generic"~~
  — resolved: renamed to `ConditionsData`, expanded to the 11-method subset
  of `admission.Attributes`.
- ~~"Decide on a maximum amount of conditions"~~ — resolved: 128 per
  `ConditionsMap`.
- ~~"Do we want UID like AdmissionReview here?"~~ — resolved: yes, the
  `AuthorizationConditionsResponse` requires the `UID` to be copied from
  the request.

## Alternatives Considered

### Expose all conditions in AdmissionReview, and have admission plugins “acknowledge” the conditions

The SIG Auth meeting of September 4, 2025 concluded that this feature should
support also condition types that are not built into Kubernetes. Thus does there
need to be some way to evaluate the not-natively-supported conditions in the
admission phase. The most logical way, would be to add some fields to
AdmissionReview, and thus let admission webhooks let the API server know
(*besides* the AdmissionReview's primary response.allowed field) what the
conditions evaluated to.

However, this turned out to be unnecessarily complicated in practice, when
taking the idea further. Should all conditions from potentially every authorizer
in the chain be sent to every admission webhook? Probably not.

Can an admission webhook choose to evaluate individual conditions of some
specific authorizer, or does the admission webhook need to evaluate all
conditions produced by a certain authorizer at once, returning the result of the
whole condition set according to the defined semantics? The latter solution is
much simpler for both users and implementers to understand, so probably the
latter.

However, then, how can one know that a certain admission webhook has the right
to acknowledge a certain authorizer's conditions? What if the conditional
authorizer is controlled by the cloud provider or infrastructure team, but a
(malicious) user dynamically registers its own admission webhook that wants to
acknowledge the conditions from the cloud provider's authorizer? What happens if
there are multiple (dynamically registered) admission webhooks that evaluated
the same input data (conditions+request body) to two different outputs?

These questions led us to realize that the safest initial plan is to require a
1:1 mapping between the authorizer (registered through
`AuthorizationConfiguration`) and the authorizer's condition enforcer. As normal
users anyways cannot dynamically register authorizers, there is no need to
dynamically register authorizer condition enforcers either for normal users.
Thus is the most logical place to register the authorizer's condition enforcer,
in the same place the authorizer is defined in `AuthorizationConfiguration`.

In other words, only the authorizer itself can evaluate its own conditions in
the admission phase, and all at once only (as a set), not partially.

### Propagate an API server-generated request UID to both authorization and admission

This would have helped solve the atomicity concern, but it is not a full
long-term solution, as it still relies on people setting up webhooks.

### Only one ConditionSet exposed as part of SubjectAccessReview status

However, if only one condition set is exposed, it might be impossible for a user
to understand what conditions it is subject to for a given request through a
(Self/Local/Standard) SubjectAccessReview, as the first conditional response
might be just a “deny dangerous operations”-type of conditional response.

The user should thus see all conditional allows and denies until there is an
unconditional response.

### Require the client to annotate its write request with field or label selectors

This would be a breaking change for clients, as whenever conditional authorizers
would hit production usage, every client would need to annotate its every
request with all selectors “just in case” some authorizer would make use of it,
to higher the chances of getting authorized. This could duplicate a fair amount
of the request data.

The other problem is updates: would the selector apply only to the request
object, only to the stored one, or both at once.

### Extract label and field selectors from the request and current object in etcd, and supply that to the authorization process

If the client was not required to send all this data, but the API server would
decode the object to extract “just” label and field selectors, the DoS vector
occurs, where a malicious party could send huge requests with bogus data, that
the API server would decode before authorization takes place. In addition, would
this make the authorization process state-dependent (if the selector would need
to apply to both the request and stored object), something which is considered
an explicit anti-pattern.

### Do nothing, force implementers to implement all of this out of tree

Pros:

- No extra code is added to Kubernetes.

Drawbacks:

- Authorizers would need to fold a conditional allow into a concrete `Allow` in
  authorization responses. This is confusing, and could easily be misunderstood,
  for example composite authorization of `update` requests turning into
  `create`s would not respect conditions, which could be unsafe and unexpected.
- Likewise, Constrained Impersonation could not be made more expressive.
- Requires the cluster administrator to install a validating webhook that never
  can become deleted (which normal admission webhooks can).
- Users would not see their conditions in the `SelfSAR`, and e.g. conditional
  read policies (see below) would be more or less impossible to discover.
- Two webhooks are always needed for every request, even if the condition could
  be expressed in CEL, which in theory would not require a webhook.
- Evaluation of policies is not atomic across authorization and admission
  phases. A full re-evaluation of all policies need to be done twice.
- Only one conditional authorizer could effectively be supported, instead of
  many in this framework.
- Without a clear framework on how to do this (with reference implementations),
  the risk of wrong or incompatible implementations is higher.
- Kubernetes could not use this itself, even though it could be useful.

## Drawbacks

- Added complexity to core (complexity which today is either at the cost of
  expressiveness, or for users to deal with)

## Appendix A: Further resources

- SIG Auth meeting June 4, 2025:
  [meeting notes](https://docs.google.com/document/d/1woLGRoONE3EBVx-wTb4pvp4CI7tmLZ6lS26VTbosLKM/edit?tab=t.0#heading=h.2p3xwolypqkm),
  [video](https://youtu.be/Clg-rz9qlUA?si=Ay4Dddd-iJRnC89R),
  [slides](https://speakerdeck.com/luxas/conditional-authorization-for-kubernetes-sig-auth-presentation)
- SIG Auth Deep Dive on Conditional Authorization Sept 4, 2025:
  [meeting notes](https://docs.google.com/document/d/1woLGRoONE3EBVx-wTb4pvp4CI7tmLZ6lS26VTbosLKM/edit?tab=t.0#heading=h.147ygvibasgh),
  [video](https://zoom.us/rec/share/24DwlfWfrP7UZEMtkpk1XvpNP_sQuRrE7FQxKoJDRRbJ-vJTBarrEermV2-XSD5p.LSzKv2wS797xMYTs),
  [slides](https://speakerdeck.com/luxas/conditional-authorization-sig-auth-deep-dive)
- KubeCon Atlanta talk Nov 13, 2025:
  [slides](https://speakerdeck.com/luxas/tools-and-strategies-for-making-the-most-of-kubernetes-access-control),
  [video](https://youtu.be/JBM0PRyDaPs?si=kACoiZj_iOHQGSrY)
- Proof of Concept Policy Author Interface implementation: [upbound/kubernetes-cedar-authorizer](https://github.com/upbound/kubernetes-cedar-authorizer)
- Proof of Concept Kubernetes implementation:
  [luxas/conditional_authz_4](https://github.com/kubernetes/kubernetes/compare/master...luxas:kubernetes:conditional_authz_4?expand=1)
  branch
- Lucas
  [Master's thesis](https://github.com/luxas/research/blob/main/msc_thesis.pdf)
  with detailed design information

## Appendix B: Future addition sketch: Conditional Reads

Together with the
[Authorize with Selectors KEP](https://github.com/kubernetes/enhancements/blob/2871b58880f5629f948b4ef50bffec0d1a677eeb/keps/sig-auth/4601-authorize-with-selectors/README.md),
it becomes possible to provide policy authors to write unified policies across
both authorization and admission, and **reads and writes**, at least whenever
operating on field-selectable fields. A practical example would be “allow user
Alice to perform *any verb* on PersistentVolumes, *but only when
spec.storageClassName is "dev"*” (assuming storageClassName is/would become
field-selectable).

Consider that before this KEP, a user might need to use two or even three
different paradigms to protect both data and metadata across reads and writes:

![Read/write and data/metadata consistency before this KEP](images/authorize-with-selectors-before.png)

But after this KEP, it is possible to use a unified paradigm for all types:

![Read/write and data/metadata consistency after this KEP](images/authorize-with-selectors-after.png)

For a practical example of what this unified interface can look like, take a
look at Lucas' proof of concept at
[upbound/kubernetes-cedar-authorizer](https://github.com/upbound/kubernetes-cedar-authorizer),
in particular the
[getting started guide](https://github.com/upbound/kubernetes-cedar-authorizer/blob/main/docs/GETTING_STARTED.md).
If this project proves generally useful, it can be donated to a fitting place in
the CNCF ecosystem (e.g. `kubernetes-sigs` or Cedar, which is now a CNCF Sandbox
project). For more detailed information about the project and the philosophy
behind it, take a look at
[Lucas' Master's thesis](https://github.com/luxas/research/blob/main/msc_thesis.pdf)
(written at Aalto University).

A concrete example of how a future version of Kubernetes could integrate this
would be that authorizers are allowed to return conditions also on read
requests. The syntax of the condition must be a
[generalized selector](github.com/kubernetes/kubernetes/issues/128154) (most
likely a subset of CEL) of a well-known condition type. Note that extraction of
values from an object does not need to change, we can limit expressiveness to
labels and existing simple JSONpath-based extractors.

Consider the following fictional authorizer chain decisions:

- Authorizer 1:
  - `effect=Deny` condition: `metadata.labels.owner != "lucas"`
  - `effect=NoOpinion` condition: `metadata.labels.visible != "true"`
  - `effect=Allow` condition: `object.type == "k8s.io/basic-auth"`
  - `effect=Allow` condition: `metadata.labels.public == "true"`
- Authorizer 2:
  - `effect=Allow` condition: `metadata.labels.env == "dev"`

These conditions turn into the following boolean predicate:

```cel
isAuthorized(object) = !(object.metadata.labels.owner != "lucas") AND (
  (
    !(object.metadata.labels.visible != "true") AND
    (
      (object.type == "k8s.io/basic-auth") OR
      (object.metadata.labels.public == "true")
    )
  ) OR
  (
    (object.metadata.labels.env == "dev")
  )
)
```

which could also be written in Disjunctive Normal Form (DNF) as follows:

```cel
isAuthorized(object) = (
  (object.metadata.labels.owner == "lucas") AND
  (object.metadata.labels.visible == "true") AND
  (object.type == "k8s.io/basic-auth")
) OR
(
  (object.metadata.labels.owner == "lucas") AND
  (object.metadata.labels.visible == "true") AND
  (object.metadata.labels.public == "true")
) OR
(
  (object.metadata.labels.owner == "lucas") AND
  (object.metadata.labels.env == "dev")
)
```

Note that the authorizer 1's `effect=Deny` condition must evaluate to false for
an object to be matched. However, the `effect=NoOpinion` is scoped only to
authorizer 1, if an object was such that `metadata.labels.owner == "lucas"` and
`metadata.labels.env == "dev"`, it is authorized by authorizer 2, even though
`metadata.labels.visible == "false"` (which yields a `NoOpinion` response from
authorizer 1).

The API server must make sure that every object that is returned from storage is
authorized. The API server cannot know what objects are in storage (as one of
the authorization requirements is to be stateless with regards to the data
store), but it can prove something stronger: for every possible `object` that
could be constructed, that matches the given `objectSelected(object)` selector,
`isAuthorized(object)` is true.

This equation can be resolved with a SAT/SMT solver as follows:

```text
(forall object: objectSelected(object) => isAuthorized(object)) == TRUE
=== (forall object: (not objectSelected(object)) OR isAuthorized(object)) == TRUE
=== (exists object: objectSelected(object) AND (not isAuthorized(object))) == FALSE
```

A client who wants to ask "show me all instances of resource X that I can see"
can thus perform a SelfSAR, construct a selector `objectSelected` which is equal
to `isAuthorized` (and thus correct-by-construction), and thus see all objects
that it can, without having to know its permissions up front, or issue `n`
different requests (e.g. for each namespace). This would work for
controllers/watches as well. Even more conveniently, the API server could
provide the client with a mode that "downgrades" an unconstrained request (e.g.
`GET /api/v1/pods`) by the server adding the selector that the client is
authorized to see.

However, note that Conditional Reads are NOT part of this proposal right now,
another KEP is expected for that eventually (if people like the idea), but I
felt it is good to mention the sketch up-front here so that reviewers have an
idea how conditional authorization can become usable for both reads and writes,
eventually.
