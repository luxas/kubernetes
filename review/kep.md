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
  - [Properties](#properties)
  - [Condition and ConditionsMap data model](#condition-and-conditionsmap-data-model)
  - [Computing a concrete decision from a ConditionsMap](#computing-a-concrete-decision-from-a-conditionsmap)
  - [Computing a concrete decision from a conditional authorization chain](#computing-a-concrete-decision-from-a-conditional-authorization-chain)
  - [<code>AuthorizationConditionsEnforcer</code> admission controller](#authorizationconditionsenforcer-admission-controller)
    - [Admission runs before authorization is final](#admission-runs-before-authorization-is-final)
  - [Changes to <code>(Self)SubjectAccessReview</code>](#changes-to-selfsubjectaccessreview)
  - [Supporting webhooks through the <code>AuthorizationConditionsReview</code> API](#supporting-webhooks-through-the-authorizationconditionsreview-api)
  - [Composite / Union Authorizer Support](#composite--union-authorizer-support)
    - [Worked example (single kube-apiserver)](#worked-example-single-kube-apiserver)
    - [Future: aggregated API servers](#future-aggregated-api-servers)
  - [Built-in CEL conditions evaluator](#built-in-cel-conditions-evaluator)
  - [Feature availability and version skew](#feature-availability-and-version-skew)
    - [Enablement: three switches plus one per-webhook opt-in](#enablement-three-switches-plus-one-per-webhook-opt-in)
    - [Version skew](#version-skew)
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
- [Alternatives Considered](#alternatives-considered)
  - [Expose all conditions in AdmissionReview, and have admission plugins “acknowledge” the conditions](#expose-all-conditions-in-admissionreview-and-have-admission-plugins-acknowledge-the-conditions)
  - [Propagate an API server-generated request UID to both authorization and admission](#propagate-an-api-server-generated-request-uid-to-both-authorization-and-admission)
  - [Only one ConditionsMap exposed as part of SubjectAccessReview status](#only-one-conditionsmap-exposed-as-part-of-subjectaccessreview-status)
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

1. compute an `Allow`, `Deny` or `NoOpinion` decision, or a conditional decision,
   during the authorization phase. A conditional decision is either a
   `ConditionsMap` (one authorizer's conditions) or a `Union` (an ordered list of
   several authorizers' decisions), and is returned to Kubernetes.
1. evaluate any conditions on the old/new object(s) during the validating admission
   phase, and enforce the concrete `Allow`, `Deny` or `NoOpinion` result.

Through this KEP, Kubernetes guarantees to the authorizer that its scoped-down
authorization policy will be enforced, without the authorizer having to rely on
existence of other specific admission plugins, for every request that reaches
admission. The unsafe corrupt-object delete skips admission, so a conditionally
authorized `delete` of a corrupt object completes without enforcement (see
below).

> **TODO(decision D-1):** Two request paths do not reach the conditions enforcer
> today: writes to API groups served by aggregated API servers (kube-apiserver
> classifies them as conditional, performs no enforcement in its proxy, and the
> aggregated server re-authorizes unconditionally and so fails closed), and the
> unsafe corrupt-object delete, which skips admission. Undecided: classify such
> requests as unconditional, refuse them unless the decision is an unconditional
> Allow, or implement the pass-through model for aggregated API servers.

Concretely, all `SubjectAccessReview` (SAR) APIs are extended such that a client
can ask for conditions (by listing the conditional decision types in
`spec.authorizationOptions.handledDecisionTypes`) and the authorizer can respond
with conditions (in `status.conditionalDecision`). A user can thus discover what
restrictions they are subject to through a `SelfSubjectAccessReview` that opts in.
`kubectl auth can-i` does not send `authorizationOptions`, so it shows only the
unconditional fold-down; conditions are visible only to SAR clients that opt in.
In addition, a new `AuthorizationConditionsReview` wire type is added, which the
API server sends to a webhook authorizer to let it evaluate its own conditions
against the request data.

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
- Initially support enforcement of write requests (resource requests with the
  verbs `create`, `update`, `patch`, `delete` and `deletecollection`, i.e. the
  requests for which admission runs) in kube-apiserver. Enforcement is split
  between a separate, conditions-aware HTTP authorization filter
  (`k8s.io/apiserver/pkg/endpoints/filters.WithConditionsAwareAuthorization`),
  which lets a conditionally allowed request proceed, and the
  `AuthorizationConditionsEnforcer` validating admission plugin, which evaluates
  the conditions. The existing `WithAuthorization` filter keeps its decisions;
  with the gate on it also attaches its `Allow` decision to the request context
  for the enforcer. Connect
  requests are covered when they arrive as `POST` (verb `create`, e.g.
  `create pods/exec`); connect requests that arrive as `GET` are authorized
  unconditionally in alpha. Coverage of read[^2], `GET` connect and impersonate
  verbs can be added later.
  - However, conditions can be returned for any verb in `SubjectAccessReview`
    responses, so extensions can be built arbitrarily on top. For instance,
    aggregated API servers can choose to enforce conditions on whatever custom
    verbs it wants, and authorizer can return conditions for any verb it likes.
- Allow any authorizer's conditions to be expressed in both transparent,
  analyzable forms (like Cedar or CEL), or opaque ones (like just `policy16`).
- Support expressing conditions with `Allow`, `Deny` and `NoOpinion` effects.
- Provide the foundational framework on top of which we can build other
  authorization features, such as Constrained Impersonation, RBAC++ and
  Referential Authorization.
- Ensure that a request is evaluated against an atomic set of policies in the
  authorizer, even in presence of cached authorization decisions.

  *Alpha status (v1.38): not yet implemented; see Beta criteria.* The request
  context stores the reloadable root authorizer, not a snapshot of the chain that
  authored the decision, so if the authorization configuration is reloaded between
  the authorization filter and admission, the conditions are evaluated by the
  authorizer chain that is current at admission time.

  Deliberately outside this guarantee are secondary authorization checks that a
  condition itself makes: the in-process CEL evaluator's `authorizer` variable
  calls the API server's live root authorizer at evaluation time, with the same
  semantics as `authorizer` in `ValidatingAdmissionPolicy`.

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
authorizer returning its conditions to Kubernetes, one could
imagine two other methods, as follows:

1. The authorizer does not return conditions, but relies on Kubernetes to
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
         by partial evaluation and enforced as computed at admission, so only
         the authorization-time policy store semantics apply. Before sending the
         decision back to the authorizer for evaluation, the API server may
         refine it in-process: it may drop conditions that evaluated to false
         and replace parts of the decision that are already decided by their
         outcome, but it never adds conditions. (See [Goals](#goals) for the
         alpha status of this guarantee across authorizer configuration reloads.)
   3. **Tight coupling between conditions authoring and evaluation**: The
      authorizer would be the only entity which would be able to evaluate the
      conditional response in the admission stage, which forms a forced tight
      coupling. Two webhooks per authorizer per request is necessary.
      1. With this proposal, builtin (in-process) conditions evaluators might
         evaluate the conditions inside the API server, without a need for
         another webhook in admission. The builtin evaluator in this KEP is
         CEL-based (condition type `authorizer.kubernetes.io/cel`). This is
         faster and more reliable.
   4. **Not observable through (Self)SubjectAccessReview**: As for admission
      today, a user subject to a policy would not know what policy they are
      subject to before they execute a request that violates it (hopefully with
      a nice error message).
      1. With this proposal, a user can see the conditions serialized in the
         `(Self)SubjectAccessReview` status, if the request opts in to receive
         them. Some of the conditions might be opaque (like `policy16`), yes,
         but at least the user might know where to look next.
2. The authorizer does not return conditions, but instead caches the
   conditions in a memory. The authorizer relies on Kubernetes to generate a
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
      to conditions internally. If the authorizer needs to be horizontally
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

Go identifiers below are in `k8s.io/apiserver/pkg/authorization/authorizer`
unless stated otherwise; wire types are in `authorization.k8s.io/v1` unless
stated otherwise.

- **Residual**: Expression which is a deterministic function of data that was
  unknown during partial evaluation.
- **Condition**: a residual returned by an authorizer, with an ID (unique within
  its `ConditionsMap`), a condition type (e.g. `authorizer.kubernetes.io/cel`, or
  an authorizer-specific opaque type), the condition text, and an optional
  description. A condition's effect is not a field: it is given by which list of
  the `ConditionsMap` the condition is in.
- **`ConditionsAwareDecision`**: the result of conditions-aware authorization.
  In Go it is the struct `ConditionsAwareDecision`; on the wire it is the
  discriminated union `ConditionsAwareDecision` with a `type` field. It has five
  variants: `Allow`, `Deny`, `NoOpinion`, `ConditionsMap` and `Union`. The zero
  value is `Deny`. The existing `Decision` type (`DecisionAllow`, `DecisionDeny`,
  `DecisionNoOpinion`) stays, and is used for unconditional decisions.
- **`ConditionsMap`**: the conditional decision of one authorizer. It holds three
  lists of conditions, `denyConditions`, `noOpinionConditions` and
  `allowConditions`, with at most 128 conditions in total and IDs unique across
  all three lists. It is evaluated with precedence Deny > NoOpinion > Allow: a
  true deny condition gives `Deny`; otherwise a true no-opinion condition gives
  `NoOpinion`; otherwise a true allow condition gives `Allow`; if no condition is
  true, the result is `NoOpinion`. A map with only no-opinion conditions is
  folded to `NoOpinion` on construction.
- **`Union`**: an ordered list of named sub-decisions, one per authorizer that
  was consulted, built with `ConditionsAwareDecisionUnion`. Each name is a
  DNS-1123 subdomain, unique within that union. Sub-decisions may themselves be
  unions, so a decision is a tree. A union evaluates like the union authorizer:
  in order, the first `Allow` or `Deny` wins, and `NoOpinion` continues to the
  next entry. On the wire it is `union`, a list of `NamedConditionsAwareDecision`.
- **`PossibleDecisions`**: the non-empty subset of {`Allow`, `Deny`,
  `NoOpinion`} that a decision can evaluate to, for some request data.
- **Unconditional (concrete) decision**: one of `Allow`, `Deny`, `NoOpinion`
  (`IsUnconditional()`). For every decision built through the package's
  constructors, this is the case exactly when `PossibleDecisions` is a singleton.
- **Conditional decision**: a `ConditionsMap` or a `Union` whose
  `PossibleDecisions` has more than one element.
- **Conditionally allowed**: a conditional decision whose `PossibleDecisions`
  contains `Allow`. Only conditionally allowed requests proceed from the
  authorization filter to admission. A conditional decision that cannot become
  `Allow` is rejected in the filter, without decoding the request body.
- **`FailureDecision`**: the unconditional decision to use when a conditional
  decision cannot be processed (for example, the consumer is conditions-unaware,
  or the conditions cannot be evaluated): `Deny` if `Deny` is in
  `PossibleDecisions`, otherwise `NoOpinion`.
- **Condition evaluation result** (`ConditionEvaluationResult`): evaluating one
  condition yields true, false, an error, or **unevaluatable**. Unevaluatable
  means the evaluator cannot evaluate this condition (for example, it does not
  recognize the condition type); partial evaluation keeps such conditions in the
  decision for a later evaluator.
- **Conditions-aware caller**: a caller that can handle a conditional decision.
  In Go it calls `Authorizer.ConditionsAwareAuthorize` instead of `Authorize`;
  on the wire it sets `spec.authorizationOptions.handledDecisionTypes` to include
  `ConditionsMap` and `Union`. An authorizer must not return a conditional
  decision to any other caller; it folds the decision to its `FailureDecision`
  instead.
- **Classifier** (`k8s.io/apiserver/pkg/endpoints/filters.ConditionalAuthorizationRequestClassifier`):
  a function of the request attributes that tells the conditions-aware
  authorization filter whether the request is subject to conditions enforcement,
  in which case the filter calls `ConditionsAwareAuthorize`; otherwise it calls
  `Authorize`. It may only return true for requests that reach the enforcer.
  kube-apiserver's classifier returns true for resource requests with the verbs
  `create`, `update`, `patch`, `delete` and `deletecollection` whose
  GroupResource is not excluded from admission.
- **Enforcer**: the `AuthorizationConditionsEnforcer` validating admission
  plugin. It reads the conditional decision that the filter stored in the request
  context, and evaluates it by calling the root authorizer's `EvaluateConditions`
  with the request data (`ConditionsData`). Only an `Allow` result admits the
  request.
- **In-process (builtin) evaluator**: an evaluator that runs inside the API
  server for condition types it recognizes (`BuiltinConditionsEvaluatorBuilder`,
  `BuiltinConditionsEvaluator`). The CEL evaluator handles
  `authorizer.kubernetes.io/cel`. The webhook authorizer runs it first, and sends
  only what remains conditional to the webhook. Conditions it does not recognize,
  or that fail to evaluate in-process, are treated as unevaluatable.
- **`AuthorizationConditionsReview`** (`authorization.k8s.io/v1alpha1`): the wire
  type the API server sends to a webhook authorizer to evaluate that webhook's
  conditions. The request carries the (possibly refined) `decision` and the
  `admissionRequest`; the response echoes `uid` and carries an unconditional
  `decision`. It is not served as a REST resource by any API server.

## Proposal

To achieve the above mentioned goals, at a high level, the following changes are
proposed:

- The Go authorizer interface is split in two, and the `SubjectAccessReview`
  API is extended:
  - `authorizer.UnconditionalAuthorizer` holds only the existing, unchanged
    `Authorize` method. `authorizer.Authorizer` embeds it and adds
    `ConditionsAwareAuthorize` and `EvaluateConditions`. A caller signals that
    it can handle conditions by calling `ConditionsAwareAuthorize` (and
    statically, by holding an `Authorizer` rather than an
    `UnconditionalAuthorizer`).
  - Besides the existing unconditional `Allow`, `Deny` and `NoOpinion`
    decisions, a conditions-aware authorizer can return a conditional decision:
    a `ConditionsMap` (conditions grouped by effect) or a `Union` (an ordered,
    named list of sub-decisions, which forms a tree).
  - On the wire, a `SubjectAccessReview` client opts in with
    `spec.authorizationOptions.handledDecisionTypes`, and a webhook answers with
    `status.conditionalDecision`.
- A new `WithConditionsAwareAuthorization` HTTP filter is installed instead of
  the `WithAuthorization` filter when the `ConditionalAuthorization`
  feature gate is on, the server has a `ConditionalAuthorizationRequestClassifier`
  (only kube-apiserver sets one), and the `AuthorizationConditionsEnforcer`
  admission plugin is enabled. For a request the classifier accepts, the filter
  calls `ConditionsAwareAuthorize` and lets the request proceed in the request
  chain if the decision is:
  - An unconditional `Allow`, just like before, or
  - A conditional decision whose possible outcomes include `Allow`.

  For every other request it calls the legacy `Authorize`. The decision is
  stored in the request context together with the authorizer that produced it.
  If the gate is on but the enforcer plugin is disabled, the legacy filter is
  installed and a warning is logged, so no conditionally allowed request can
  reach admission without the enforcer.
- A new `k8s.io/apiserver`-built-in `AuthorizationConditionsEnforcer`
  validating admission plugin, which evaluates the conditions (if any) of the
  decision in the context and lets the request through only if they evaluate
  to `Allow`. It is enabled by default in kube-apiserver, can be disabled, and
  is inert when the feature gate is off. It runs after all mutating admission
  plugins, every built-in validating plugin and `ValidatingAdmissionPolicy`,
  and before `ValidatingAdmissionWebhook`, `ResourceQuota` and `AlwaysDeny`.
  The order after `ValidatingAdmissionPolicy` is deliberate: it avoids sending
  an `AuthorizationConditionsReview` for requests that a policy rejects anyway.

  > **TODO(decision D-6):** The enforcer's position is undecided: keep it after `ValidatingAdmissionPolicy` (and document that earlier plugins and webhooks see, and may act on, requests the authorizer will deny, plus add a side-effect guard), move it to be the first validating plugin, or evaluate the conditions before mutating admission.

  - To let out-of-tree (webhook) authorizers evaluate their (opaque)
    conditions, a new `AuthorizationConditionsReview` (`authorization.k8s.io/v1alpha1`)
    type is added. It is a wire type: the webhook authorizer sends it to the
    endpoint configured in `webhook.conditionsReview`, and no API server serves
    it as a resource. Evaluation on behalf of aggregated API servers through
    kube-apiserver is future work.
- A `k8s.io/apiserver`-built-in CEL condition evaluator, which lets conditions
  of type `authorizer.kubernetes.io/cel` be evaluated in-process, without a
  webhook call. On HEAD it is built per webhook authorizer, and only when the
  feature gate is on and that webhook has `conditionsReview` configured. The
  webhook authorizer evaluates what it can in-process first, and sends the
  remaining (refined) decision in the `AuthorizationConditionsReview` only if
  the result is still conditional.

  > **TODO(decision D-5):** It is undecided whether in-process CEL stays tied to `webhook.conditionsReview` (today's behaviour), is built whenever the feature gate is on (so a CEL-only webhook needs no `AuthorizationConditionsReview` endpoint), or gets an explicit configuration knob.

Notably, this design achieves its goal of unified authorization expressions
across authorization and admission, without breaking the reasons why
authorizers do not have direct access to the request body in the authorization
stage:

1. Conditional Authorization is only enforced for certain requests, namely
   those for which admission is invoked. In kube-apiserver these are resource
   requests with verb `create`, `update`, `patch`, `delete` or
   `deletecollection` whose resource is not excluded from admission. Connect
   requests are covered when they are issued with HTTP POST (verb `create`, e.g.
   `create pods/exec`). In alpha, connect requests issued with HTTP GET (verb
   `get`) are classified unconditional, i.e. a conditional answer for them
   fails closed; supporting them is a beta item.
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
`ConditionsAwareDecision` has five variants: the unconditional `Allow`, `Deny`
and `NoOpinion`, and the conditional `ConditionsMap` and `Union`. A
`ConditionsMap`, returned by some authorizer, holds three ordered lists of
conditions (deny, noOpinion and allow), with IDs that are unique across the
map. A `Union` is an ordered list of sub-decisions, each named by the
authorizer that produced it (names are unique within one union), and is what a
union of authorizers returns when its answer is conditional.

Let `ConditionsData` be the term for the data unknown at authorization time
(the request, the stored object and the request options). A condition is a
deterministic function `condition: ConditionsData → Boolean` that may also
evaluate to an error. Note that the condition is only a function of the unknown
data; already-known data should be constants of the condition (see the
[partial evaluation section](#what-is-partial-evaluation) for an example). The
*effect* of a condition is the list it is in: a true condition in the deny list
produces `Deny`, one in the noOpinion list produces `NoOpinion`, and one in the
allow list produces `Allow`, with precedence Deny > NoOpinion > Allow.

Note that even though the “full” new and old objects are given as inputs to the
condition in this model, the authorizer is free to choose how much of that API
surface is exposed to policy authors. Some authorizer might decide to e.g. only
expose field-selectable fields in the expression model given to the policy
author.

Evaluating a `ConditionsAwareDecision` is a deterministic function
`evaluate: ConditionsAwareDecision x ConditionsData → Decision`, where `Decision`
is one of `Allow`, `Deny` or `NoOpinion`, and the result is always one of the
decision's possible outcomes (`PossibleDecisions()`). The API server may
partially evaluate a decision before handing it back to its authorizer (see the
built-in CEL evaluator); it only removes already-decided parts and never adds a
possible outcome. Note that conditions evaluation *should not* have access to
the policy store; this is by design, as it makes this two-stage mechanism
*atomic*, just like it would have been if it could have been evaluated directly.

*Alpha status (v1.38): not yet implemented; see Beta criteria.* The context
stores the reloadable authorizer resolver rather than the authorizer chain that
produced the decision, so `EvaluateConditions` runs against the chain that is
current at admission time, which can differ from the one at authorization time
if the authorization configuration is reloaded in between.

One deliberate exception exists: a `authorizer.kubernetes.io/cel` condition may
use the optional `authorizer` variable, which, as in
`ValidatingAdmissionPolicy`, performs secondary authorization checks against
the API server's live root authorizer (cached for the duration of one
in-process evaluation, i.e. one webhook `EvaluateConditions` call; a request can
make several such calls) at admission time. Such checks are not atomic with the original decision.

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
  and `deletecollection` in authorization turns into a `delete` in admission
  (evaluated once per object).

  *Alpha status (v1.38): not yet implemented; see Beta criteria.* The secondary
  `create` check for an `update`/`patch` that creates the object uses the
  unconditional `Authorize`, and the enforcer evaluates the conditions of the
  original `update`/`patch` decision against admission attributes whose
  operation is `CREATE`.
- Must work with aggregated API servers.

  *Alpha status (v1.38): not yet implemented; see Beta criteria.* Generic
  (aggregated) API servers set no request classifier, so they never install the
  conditions-aware filter, and their delegating authorizer calls only the
  unconditional `Authorize`; a conditional answer from kube-apiserver therefore
  fails closed there. kube-apiserver's classifier does not check whether the
  API group is served locally, so it classifies writes to aggregated groups as
  conditional although admission for them runs in the aggregated server and
  kube-apiserver never enforces the conditions.

  > **TODO(decision D-1):** It is undecided how kube-apiserver treats requests whose conditions it cannot enforce (writes proxied to aggregated API servers, and the unsafe corrupt-object delete, which skips admission): classify them as not conditional, refuse them unless the decision is an unconditional `Allow`, or implement the pass-through model in which the aggregated server enforces the conditions.
- Must work with any authorizer chain that is formed as a DAG.

### Core interface changes

`authorizer.Decision` stays an `int` enum for unconditional decisions. A new,
separate struct `authorizer.ConditionsAwareDecision` carries the conditional
variants (Go does not support enums with attached data). The
`authorizer.Authorizer` interface is split so that a holder of the smaller
`UnconditionalAuthorizer` can only call the unchanged `Authorize` method. There
is no attribute through which a caller signals conditions-readiness; the caller
signals it by which method it calls.

```go
package authorizer // k8s.io/apiserver/pkg/authorization/authorizer

// UnconditionalAuthorizer is a downscoped variant of Authorizer, which only gives the
// caller the ability to call the conditions-unaware Authorize method.
type UnconditionalAuthorizer interface {
	Authorize(ctx context.Context, a Attributes) (authorized Decision, reason string, err error)
}

// Authorizer makes an authorization decision based on information gained by making
// zero or more calls to methods of the Attributes interface. It might return
// an error together with any decision. It is up to the caller to decide whether
// that error is critical or not.
//
// The kube-apiserver WithAuthorization filter ignores errors when the decision is
// Allow, but returns response code 500 if an error is returned with a Deny or
// NoOpinion (instead of the usual 403).
//
// Any authorizer must implement this interface, but when passing a handle to an
// authorizer, one might choose whether to pass the Authorizer or smaller UnconditionalAuthorizer
// interface, depending on whether the receiver should be able to perform conditional
// authorization or not.
type Authorizer interface {
	UnconditionalAuthorizer

	// ConditionsAwareAuthorize returns an unconditional, conditional, or unioned
	// decision, where the error and reason is part of the Decision struct.
	//
	// An authorizer who is not conditions-aware MUST implement this function as
	// "return authorizer.ConditionsAwareDecisionFromParts(self.Authorize(ctx, a))",
	// such that conditions-aware callers to this authorizer get the same output
	// as if they called Authorize. Callers are only expected to call one of
	// Authorize or ConditionsAwareAuthorize, not both.
	ConditionsAwareAuthorize(ctx context.Context, a Attributes) ConditionsAwareDecision

	// EvaluateConditions evaluates a conditional or unioned ConditionsAwareDecision against previously-unknown data.
	//
	// An authorizer who does not support conditions should fail closed and
	// return authorizer.DecisionDeny, "", authorizer.ErrorConditionEvaluationNotSupported
	//
	// The context should only be used for timeouts/cancellation/tracing, and should not influence the
	// evaluation outcome. Only the given decision and data may influence the outcome. data must be non-nil.
	EvaluateConditions(ctx context.Context, decision ConditionsAwareDecision, data ConditionsData) (authorized Decision, reason string, err error)
}

// ErrorConditionEvaluationNotSupported is returned by authorizer implementations
// that do not support condition evaluation.
var ErrorConditionEvaluationNotSupported = errors.New("condition evaluation not supported")

// Decision represents an final, unconditional authorization decision.
// The zero value (0) of Decision is DecisionDeny.
type Decision int

const (
	// DecisionDeny means that an authorizer decided to deny the action.
	DecisionDeny Decision = iota
	// DecisionAllow means that an authorizer decided to allow the action.
	DecisionAllow
	// DecisionNoOpinion means that an authorizer has no opinion on whether
	// to allow or deny an action. If there are multiple unioned authorizers,
	// this means that the request can thus get allowed by some later authorizer.
	DecisionNoOpinion
)
```

The rules every authorizer and caller must follow:

1. An authorizer that is not conditions-aware MUST implement
   `ConditionsAwareAuthorize` as
   `return authorizer.ConditionsAwareDecisionFromParts(self.Authorize(ctx, a))`.
2. An authorizer that does not support conditions MUST fail closed in
   `EvaluateConditions` and return
   `authorizer.DecisionDeny, "", authorizer.ErrorConditionEvaluationNotSupported`.
   `authorizer.AuthorizerFunc` implements both rules for a plain function.
3. A caller calls only one of `Authorize` or `ConditionsAwareAuthorize` for a
   given check, not both.
4. `EvaluateConditions` uses its context only for timeouts, cancellation and
   tracing; only the given decision and data may influence the outcome, and
   `data` must be non-nil.
5. A pass-through wrapper (the reloadable authorizer resolver, the metrics
   instrumentation wrapper, the union authorizer) MUST forward all three
   methods to its delegate(s).

All in-tree authorizers add the two methods; only the union and webhook
authorizers are conditions-aware. Their `Authorize` methods keep their decisions,
with two ungated changes: the union's `Authorize` prefixes aggregated `NoOpinion`
reasons with `<authorizerName>: `, and the webhook's `Authorize` folds an
unrequested `status.conditionalDecision` to its `FailureDecision()` plus an error
(see [Properties](#properties), items 4 and 5). All other in-tree `Authorize` methods are unchanged.
Composition uses `union.New(...union.NamedAuthorizer) (authorizer.Authorizer, error)`,
where every `NamedAuthorizer` has a non-empty name that is unique within that
union.

The zero value of both types is `Deny`: `Decision(0) == DecisionDeny`, and
`ConditionsAwareDecision{}` is equivalent to `ConditionsAwareDecisionDeny("", nil)`.

```go
package authorizer // k8s.io/apiserver/pkg/authorization/authorizer

// ConditionsAwareDecision models an authorization decision that is conditions-aware.
// It is an enum type of the following five variants:
// - Allow: unconditional Allow.
// - Deny: unconditional Deny.
// - NoOpinion: unconditional NoOpinion.
// - ConditionsMap: conditional, expressed as a map of conditions to be evaluated later.
// - Union: an ordered list of sub-decisions, which forms a tree of decisions.
//
// The zero value (ConditionsAwareDecision{}) is equivalent to ConditionsAwareDecisionDeny("", nil).
// A ConditionsAwareDecision is passed by value.
// Important: A ConditionsAwareDecision is immutable after construction.
type ConditionsAwareDecision struct {
	decisionType conditionsAwareDecisionType

	conditionsMap ConditionsMap
	union         ConditionsAwareDecisionUnion

	reason string
	err    error
}

// ConditionsAwareDecisionDeny constructs a Deny decision with the given reason and error.
func ConditionsAwareDecisionDeny(reason string, err error) ConditionsAwareDecision

// ConditionsAwareDecisionAllow constructs an Allow decision with the given reason and error.
func ConditionsAwareDecisionAllow(reason string, err error) ConditionsAwareDecision

// ConditionsAwareDecisionNoOpinion constructs a NoOpinion decision with the given reason and error.
func ConditionsAwareDecisionNoOpinion(reason string, err error) ConditionsAwareDecision

// ConditionsAwareDecisionFromParts is meant to be used by conditions-unaware Authorizer implementations
// in order to implement ConditionsAwareAuthorize as:
// "return authorizer.ConditionsAwareDecisionFromParts(self.Authorize(ctx, a))"
func ConditionsAwareDecisionFromParts(unconditional Decision, reason string, err error) ConditionsAwareDecision

// IsAllow returns true if the decision is an unconditional Allow.
func (d ConditionsAwareDecision) IsAllow() bool

// IsNoOpinion returns true if the decision is an unconditional NoOpinion.
func (d ConditionsAwareDecision) IsNoOpinion() bool

// IsDeny returns true if the decision is an unconditional Deny.
func (d ConditionsAwareDecision) IsDeny() bool

// IsConditionsMap returns true if the decision is a conditional response
// with a map of conditions to evaluate.
func (d ConditionsAwareDecision) IsConditionsMap() bool

// ConditionsMap returns the ConditionsMap, which is non-empty
// if and only if IsConditionsMap is true.
func (d ConditionsAwareDecision) ConditionsMap() ConditionsMap

// IsUnion returns true if the decision consists of other sub-decisions
// unioned together in a tree-like structure.
func (d ConditionsAwareDecision) IsUnion() bool

// IsUnconditional is true if d is Allow, Deny or NoOpinion.
func (d ConditionsAwareDecision) IsUnconditional() bool

// UnconditionalPartsOrError splits a ConditionsAwareDecision into the
// standard (unconditional Decision, reason, error) triple.
// A caller is expected to guard this call with d.IsUnconditional() first.
// If this function is called on a conditional decision, an error is returned.
func (d ConditionsAwareDecision) UnconditionalPartsOrError() (Decision, string, error)

// UnconditionalPartsOrFailClosed splits a ConditionsAwareDecision into the
// standard (unconditional Decision, reason, error) triple.
// If d is conditional, d.FailureDecision() will be returned along with
// a reason describing that the decision would have been conditional,
// if the caller opted into it.
// No error is returned in the fail closed case, which means a 403 response code (as opposed to 500).
func (d ConditionsAwareDecision) UnconditionalPartsOrFailClosed() (Decision, string, error)

// PossibleDecisions details what are the possible decision outcomes of this
// ConditionsAwareDecision. The return value is a subset of {Allow, Deny, NoOpinion},
// but never the empty set. If the set only contains a single value, it means the
// decision is unconditional.
func (d ConditionsAwareDecision) PossibleDecisions() sets.Set[Decision]

// FailureDecision returns either a Deny or NoOpinion decision that the caller can
// use if the caller encounters an unrecoverable error while processing a
// ConditionsAwareDecision. If this decision is or could evaluate to Deny
// this function returns DecisionDeny to the caller, in order to fail closed
// as a conservative approximation. Otherwise, NoOpinion is returned.
func (d ConditionsAwareDecision) FailureDecision() Decision

// ContainsUnconditionalAllowOrDeny returns true if this decision's tree contains at least
// one unconditional Allow or Deny leaf.
func (d ConditionsAwareDecision) ContainsUnconditionalAllowOrDeny() bool

// UnionedDecisions returns an iterator for unioned sub-decisions.
// This iterator is non-empty if and only if IsUnion() == true.
// Sub-decisions iteration order is preserved.
func (d ConditionsAwareDecision) UnionedDecisions() iter.Seq2[string, ConditionsAwareDecision]

// Reason returns the reason supplied when constructing
// an unconditional decision.
// Reason is an empty string for conditional decisions.
func (d ConditionsAwareDecision) Reason() string

// Error returns the error supplied when constructing
// an unconditional decision.
// Error is nil for conditional decisions.
func (d ConditionsAwareDecision) Error() error

// String returns a human-readable representation of the decision.
func (d ConditionsAwareDecision) String() string
```

The conditional variants are built with the `ConditionsMap` constructor and the
`ConditionsAwareDecisionUnion` builder. Both validate their input and fail
closed (to `FailureDecision()` of what was given, with an error) instead of
returning an invalid decision; the union builder also folds a union whose only
possible outcome is a single decision into that unconditional decision.

```go
package authorizer // k8s.io/apiserver/pkg/authorization/authorizer

// Condition represents one authorization condition that is part of a ConditionsMap.
// The effect of a condition is defined by whether it is part of the Deny/NoOpinion/Allow
// conditions list in the ConditionsMap.
//
// A Condition must be immutable and thread-safe.
type Condition interface {
	// GetID uniquely identifies this condition within the scope of the authorizer
	// that authored it. Validated as a Kubernetes label key.
	// Any domain of form *.k8s.io or *.kubernetes.io is reserved for Kubernetes use.
	// Required.
	GetID() string

	// GetType describes the type of the condition, if there are multiple possibilities.
	// Should be formatted as a Kubernetes label key.
	// Any domain of form *.k8s.io or *.kubernetes.io is reserved for Kubernetes use.
	// Optional. Can be omitted if the authorizer already knows how to evaluate the condition.
	GetType() string

	// GetCondition returns a string encoding of the condition to be evaluated.
	// It is a pure, deterministic function from ConditionsData to a boolean (or error).
	// Might or might not be human-readable.
	// Optional, if the ID alone is enough for the authorizer to know how to evaluate the condition.
	GetCondition() string

	// GetDescription is an optional human-friendly description that can be shown
	// as an error message or for debugging. Optional.
	GetDescription() string

	// Evaluate evaluates the condition to a boolean, returns an error, or returns "unevaluatable".
	// If an authorizer already has a pre-compiled condition, this avoids one serialization roundtrip,
	// with potentially expensive deserialization/parsing. However, if the condition underwent a
	// serialize/deserialize roundtrip (e.g. when the caller is an aggregated API server), the authorizer
	// might have to evaluate the condition from its serialized form using evaluateFunc in
	// ConditionsMap.Evaluate.
	// Evaluate must be safe to call repeatedly and concurrently.
	//
	// The context should only be used for timeouts/cancellation/tracing, and should not influence the
	// evaluation outcome. Only the condition itself and data can infuence the outcome.
	Evaluate(ctx context.Context, data ConditionsData) ConditionEvaluationResult
}

// ConditionsAwareDecisionConditionsMap creates a ConditionsMap decision.
// The conditions are grouped by their effects: Deny, NoOpinion and Allow, that function as follows:
//   - Deny: If a Deny condition evaluates to true, the ConditionsMap necessarily evaluates to Deny.
//     In this case, no further authorizers are consulted.
//   - NoOpinion: If a NoOpinion condition evaluates to true, the given authorizer's ConditionsMap cannot
//     evaluate to Allow anymore, but necessarily Deny or NoOpinion, depending on whether there are any true
//     Deny conditions. However, later authorizers in the chain can still Allow or Deny.
//     It is effectively a softer deny that just overrides the authorizer's own allow policies.
//   - Allow: If any Allow condition evaluates to true, the ConditionsMap evaluates to Allow,
//     unless any Deny/NoOpinion condition also evaluates to true (in which case the Deny/NoOpinion conditions
//     have precedence).
//
// All conditions must be non-nil, this function panics if any condition is nil.
func ConditionsAwareDecisionConditionsMap(denyConditions []Condition, noOpinionConditions []Condition, allowConditions []Condition) ConditionsAwareDecision

// ConditionsAwareDecisionUnion is a builder struct for a Union-typed ConditionsAwareDecision.
// ConditionsAwareDecisionUnion is not thread-safe.
type ConditionsAwareDecisionUnion struct {
	// private fields omitted
}

// Add adds a named sub-decision to the current Union ConditionsAwareDecision builder.
// Add is a no-op if ContainsUnconditionalAllowOrDeny() is true, as adding decisions after
// an Allow or Deny will never change the final evaluated outcome.
// Invalid inputs (empty name, duplicate name, invalid DNS-1123 subdomain) are recorded as
// aggregated errors and surfaced by ToDecision(); Add itself never returns.
// Add is not thread-safe.
func (unionMap *ConditionsAwareDecisionUnion) Add(authorizerName string, d ConditionsAwareDecision)

// FailureDecision returns either a Deny or NoOpinion decision that the caller can
// use if the caller encounters an unrecoverable error while processing a
// ConditionsAwareDecision. If this decision is or could evaluate to Deny
// this function returns DecisionDeny to the caller, in order to fail closed
// as a conservative approximation. Otherwise, NoOpinion is returned.
// FailureDecision is not thread-safe.
func (unionMap *ConditionsAwareDecisionUnion) FailureDecision() Decision

// ContainsUnconditionalAllowOrDeny returns true whether there union contains at least one
// Allow or Deny decision within the unioned decisions.
// ContainsUnconditionalAllowOrDeny is not thread-safe.
func (unionMap *ConditionsAwareDecisionUnion) ContainsUnconditionalAllowOrDeny() bool

// PossibleDecisions details what are the possible decision outcomes of this
// ConditionsAwareDecisionUnion. The return value is a subset of {Allow, Deny, NoOpinion},
// but never the empty set.
// PossibleDecisions is not thread-safe.
func (unionMap *ConditionsAwareDecisionUnion) PossibleDecisions() sets.Set[Decision]

// ConditionsAwareDecisionUnion unions some amount of decisions together into a tree structure,
// where Allow/Deny/NoOpinion/ConditionsMap decisions are leafs, and Union decisions are internal
// tree nodes.
// ToDecision is not thread-safe.
func (unionMap *ConditionsAwareDecisionUnion) ToDecision() ConditionsAwareDecision
```

A conditions-aware authorizer's `Authorize` method must never return `Allow` for
a request it would only conditionally allow. If it would otherwise have
answered conditionally, the safe unconditional answer is the decision's
`FailureDecision()`: `Deny` if a `Deny` outcome is possible, otherwise
`NoOpinion`. On HEAD, the webhook authorizer's `Authorize`, when a webhook
answers with a `status.conditionalDecision` that was not requested (and not
`denied`), returns that `FailureDecision()` together with an error. If that
result is final, the `WithAuthorization` filter turns it into a 500 response. If
`FailureDecision()` is `NoOpinion`, the union continues instead: a later `Allow`
admits the request, and a later `Deny` gives that authorizer's own result
(normally a 403).
`UnconditionalPartsOrFailClosed`, which returns the same decision with a
descriptive reason and no error (a 403), has no production caller. The
conditions-aware filter answers a conditional decision that cannot reach
`Allow` with a 403 whose reason is empty.

> **TODO(decision D-2):** The response to a conditional answer that a conditions-unaware consumer cannot use is undecided: keep the 500 on the legacy path, return a 403 everywhere (e.g. through `UnconditionalPartsOrFailClosed`), or split (500 for the protocol violation of an unrequested conditional webhook answer, a descriptive 403 at the conditions-aware filter).

Evaluating a conditional decision into an unconditional one is done by the
authorizer that authored it, through `EvaluateConditions`; in kube-apiserver
the `AuthorizationConditionsEnforcer` is the only caller. The data passed in is
all the data that was not present earlier, but which authorization policies
are allowed to use. If the partial evaluation process was done correctly, the
condition is a pure function of this data:

```go
package authorizer // k8s.io/apiserver/pkg/authorization/authorizer

// AdmissionOperation represents the admission operation,
// for example CREATE, UPDATE, DELETE. The constants are
// defined in k8s.io/apiserver/pkg/admission, but the
// type is defined here, because this package is more generic
// than the admission package (thus avoiding import cycles)
type AdmissionOperation string

// ConditionsData represents the data available for conditions
// to evaluate against. This is by design a subset of admission.Attributes.
type ConditionsData interface {
	// GetName returns the name of the object as presented in the request. On a CREATE operation, the client
	// may omit name and rely on the server to generate the name. If that is the case, this method will return
	// the empty string
	GetName() string
	// GetNamespace is the namespace associated with the request (if any)
	GetNamespace() string
	// GetResource is the name of the resource being requested. This is not the kind. For example: pods
	GetResource() schema.GroupVersionResource
	// GetSubresource is the name of the subresource being requested. This is a different resource, scoped to the parent resource, but it may have a different kind.
	// For instance, /pods has the resource "pods" and the kind "Pod", while /pods/foo/status has the resource "pods", the sub resource "status", and the kind "Pod"
	// (because status operates on pods). The binding resource for a pod though may be /pods/foo/binding, which has resource "pods", subresource "binding", and kind "Binding".
	GetSubresource() string
	// GetOperation is the operation being performed
	GetOperation() AdmissionOperation
	// GetOperationOptions is the options for the operation being performed
	GetOperationOptions() runtime.Object
	// IsDryRun indicates that modifications will definitely not be persisted for this request. This is to prevent
	// admission controllers with side effects and a method of reconciliation from being overwhelmed.
	// However, a value of false for this does not mean that the modification will be persisted, because it
	// could still be rejected by a subsequent validation step.
	IsDryRun() bool
	// GetObject is the object from the incoming request. Only populated for CREATE and UPDATE requests.
	// The object should be versioned in the external version corresponding to GetKind().
	GetObject() runtime.Object
	// GetOldObject is the existing object in storage. Only populated for UPDATE and DELETE requests.
	// The old object should be versioned in the external version corresponding to GetKind().
	GetOldObject() runtime.Object
	// GetKind is the type of object being manipulated. For example: Pod
	GetKind() schema.GroupVersionKind
	// GetUserInfo is information about the requesting user
	GetUserInfo() user.Info
}
```

The enforcer passes `admission.VersionedAttributes` for the request's kind, in
the validating phase. Both the new and the old object are therefore in the
external version of `GetKind()`, and the new object is the one after mutating
admission and defaulting.

During evaluation a single condition yields one of four results: true, false,
an error, or "unevaluatable" (it cannot be evaluated by this evaluator; this is
what makes partial evaluation possible). In-process evaluators plug in through
`MaybeEvaluateConditionFunc` and the `BuiltinConditionsEvaluatorBuilder`;
`PartiallyEvaluateConditionsAwareDecision` refines a decision with whatever the
evaluator can decide, and returns it unconditional only if everything needed
was evaluatable:

```go
package authorizer // k8s.io/apiserver/pkg/authorization/authorizer

// ConditionEvaluationResult is an enum type with four variants:
// - true and false: Evaluation was successful, and evaluated to this value
// - error: The condition could be evaluated, but errored during eval.
// - unevaluatable: The condition cannot readily be evaluated. This is the struct zero value.
type ConditionEvaluationResult struct {
	resultType partialConditionEvaluationResultType
	err        error
}

// ConditionEvaluationResultBoolean constructs an evaluation result with a boolean value.
func ConditionEvaluationResultBoolean(evalResult bool) ConditionEvaluationResult

// ConditionEvaluationResultError indicates that the condition could be evaluated, but failed.
func ConditionEvaluationResultError(err error) ConditionEvaluationResult

// ConditionsEvaluationResultUnevaluatable indicates direct conditions evaluation is not possible.
func ConditionsEvaluationResultUnevaluatable() ConditionEvaluationResult

// IsTrue indicates that the conditions evaluation was successful, and evaluated to true, which means it influences the ConditionsMap decision.
func (r ConditionEvaluationResult) IsTrue() bool

// IsFalse indicates that the conditions evaluation was successful, but evaluated to false, and it not thus taken into account.
func (r ConditionEvaluationResult) IsFalse() bool

// IsError indicates whether conditions evaluation failed.
func (r ConditionEvaluationResult) IsError() bool

// Error returns the evaluation error, if any.
func (r ConditionEvaluationResult) Error() error

// IsUnevaluatable is true whenever none of the other variants is, that is, the zero value.
func (r ConditionEvaluationResult) IsUnevaluatable() bool

// MaybeEvaluateConditionFunc allows potentially evaluating a condition, returning Unevaluatable if a truth value or error cannot be assigned.
type MaybeEvaluateConditionFunc func(ctx context.Context, condition Condition, data ConditionsData) ConditionEvaluationResult

// PartiallyEvaluateConditionsAwareDecision evaluates the ConditionsAwareDecision primarily using any conditions' own Evaluate() function,
// and secondarily/optionally using evaluateConditionFn, if set. If evaluateConditionFn is non-nil and never returns
// ConditionsEvaluationResultUnevaluatable, the returned decision is guaranteed to be Allow/Deny/NoOpinion.
// However, this method can also be used to evaluate a subset of the conditions (e.g. for builtin
// conditions evaluators that only support a certain conditions type), returning ConditionsEvaluationResultUnevaluatable
// for conditions that the evaluator does not recognize. In the latter case, a partially evaluated ConditionsAwareDecision is returned.
// When evaluating a ConditionsMap, only the first matching (true) condition short-circuits the process,
// in order for the evaluation to be as efficient as possible.
func PartiallyEvaluateConditionsAwareDecision(ctx context.Context, unevaluatedDecision ConditionsAwareDecision, data ConditionsData, evaluateConditionFn MaybeEvaluateConditionFunc) ConditionsAwareDecision

// ConditionTypeAuthorizationCEL is a well-known conditions type for the CEL environment of the kube-apiserver,
// for authorization conditions evaluation.
// This CEL environment strives to be equal to the ValidationAdmissionPolicy CEL environment.
const ConditionTypeAuthorizationCEL = "authorizer.kubernetes.io/cel"

// BuiltinConditionsEvaluatorBuilder builds an in-process conditions evaluator for the given data.
// This means authorizers (e.g. the webhook authorizer) may try cheaper ways of evaluating a condition
// (e.g. in-process CEL evaluation) before more expensive ways (sending the webhook).
type BuiltinConditionsEvaluatorBuilder interface {
	// EvaluatorForData returns a BuiltinConditionsEvaluator from the given ConditionsData,
	// in order to initialize an evaluation environment only once.
	// apiServerAuthorizer is the API server's authorizer (not the authorizer that authored the condition), which
	// conditions may use for compound authorization, like in ValidatingAdmissionPolicy. It may be nil.
	EvaluatorForData(ctx context.Context, data ConditionsData, apiServerAuthorizer Authorizer) (BuiltinConditionsEvaluator, error)
}

// BuiltinConditionsEvaluator might allow in-process evaluation of a condition of a
// certain type, in the context of a given ConditionsData.
// If the condition type is not handled, return ConditionsEvaluationResultUnevaluatable().
type BuiltinConditionsEvaluator interface {
	// EvaluateCondition evaluates a single condition in the current ConditionsData context
	// into a ConditionEvaluationResult if possible, or returns ConditionsEvaluationResultUnevaluatable().
	EvaluateCondition(ctx context.Context, condition Condition) ConditionEvaluationResult
}
```

The precise evaluation rules (precedence, short-circuiting, and how errors map
to decisions) are specified in the following sections on computing a concrete
decision from a `ConditionsMap` and from a union.

### Properties

The machine-checkable invariants of this design are catalogued in
`review/properties.md` (IDs `P-n` below), several with a Lean model. The
catalogue and the Lean model are review artefacts accompanying this revision and
are not part of the KEP's normative text. The KEP relies on these five:

1. **Fail closed for conditions-unaware consumers.** A conditional decision
   never becomes `Allow` for a consumer that did not request conditions; the
   fallback is `FailureDecision()` (`Deny` iff `Deny` is possible, otherwise
   `NoOpinion`), and a conditions-unaware authorizer's `EvaluateConditions`
   fails closed (P-10, P-11, P-49). Which response code the consumer then sees
   is decision D-2.
2. **Soundness of `PossibleDecisions`.** Evaluating a decision with any total
   evaluator yields one of its `PossibleDecisions()` (P-18, P-37). Partial
   evaluation never adds a possible outcome (P-25), which holds for unions
   whose names are well-formed (non-empty, unique, DNS-1123). The union
   authorizer's `EvaluateConditions` clamps each sub-authorizer's answer into
   that sub-decision's possible outcomes and never fails open (P-44); the
   argument needs every conditional child to be well-formed, i.e. to have at
   least two possible outcomes.
3. **Precedence and error rules.** Within a `ConditionsMap`, Deny > NoOpinion >
   Allow; within one effect, true > error > unevaluatable > false, and the first
   true condition short-circuits (P-20, P-21, P-22, P-24). On HEAD, an error in
   the deny phase yields `Deny` with the error, and an error in the noOpinion or
   allow phase yields `NoOpinion` with the error; a carried error becomes a 500
   at the enforcer.

   > **TODO(decision D-3):** How condition evaluation errors are surfaced is undecided: ignore errors of allow conditions (the original KEP text), keep surfacing every error as today (500 at the enforcer), or introduce a non-fatal error class that still yields a 403.
4. **Unconditional chains are unchanged.** For a union whose leaves are all
   unconditional, `ConditionsAwareAuthorize` returns the same decision as the
   legacy `Authorize`, i.e. the first non-`NoOpinion` answer wins (P-41). The
   reason text differs between the two paths, and the legacy `Authorize` now
   prefixes aggregated `NoOpinion` reasons with `<authorizerName>: `.

   > **TODO(decision D-4):** The ungated `<authorizerName>: ` reason prefix on the legacy union path, visible in 403 bodies and SAR reasons, is undecided: ship it with a release note, revert it on the legacy path, or put it behind the feature gate.
5. **Gate off.** With the `ConditionalAuthorization` gate off, no conditional
   decision is produced, advertised or evaluated in production, the
   conditions-aware filter is not installed, the enforcer is inert, and the new
   `SubjectAccessReview` fields are cleared or forbidden (P-80). One new code
   path stays reachable: the webhook authorizer's `Authorize` folds an
   unrequested `status.conditionalDecision` as described above even with the
   gate off (P-81).

Confluence of partial and full evaluation (evaluating in-process first and
then handing the refined decision to the authorizer gives the same decision as
the authorizer evaluating the original) holds only when the partial evaluator
returns no errors, agrees with the full evaluator wherever it gives an answer,
and the full evaluator is total (P-27); with an error-returning partial
evaluator it fails, e.g. an errored allow condition next to an unevaluatable
allow condition that is true. The webhook authorizer meets the restriction
because it treats every in-process evaluation error as unevaluatable.
`PartiallyEvaluateConditionsAwareDecision` as a library function accepts
errors and does not. Likewise, partial evaluation with a total evaluator equals
full evaluation (P-28) only for unions with well-formed names.

### Condition and ConditionsMap data model

A conditional decision from a single authorizer is a `ConditionsMap`: a set of
conditions, each with an ID that is unique within the map, grouped by effect.
There is no effect field and no effect enum: a condition's effect is the list it
is placed in. A condition is described by the `Condition` interface in
`k8s.io/apiserver/pkg/authorization/authorizer`:

```go
// Condition represents one authorization condition that is part of a ConditionsMap.
// The effect of a condition is defined by whether it is part of the Deny/NoOpinion/Allow
// conditions list in the ConditionsMap.
//
// A Condition must be immutable and thread-safe.
type Condition interface {
	// GetID uniquely identifies this condition within the scope of the authorizer
	// that authored it. Validated as a Kubernetes label key.
	// Any domain of form *.k8s.io or *.kubernetes.io is reserved for Kubernetes use.
	// Required.
	GetID() string

	// GetType describes the type of the condition, if there are multiple possibilities.
	// Should be formatted as a Kubernetes label key.
	// Any domain of form *.k8s.io or *.kubernetes.io is reserved for Kubernetes use.
	// Optional. Can be omitted if the authorizer already knows how to evaluate the condition.
	GetType() string

	// GetCondition returns a string encoding of the condition to be evaluated.
	// It is a pure, deterministic function from ConditionsData to a boolean (or error).
	// Might or might not be human-readable.
	// Optional, if the ID alone is enough for the authorizer to know how to evaluate the condition.
	GetCondition() string

	// GetDescription is an optional human-friendly description that can be shown
	// as an error message or for debugging. Optional.
	GetDescription() string

	// Evaluate evaluates the condition to a boolean, returns an error, or returns "unevaluatable".
	// ...
	// Evaluate must be safe to call repeatedly and concurrently.
	Evaluate(ctx context.Context, data ConditionsData) ConditionEvaluationResult
}
```

`GenericCondition` is the concrete implementation used by decoders and
authorizers. `EvaluateFunc` is an optional in-process fast path; when it is nil,
`Evaluate` returns "unevaluatable" and the authorizer that authored the
condition evaluates it from its serialized form:

```go
type GenericCondition struct {
	ID           string
	Condition    string
	Type         string
	Description  string
	EvaluateFunc func(ctx context.Context, data ConditionsData) ConditionEvaluationResult
}
```

The map itself has only private fields and is built through a validating
constructor:

```go
type ConditionsMap struct {
	// invariant: len(denyConditions) != 0 || len(allowConditions) != 0
	denyConditions      []Condition
	noOpinionConditions []Condition
	allowConditions     []Condition
}

const (
	// MaxConditionsPerMap is the maximum number of conditions allowed in a single ConditionsMap.
	MaxConditionsPerMap = 128

	// MaxConditionBytes is the maximum number of bytes a condition can consist of.
	MaxConditionBytes = 10240

	// MaxConditionDescriptionBytes is the maximum number of bytes a condition's description can consist of.
	MaxConditionDescriptionBytes = 1024
)

func ConditionsAwareDecisionConditionsMap(denyConditions []Condition, noOpinionConditions []Condition, allowConditions []Condition) ConditionsAwareDecision
```

The three effects mean:

- **Deny**: if a Deny condition evaluates to true, the map evaluates to `Deny`,
  and no further authorizers are consulted.
- **NoOpinion**: if a NoOpinion condition evaluates to true, the map can no
  longer evaluate to `Allow`, only to `Deny` or `NoOpinion`. Later authorizers
  in the chain can still allow or deny. This is a softer deny that overrides the
  authorizer's own allow policies, for example when the authorizer does not
  consider itself authoritative for the request.
- **Allow**: if an Allow condition evaluates to true, the map evaluates to
  `Allow`, unless a Deny or NoOpinion condition is also true.

Conditions are evaluated against `ConditionsData` after mutating admission (see
[Core interface changes](#core-interface-changes)).

Field rules:

- **ID** (required) and **type** (optional) are domain-prefixed label keys: a
  DNS-1123 subdomain prefix, a `/`, and a name of at most 63 characters, for
  example `company.com/no-pod-exec`. The prefix is required. The wire API uses the
  same rule (`+k8s:format=k8s-prefixed-label-key` on
  `k8s.io/api/authorization/v1.Condition`). IDs are unique across all three
  lists of a map, and appear in reasons, e.g.
  `condition "company.com/no-pod-exec" denied the request`.
- **condition** is at most 10240 bytes. It is optional when the ID alone tells
  the authorizer what to evaluate. It may or may not be human-readable.
- **description** is at most 1024 bytes.
- A map holds at most 128 conditions in total, across all three lists.
- The type is per condition, not per map, so one map can mix condition types.
  The well-known type `authorizer.kubernetes.io/cel`
  (`authorizer.ConditionTypeAuthorizationCEL`) names the kube-apiserver CEL
  environment (see [Built-in CEL conditions evaluator](#built-in-cel-conditions-evaluator)).
  An authorizer must be able to evaluate every condition it authors.
- Domains of the form `*.k8s.io` and `*.kubernetes.io` are reserved for types
  and IDs whose meaning Kubernetes defines. The reservation is documented, not
  enforced: an authorizer may author conditions of a Kubernetes-defined type
  such as `authorizer.kubernetes.io/cel`, but must not invent new meanings under
  these domains.

*Alpha status (v1.38): not yet implemented; see Beta criteria.* API validation
enforces at most 128 conditions per list (up to 384 per map on the wire) and
unique IDs within each list only. The 128-in-total limit and ID uniqueness
across the three lists are enforced only by the constructor, which fails closed.

The constructor validates its input and never returns an invalid map:

- Zero conditions: `NoOpinion` with an error.
- More than 128 conditions in total: fails closed (as below).
- Only NoOpinion conditions: folds to an unconditional `NoOpinion` without an
  error, since such a map can never evaluate to anything else. This fold happens
  before the remaining checks, so a NoOpinion-only map with duplicate or invalid
  IDs also gives `NoOpinion` without an error.
- A duplicate ID in any of the three lists, an invalid ID or type, or an
  oversized condition or description: fails closed to `Deny`
  (reason `failed closed`, with the error) if the map has any Deny condition,
  otherwise to `NoOpinion`.

The same rule (`Deny` iff `Deny` is a possible outcome) is the decision's
`FailureDecision()`, which callers use whenever they cannot process a
conditional decision.

For a webhook authorizer, an invalid conditions map in a `SubjectAccessReview`
response is a malformed response, and the operator's configured `failurePolicy`
decides how it is handled.

The webhook validates the returned status with declarative validation before it
decodes the map. Malformed IDs or types, an oversized condition or description,
more than 128 conditions in one list, and duplicate IDs within one list are
rejected by validation and follow `failurePolicy`.

*Alpha status (v1.38): not yet implemented; see Beta criteria.* An empty map,
duplicate IDs across lists, and more than 128 conditions in total across the
three lists pass validation, because validation checks the count and ID
uniqueness per list only. The constructor then rejects such a map, which fails
closed to `Deny` iff the map contains Deny conditions, otherwise `NoOpinion`,
regardless of `failurePolicy`.

A map contains conditions only. When several authorizers contribute to one
decision, conditional and unconditional answers are combined in a `Union`
decision, whose leaves are `Allow`, `Deny`, `NoOpinion` or `ConditionsMap`
decisions and whose internal nodes are nested unions, each named by the
authorizer that produced it (see
[Computing a concrete decision from a conditional authorization chain](#computing-a-concrete-decision-from-a-conditional-authorization-chain)).
A union tree is bounded in width and depth.

*Alpha status (v1.38): not yet implemented; see Beta criteria.* Neither the Go
type nor the wire API (`union` in `k8s.io/api/authorization/v1.ConditionsAwareDecision`)
limits the width or depth of a union tree.

### Computing a concrete decision from a ConditionsMap

Evaluating a `ConditionsMap` against `ConditionsData` has two steps:

1. Evaluate each condition to a `ConditionEvaluationResult`, which has four
   variants: **true**, **false**, **error**, or **unevaluatable**. The last means
   the evaluator cannot assign a truth value (for example, an in-process
   evaluator that does not recognize the condition's type). Unevaluatable
   conditions are what makes partial evaluation possible: they stay in the
   resulting, smaller `ConditionsMap`.
2. Combine the results into one decision, with precedence
   **Deny > NoOpinion > Allow** between effects, and **true > error >
   unevaluatable > false** within an effect. Within an effect, the first true
   condition short-circuits; the remaining conditions of that effect are not
   evaluated.

The normative rules, as implemented by
`authorizer.PartiallyEvaluateConditionsAwareDecision` and
`ConditionsMap.Evaluate`:

| Deny conditions | NoOpinion conditions | Allow conditions | Result |
|---|---|---|---|
| any true | – | – | `Deny`, reason names the condition, no error |
| none true, any error | – | – | `Deny` + aggregated errors |
| none true/error, any unevaluatable | – | – | `ConditionsMap` of the unevaluatable Deny conditions plus all NoOpinion and Allow conditions |
| all false | any true | – | `NoOpinion`, reason names the condition, no error |
| all false | none true, any error | – | `NoOpinion` + aggregated errors |
| all false | none true/error, any unevaluatable | – | `ConditionsMap` of the unevaluatable NoOpinion conditions plus all Allow conditions (folds to `NoOpinion` if there are no Allow conditions) |
| all false | all false | any true | `Allow`, reason names the condition, no error |
| all false | all false | none true, any error | `NoOpinion` + aggregated errors |
| all false | all false | none true/error, any unevaluatable | `ConditionsMap` of the unevaluatable Allow conditions |
| all false | all false | all false | `NoOpinion` (`no conditions matched`) |

An error carried by a non-`Allow` result is not ignored: when the decision
reaches the `AuthorizationConditionsEnforcer`, a `Deny` with an error is
answered with HTTP 500, not 403, and so is a `NoOpinion` with an error unless a
later authorizer in the union allows or denies the request. A true Deny or NoOpinion condition returns no
error, so that a definite denial is a 403. Errors from conditions evaluated
before the first true condition are dropped, since the list would be
incomplete.

> **TODO(decision D-3):** How condition evaluation errors surface is open. Today a Deny-effect error gives `Deny` + error and a NoOpinion- or Allow-effect error gives `NoOpinion` + error, and the enforcer turns a carried error into a 500. Options: ignore Allow-effect errors (the original proposal), keep surfacing them, or introduce a non-fatal error class that is logged but yields 403.

<!-- image needs redraw: shows per-condition effect and 'Allow errors ignored' from the original design -->
![How a decision is computed from an evaluated ConditionsMap](images/conditionsmap-evaluation.png)

One subtle detail of partial evaluation is the short-circuiting of operators
such as `&&` and `||`, especially with regard to errors. `false && <residual>`
can be simplified to `false`. However, `<residual> && false` is either `false`
or `<error>`, if evaluating `<residual>` can produce an error. Thus `&&` and
`||` are **not** commutative.

An authorizer *should* only return conditions that *could* contribute to an
`Allow`; returning a map that can only evaluate to `NoOpinion` or `Deny` wastes
resources. Concretely, the authorizer should not return Allow conditions of the
form `<residual> && false`, as such conditions are either `false` or `<error>`,
and never contribute to an `Allow`. The same pruning cannot be done for Deny or
NoOpinion conditions, because an evaluation error there fails closed to `Deny`
or `NoOpinion`.

### Computing a concrete decision from a conditional authorization chain

A single `ConditionsMap` evaluates, together with the `ConditionsData`, into the
decision the authorizer would have returned directly had it had access to that
data. Next are the semantics of several authorizers chained together in the
[union](https://pkg.go.dev/k8s.io/apiserver/pkg/authorization/union)
authorizer (`union.New(...NamedAuthorizer)`, where each sub-authorizer has a
non-empty name that is unique within the union; a name that is not a DNS-1123
subdomain is rejected at run time by the decision builder, which then fails the
decision closed).

The semantics of `Allow`, `Deny` and `NoOpinion` do not change. A `NoOpinion`
is skipped (even if it carries an error) and the next authorizer is consulted,
so safety-critical errors must be turned into `Deny` if failing closed is
required. A chain with the prefix `NoOpinion, …, NoOpinion, Allow` still
returns a concrete `Allow`, and `NoOpinion, …, NoOpinion, Deny` returns `Deny`.

**At authorization time the union is eager.** `ConditionsAwareAuthorize` calls
each sub-authorizer's `ConditionsAwareAuthorize` in order and adds every answer
to a `ConditionsAwareDecisionUnion` builder under the sub-authorizer's name. It
stops at the first answer that contains an unconditional `Allow` or `Deny` leaf;
later authorizers are not called. The builder then normalises the result:

- If exactly one outcome is possible, the union folds into that unconditional
  decision. For example, a map that can only evaluate to `Deny` or `NoOpinion`,
  followed by a concrete `Deny`, folds to `Deny`[^5]; a chain of `NoOpinion`s
  folds to `NoOpinion`.
- Otherwise the result is a `Union` decision. Its `PossibleDecisions()` is the
  union of its leaves' possible outcomes, without `NoOpinion` once a leaf is an
  unconditional `Allow` or `Deny`. For example, a map that can only evaluate to
  `Deny` or `NoOpinion`, followed by a concrete `Allow`, is a union whose possible
  outcomes are `{Allow, Deny}`: if the deny conditions are all false, the first
  authorizer has no opinion and the second allows the request.
- An empty, duplicate or invalid sub-authorizer name fails closed to the union's
  `FailureDecision()`.

[^5]: Because `Deny`-or-`NoOpinion` followed by `Deny` is folded into `Deny`
directly, the audit log records that one of the authorizers (in this case, the
latter) denied it, not necessarily the first one.

The DRA AdminAccess feature is a good example of a feature that could be
modelled as an authorizer early in the chain that returns `NoOpinion` for most
requests, and a map with only Deny conditions for some requests (namely,
creates and updates of `ResourceClaim(Template)s`). In contrast to
`ValidatingAdmissionPolicy`, an authorizer does not need to allow for its
policies to be deleted. In contrast to the existing DRA AdminAccess
implementation at the storage layer, the condition shows up in
`SubjectAccessReviews`.

**At evaluation time the union is lazy.** `EvaluateConditions` walks the
union's leaves in order: an `Allow` or `Deny` leaf is returned as is; a
`NoOpinion` leaf contributes its reason and error and the walk continues; a
`ConditionsMap` or nested `Union` leaf is routed by name to the sub-authorizer
that produced it, whose `EvaluateConditions` returns an unconditional decision.
If that decision is not in the leaf's `PossibleDecisions()`, the union replaces
it with the leaf's `FailureDecision()` and an error. The first `Allow` or `Deny`
ends the walk; if every leaf is `NoOpinion`, the result is `NoOpinion` with the
leaves' reasons (each prefixed with `<authorizer name>: `) and errors
aggregated. Because the walk stops at the first leaf that evaluates to `Allow`
or `Deny`, and every leaf is guarded to its possible outcomes, the two-phase
result equals what a single-phase chain would have returned.

**The conditions-aware authorization filter.** Among the request filters, only the new filter
`WithConditionsAwareAuthorization` in `k8s.io/apiserver/pkg/endpoints/filters`
asks for conditional decisions (the `SubjectAccessReview` registries also return
them to opted-in clients);
the existing `WithAuthorization` filter keeps its signature and takes an
`authorizer.UnconditionalAuthorizer`:

```go
// ConditionalAuthorizationRequestClassifier is a function that returns true if a request with the given attributes supports conditional authorization.
// If the function returns true, it MUST guarantee that there is some conditions enforcement later in the request handler chain.
type ConditionalAuthorizationRequestClassifier func(attrs authorizer.Attributes) bool

func WithConditionsAwareAuthorization(hhandler http.Handler, auth authorizer.Authorizer, s runtime.NegotiatedSerializer, conditionalAuthzClassifier ConditionalAuthorizationRequestClassifier) (http.Handler, error)
```

The server installs this filter only when the `ConditionalAuthorization` feature
gate is on, a classifier is configured, and the `AuthorizationConditionsEnforcer`
admission plugin is enabled; otherwise it installs `WithAuthorization` (see
[Feature availability and version skew](#feature-availability-and-version-skew)).
Per request, the filter:

1. Calls `ConditionsAwareAuthorize` if the classifier returns true for the
   request's attributes, and the legacy `Authorize` otherwise. A non-classified
   request therefore always gets an unconditional decision.
2. Stores the decision in the request context together with the authorizer
   that produced it (`request.WithConditionallyAuthorizedDecision(ctx, authorizer, decision)`,
   read back with `request.ConditionallyAuthorizedDecisionFrom(ctx)`), so that
   admission can call the same authorizer back.
3. On `Allow`, proceeds. On a conditional decision whose `PossibleDecisions()`
   contains `Allow`, adds the audit annotation
   `authorization.k8s.io/is-conditional-decision=true` and proceeds; the request
   body is decoded and admission runs. Otherwise it answers 500 if the decision
   carries an error, and 403 if not.

With the gate on, the legacy `WithAuthorization` filter also stores an `Allow`
decision in the context, so that the enforcer works with either filter.

The legacy `Authorize` path never asks for conditions: a webhook authorizer
called through `Authorize` does not advertise conditional decision types to its
webhook. If a webhook answers with a conditional decision anyway, this is a
protocol violation: `Authorize` returns the decision's `FailureDecision()` plus
an error. The filter answers HTTP 500 if that non-`Allow` result with an error is
final; if `FailureDecision()` is `NoOpinion`, the union continues, and a later
`Allow` admits the request while a later `Deny` gives that authorizer's own
result (normally a 403). A conditional decision on the
conditions-aware path that cannot become `Allow` gets a 403 whose reason is
empty. `ConditionsAwareDecision.UnconditionalPartsOrFailClosed`, which would
produce a descriptive 403, has no production caller.

> **TODO(decision D-2):** The fold-down for conditions-unaware consumers is open. Today a protocol violation on the legacy path is a 500, and a conditional decision that cannot reach `Allow` at the conditions-aware filter is a reasonless 403. Options: keep the 500, use a 403 everywhere, or split (500 for the protocol violation, descriptive 403 at the filter).

**Which requests kube-apiserver classifies as conditional.** The kube-apiserver classifier returns true when all of the following hold:

- the request is a resource request;
- the verb is `create`, `update`, `patch`, `delete` or `deletecollection`, i.e.
  one for which admission runs;
- the GroupResource is not excluded from admission (for example
  `subjectaccessreviews`, `localsubjectaccessreviews` and `tokenreviews`).

Connect requests that arrive as `POST` (verb `create`, e.g. `create pods/exec`)
are therefore classified conditional, and the enforcer evaluates their
conditions. Connect requests that arrive as `GET` (e.g. `get pods/exec`) are
not classified and are authorized unconditionally. Other `get` requests are not
covered by admission either (`get pods/log` is an example), so the classifier
cannot rely on the verb alone. A literal `*` in the resource or name path
segment is not excluded: it is parsed as an ordinary resource request that goes
through admission.

The classifier does not check whether the resource is served by kube-apiserver
itself. Writes to API groups served by an aggregated API server are classified
conditional, so a conditional decision can pass kube-apiserver's filter. The
proxy to the aggregated server performs no condition enforcement. The
aggregated server re-authorizes the request through its delegating webhook
authorizer, which calls only `Authorize`, so a conditional answer from
kube-apiserver fails closed there. Aggregated API servers get no classifier and
always use the legacy filter. Support for conditions in aggregated API servers
is a Beta goal (see [Technical Requirements](#technical-requirements)).

> **TODO(decision D-1):** How kube-apiserver handles writes to aggregated API groups is open. Today they are classified conditional, the proxy enforces nothing, and the aggregated server re-authorizes unconditionally and fails closed. Options: classify them as not conditional, refuse them unless the decision is an unconditional `Allow`, or implement the pass-through model in which the aggregated server enforces the conditions.

A diagram to summarize how the decisions of an authorizer chain are combined:

![How various authorizer chain decisions are computed into one](images/authorizer-chain-computation.png)

### `AuthorizationConditionsEnforcer` admission controller

`AuthorizationConditionsEnforcer`
(`k8s.io/apiserver/pkg/admission/plugin/authorizer/conditionsenforcer`) is a
validating admission plugin that evaluates the conditional decision stored in
the request context and enforces the result. It is on by default in
kube-apiserver and is inert when the `ConditionalAuthorization` feature gate is
off (`Handles` returns false).

If the feature gate is on but the plugin is disabled, the API server still
starts. It installs the legacy `WithAuthorization` filter instead of
`WithConditionsAwareAuthorization` and logs a warning. The legacy filter calls
only `Authorize`, so no conditional decision can reach admission, and
enforcement is effectively off; `SubjectAccessReview`, `SelfSubjectAccessReview`
and `LocalSubjectAccessReview` still return conditional decisions to opted-in
clients. This keeps the invariant that a request classified
as conditional can only leave the authorization filter without an `Allow` if
the enforcer is in the admission chain.

The filter and the enforcer must observe the same feature-gate state, so that
the feature is never enabled without enforcement.

*Alpha status (v1.38): not yet implemented; see Beta criteria.* The filter
selection reads the process-global feature gate, while the enforcer reads the
feature gate injected at admission initialization; in kube-apiserver both are
the same gate, but nothing enforces that they agree.

The enforcer operates on the fully-mutated request object, like other validating
admission plugins, by design. In kube-apiserver's plugin order it runs after
all mutating plugins (including MutatingAdmissionPolicy and
MutatingAdmissionWebhook), after every built-in validating plugin and after
ValidatingAdmissionPolicy, and before ValidatingAdmissionWebhook,
ResourceQuota and AlwaysDeny. The generic apiserver's recommended order places
it the same way relative to the policy and webhook plugins. Running after
ValidatingAdmissionPolicy avoids calling conditions-review webhooks for
requests that VAP rejects anyway.

> **TODO(decision D-6):** The enforcer's position is open. Today it runs after mutating admission, all built-in validators and VAP. Options: keep this position, document it and add a side-effect guard; make it the first validating plugin; or evaluate the conditions before mutating admission.

For each admission invocation, the enforcer:

| Context decision | Behaviour |
|---|---|
| none in the context | returns an error, guarding against a context detached between the filter and admission |
| `Allow` | admits; the filter already wrote the audit annotations |
| `Deny`, `NoOpinion`, or a conditional decision that cannot become `Allow` | HTTP 500: such a decision should have been rejected by the filter |
| `ConditionsMap` or `Union` | calls the stored authorizer's `EvaluateConditions` with `admission.NewVersionedAttributes(a, a.GetKind(), o)`, so both the object and the old object are in the external version of `GetKind()` |

The evaluated decision is guarded to the stored decision's
`PossibleDecisions()`: an impossible result becomes `Deny` with reason `failed
closed` and an error. Then, matching the filter:

- `Allow`: admits, and writes the `authorization.k8s.io/decision` and
  `authorization.k8s.io/reason` audit annotations;
- otherwise, if there is an error: HTTP 500;
- otherwise (`Deny` or `NoOpinion`): HTTP 403 with the evaluation's reason.

Conditions are evaluated once per admission invocation. A `deletecollection`
request runs delete admission once per object, so its conditions are evaluated
per object. Retries inside the storage layer may run validating admission, and
thus the evaluation, more than once. The audit annotations reflect the final
decision of the request.

*Alpha status (v1.38): not yet implemented; see Beta criteria.* Audit
annotations are first-writer-wins, so when the enforcer runs several times for
one request (deletecollection, retries) the annotation records the first
evaluation, and a request that is ultimately denied can be audited as allowed.

A conditional `delete` must not complete without the enforcer having evaluated
its conditions.

*Alpha status (v1.38): not yet implemented; see Beta criteria.* With the
`AllowUnsafeMalformedObjectDeletion` feature gate and
`ignoreStoreReadErrorWithClusterBreakingPotential`, the unsafe corrupt-object
deleter skips admission validation, so a conditionally authorized delete of a
corrupt object completes without the enforcer.

> **TODO(decision D-1):** Whether the unsafe corrupt-object delete must fail closed for a conditional decision in the context, alongside the aggregated-API handling above. Today it skips admission and hence the enforcer. Options: fail closed unless the decision is an unconditional `Allow`, or route it through the enforcer.

#### Admission runs before authorization is final

Because the enforcer runs late in the validating phase, part of admission runs
for a conditionally authorized request before its authorization is final.
Policy and webhook authors must account for the following:

- Mutating admission (MutatingAdmissionPolicy, MutatingAdmissionWebhook), the
  built-in validating plugins and ValidatingAdmissionPolicy see, and may log or
  act on, requests that the authorizer will deny. Webhook side effects happen
  before the authorization decision is final.
- An admission rejection earlier in the chain can disclose policy outcomes to a
  user who would not have been authorized.
- Conditions are evaluated against the post-mutation object, so mutation by
  other plugins can make a request satisfy or fail its conditions.
- ValidatingAdmissionWebhook and ResourceQuota run after the enforcer, so they
  see only requests that are authorized.

### Changes to `(Self)SubjectAccessReview`

One of the core goals of this KEP is to make it easier for users subject to
authorization policies that span authorization and admission to understand what
policies they are subject to. The conditions are therefore returned in
`SubjectAccessReview`, `SelfSubjectAccessReview` and `LocalSubjectAccessReview`
(together: SAR) responses, to clients that opt in. Two details shape the API:

- The same request might be subject to multiple conditional authorizers in the
  authorizer chain. If two authorizers in a chain both return a `ConditionsMap`,
  the first one has precedence over the second, so the two maps cannot be merged.
  The SAR response must retain the ordering of the authorizers' decisions, so that
  the user (and the evaluator) can reason about them.
- Consider a two-authorizer chain, where the first returns a `ConditionsMap` and
  the second `Allow`. The `ConditionsMap` could evaluate to `Deny` (if it has deny
  conditions), so the structure must be able to model both conditional and
  unconditional decisions in the same ordered list.

Both are covered by modelling a decision as a tree: `ConditionsAwareDecision` is a
discriminated union whose leaves are `Allow`, `Deny`, `NoOpinion` or
`ConditionsMap`, and whose internal nodes are `Union`s of named sub-decisions,
visited in depth-first order.

The client opts in through a new `spec.authorizationOptions` field, present on
`SubjectAccessReviewSpec` (used by `SubjectAccessReview` and
`LocalSubjectAccessReview`) and on `SelfSubjectAccessReviewSpec`:

```go
type SubjectAccessReviewSpec struct {
	// ... resourceAttributes, nonResourceAttributes, user, groups, extra, uid as before

	// authorizationOptions contains options for specifying the client's authorization abilities.
	// If unset, only unconditional authorization is supported, for backwards-compatibility.
	// Requires the ConditionalAuthorization feature to be enabled.
	// +optional
	// +featureGate=ConditionalAuthorization
	// +k8s:ifEnabled("ConditionalAuthorization")=+k8s:optional
	// +k8s:ifDisabled("ConditionalAuthorization")=+k8s:forbidden
	AuthorizationOptions *AuthorizationOptions `json:"authorizationOptions,omitempty" protobuf:"bytes,7,opt,name=authorizationOptions"`
}

type SelfSubjectAccessReviewSpec struct {
	// ... resourceAttributes, nonResourceAttributes as before

	// authorizationOptions contains options for specifying the client's authorization abilities.
	// If unset, only unconditional authorization is supported, for backwards-compatibility.
	// Requires the ConditionalAuthorization feature to be enabled.
	// +optional
	// +featureGate=ConditionalAuthorization
	// +k8s:ifEnabled("ConditionalAuthorization")=+k8s:optional
	// +k8s:ifDisabled("ConditionalAuthorization")=+k8s:forbidden
	AuthorizationOptions *AuthorizationOptions `json:"authorizationOptions,omitempty" protobuf:"bytes,3,opt,name=authorizationOptions"`
}

// AuthorizationOptions contains options for specifying the client's authorization abilities.
type AuthorizationOptions struct {
	// handledDecisionTypes specifies what decision types the client can handle in the context it is in.
	// Currently valid values are:
	// - [Allow, Deny, NoOpinion] (for conditions-unaware clients) or
	// - [Allow, Deny, NoOpinion, ConditionsMap, Union, ...] (for conditions-aware clients)
	// If the authorizer would like to return conditions, but the client does not opt in to handle those here,
	//   the authorizer must fail closed to a safe unconditional decision
	//   (Deny if any Deny conditions were present, otherwise NoOpinion).
	// Order does not matter in this slice; set semantics should be used.
	// The server does not reject unrecognized decision types, but focuses on whether the client
	// supports a mode that the server does. All clients must support "classic", conditions-unaware authorization.
	// +listType=set
	// +k8s:listType=set
	// +k8s:required
	// +required
	// +k8s:eachVal=+k8s:opaqueType
	// +k8s:maxItems=32
	HandledDecisionTypes []ConditionsAwareDecisionType `json:"handledDecisionTypes" protobuf:"bytes,1,rep,name=handledDecisionTypes"`
}
```

The `SubjectAccessReviewStatus` gains one field, and the documentation of
`allowed` and `denied` is updated to account for it:

```go
// SubjectAccessReviewStatus
type SubjectAccessReviewStatus struct {
	// allowed is true if the action would be allowed, false otherwise.
	// allowed=true is mutually exclusive with denied=true and conditionalDecision != nil.
	// +optional
	Allowed bool `json:"allowed" protobuf:"varint,1,opt,name=allowed"`
	// denied is optional. True if the action would be denied, otherwise false
	// If allowed is false, denied is false, and conditionalDecision is unset,
	// then the authorizer has no opinion on whether to authorize the action.
	// denied=true is mutually exclusive with allowed=true and conditionalDecision != nil.
	// +optional
	Denied bool `json:"denied,omitempty" protobuf:"varint,4,opt,name=denied"`
	// reason is optional.  It indicates why a request was allowed or denied.
	// +optional
	Reason string `json:"reason,omitempty" protobuf:"bytes,2,opt,name=reason"`
	// evaluationError is an indication that some error occurred during the authorization check.
	// It is entirely possible to get an error and be able to continue determine authorization status in spite of it.
	// For instance, RBAC can be missing a role, but enough roles are still present and bound to reason about the request.
	// +optional
	EvaluationError string `json:"evaluationError,omitempty" protobuf:"bytes,3,opt,name=evaluationError"`

	// conditionalDecision represents a conditional decision returned by the authorizer.
	// When conditionalDecision is set, allowed, denied, reason and evaluationError must have their zero values.
	// The top-level decision type should be ConditionsAwareDecisionTypeConditionsMap or
	// ConditionsAwareDecisionTypeUnion, as Allow/Deny/NoOpinion decisions can be represented
	// with SubjectAccessReviewStatus.Allowed and SubjectAccessReviewStatus.Denied alone.
	// May only be set if spec.authorizationOptions.handledDecisionTypes includes `ConditionsMap` and `Union`.
	// Requires the ConditionalAuthorization feature to be enabled.
	// +optional
	// +featureGate=ConditionalAuthorization
	// +k8s:ifEnabled("ConditionalAuthorization")=+k8s:optional
	// +k8s:ifDisabled("ConditionalAuthorization")=+k8s:forbidden
	ConditionalDecision *ConditionsAwareDecision `json:"conditionalDecision,omitempty" protobuf:"bytes,5,opt,name=conditionalDecision"`
}
```

The decision tree and condition types, all in `authorization.k8s.io/v1`:

```go
// Condition represents a single authorization condition to be evaluated against
// data available later in the request chain, e.g. objects available in admission.
type Condition struct {
	// id uniquely identifies this condition within the scope of the authorizer
	// that authored it and ConditionsMap it is part of. Validated as a Kubernetes label key.
	// Any domain of form *.k8s.io or *.kubernetes.io is reserved for Kubernetes use.
	// +k8s:required
	// +k8s:format=k8s-prefixed-label-key
	// +required
	ID string `json:"id" protobuf:"bytes,1,opt,name=id"`

	// condition returns a string encoding of the condition to be evaluated.
	// It is a pure, deterministic function from ConditionsData to a boolean (or error).
	// Might or might not be human-readable.
	// Optional, if the ID alone is enough for the authorizer to know how to evaluate the condition.
	// +k8s:maxBytes=10240
	// +k8s:optional
	// +optional
	Condition string `json:"condition,omitempty" protobuf:"bytes,2,opt,name=condition"`

	// type describes the type of the condition, if there are multiple possibilities.
	// Should be formatted as a Kubernetes label key.
	// Any domain of form *.k8s.io or *.kubernetes.io is reserved for Kubernetes use.
	// authorizer.kubernetes.io/cel is a conditions type for CEL, handled by kube-apiserver.
	// Optional. Can be omitted if the authorizer already knows how to evaluate the condition.
	// +k8s:format=k8s-prefixed-label-key
	// +k8s:optional
	// +optional
	Type string `json:"type,omitempty" protobuf:"bytes,3,opt,name=type"`

	// description is an optional human-friendly description that can be shown
	// as an error message or for debugging. Optional.
	// +k8s:maxBytes=1024
	// +k8s:optional
	// +optional
	Description string `json:"description,omitempty" protobuf:"bytes,4,opt,name=description"`
}

// ConditionsMap represents a map of conditions, keyed by ID across all conditions, across
// all effects. The ConditionsMap must have at least one Allow condition or at least one
// Deny condition. It cannot contain more than 128 conditions in total. The conditions are evaluated
// against data available later, to determine whether the authorizer that authored the conditions
// allows or denies the request.
// If all conditions in the map evaluate to false, the final decision must be NoOpinion.
type ConditionsMap struct {
	// denyConditions contains the conditions with Deny effect. If any such condition evaluates to
	// true or error, the ConditionsMap as a whole must evaluate to Deny.
	// +listType=map
	// +listMapKey=id
	// +k8s:listType=map
	// +k8s:listMapKey=id
	// +k8s:maxItems=128
	// +k8s:optional
	// +optional
	DenyConditions []Condition `json:"denyConditions,omitempty" protobuf:"bytes,1,rep,name=denyConditions"`

	// noOpinionConditions contains the conditions with NoOpinion effect. If any such condition evaluates to
	// true or error, the ConditionsMap as a whole must evaluate to NoOpinion.
	// +listType=map
	// +listMapKey=id
	// +k8s:listType=map
	// +k8s:listMapKey=id
	// +k8s:maxItems=128
	// +k8s:optional
	// +optional
	NoOpinionConditions []Condition `json:"noOpinionConditions,omitempty" protobuf:"bytes,2,rep,name=noOpinionConditions"`

	// allowConditions contains the conditions with Allow effect. If any such condition evaluates to
	// true, the ConditionsMap as a whole must evaluate to Allow.
	// +listType=map
	// +listMapKey=id
	// +k8s:listType=map
	// +k8s:listMapKey=id
	// +k8s:maxItems=128
	// +k8s:optional
	// +optional
	AllowConditions []Condition `json:"allowConditions,omitempty" protobuf:"bytes,3,rep,name=allowConditions"`
}

// ConditionsAwareDecisionType is an enum representing what kind of authorization decision
// the ConditionsAwareDecision represents.
// +k8s:enum
type ConditionsAwareDecisionType string

const (
	// ConditionsAwareDecisionTypeDeny represents an unconditional Deny authorizer decision.
	ConditionsAwareDecisionTypeDeny ConditionsAwareDecisionType = "Deny"

	// ConditionsAwareDecisionTypeAllow represents an unconditional Allow authorizer decision.
	ConditionsAwareDecisionTypeAllow ConditionsAwareDecisionType = "Allow"

	// ConditionsAwareDecisionTypeNoOpinion represents an unconditional NoOpinion authorizer decision,
	// which means that the authorizer does not have a specific opinion on whether the request
	// should be allowed or denied, and thus can other authorizers later in the union have their say.
	ConditionsAwareDecisionTypeNoOpinion ConditionsAwareDecisionType = "NoOpinion"

	// ConditionsAwareDecisionTypeConditionsMap represents an authorizer decision that is dependent
	// on request data available later in the request chain, and thus at this stage conditional.
	ConditionsAwareDecisionTypeConditionsMap ConditionsAwareDecisionType = "ConditionsMap"

	// ConditionsAwareDecisionTypeUnion is a decision type whose final decision is computed by
	// an ordered list of sub-authorizers, with their individual decisions. A decision can thus
	// be represented as a tree, with Union decisions being internal nodes, and
	// Deny/Allow/NoOpinion/ConditionsMap decisions being leaf nodes, which are visited in depth-first order.
	ConditionsAwareDecisionTypeUnion ConditionsAwareDecisionType = "Union"
)

// ConditionsAwareDecision represents one authorizer's decision. It is an enum type,
// with variants described in ConditionsAwareDecisionType, plus a reason and error.
type ConditionsAwareDecision struct {
	// type describes the type of the decision, and acts as an enum discriminator.
	// +k8s:unionDiscriminator
	// +k8s:required
	// +required
	Type ConditionsAwareDecisionType `json:"type" protobuf:"bytes,1,opt,name=type,casttype=ConditionsAwareDecisionType"`

	// deny represents an unconditional Deny decision.
	// Must be non-null when type == "Deny", otherwise this field must be unset.
	// +k8s:unionMember
	// +k8s:optional
	// +optional
	Deny *UnconditionalDecision `json:"deny,omitempty" protobuf:"bytes,2,opt,name=deny"`

	// noOpinion represents an unconditional NoOpinion decision.
	// Must be non-null when type == "NoOpinion", otherwise this field must be unset.
	// +k8s:unionMember
	// +k8s:optional
	// +optional
	NoOpinion *UnconditionalDecision `json:"noOpinion,omitempty" protobuf:"bytes,3,opt,name=noOpinion"`

	// allow represents an unconditional Allow decision.
	// Must be non-null when type == "Allow", otherwise this field must be unset.
	// +k8s:unionMember
	// +k8s:optional
	// +optional
	Allow *UnconditionalDecision `json:"allow,omitempty" protobuf:"bytes,4,opt,name=allow"`

	// conditionsMap represents a conditional decision, modelled as a map of conditions.
	// Must be non-null when type == "ConditionsMap", otherwise this field must be unset.
	// +k8s:unionMember
	// +k8s:optional
	// +optional
	ConditionsMap *ConditionsMap `json:"conditionsMap,omitempty" protobuf:"bytes,5,opt,name=conditionsMap"`

	// union forms an ordered tree of decisions, where the union decision is represented by
	// an internal node, and all other decision types are leaf nodes. During evaluation, the
	// leaf decisions are evaluated in depth-first order, until an Allow or Deny decision is found.
	// The order of the decisions should match the order of the authorizers in the union authorizer
	// for interpretability, but the authorizerName is the map key.
	// At least one of the leaves must be of type ConditionsMap, as otherwise the union could be trivially
	// reduced to just a single Allow/Deny/NoOpinion.
	//
	// Must have at least one element when type == "Union", otherwise this field must be unset.
	//
	// +k8s:unionMember
	// +k8s:optional
	// +optional
	// +k8s:listType=map
	// +k8s:listMapKey=authorizerName
	// +listType=map
	// +listMapKey=authorizerName
	Union []NamedConditionsAwareDecision `json:"union,omitempty" protobuf:"bytes,6,rep,name=union"`
}

// NamedConditionsAwareDecision is a named ConditionsAwareDecision, returned by a unioned authorizer.
type NamedConditionsAwareDecision struct {
	// authorizerName details the name of the authorizer that authored the condition, such that
	// the right Decision can be paired with the right authorizer when evaluating the conditions,
	// even across API server replicas. The name must be stable over time.
	// This name must be unique within a given union authorizer, not necessarily globally.
	// +required
	// +k8s:required
	// +k8s:format=k8s-long-name
	AuthorizerName string `json:"authorizerName" protobuf:"bytes,1,opt,name=authorizerName"`

	// decision carries the inner decision returned from the authorizer.
	// +required
	Decision ConditionsAwareDecision `json:"decision" protobuf:"bytes,2,opt,name=decision"`
}

// UnconditionalDecision represents the data associated with an unconditional decision.
type UnconditionalDecision struct {
	// reason is optional. It indicates why a request was allowed or denied.
	// +k8s:optional
	// +optional
	Reason string `json:"reason,omitempty" protobuf:"bytes,1,opt,name=reason"`

	// evaluationError is an indication that some error occurred during the authorization check.
	// It is entirely possible to get an error and be able to continue determine authorization status in spite of it.
	// For instance, RBAC can be missing a role, but enough roles are still present and bound to reason about the request.
	// +k8s:optional
	// +optional
	EvaluationError string `json:"evaluationError,omitempty" protobuf:"bytes,2,opt,name=evaluationError"`
}
```

There is no stored failure mode, per-condition effect or per-map condition type:
the effect of a condition is the list it is in, the type is per condition, and the
fail-closed decision is derived from the tree (`FailureDecision()`: `Deny` if
`Deny` is a possible outcome, otherwise `NoOpinion`).

**Opting in.** `handledDecisionTypes` has superset semantics, implemented by
`k8s.io/api/authorization/v1.SupportsConditionalAuthorization` and
`SupportsUnconditionalAuthorization`:

- unset `authorizationOptions` means `{Allow, Deny, NoOpinion}`, i.e. the
  conditions-unaware behaviour of 1.37;
- a set that is a superset of `{Allow, Deny, NoOpinion, ConditionsMap, Union}`
  makes the client conditions-aware;
- any other superset of `{Allow, Deny, NoOpinion}` is conditions-unaware;
  unrecognized values are ignored;
- a set that is not a superset of `{Allow, Deny, NoOpinion}` is rejected by
  validation (`set must at least contain {Allow, Deny, NoOpinion}`); an empty
  list or more than 32 items is rejected by declarative validation. The
  registries additionally answer `400 Bad Request` if the options resolve to
  neither mode, which validation makes unreachable in practice.

**Server behaviour.** The `SubjectAccessReview`, `SelfSubjectAccessReview` and
`LocalSubjectAccessReview` registries in kube-apiserver behave identically:

1. `status` is cleared before validation, so a client-supplied status is ignored
   (as in 1.37) and the new status validation rules cannot reject old clients.
2. If the `ConditionalAuthorization` feature gate is off, `spec.authorizationOptions`
   is cleared, and the request takes the conditions-unaware path even if both the
   client and the authorizer support conditions. With the gate off, declarative
   validation forbids both `spec.authorizationOptions` and `status.conditionalDecision`.
3. A conditions-aware client gets `ConditionsAwareAuthorize` from the root
   authorizer. An unconditional result is written to `allowed`/`denied`/`reason`/
   `evaluationError` exactly as before. A `ConditionsMap` or `Union` result is
   written to `status.conditionalDecision` with all other status fields empty. If
   encoding the decision fails, the status is `FailureDecision()` (`denied=true`
   iff it is `Deny`) with reason `failed closed` and the error in
   `evaluationError`.
4. Every other client gets `Authorize`, unchanged from 1.37.

The registries return conditions for any verb and resource to an opted-in client;
whether the conditions would be enforced for a real request is decided by the
request classifier of the authorization filter (see Feature availability and
version skew).

**Validation of a returned status** (`k8s.io/apiserver/pkg/apis/authorization/validation.ValidateSubjectAccessReviewStatus`,
applied by the webhook authorizer on its conditions-aware path to the statuses it
receives; the legacy `Authorize` path does not validate the status):

- `allowed` and `denied` are mutually exclusive;
- `conditionalDecision` may only be set if the request's `authorizationOptions`
  made the client conditions-aware;
- when set, its top-level `type` must be `ConditionsMap` or `Union` (an
  unconditional decision must use `allowed`/`denied`), and `allowed`, `denied`,
  `reason` and `evaluationError` must be empty;
- the discriminated-union shape, the condition ID/type formats and sizes, and the
  per-list limits are enforced declaratively from the tags above;
- `metadata` must be empty (for `LocalSubjectAccessReview`: empty except for
  `namespace`).

**Old clients.** A client that does not send `authorizationOptions` never receives
`conditionalDecision`. `authorization.k8s.io/v1beta1` has neither new field; when
an internal status carrying a `conditionalDecision` is converted to `v1beta1`,
the conversion sets `allowed=false` and `denied=true` if the decision's
`FailureDecision()` is `Deny` (`denied=false` if it is `NoOpinion`), and copies a
decode reason or error into `reason`/`evaluationError`.

**Example: a webhook's conditional SAR response (`ConditionsMap`).** The
kube-apiserver webhook authorizer sends this request to a webhook configured
with `conditionsReview` (see next section); the webhook answers with a
`ConditionsMap`:

```yaml
apiVersion: authorization.k8s.io/v1
kind: SubjectAccessReview
spec:
  user: alice
  groups: ["system:authenticated"]
  resourceAttributes:
    verb: create
    version: v1
    resource: configmaps
    namespace: team-a
  authorizationOptions:
    handledDecisionTypes: ["Allow", "ConditionsMap", "Deny", "NoOpinion", "Union"]
status:
  allowed: false
  conditionalDecision:
    type: ConditionsMap
    conditionsMap:
      denyConditions:
      - id: policy.example.com/no-protected-label
        type: authorizer.kubernetes.io/cel
        condition: "has(object.metadata.labels) && 'protected' in object.metadata.labels"
        description: "ConfigMaps labelled 'protected' may not be written"
      allowConditions:
      - id: policy.example.com/owner-is-requester
        type: policy.example.com/rego
        condition: "data.k8s.owner_is_requester"
        description: "The requester must own the ConfigMap"
```

**Example: kube-apiserver's conditional SAR response (`Union`).** A client that
can create `subjectaccessreviews` asks kube-apiserver about the same request. The
root authorizer is a union of `system-privileged-group.authorizer.kubernetes.io`,
the webhook (named `conditional-webhook` in the `AuthorizationConfiguration`) and
`rbac`. Because no leaf is an unconditional `Allow` or `Deny`, every authorizer is
asked and every answer is kept, in chain order:

```yaml
apiVersion: authorization.k8s.io/v1
kind: SubjectAccessReview
spec:
  user: alice
  groups: ["system:authenticated"]
  resourceAttributes:
    verb: create
    version: v1
    resource: configmaps
    namespace: team-a
  authorizationOptions:
    handledDecisionTypes: ["Allow", "ConditionsMap", "Deny", "NoOpinion", "Union"]
status:
  allowed: false
  conditionalDecision:
    type: Union
    union:
    - authorizerName: system-privileged-group.authorizer.kubernetes.io
      decision:
        type: NoOpinion
        noOpinion: {}
    - authorizerName: conditional-webhook
      decision:
        type: ConditionsMap
        conditionsMap:
          denyConditions:
          - id: policy.example.com/no-protected-label
            type: authorizer.kubernetes.io/cel
            condition: "has(object.metadata.labels) && 'protected' in object.metadata.labels"
            description: "ConfigMaps labelled 'protected' may not be written"
          allowConditions:
          - id: policy.example.com/owner-is-requester
            type: policy.example.com/rego
            condition: "data.k8s.owner_is_requester"
            description: "The requester must own the ConfigMap"
    - authorizerName: rbac
      decision:
        type: NoOpinion
        noOpinion: {}
```

**Disclosure.** With the gate on, a client that may create
`subjectaccessreviews` or `localsubjectaccessreviews` and opts in receives the
complete conditions tree of *another* subject: every condition's text and
description, and the names of all authorizers in the chain. A webhook authorizer
cannot restrict this, because the SAR it receives names the subject, not the
caller of the SAR API. The built-in authorizer names
(`*.authorizer.kubernetes.io`) are thereby visible on the wire and must stay
stable. `SelfSubjectAccessReview` only discloses the caller's own conditions. See
Risks and Mitigations.

> **TODO(decision D-7):** Whether SAR and LocalSAR should return another subject's complete conditions tree to any opted-in client. Options: keep and document it; fold the decision to `FailureDecision()` unless the subject equals the requester; or require a separate verb or permission for conditions-aware SAR/LocalSAR.

### Supporting webhooks through the `AuthorizationConditionsReview` API

A webhook authorizer may return a conditional decision in its SAR response: a
`ConditionsMap`, or a `Union` tree (as a composite authorizer such as
kube-apiserver would). The webhook authorizer decodes either into an
`authorizer.ConditionsAwareDecision`.

Unless the API server can evaluate the returned conditions itself (see Built-in
CEL conditions evaluator), it must call the authorizer again once the admission
data is available. For this, a new `AuthorizationConditionsReview` (ACR) type,
similar to `AdmissionReview`, is added in `authorization.k8s.io/v1alpha1`. ACR is
a webhook wire type only: it is registered in the API schemes and in client-go
(`+genclient:onlyVerbs=create`, resource `authorizationconditionsreviews`) and is
validated, but no API server serves it. A webhook authorizer sends it to the
endpoint given by its `conditionsReview` configuration.

```go
// AuthorizationConditionsReview describes a request to evaluate authorization conditions.
type AuthorizationConditionsReview struct {
	metav1.TypeMeta `json:",inline"`
	// metadata is the standard list metadata.
	// In AuthorizationConditionsReview, it must be an empty struct.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata
	// +optional
	// +k8s:opaqueType
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// request describes the attributes for the authorization conditions request.
	// +k8s:optional
	// +optional
	Request *AuthorizationConditionsRequest `json:"request,omitempty" protobuf:"bytes,2,opt,name=request"`
	// response describes the attributes for the authorization conditions response.
	// +k8s:optional
	// +optional
	Response *AuthorizationConditionsResponse `json:"response,omitempty" protobuf:"bytes,3,opt,name=response"`
}

// AuthorizationConditionsRequest describes the authorization conditions request.
type AuthorizationConditionsRequest struct {
	// decision contains the conditional decision the authorizer authored at authorization time.
	// The API server may refine the decision before sending it, by evaluating some of the conditions in-process,
	// e.g. removing conditions that evaluated to false.
	// +required
	Decision authorizationv1.ConditionsAwareDecision `json:"decision" protobuf:"bytes,1,opt,name=decision"`

	// admissionRequest may contain additional information for evaluating the conditions.
	// +k8s:required
	// +required
	AdmissionRequest *admissionv1.AdmissionRequest `json:"admissionRequest,omitempty" protobuf:"bytes,2,opt,name=admissionRequest"`
}

// AuthorizationConditionsResponse describes an authorization conditions response.
type AuthorizationConditionsResponse struct {
	// uid is an identifier for the individual request/response.
	// This must be copied over from request.admissionRequest.uid of the corresponding
	// AuthorizationConditionsReview.
	// It is possible that the same request content (except uid) is sent to the
	// authorizer multiple times.
	// +k8s:required
	// +required
	UID types.UID `json:"uid" protobuf:"bytes,1,opt,name=uid"`

	// decision contains the authorizer's decision after seeing the data.
	// Currently, this must return an unconditional decision, that is, one of {Allow, Deny, NoOpinion}.
	// +required
	Decision authorizationv1.ConditionsAwareDecision `json:"decision" protobuf:"bytes,2,opt,name=decision"`
}
```

Validation (`k8s.io/apiserver/pkg/apis/authorization/validation.ValidateAuthorizationConditionsReview`):
`metadata` must be empty; `request.decision.type` must be `ConditionsMap` or
`Union`; `response.decision.type` must be `Allow`, `Deny` or `NoOpinion` (an
evaluation cannot yield further conditions in v1alpha1); `type`, `uid` and
`admissionRequest` are required. `AuditAnnotations` and `Warnings`, as in
`AdmissionReview`, are deferred to a later version.

**Request.** The webhook authorizer's `EvaluateConditions` receives only the
sub-decision that this webhook authored (the union authorizer routes each leaf to
its authorizer by `authorizerName`). It first refines it with the in-process
evaluator, if one exists, and sends the *refined* decision; the authorizer must
therefore not expect to receive back exactly the decision it issued. The
`admissionRequest` carries a fresh UID per call, the kind, resource and
subresource (also as `requestKind`/`requestResource`/`requestSubResource`), name,
namespace, operation, user info, `object`, `oldObject`, `dryRun` and the operation
options. Objects are sent in the external version of the request's kind; an
object without `apiVersion` and `kind` makes the call fail closed before it is
sent.

**Response checks.** The webhook authorizer accepts the response only if it is
set, passes validation, echoes the request UID in `response.uid`, and its
decision is among the `PossibleDecisions()` of the refined decision that was
sent. Any failure here (transport error, missing response, validation error,
UID mismatch, impossible decision) yields the refined decision's
`FailureDecision()` with reason `failed closed` and the error. The webhook's
`failurePolicy` does not apply to ACR failures. ACR responses are not cached.

**Example ACR request and response**, for the `conditional-webhook` decision of
the SAR example above, on `create configmaps` in `team-a`. The in-process CEL
evaluator found the deny condition false and removed it; the `rego` condition is
unevaluatable in-process and is sent to the webhook:

```yaml
apiVersion: authorization.k8s.io/v1alpha1
kind: AuthorizationConditionsReview
request:
  decision:
    type: ConditionsMap
    conditionsMap:
      allowConditions:
      - id: policy.example.com/owner-is-requester
        type: policy.example.com/rego
        condition: "data.k8s.owner_is_requester"
        description: "The requester must own the ConfigMap"
  admissionRequest:
    uid: 7b3c1f0e-2a4d-4c55-9b0e-5f1f2d9a8c11
    kind: {group: "", version: v1, kind: ConfigMap}
    resource: {group: "", version: v1, resource: configmaps}
    requestKind: {group: "", version: v1, kind: ConfigMap}
    requestResource: {group: "", version: v1, resource: configmaps}
    name: settings
    namespace: team-a
    operation: CREATE
    userInfo:
      username: alice
      groups: ["system:authenticated"]
    object:
      apiVersion: v1
      kind: ConfigMap
      metadata:
        name: settings
        namespace: team-a
        labels:
          owner: alice
      data:
        mode: fast
    oldObject: null
    dryRun: false
    options:
      apiVersion: meta.k8s.io/v1
      kind: CreateOptions
---
apiVersion: authorization.k8s.io/v1alpha1
kind: AuthorizationConditionsReview
response:
  uid: 7b3c1f0e-2a4d-4c55-9b0e-5f1f2d9a8c11
  decision:
    type: Allow
    allow:
      reason: "condition policy.example.com/owner-is-requester is true"
```

**Configuration.** A webhook authorizer opts into conditional authorization with
the new `conditionsReview` stanza of its `AuthorizationConfiguration` entry,
available in `apiserver.config.k8s.io/v1`:

```go
	// conditionsReview defines the configuration for evaluating authorization
	// conditions via AuthorizationConditionsReview. When set, enables
	// conditional authorization support for this webhook authorizer.
	// The conditions review endpoint is reached via the given context
	// within the same kubeconfig file specified in connectionInfo.
	// +optional
	ConditionsReview *ConditionsReviewConfiguration `json:"conditionsReview,omitempty"`
}

// ConditionsReviewConfiguration configures the connection to the conditions
// review endpoint for conditional authorization.
type ConditionsReviewConfiguration struct {
	// version is the API version of AuthorizationConditionsReview to use.
	// Valid values: v1alpha1
	// Required.
	// +required
	Version string `json:"version"`

	// kubeConfigContextName is the name of the context within the webhook's
	// kubeconfig file to use for conditions review requests.
	// Can only be specified when connectionInfo.type = KubeConfigFile.
	// If unset and connectionInfo.type = KubeConfigFile, the default kubeconfig
	// context is used, which means the API server sends both SubjectAccessReview and
	// AuthorizationConditionsReview payloads to the same HTTP endpoint, and the
	// caller must distinguish between these through TypeMeta information.
	// Optional.
	// +optional
	KubeConfigContextName string `json:"kubeConfigContextName,omitempty"`
}
```

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AuthorizationConfiguration
authorizers:
- type: Webhook
  name: conditional-webhook
  webhook:
    timeout: 3s
    subjectAccessReviewVersion: v1
    matchConditionSubjectAccessReviewVersion: v1
    failurePolicy: NoOpinion
    connectionInfo:
      type: KubeConfigFile
      kubeConfigFile: /etc/kubernetes/authz-webhook.kubeconfig
    # New. If unset, the webhook is conditions-unaware.
    conditionsReview:
      version: v1alpha1
      # Optional. If unset, the kubeconfig's current context is used, i.e. the
      # same endpoint receives SubjectAccessReview and
      # AuthorizationConditionsReview, distinguished by apiVersion/kind.
      kubeConfigContextName: authorization-conditions
- type: RBAC
  name: rbac
```

`conditionsReview` is rejected unless the `ConditionalAuthorization` gate is on
and `subjectAccessReviewVersion` is `v1`; `version` is required and only
`v1alpha1` is accepted; `kubeConfigContextName` is forbidden unless
`connectionInfo.type` is `KubeConfigFile`. The timeout of the webhook entry also
applies to ACR calls.

**Webhook authorizer behaviour.**

- *Advertising.* The webhook sends
  `spec.authorizationOptions.handledDecisionTypes` = `[Allow, ConditionsMap, Deny, NoOpinion, Union]`
  only from `ConditionsAwareAuthorize`, and only if it has an ACR client, i.e.
  `conditionsReview` is configured and the gate is on. Otherwise it sends no
  `authorizationOptions`, so a well-behaved webhook answers unconditionally,
  instead of answering with conditions that could then only fail closed.
- *Legacy path (`Authorize`).* No `authorizationOptions` are sent. `allowed` and
  `denied` both true gives `Deny` with an error; `denied` gives `Deny`; an
  unrequested `conditionalDecision` gives the decision's `FailureDecision()`
  **plus an error**; otherwise `allowed`/`NoOpinion` as in 1.37. Through the union
  and the authorization filter, that error becomes a 500 response when the
  fail-closed result is final. If `FailureDecision()` is `NoOpinion`, the union
  continues: a later `Allow` admits the request, and a later `Deny` gives that
  authorizer's own result (normally a 403).

> **TODO(decision D-2):** How a conditions-unaware consumer folds an unrequested or unenforceable conditional answer. Today the webhook's legacy `Authorize` returns `FailureDecision()` plus an error (a 500), the conditions-aware filter answers an Allow-impossible conditional decision with a reasonless 403, and `UnconditionalPartsOrFailClosed` (a descriptive 403) is unused. Options: keep the 500; 403 everywhere; or split (500 for the protocol violation, descriptive 403 at the filter).

- *Conditions-aware path (`ConditionsAwareAuthorize`).* matchConditions are
  evaluated first, as for `Authorize`. A transport error, or a matchCondition
  error, maps to `failurePolicy` (`decisionOnError`: `Deny` or `NoOpinion`, with
  reason `failed closed` and the error). Then: `allowed` and `denied` both true
  gives `Deny` with an error; next, the status is validated as described in the
  previous section, and a validation failure also maps to `failurePolicy`; a valid
  status gives `Deny`, the decoded `conditionalDecision`, `Allow` or `NoOpinion`,
  in that order; an unconditional result carries `evaluationError` as its error. A
  conditional decision that passes validation but that the decoder rejects (an
  empty map, duplicate IDs across lists, more than 128 conditions in total) fails
  closed to its `FailureDecision()` regardless of `failurePolicy`, as described in
  Condition and ConditionsMap data model.
  An explicit `denied=true` from the webhook is final and is never weakened by
  `failurePolicy`.
  *Alpha status (v1.38): not yet implemented; see Beta criteria.* The
  conditions-aware path checks `denied` only together with `allowed` before
  validation, so a `denied=true` status that fails validation (for example,
  together with a `conditionalDecision`) is weakened to `failurePolicy`, which
  may be `NoOpinion`; the legacy path keeps `Deny`.
- *Evaluation (`EvaluateConditions`).* As described above: in-process refinement,
  then an ACR call with the refined decision, failing closed to
  `FailureDecision()`.
- *Caching.* The SAR response cache is keyed by the complete SAR spec. When the
  webhook has a `conditionsReview` client, the conditions-aware path sends
  `authorizationOptions` and the legacy path does not, so the two paths are
  cached separately; without one, both paths send the same spec and share cache
  entries. A conditional status is cached with the authorized TTL, like an
  `Allow`, if the request advertised conditions, and with the unauthorized TTL
  otherwise; it is cached as returned, before validation, and
  is re-validated on every use. Caching all conditions together with the decision
  means evaluation always happens against the policy revision that authored them,
  without the authorizer needing snapshot reads. ACR responses are not cached.

If the API server can evaluate the conditions in-process with a built-in
conditions evaluator (the CEL one, see Built-in CEL conditions evaluator), no ACR
call is needed, as per the following table:

| Webhook calls during phase: | Authorization response not cached | Authorization response cached |
| :---- | :---- | :---- |
| Condition type not supported by the built-in evaluator (or its evaluation errors) | SAR webhook + ACR webhook | ACR webhook |
| Condition type supported | SAR webhook | Neither |

*Alpha status (v1.38): not yet implemented; see Beta criteria.* The in-process
evaluator is built only for webhooks that have `conditionsReview` configured, and
conditional decision types are advertised only when an ACR client exists, so a
webhook whose conditions are all `authorizer.kubernetes.io/cel` still needs an ACR
endpoint configured.

**Generic API servers.** The delegating authorizer of generic (aggregated) API
servers should be conditions-aware only once there is an endpoint that can
evaluate its conditions.
*Alpha status (v1.38): not yet implemented; see Beta criteria.* The delegating
authorizer is wired with an ACR client that posts to
`/apis/authorization.k8s.io/v1alpha1/authorizationconditionsreviews` on
kube-apiserver, which is not served. This is inert today: generic API servers have
no request classifier, so they only call `Authorize`, send no
`authorizationOptions`, and receive an unconditional (folded) answer from
kube-apiserver.

**Future: aggregated API servers.** The intended design for aggregated API
servers is that the aggregated server consults kube-apiserver as a
conditions-aware webhook, receives kube-apiserver's `Union` decision, and has it
evaluated at admission time, with kube-apiserver (or the aggregated server
itself) evaluating each leaf by `authorizerName`. This requires an evaluation
endpoint for ACR (or another transport), a classifier in the aggregated server,
and a decision on what kube-apiserver does with writes it proxies. None of this
exists in v1.38: kube-apiserver classifies writes to aggregated groups as
conditional but does not enforce conditions on proxied requests, and the
aggregated server re-authorizes unconditionally, so a conditionally allowed
request fails closed there.

> **TODO(decision D-1):** How aggregated API servers participate. Today kube-apiserver's classifier marks writes to aggregated groups as conditional, the aggregated server re-authorizes unconditionally (fails closed), the proxy performs no enforcement, and the unsafe corrupt-object delete path skips admission. Options: classify such requests as unconditional; refuse them unless the decision is an unconditional Allow; or implement the pass-through model described above.

### Composite / Union Authorizer Support

Some authorizers, like kube-apiserver itself, do not perform authorization logic
themselves, but delegate the actual decision to an ordered list of named
sub-authorizers. The union authorizer
(`k8s.io/apiserver/pkg/authorization/union`, constructed with
`union.New(...NamedAuthorizer)`) supports conditions through the `Union` variant
of `ConditionsAwareDecision`: an ordered tree whose internal nodes are `Union`
decisions and whose leaves are `Allow`, `Deny`, `NoOpinion` or `ConditionsMap`
decisions. A sub-authorizer may itself return a `Union`, so trees nest.

The union authorizer behaves as follows:

- **Authorization is eager.** `ConditionsAwareAuthorize` calls every
  sub-authorizer in order, adding each decision to a
  `ConditionsAwareDecisionUnion` builder, until a sub-decision contains an
  unconditional `Allow` or `Deny` leaf, or the chain ends. Nothing is deferred:
  the resulting tree holds only already-computed sub-decisions.
- **Unconditional sub-decisions are kept.** A `NoOpinion` sub-decision stays in
  the tree as a `NoOpinion` leaf, with its reason and error, so that the final
  reason and error can be reported. The builder folds the tree into a single
  unconditional decision only when exactly one outcome is possible (for example,
  a chain of only `NoOpinion`s folds to `NoOpinion`).
- **Evaluation is ordered and lazy.** `EvaluateConditions` walks the leaves in
  depth-first order. `NoOpinion` leaves are skipped (their reason and error are
  collected). `ConditionsMap` and `Union` leaves are routed by `authorizerName`
  to the sub-authorizer that authored them. The first `Allow` or `Deny` ends the
  walk. Each routed result is checked against the leaf's `PossibleDecisions()`;
  an impossible result fails closed to the leaf's `FailureDecision()`.
- **Names.** `authorizerName` is unique within one union (one tree level), not
  globally, and must be a DNS-1123 subdomain. `union.New` rejects empty and
  duplicate names at construction; the builder additionally rejects non-DNS-1123
  names and then fails the whole decision closed. Names are visible on the wire
  (in `SubjectAccessReview` status and in `AuthorizationConditionsReview`
  requests), including the built-in names of the form
  `*.authorizer.kubernetes.io`, such as
  `system-privileged-group.authorizer.kubernetes.io`, which kube-apiserver puts
  first in every chain. Names must therefore stay stable across releases and
  replicas.
- **Within a `ConditionsMap`, the first `true` condition of the deciding effect
  short-circuits** (see
  [Computing a concrete decision from a ConditionsMap](#computing-a-concrete-decision-from-a-conditionsmap));
  the order of conditions within a list carries no meaning beyond that, only the
  order of the union's entries does.
- **Bounds.** The tree is bounded by width and depth, and each `ConditionsMap`
  by 128 conditions in total.

*Alpha status (v1.38): not yet implemented; see Beta criteria.* The `union`
list has no maximum length and nesting depth is unbounded; only the per-map
condition limits are enforced.

#### Worked example (single kube-apiserver)

kube-apiserver is configured with a conditional webhook authorizer followed by
RBAC. The webhook has `conditionsReview` set, so it advertises conditional
support and receives the in-process CEL evaluator (see
[Built-in CEL conditions evaluator](#built-in-cel-conditions-evaluator)):

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AuthorizationConfiguration
authorizers:
- type: Webhook
  name: policy-engine
  webhook:
    timeout: 3s
    authorizedTTL: 30s
    unauthorizedTTL: 30s
    subjectAccessReviewVersion: v1   # conditionsReview requires v1
    matchConditionSubjectAccessReviewVersion: v1
    failurePolicy: Deny
    connectionInfo:
      type: KubeConfigFile
      kubeConfigFile: /etc/kubernetes/policy-engine.kubeconfig
    conditionsReview:
      version: v1alpha1
      # Optional. If unset, SubjectAccessReview and AuthorizationConditionsReview
      # are sent to the same endpoint, distinguished by TypeMeta.
      kubeConfigContextName: conditions
- type: RBAC
  name: rbac
```

The resulting top-level union is `system-privileged-group.authorizer.kubernetes.io`,
`policy-engine`, `rbac`.

1. User `alice` sends `POST /apis/apps/v1/namespaces/team-a/deployments`
   (verb `create`). The kube-apiserver classifier marks the request as
   conditional (resource request, admission verb, GroupResource not excluded
   from admission), so `WithConditionsAwareAuthorization` calls
   `ConditionsAwareAuthorize` on the root authorizer.
1. `system-privileged-group.authorizer.kubernetes.io` returns `NoOpinion`.
1. The `policy-engine` webhook receives a `SubjectAccessReview` that opts in to
   conditional decisions:

   ```yaml
   apiVersion: authorization.k8s.io/v1
   kind: SubjectAccessReview
   spec:
     user: alice
     groups: ["dev", "system:authenticated"]
     resourceAttributes:
       namespace: team-a
       verb: create
       group: apps
       version: v1
       resource: deployments
     authorizationOptions:
       handledDecisionTypes: ["Allow", "ConditionsMap", "Deny", "NoOpinion", "Union"]
   ```

   The webhook models two internal tiers, `system` and `user`, and answers with
   a `Union` of two `ConditionsMap`s. The `system` tier uses the built-in CEL
   type; the `user` tier uses a type only the webhook understands:

   ```yaml
   apiVersion: authorization.k8s.io/v1
   kind: SubjectAccessReview
   status:
     allowed: false      # allowed, denied, reason, evaluationError must be zero
     conditionalDecision:
       type: Union
       union:
       - authorizerName: system
         decision:
           type: ConditionsMap
           conditionsMap:
             denyConditions:
             - id: example.com/max-replicas
               type: authorizer.kubernetes.io/cel
               condition: "object.spec.replicas > 10"
               description: "Deployments in team namespaces may have at most 10 replicas"
       - authorizerName: user
         decision:
           type: ConditionsMap
           conditionsMap:
             allowConditions:
             - id: example.com/team-owns-image
               type: example.com/opaque-policy
               condition: "<opaque to the API server>"
   ```

   The webhook validates the status and decodes it. The `system` map can yield
   `{Deny, NoOpinion}`, the `user` map `{Allow, NoOpinion}`, so the webhook's
   decision can yield `{Allow, Deny, NoOpinion}`.
1. The webhook decision contains no unconditional `Allow` or `Deny` leaf, so the
   walk continues eagerly to `rbac`. `alice` has no binding; RBAC returns
   `NoOpinion` with an empty reason. Had RBAC allowed, its `Allow` leaf would
   have ended the walk, and the union would still be conditional (`{Allow, Deny}`),
   because the `policy-engine` Deny condition comes first.
1. The union holds three leaves-or-subtrees. Encoded as kube-apiserver would
   return it in a `SubjectAccessReview` to an opted-in client, it is:

   ```yaml
   type: Union
   union:
   - authorizerName: system-privileged-group.authorizer.kubernetes.io
     decision:
       type: NoOpinion
       noOpinion: {}           # kept as a leaf, with its (here empty) reason and error
   - authorizerName: policy-engine
     decision:
       type: Union
       union:
       - authorizerName: system
         decision: {type: ConditionsMap, conditionsMap: {denyConditions: [...]}}
       - authorizerName: user
         decision: {type: ConditionsMap, conditionsMap: {allowConditions: [...]}}
   - authorizerName: rbac
     decision:
       type: NoOpinion
       noOpinion: {}
   ```

1. `PossibleDecisions()` of the union contains `Allow`, so the filter records
   the audit annotation `authorization.k8s.io/is-conditional-decision: "true"`,
   stores the `(authorizer, decision)` pair in the request context, and lets the
   request proceed: the body is decoded and admission runs. (Had `Allow` been
   impossible, the filter would have answered 403, or 500 if the decision carried
   an error.)
1. After mutating admission, the built-in validators and
   `ValidatingAdmissionPolicy`, the `AuthorizationConditionsEnforcer` builds
   `VersionedAttributes` for `apps/v1` `Deployment` (the post-mutation object)
   and calls `EvaluateConditions` on the stored authorizer with the stored
   decision.
1. The top-level union skips the first `NoOpinion` leaf and routes the
   `policy-engine` subtree to the webhook authorizer.
1. The webhook first evaluates in-process. The `authorizer.kubernetes.io/cel`
   condition `object.spec.replicas > 10` evaluates to `false` for a 3-replica
   Deployment, so the `system` map evaluates to `NoOpinion` ("no conditions
   matched"). The `user` condition has a type the built-in evaluator does not
   handle, so it is unevaluatable and the map stays conditional. The refined
   decision keeps the decided `system` entry as a `NoOpinion` leaf, and can now
   only yield `{Allow, NoOpinion}`.

   Variant: for a 20-replica Deployment the Deny condition is `true`, the
   refined decision is an unconditional `Deny`, the webhook returns it without
   any network call, and the enforcer answers 403 with reason
   `system: {condition "example.com/max-replicas" denied the request with description "…"}`.
1. The refined decision is not unconditional, so the webhook sends an
   `AuthorizationConditionsReview` to the `conditions` context:

   ```yaml
   apiVersion: authorization.k8s.io/v1alpha1
   kind: AuthorizationConditionsReview
   request:
     decision:                 # the refined decision, not the original one
       type: Union
       union:
       - authorizerName: system
         decision:
           type: NoOpinion
           noOpinion:
             reason: no conditions matched
       - authorizerName: user
         decision:
           type: ConditionsMap
           conditionsMap:
             allowConditions:
             - id: example.com/team-owns-image
               type: example.com/opaque-policy
               condition: "<opaque to the API server>"
     admissionRequest:
       uid: 5d2f6c0e-…         # fresh per call
       kind: {group: apps, version: v1, kind: Deployment}
       resource: {group: apps, version: v1, resource: deployments}
       requestKind: {group: apps, version: v1, kind: Deployment}
       requestResource: {group: apps, version: v1, resource: deployments}
       name: web
       namespace: team-a
       operation: CREATE
       userInfo:
         username: alice
         groups: ["dev", "system:authenticated"]
       object: {apiVersion: apps/v1, kind: Deployment, …}   # must carry apiVersion and kind
       oldObject: null
       dryRun: false
       options: {apiVersion: meta.k8s.io/v1, kind: CreateOptions, …}
   ```

1. The webhook evaluates its own condition and answers with an unconditional
   decision, echoing the UID:

   ```yaml
   apiVersion: authorization.k8s.io/v1alpha1
   kind: AuthorizationConditionsReview
   response:
     uid: 5d2f6c0e-…
     decision:
       type: Allow
       allow:
         reason: "team-a owns registry.example.com/team-a/web"
   ```

   kube-apiserver validates the response, checks the UID, and checks that
   `Allow` is in the refined decision's `PossibleDecisions()`. A failure of any
   of these fails closed to the refined decision's `FailureDecision()`.
1. The webhook returns `Allow`; the top-level union stops at it and returns
   `Allow` with the webhook's reason. The enforcer re-checks the result against
   the original decision's `PossibleDecisions()`, records
   `authorization.k8s.io/decision: allow` with the reason, and the request
   continues to `ValidatingAdmissionWebhook`, `ResourceQuota` and storage.

   Variant: had the ACR answered `NoOpinion`, the top-level union would have
   continued to the `rbac` leaf (`NoOpinion`), the result would be `NoOpinion`,
   and the enforcer would answer 403 with the aggregated reason
   `policy-engine: <reason from the ACR response>`.

> **TODO(decision D-4):** NoOpinion reasons aggregated by the union are prefixed with `<authorizerName>: ` (ungated, also on the legacy `Authorize` path) and appear in 403 bodies, while short-circuit Allow/Deny reasons are unprefixed and the conditions-aware fold uses a `name: {reason}` format. Options: ship with a release note, revert the prefix on the legacy path, or gate it.

#### Future: aggregated API servers

The target design extends this to aggregated API servers, where an aggregated
server's first authorizer is a webhook to kube-apiserver, which in turn walks
its own union:

![Directed Acyclic Graph](images/composite-chain.png)

The aggregated server would receive kube-apiserver's `Union` tree in the
`SubjectAccessReview` status, store it in its request context, evaluate the
conditions it can evaluate in-process during its own admission, and ask
kube-apiserver to evaluate the rest, after which evaluation of its own chain
resumes lazily on `NoOpinion`.

None of this works in v1.38 alpha. Aggregated API servers have no conditional
request classifier, so they always use the legacy `WithAuthorization` filter,
and their delegating webhook authorizer only calls `Authorize`: a conditional
answer from kube-apiserver fails closed there. `AuthorizationConditionsReview`
is not served by kube-apiserver. On the kube-apiserver side, the classifier
marks writes to aggregated groups as conditional although kube-apiserver
proxies them and never runs admission for them; the aggregated server
re-authorizes unconditionally and fails closed. Separately, the deletion path
for unsafe corrupt objects skips admission, and therefore the enforcer.

> **TODO(decision D-1):** How aggregated API servers and the unsafe corrupt-object delete interact with conditional decisions is undecided. Options: classify such requests as not conditional, refuse them unless the decision is an unconditional Allow, or implement the pass-through model sketched above.

### Built-in CEL conditions evaluator

*Targeted for v1.38 alpha, PR pending (kubernetes/kubernetes#143024).*

Kubernetes provides one built-in condition type, `authorizer.kubernetes.io/cel`
(`k8s.io/apiserver/pkg/authorization/authorizer.ConditionTypeAuthorizationCEL`).
It re-uses the CEL infrastructure of `ValidatingAdmissionPolicy`, so that an
authorizer can author CEL conditions and let the API server evaluate them
in-process, and so that authors familiar with VAP get the same model. The type
is unversioned.

**Shape.** In-process evaluation is not a global registry and not an argument
of the enforcement point. Each webhook authorizer is constructed with its own
`authorizer.BuiltinConditionsEvaluatorBuilder`:

```go
package authorizer

type BuiltinConditionsEvaluatorBuilder interface {
	// EvaluatorForData returns a BuiltinConditionsEvaluator from the given ConditionsData,
	// in order to initialize an evaluation environment only once.
	// apiServerAuthorizer is the API server's authorizer (not the authorizer that authored the condition), which
	// conditions may use for compound authorization, like in ValidatingAdmissionPolicy. It may be nil.
	EvaluatorForData(ctx context.Context, data ConditionsData, apiServerAuthorizer Authorizer) (BuiltinConditionsEvaluator, error)
}

type BuiltinConditionsEvaluator interface {
	// EvaluateCondition evaluates a single condition in the current ConditionsData context
	// into a ConditionEvaluationResult if possible, or returns ConditionsEvaluationResultUnevaluatable().
	EvaluateCondition(ctx context.Context, condition Condition) ConditionEvaluationResult
}
```

The builder does not advertise which types it supports; the evaluator returns
"unevaluatable" for any type it does not handle.

**Flow.** When the enforcer calls `EvaluateConditions` and the union routes a
leaf to a webhook authorizer, the webhook:

1. Builds an evaluator for this request (`EvaluatorForData`). This looks up the
   namespace, builds the CEL activation, and wraps the API server's root
   authorizer (taken from the request context, not the webhook itself) in a
   caching authorizer for the duration of this evaluation.
1. Runs `PartiallyEvaluateConditionsAwareDecision` over its decision, using the
   evaluator for `authorizer.kubernetes.io/cel` conditions. Other types are
   unevaluatable. **Any error from the built-in evaluator** (compile error,
   runtime error, cost budget exceeded) **is treated as unevaluatable**, so the
   condition is deferred to the webhook rather than producing an error.
1. If the result is unconditional, returns it without contacting the webhook.
1. Otherwise sends the **refined** decision in the
   `AuthorizationConditionsReview`, and checks the response against the refined
   decision's `PossibleDecisions()`.

The refinements an authorizer must expect in the ACR, instead of exactly the
decision it issued, are:

- conditions that evaluated to `false` are removed;
- a map whose remaining conditions cannot change the outcome folds, e.g. a map
  with no Deny or Allow conditions left becomes `NoOpinion`;
- union entries decided in-process become `NoOpinion` leaves that keep their
  reason and error;
- entries after a leaf containing an unconditional `Allow` or `Deny` are
  dropped, and entries after the first still-conditional entry are left
  untouched.

**Environment.** The environment is that of `ValidatingAdmissionPolicy`, built
with `environment.StoredExpressions` at the default compatibility version:
`object`, `oldObject`, `request`, `namespaceObject`, and the optional
`authorizer` (with `authorizer.requestResource`). There are no `params`. The
objects are in the external version of the request's kind, after mutating
admission. `authorizer` performs secondary checks against the API server's
**root** authorizer, through a per-evaluation caching authorizer, and calls it
unconditionally (`Authorize`), as VAP does. This lets the authorization layer
express API-author-designated secondary checks (e.g. require `sign` on a signer
for writers of `CertificateSigningRequest`), and it means such checks see the
authorizer chain at evaluation time, not at authorization time.

**Cost and performance.** Evaluation should be of the same magnitude as
`ValidatingAdmissionPolicy`, which runs pre-compiled programs.

*Alpha status (v1.38): not yet implemented; see Beta criteria.* Each condition
expression is compiled on every evaluation call; there is no cache of compiled
programs.

The total CEL cost of evaluating one request's conditions is bounded.

*Alpha status (v1.38): not yet implemented; see Beta criteria.* Each condition
gets its own `RuntimeCELCostBudget` (10M) and the remainder is discarded, so a
map of 128 conditions can spend 128 budgets; because cel-go charges a call's
cost after the call returns, a single expensive call can exceed both the 1M
`PerCallLimit` and the 10M budget in one step, and neither limit bounds the CPU
spent inside that call.

**Availability.** The intended design lets a webhook that authors only
`authorizer.kubernetes.io/cel` conditions be used without a second
(`AuthorizationConditionsReview`) endpoint.

*Alpha status (v1.38): not yet implemented; see Beta criteria.* The builder is
constructed only when the feature gate is on **and** the webhook has
`conditionsReview` configured, and a webhook without `conditionsReview` does not
advertise conditional decision types in its `SubjectAccessReview`s.

> **TODO(decision D-5):** Whether in-process CEL should keep requiring `webhook.conditionsReview` is undecided. Options: keep the coupling, build the evaluator whenever the gate is on, or add an explicit configuration knob.

**Requirement conflict.** The authorizer requirements say an authorizer must be
able to evaluate every condition it authored, regardless of in-process
capabilities. A CEL condition may reference `namespaceObject` and `authorizer`,
but the `AuthorizationConditionsReview` carries neither: it carries only the
`AdmissionRequest` (objects, user, operation, options). When such a condition
is deferred to the webhook (e.g. after an in-process error), the webhook cannot
reproduce the in-process environment. The KEP has not resolved whether to
restrict the variables CEL conditions may use, or to specify what the ACR
carries for them.

**Version skew.** An authorizer does not know the CEL capabilities of the API
server that will evaluate its conditions. The environment grows additively
between releases. If a newer authorizer returns a condition that uses, say, a
function an older API server does not know, in-process compilation fails, the
error is treated as unevaluatable, and the condition is sent to the authorizer
in the `AuthorizationConditionsReview`. Since the authorizer authored it, it can
evaluate it: the result is correct, only slower. This is why the type carries no
version suffix. If a semantic change to an existing function were ever needed,
it would require a new condition type.

### Feature availability and version skew

Conditional authorization is available for a request when all of the following
hold:

- The authorizer supports conditions:
  - an in-tree authorizer implements `ConditionsAwareAuthorize` returning a
    `ConditionsMap` or `Union`, and `EvaluateConditions`;
  - a webhook authorizer has `webhook.conditionsReview` configured and responds
    to an opted-in `SubjectAccessReview` with `status.conditionalDecision` set
    (and `allowed`, `denied`, `reason`, `evaluationError` at their zero values).
- The API server enables the three switches below, and the request is
  classified as conditional.

`SubjectAccessReview`, `SelfSubjectAccessReview` and
`LocalSubjectAccessReview` are not restricted by the classifier: with the gate
on, kube-apiserver returns a `conditionalDecision` for **any** verb and resource
to a client that sets `spec.authorizationOptions.handledDecisionTypes` to a
superset of `{Allow, Deny, NoOpinion, ConditionsMap, Union}`. Only enforcement is
restricted to classified requests. See Risks and Mitigations for the disclosure
this implies.

#### Enablement: three switches plus one per-webhook opt-in

1. **Feature gate** `ConditionalAuthorization` (Alpha, default off, v1.38),
   defined in `k8s.io/apiserver/pkg/features`.
1. **Classifier.** `Config.Authorization.ConditionalAuthorizationRequestClassifier`
   decides which requests are authorized with `ConditionsAwareAuthorize`. Only
   kube-apiserver sets it, and only with the gate on. Its rule: a resource
   request, with verb `create`, `update`, `patch`, `delete` or
   `deletecollection`, whose GroupResource is not excluded from admission.
   Wildcards are not special-cased. GET connect requests are not classified.
   The "served by the current API server" check is not implemented (see
   [Future: aggregated API servers](#future-aggregated-api-servers)).
1. **Enforcer plugin** `AuthorizationConditionsEnforcer` enabled. It is in
   kube-apiserver's default-on plugin list and is inert (`Handles` returns
   false) when the gate is off. `Config.Authorization.ConditionsEnforcerPluginEnabled`
   is computed from the enabled admission plugins.
1. **Per webhook:** `authorizers[].webhook.conditionsReview` (`version: v1alpha1`,
   optional `kubeConfigContextName`), in `apiserver.config.k8s.io/v1` only. It
   requires the gate and `subjectAccessReviewVersion: v1`. Only such a webhook
   advertises `handledDecisionTypes` in its `SubjectAccessReview`s and receives
   the in-process CEL evaluator.

`DefaultBuildHandlerChain` installs `WithConditionsAwareAuthorization` only if
switches 1, 2 and 3 all hold. Otherwise it installs the unchanged
`WithAuthorization`, which never produces a conditional decision; with the gate
on it still stores its unconditional `Allow` in the request context, for the
enforcer. If the gate is on but the enforcer plugin is disabled, the API server
starts with the legacy filter and logs a warning; conditional decisions are then
never used.

`SubjectAccessReview`, `SelfSubjectAccessReview` and `LocalSubjectAccessReview`
need only the gate and the client opt-in.

The invariant this design keeps: there must not be a configuration in which a
request is let through on a conditional decision without the enforcer in the
admission chain to evaluate it.

*Alpha status (v1.38): not yet implemented; see Beta criteria.* The filter
selection reads the gate from the process-global `utilfeature.DefaultFeatureGate`,
while the enforcer reads the feature gate injected at admission initialization,
so the invariant relies on both sources agreeing, which they do in
kube-apiserver.

Aggregated API servers built on `k8s.io/apiserver` have no classifier and
therefore always use the legacy filter.

#### Version skew

| Version skew matrix | Old API server | New API server |
| :---- | :---- | :---- |
| Old webhook | Conditions never returned | Conditions never returned (the webhook ignores `authorizationOptions`) |
| New webhook | The `SubjectAccessReview` has no `authorizationOptions`; the webhook must answer unconditionally | Conditions returned only when the `SubjectAccessReview` carries `authorizationOptions` (webhook has `conditionsReview`, request classified, or an opted-in SAR client) |

A webhook that receives no `authorizationOptions` must fold any conditional
answer to an unconditional one: `Deny` if a Deny condition is present, otherwise
`NoOpinion` (`FailureDecision()`). An old API server does not know
`status.conditionalDecision`. If a new webhook answers a new API server
conditionally without having been asked:

- on the legacy path (`Authorize`: unclassified requests, unaware SAR clients,
  other in-process `Authorize` callers), the webhook returns
  `FailureDecision()` **with an error**. In the filter this is a 500 if that
  result is final; if `FailureDecision()` is `NoOpinion`, a later `Allow` in the
  union admits the request and a later `Deny` gives that authorizer's own result
  (normally a 403);
- on the conditions-aware path for a webhook without `conditionsReview`, the
  status fails validation (`conditionalDecision` set although the client did not
  opt in), and the webhook returns its `failurePolicy` decision with the
  validation error.

`UnconditionalPartsOrFailClosed`, which would give a descriptive 403 instead,
has no production caller.

> **TODO(decision D-2):** How conditions-unaware consumers fold an unrequested or unusable conditional decision is undecided: today the legacy path yields a 500, and the conditions-aware filter answers a decision that cannot reach Allow with a reasonless 403. Options: keep the 500, return 403 everywhere, or split (500 for the protocol violation, descriptive 403 at the filter).

## Other Kubernetes authorization enforcement points, with and without conditions-awareness

This section lists the places where conditional authorization applies, or
could apply in the future. An `Authorize` call that is not described here as
supporting conditional authorization does not support it. Such a caller always
receives an unconditional answer: no built-in authorizer returns conditions
from `Authorize`, and the webhook authorizer's `Authorize` sends its
`SubjectAccessReview` without `spec.authorizationOptions`. A webhook that
returns a `status.conditionalDecision` anyway is treated as misbehaving, and its
answer is folded to `FailureDecision()` together with an error (see
[Authorizer requirements](#authorizer-requirements)).

The Go type system makes the distinction explicit. A caller holding a
`k8s.io/apiserver/pkg/authorization/authorizer.UnconditionalAuthorizer` can only
call `Authorize`. A caller holding an `authorizer.Authorizer` can also call
`ConditionsAwareAuthorize` and `EvaluateConditions`. In-tree admission plugins
receive an `UnconditionalAuthorizer` through the
`k8s.io/apiserver/pkg/admission/initializer.WantsUnconditionalAuthorizer`
initializer. The `WantsAuthorizer` initializer, which keeps its 1.36 signature,
hands the full `Authorizer` interface to out-of-tree plugins. Such a plugin that
calls `ConditionsAwareAuthorize` must either evaluate the returned conditions or
fail closed, using `FailureDecision()`.

One thing that needs to be taken into account for secondary authorization
checks: today some of the checks set `APIVersion="*"` (for unknown reason) when
there is no logical API version at hand. If such checks would need to start
supporting conditional authorization, we'd need to propagate a concrete, logical
API version instead, as conditional authorization requires API version to be
concrete (not a wildcard).

### Compound Authorization for Connectible Resources

After the move to WebSockets
([KEP 4006](https://github.com/kubernetes/enhancements/tree/master/keps/sig-api-machinery/4006-transition-spdy-to-websockets#proposal-synthetic-rbac-create-authorization-check)),
connect requests are initially authorized as e.g. `get pods/exec`, which can
lead someone thinking that giving `get *` gives only read-only access, and not
also write access. To mitigate this privilege-escalation vector, when the
`AuthorizePodWebsocketUpgradeCreatePermission` feature gate is enabled (GA and
locked on in 1.38), `pods/attach`, `pods/exec` and `pods/portforward` are
subject to compound authorization, where effectively it is made sure that the
requestor also is authorized to `create` the corresponding connectible
resource. However, this check is not added (yet at least) for `pods/proxy`,
`services/proxy` and `nodes/proxy`.

**Alpha state (v1.38).** Connect requests support conditional authorization only
when they arrive as an HTTP POST, that is, with verb `create` (for example
`create pods/exec`). The kube-apiserver request classifier treats such a request
like any other `create`: the conditions-aware filter propagates the decision,
and the `AuthorizationConditionsEnforcer` evaluates it during connect admission,
with `operation == CONNECT`, `object == <connect options>` (e.g.
`PodExecOptions`), `oldObject == null` and `options == null`. Connect requests
that arrive as an HTTP GET (verb `get`) are not classified as conditional, so
they receive an unconditional decision. The compound `create` check in
`k8s.io/kubernetes/pkg/registry/core/pod/rest.ensureAuthorizedForVerb` holds an
`UnconditionalAuthorizer` and is unconditional. There is no integration test
for conditional connect requests.

**Proposed for beta.** It is proposed that we uniformly and generally require
the requestor to have the `create` verb using compound authorization in the
`ConnectResource` handler, whenever the feature gate (or a new one) is enabled.
Both the initial (`get`) and compound (`create`) check would support conditional
authorization, with the same `ConditionsData` as connect admission above.

Such a check thus becomes a generalization of [KEP-2862: Fine-grained Kubelet
API
Authorization](https://github.com/kubernetes/enhancements/blob/master/keps/sig-node/2862-fine-grained-kubelet-authz/README.md),
as now an authorizer can say "allow lucas to `create nodes/proxy`, but only when
`options.path == "/configz"`", or any other such policy that the administrator
might fancy.

### Compound Authorization for update/patch → create

If an `update` or `patch` turns into a `create`, the API server performs compound
authorization to make sure the requestor also has the privilege to create the
resource. This KEP also applies conditional authorization support for this
compound authorization check.

*Alpha status (v1.38): not yet implemented; see Beta criteria.* The secondary
`create` check (`withAuthorization` in
`k8s.io/apiserver/pkg/endpoints/handlers`, shared by update, patch and the CRD
handler) holds an `UnconditionalAuthorizer` and calls `Authorize`; the
conditional decision for the primary `update`/`patch` is then evaluated by the
enforcer against the `CREATE` operation, with no old object.

### Constrained Impersonation through Conditional Authorization

**Future work.** Impersonation checks are unconditional on HEAD: both the
legacy impersonation filter and constrained impersonation
(`k8s.io/apiserver/pkg/endpoints/filters/impersonation`) call `Authorize` on an
`UnconditionalAuthorizer`. This section describes a possible future
application.

[KEP-5284: Constrained Impersonation](https://github.com/kubernetes/enhancements/tree/master/keps/sig-auth/5284-constrained-impersonation)
proposes a way to restrict impersonation such that the requestor both needs the
permission to impersonate the specified user, but the permission to impersonate
certain types of requests, e.g.
`lucas can only impersonate node foo, but only to get pods`. This is a perfect
example of where conditional authorization shines; the request that is being
performed is the initially-unknown data that an authorizer might want to specify
conditions on.

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
      - id: example.com/lucas-only-impersonate-node-get-pods
        type: authorizer.kubernetes.io/cel
        condition: |
          impersonatedRequest.apiGroup == "" &&
          impersonatedRequest.resource == "pods" &&
          impersonatedRequest.verb == "get"
```

Now, the impersonation filter can evaluate the condition, either through the
builtin CEL evaluator (if applicable), or by calling the Authorizer's
`EvaluateConditions` method with the missing data (the information about the
impersonated request). Neither `ConditionsData` nor the
`authorizer.kubernetes.io/cel` environment carries an `impersonatedRequest` on
HEAD, so this needs an extension of both.

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
   directly afterwards run `EvaluateConditions()` / an
   `AuthorizationConditionsReview` with more information: namely the
   `impersonatedRequest` metadata. After this step, the condition produced by
   partial evaluation with this additional information yields:

    ```cel
    has(object.metadata.labels["lucas-impersonated"]) &&
    object.metadata.labels["lucas-impersonated"] == "true"
    ```

   This step requires an API change. On HEAD, evaluation always yields an
   unconditional result: `Authorizer.EvaluateConditions` returns an
   `authorizer.Decision`, and validation of an `AuthorizationConditionsReview`
   rejects a `response.decision` of type `ConditionsMap` or `Union` ("currently
   must evaluate to an unconditional decision").

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
      This depends on aggregated API server support, which is also future work
      (see Technical Requirements).
   1. The conditions-aware impersonation authorizer would need to either cache
      the conditions internally using a context key, or pass the conditions
      transparently to the client, so that it can evaluate those later itself
      when passed back.

Initially, however, we do not need to go this far as to implement object-level
constraints during impersonation, but this design should be future-proof as
keeps the option open.

### Node authorizer

**Future work.** On HEAD the Node authorizer is not conditions-aware: its
`ConditionsAwareAuthorize` lifts `Authorize` with
`authorizer.ConditionsAwareDecisionFromParts`, and its `EvaluateConditions` is
not supported.

The Node authorizer was the first conditional authorizer in that it had both an
authorization and admission part that always were designed and evolved in
tandem. This proposal generalizes this; now the Node authorizer could return
conditional responses with a condition type of its own in the
`*.authorizer.kubernetes.io` style (no such type is defined today), and either
transparent conditions written in CEL (`authorizer.kubernetes.io/cel`), if
possible, or opaque ones, e.g.
`condition: '{"condition": "require-pod-node-name", "nodeName": "foo"}'`.

In the opaque condition case, the Node authorizer will get a callback on its
`EvaluateConditions()` method to, even in native code, enforce e.g.
a Pod's `spec.nodeName` actually matches what it should be. If this were the case,
all logic is centralized in the authorizer, instead of being split between two
components, and `SubjectAccessReview` shows what policies apply.

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
verb that is not served by the API server. On HEAD, VAP and MAP secondary checks
go through the per-request caching authorizer in
`k8s.io/apiserver/pkg/admission/plugin/authorizer`, which holds an
`UnconditionalAuthorizer`, so they are unconditional.

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

In the kube-apiserver admission order, `ValidatingAdmissionPolicy` runs
**before** the `AuthorizationConditionsEnforcer`, so VAP evaluates requests whose
authorization conditions have not been evaluated yet (see
[Risks and Mitigations](#risks-and-mitigations)).

> **TODO(decision D-6):** Whether the enforcer keeps its position after VAP and all built-in validators (documented, possibly with a side-effect guard), moves to be the first validating plugin, or evaluates before mutating admission.

### `deletecollection` support

Conditional authorization also works for `verb=deletecollection` requests,
which the kube-apiserver request classifier treats as conditional. The
condition is written just as it would be for `verb=delete`. The API server runs
delete admission once per object, so the `AuthorizationConditionsEnforcer`
evaluates the conditions once per object, with `operation == DELETE` and
`oldObject` set to that object.

The audit annotations `authorization.k8s.io/decision` and
`authorization.k8s.io/reason` record the decision for the request as a whole.

*Alpha status (v1.38): not yet implemented; see Beta criteria.* The enforcer
writes the annotations on every evaluation, and audit annotations are
first-writer-wins, so for a `deletecollection` (or an admission retry) the
annotations reflect the first object evaluated.

There is no integration test for conditional `delete` or `deletecollection`
requests yet; this is a beta test requirement.

### Complete list of all `Authorize` calls in `kube-apiserver`

The table lists every call of `Authorize`, `ConditionsAwareAuthorize` or
`EvaluateConditions` that makes an authorization decision in kube-apiserver
(and the generic API server library it uses), plus the kubelet. "Handle" is the
interface the caller holds: `UnconditionalAuthorizer` (UA) or `Authorizer` (A).
"Unconditional" means the caller can only ever receive an unconditional answer
(see the start of this section). "Gated" means that the
`ConditionalAuthorization` feature gate affects the call.

| Site | Handle | Method | Conditions handling | Gated |
|---|---|---|---|---|
| `k8s.io/apiserver/pkg/endpoints/filters.WithAuthorization` (legacy filter; used by kube-apiserver when the conditions-aware filter is not installed, by every generic and aggregated API server, by kube-scheduler and by the controller managers) | UA | `Authorize` | Unconditional. With the gate on, the unconditional Allow is attached to the request context, so the enforcer finds a decision | Partly: only the context attach |
| `filters.WithConditionsAwareAuthorization`, request classified conditional (kube-apiserver: resource requests with verb `create`, `update`, `patch`, `delete` or `deletecollection` on a GroupResource that is not excluded from admission) | A | `ConditionsAwareAuthorize` | **Propagated** in the request context, together with the authorizer. Allow continues; a decision whose `PossibleDecisions` contain Allow continues with the audit annotation `authorization.k8s.io/is-conditional-decision`; otherwise 403 (500 with an error) | Yes |
| `filters.WithConditionsAwareAuthorization`, request not classified conditional | A | `Authorize`, lifted with `ConditionsAwareDecisionFromParts` | Unconditional; attached to the request context | Yes |
| `k8s.io/apiserver/pkg/admission/plugin/authorizer/conditionsenforcer` (`AuthorizationConditionsEnforcer` validating admission plugin) | A (from the request context) | `EvaluateConditions` | **Evaluated in place** against the versioned admission attributes. The result is guarded to stay within the decision's `PossibleDecisions`, otherwise Deny "failed closed". This is the only enforcement point that evaluates conditions | Yes |
| `k8s.io/kubernetes/pkg/registry/authorization/{subjectaccessreview,localsubjectaccessreview,selfsubjectaccessreview}`, client opted in through `spec.authorizationOptions` | A | `ConditionsAwareAuthorize` | **Returned to the client** as `status.conditionalDecision`; an encoding failure falls back to `FailureDecision()` | Yes |
| Same registries, client not opted in or gate off | A | `Authorize` | Unconditional | Yes (selects the branch) |
| `k8s.io/kubernetes/pkg/registry/core/pod/rest.ensureAuthorizedForVerb` (`create` re-check for `pods/exec`, `pods/attach`, `pods/portforward`) | UA | `Authorize` | Unconditional (see [above](#compound-authorization-for-connectible-resources)) | No |
| `k8s.io/kubernetes/pkg/registry/core/serviceaccount/storage` (TokenRequest `attest` check for admission-webhook authentication tokens) | A (only `Authorize` is called) | `Authorize` | Unconditional | No |
| `k8s.io/kubernetes/pkg/registry/rbac` (`RoleEscalationAuthorized`, `BindingAuthorized`: `escalate` and `bind` verbs) | UA | `Authorize` | Unconditional | No |
| `k8s.io/kubernetes/pkg/registry/resource` (DRA ResourceClaim binding and driver status checks) | UA | `Authorize` | Unconditional | No |
| `k8s.io/kubernetes/pkg/certauthorization.IsAuthorizedForSignerName` (`sign`/`approve`/`attest` on `certificates.k8s.io signers`; called by the CSR approval and signing admission plugins, ClusterTrustBundle attest admission and the PodCertificateRequest strategy) | UA | `Authorize` | Unconditional, for the same reasoning as VAP | No |
| `k8s.io/kubernetes/pkg/registry/admissionregistration/{validating,mutating}admissionpolicy{,binding}` (`get` on the referenced parameter resource) | UA | `Authorize` | Unconditional | No |
| `k8s.io/kubernetes/plugin/pkg/admission/gc` (`delete` on the object when ownerReferences change; `update */finalizers` or `update <owner>/finalizers` for blocking owner references) | UA | `Authorize` | Unconditional | No |
| `k8s.io/kubernetes/plugin/pkg/admission/noderestriction` (`request-serviceaccounts-token-audience` for ServiceAccount token audiences; PodCertificateRequest signer check) | UA | `Authorize` | Unconditional | No |
| `k8s.io/apiserver/pkg/admission/plugin/authorizer` (per-request caching authorizer; used by VAP, MAP and the in-process CEL conditions evaluator's `authorizer` variable) | UA | `Authorize` | Unconditional. Compound authorization *inside* an `authorizer.kubernetes.io/cel` condition calls the root authorizer unconditionally | No (the in-process CEL use exists only with the gate on) |
| `k8s.io/apiserver/pkg/cel/library` (CEL `authorizer` path and resource checks; used by VAP, MAP, admission-webhook `matchConditions` and CEL conditions) | UA | `Authorize` | Unconditional | No |
| `k8s.io/apiserver/pkg/endpoints/filters/impersonation` (legacy impersonation filter and constrained impersonation) | UA | `Authorize` | Unconditional (see [above](#constrained-impersonation-through-conditional-authorization)) | No |
| `k8s.io/apiserver/pkg/endpoints/handlers` `authorizeUnsafeDelete` (delete with `ignoreStoreReadErrorWithClusterBreakingPotential`) | UA | `Authorize` | Unconditional | No |
| `k8s.io/apiserver/pkg/endpoints/handlers` `withAuthorization` (update or patch turning into create; also used by the CRD handler) | UA | `Authorize` | Unconditional (see [above](#compound-authorization-for-updatepatch--create)) | No |
| `k8s.io/kubernetes/pkg/kubelet/server.InstallAuthFilter` (kubelet API) | UA | `Authorize` | Unconditional. Conditions on the `nodes/proxy` path are future work | No |

Three kinds of authorizer pass calls through rather than enforce. They
implement all three `Authorizer` methods by delegating: the reloadable
authorizer in `k8s.io/kubernetes/pkg/kubeapiserver/authorizer`, the
instrumented authorizer in `k8s.io/apiserver/pkg/authorization/metrics`, and the
union in `k8s.io/apiserver/pkg/authorization/union`, which routes
`EvaluateConditions` to sub-authorizers by name. The built-in authorizers (RBAC,
Node, ABAC, AlwaysAllow, AlwaysDeny, privileged groups) lift `Authorize` in
their `ConditionsAwareAuthorize`.

The unsafe-delete row deserves a note. The primary `delete` decision for such a
request can be conditional, because the classifier treats `delete` as
conditional. However, the corrupt-object deleter skips delete admission, so the
`AuthorizationConditionsEnforcer` does not run for that request.

> **TODO(decision D-1):** How a conditional decision is handled where admission does not run (the unsafe corrupt-object delete, and writes to aggregated API groups, which kube-apiserver classifies as conditional but does not enforce): classify such requests as not conditional, refuse them unless the decision is an unconditional Allow, or implement the pass-through model.

## Authorizer requirements

To recap, the authorizer must adhere to the following requirements to be
considered functional:

- If the caller is not conditions-aware, no conditions must be returned. On the
  wire, this means a `SubjectAccessReview` without `spec.authorizationOptions`
  (or whose `handledDecisionTypes` do not include `ConditionsMap` and `Union`).
  In Go, it means the caller calls `Authorize` rather than
  `ConditionsAwareAuthorize`. An authorizer that would have answered
  conditionally MUST fold its answer to the decision's `FailureDecision()`: Deny
  if any Deny is possible (there is at least one deny condition), otherwise
  NoOpinion.
  - On HEAD, if a webhook returns a `status.conditionalDecision` to a SAR that did
    not opt in, the webhook authorizer's `Authorize` returns `FailureDecision()`
    together with an error. The authorization filter turns a final non-Allow
    decision with an error into an HTTP 500 rather than a 403; if
    `FailureDecision()` is `NoOpinion`, the union continues, and a later `Allow`
    or `Deny` decides with that authorizer's own result.
    `ConditionsAwareDecision.UnconditionalPartsOrFailClosed`, which would yield a
    descriptive 403, has no production caller.

> **TODO(decision D-2):** Which HTTP status a conditions-unaware consumer returns for a conditional answer it cannot use: keep the 500, return a (descriptive) 403 everywhere, or split (500 for the protocol violation by the webhook, descriptive 403 at the conditions-aware filter).

- A Go authorizer that is not conditions-aware MUST implement
  `ConditionsAwareAuthorize` as
  `return authorizer.ConditionsAwareDecisionFromParts(self.Authorize(ctx, a))`,
  and `EvaluateConditions` as
  `return authorizer.DecisionDeny, "", authorizer.ErrorConditionEvaluationNotSupported`.
- A caller calls only one of `Authorize` and `ConditionsAwareAuthorize` for a
  given request, not both.
- An authorizer that wraps other authorizers (a pass-through, such as the
  reloadable, instrumented and union authorizers listed above) MUST implement
  all three methods by delegating to the wrapped authorizer, so that conditions
  are neither lost nor evaluated by the wrong authorizer.
- A webhook authorizer without `webhook.conditionsReview` configured counts as
  conditions-unaware: it does not advertise `handledDecisionTypes` in its SARs,
  so the webhook must answer unconditionally.
- Only ever produce a conditional response if producing an unconditional
  response is not possible.
  - The effect of authorizer-internal policies determines this. If there is an
    authorizer which has `Allow`, `NoOpinion` (soft deny) and `Deny` (hard
    deny) policies, then the strength of policies are ordered as `Deny`
    (unconditional) > `Deny` (conditional) > `NoOpinion` (unconditional) >
    `NoOpinion` (conditional) > `Allow` (unconditional) > `Allow` (conditional).
  - For example, if an unconditional `Deny` policy matches, the output is always
    an unconditional `Deny`, regardless of other matches.
  - If no `Deny` or `NoOpinion` policies match, only a conditional and
    unconditional `Allow`, the unconditional `Allow` takes precedence.
  - However, if a conditional `Deny` policy matches together with an
    unconditional `Allow`, the response needs to be conditional, as before
    producing a final response, one needs to know whether the conditional `Deny`
    will override the unconditional `Allow`.
  - The API server normalises only two cases itself: a `ConditionsMap` with only
    `noOpinionConditions` becomes an unconditional NoOpinion, and a `Union`
    whose `PossibleDecisions` contain a single decision becomes that
    unconditional decision. Everything else is the authorizer's responsibility.
- The authorizer can only return `allowConditions` if there is a path for the
  request to become authorized. All pruning that is possible to do with the
  initial authorizer Attributes MUST be used.
  - For example, a policy of form `object.metadata.labels.foo == "bar" &&
    request.verb == "create"` MUST not yield a conditional response for a
    `verb="update"` request, as the RHS of `&&` is then always `false`.
- An authorizer must be API version-aware, and should only let a policy author
  refer to a field in a version-dependent manner, and/or validate that the
  policy applies successfully to all known versions.
  - The conditions are evaluated against objects in the external version that
    corresponds to `ConditionsData.GetKind()`, which is the request's API
    version. This holds for both the new object (`GetObject()`) and the old
    object (`GetOldObject()`), after mutating admission. The API server converts
    the stored object to that version before evaluation, also for CRDs; the
    conversion can fail (for example, when a CRD conversion webhook fails), and
    then the request fails.
  - For example, VAP policies today use the latter technique, which rejects
    expressions that do not compile under all possible API version-specific CEL
    environments.
  - Another technique could be to expose the object through a version-specific
    fieldpath, e.g. `v1.spec.foo` and `v2.spec.bar` could refer to logically the
    same value of a field that was renamed from `foo` in `v1` to `bar` in `v2`.
- To fail closed when new API versions are added, the authorizer could
  automatically insert restrictions that only API versions that are referenced
  in the policy can yield an allowed response. In the following example, write
  requests fail closed for API version `v3` until the policy author has had time
  to add the restriction specific to that version, as follows:

  ```cel
  request.verb in ["create", "update"] &&
  if has(v1) then
    v1.spec.foo == "baz"
  else if has(v2) then
    v2.spec.bar == "baz"
  else
    false
  ```

- An authorizer only ever evaluates its own conditions. The union authorizer
  routes each sub-decision of a `Union` to the sub-authorizer whose
  `authorizerName` it carries.
- An authorizer must be able to evaluate any condition it authored, such that
  the API server always can call the authorizer to evaluate the condition
  (regardless of in-process evaluation capabilities).
  - This conflicts with the in-process CEL environment as built. An
    `authorizer.kubernetes.io/cel` condition may reference the `namespaceObject`
    and `authorizer` variables, but an `AuthorizationConditionsReview` carries
    neither: its request contains the decision and the
    `admissionv1.AdmissionRequest` only. A webhook that receives such a condition
    in an `AuthorizationConditionsReview` cannot reproduce the in-process result.
    Either the variables that such conditions may use must be restricted, or the
    `AuthorizationConditionsReview` must specify what the evaluator receives.

> **TODO(decision D-5):** Today in-process CEL exists only for a webhook that has `webhook.conditionsReview` configured, so every webhook whose conditions can be evaluated in-process also has an `AuthorizationConditionsReview` fallback. Undecided: keep this coupling, build the in-process evaluator whenever the gate is on (which would allow CEL-only authorizers without a fallback), or add an explicit knob.

- The reason strings an authorizer returns are shown to users in 403 responses
  and SAR statuses. The API server may combine them: on HEAD, the union
  authorizer's `Authorize` prefixes each aggregated NoOpinion reason with
  `<authorizerName>: ` (an Allow or Deny reason that short-circuits the chain is
  returned unprefixed), and the conditions-aware fold of a `Union` uses a
  different format. Authorizers and clients must not parse reasons.

> **TODO(decision D-4):** Whether the ungated `<authorizerName>: ` prefix on the union's aggregated NoOpinion reasons ships as is (with a release note), is reverted on the legacy `Authorize` path, or is put behind the feature gate.

- The authorizer must make sure their conditions are safe and performant to
  execute. In particular, any CEL condition that is returned to Kubernetes must
  be within reasonable CEL cost limits. The authorizer should reject policies
  that would be too costly to execute in the request path.
  - The API server bounds what an authorizer can return: a `ConditionsMap` holds
    at most 128 conditions in total, a condition at most 10240 bytes, and a
    description at most 1024 bytes. In-process CEL evaluation is bounded by the
    runtime CEL cost budget, and the API server bounds the total in-process
    evaluation cost of all conditions of one decision.
  - *Alpha status (v1.38): not yet implemented; see Beta criteria.* API
    validation of `ConditionsMap` limits each of the three lists to 128
    conditions; the 128-in-total limit is enforced only when the webhook
    authorizer decodes the map in-process.
  - *Alpha status (v1.38): not yet implemented; see Beta criteria.* The runtime
    CEL cost budget (`RuntimeCELCostBudget`) applies per condition; there is no
    per-request total across the conditions of a decision.
  - Towards this end, it is highly recommended that the authorizer uses a
    non-Turing complete language, to avoid e.g. the [Halting problem] and remote
    code execution.
  - As a worst-case example, if an authorizer accepted Python code as
    conditions, a policy author could make the authorizer run arbitrary code,
    e.g. `import os; os.system("sudo nmap ...")`, in the request path of every
    conditionally-authorized request.

[Halting problem](https://en.wikipedia.org/wiki/Halting_problem)

### Risks and Mitigations

Showing the users what authorization conditions that they are subject to through
`SelfSubjectAccessReview` (with `spec.authorizationOptions` set) means that
badly-written access control policies which follow the pattern of
[Security Through Obscurity] would be "broken". For example, if a user can only
`create pods` conditioned on `metadata.labels.foo == "42"`, the latter condition
would be returned in the SelfSAR, whereas without this information the user
would need to "blindly" guess the number. However, these kind of practices are
highly discouraged, as they rarely are effective in practice. For example, if
the user could `list pods` otherwise (which in that case would be a reasonable
permission to have), they could most likely reverse-engineer the conditions
they are subject to, by seeing data that "got through".

This risk could be mitigated by the authorizer returning opaque conditions
(which could not be efficiently evaluated in the API server), instead of
transparent (e.g. CEL) ones. It is up to the authorizer's discretion to know
whether conditions are "secret" or can be shown to the user. For clarity to the
user, it is recommended that conditions are shown when possible and reasonable.

[Security Through Obscurity](https://en.wikipedia.org/wiki/Security_through_obscurity)

**Disclosure of other users' conditions through SAR and LocalSAR.** With the
feature gate on, any client that can `create subjectaccessreviews` or
`create localsubjectaccessreviews` and opts in through
`spec.authorizationOptions` receives **another user's** complete conditions
tree: every `ConditionsMap`, the condition expressions and descriptions, and the
authorizer names in each `Union`. A webhook authorizer cannot tell who asked,
because the SAR it receives names the subject, not the caller. The names of the
built-in authorizers (`*.authorizer.kubernetes.io`) are visible on the wire, so
they must stay stable.

> **TODO(decision D-7):** Whether SAR and LocalSAR keep returning the full conditions tree of another subject to any opted-in client (documented as a risk), fold the decision unless the subject is the requester, or require a separate verb for receiving conditions.

**Admission runs before authorization is final.** In kube-apiserver the
`AuthorizationConditionsEnforcer` runs after `MutatingAdmissionPolicy`,
`MutatingAdmissionWebhook`, every built-in validating plugin and
`ValidatingAdmissionPolicy`, and before `ValidatingAdmissionWebhook`,
`ResourceQuota` and `AlwaysDeny`. The VAP-first order is deliberate, to avoid
calling `AuthorizationConditionsReview` webhooks for requests that VAP rejects
anyway. Consequences:

- Mutating webhooks, MAP and VAP see (and may log or act on) requests that the
  authorizer will deny. Admission webhook side effects happen before the
  authorization decision is final.
- An admission rejection earlier in the chain can disclose policy outcomes to a
  user who is not authorized for the request.
- Conditions are evaluated against the **post-mutation** object, so mutation by
  other plugins can make a request satisfy or fail the conditions. Condition
  authors must account for this.

> **TODO(decision D-6):** Whether to keep this position and document it, possibly with a guard against admission side effects for conditionally-authorized requests, make the enforcer the first validating plugin, or evaluate the conditions before mutating admission.

### Test Plan

[x] I/we understand the owners of the involved components may require updates to
existing tests to make this code solid enough prior to committing the changes necessary
to implement this enhancement.

#### Prerequisite testing updates

Splitting the interface into `UnconditionalAuthorizer` and `Authorizer` meant that
call sites holding only `UnconditionalAuthorizer` did not need to change. Every
fake or test authorizer that implements `authorizer.Authorizer` gained two stub
methods, `ConditionsAwareAuthorize` and `EvaluateConditions`. These tests do not
exercise the feature; they only compile against the larger interface.

#### Unit tests

New and changed unit tests, by package:

- `k8s.io/apiserver/pkg/authorization/authorizer`: `conditions_test.go`
  (constructors, zero value, `ConditionsMap` limits and fail-closed construction,
  `Union` simplification, `PossibleDecisions`, `UnconditionalPartsOrError` /
  `UnconditionalPartsOrFailClosed`, a sample conditions-aware authorizer),
  `conditionsunion_test.go` (`ConditionsAwareDecisionUnion` builder),
  `evaluate_internal_test.go` (the precedence table for one `ConditionsMap`,
  including unevaluatable conditions and refinement), `evaluate_test.go`
  (`PartiallyEvaluateConditionsAwareDecision` over maps and unions).
- `k8s.io/apiserver/pkg/authorization/union`: `union_test.go` (legacy union
  semantics through conditions-aware fakes, `ConditionsAwareAuthorize`
  short-circuiting, `EvaluateConditions` over nested unions, routing by
  authorizer name).
- `k8s.io/apiserver/pkg/authorization/metrics`: `metrics_test.go`
  (`apiserver_authorization_decisions_total` for legacy and conditions-aware
  authorizers).
- `k8s.io/apiserver/pkg/authorization/cel`: `compile_test.go`
  (`request.authorizationOptions` in webhook `matchConditions`).
- `k8s.io/apiserver/plugin/pkg/authorizer/webhook`: `webhook_conditional_test.go`
  (SAR response parsing, legacy `Authorize` fold-down, `EvaluateConditions` and
  the `AuthorizationConditionsReview` round trip, response validation, UID and
  `PossibleDecisions` guards, conditional response caching, v1beta1 downgrade,
  and in-process CEL refinement before the ACR).
- `k8s.io/apiserver/pkg/endpoints/filters`: `authorization_test.go` (legacy and
  conditions-aware filter, with and without classifier), `metrics_test.go`
  (`conditional` attempts label and audit annotations).
- `k8s.io/apiserver/pkg/endpoints/request`: `context_test.go` (storing the
  conditionally authorized decision in the context).
- `k8s.io/apiserver/pkg/admission/plugin/authorizer/conditionsenforcer`:
  `conditionsenforcer_test.go` (initialization, gate handling, filter + handler +
  enforcer end to end), `context_invariant_test.go` (a request whose decision was
  lost from the context fails).
- `k8s.io/apiserver/pkg/admission/plugin/cel`: `authorization_conditions_test.go`
  (the in-process `authorizer.kubernetes.io/cel` evaluator: variables, errors,
  cost budget, cached `authorizer` checks).
- `k8s.io/api/authorization/v1`: `util_test.go` (`handledDecisionTypes` superset
  semantics).
- `k8s.io/apiserver/pkg/apis/authorization/v1`: `encoding_test.go` (internal ↔
  wire decision conversion).
- `k8s.io/apiserver/pkg/apis/authorization/validation`: `validation_test.go`
  (SAR spec/status and `AuthorizationConditionsReview` validation).
- `k8s.io/apiserver/pkg/apis/apiserver/validation`: `validation_test.go`
  (`webhook.conditionsReview` configuration).
- `test/declarative_validation/authorization/{subjectaccessreview,selfsubjectaccessreview,localsubjectaccessreview,authorizationconditionsreview}`
  (declarative validation rules, including gate-off forbidding of the new fields).
- `k8s.io/kubernetes/pkg/apis/authorization/v1beta1`: `conversion_test.go`
  (fold-down of a conditional status to v1beta1).
- `k8s.io/kubernetes/pkg/registry/authorization/...`: `subjectaccessreview`,
  `selfsubjectaccessreview`, `localsubjectaccessreview` `rest_test.go` and
  `util/helpers_test.go` (opt-in handling, gate-off clearing, decision → status).
- `k8s.io/kubernetes/pkg/controlplane/apiserver`: `config_test.go`
  (`TestConditionalRequestClassifier`).
- `k8s.io/kubernetes/pkg/kubeapiserver/options`: `plugins_test.go`
  (`TestAdmissionPluginOrder`, which pins `AuthorizationConditionsEnforcer`
  between `ValidatingAdmissionPolicy` and `ValidatingAdmissionWebhook`).

#### Integration tests

The integration tests live in
`k8s.io/kubernetes/test/integration/apiserver/conditionalauthorization/`
(`conditionalauthorization_test.go`, `crd_conversion_test.go`,
`hpa_conversion_test.go`, `vap_ordering_test.go`). Three top-level tests run the
same suite against a fresh kube-apiserver configured with a mock webhook
authorizer followed by RBAC:

- `TestConditionalAuthorizationEnabled`: gate on, enforcer enabled.
- `TestConditionalAuthorizationDisabled`: gate off.
- `TestConditionalAuthorizationEnforcerDisabled`: gate on,
  `--disable-admission-plugins=AuthorizationConditionsEnforcer`.

The suite has 34 table rows. The conditional rows run in up to three evaluation
variants: webhook only (a condition type the API server cannot evaluate), in-process
only (`authorizer.kubernetes.io/cel`, where any `AuthorizationConditionsReview` is a
test failure), and in-process failing with fallback to the webhook. The rows cover
unconditional decisions, `ConditionsMap` precedence, CEL over `object`,
`oldObject`, `request.operation`, `namespaceObject` and `authorizer`, and
conversion: a multi-version CRD and `HorizontalPodAutoscaler` v1/v2, where both
the new and the old object are checked in the request version. After the table:
a `SubjectAccessReview` / `SelfSubjectAccessReview` / `LocalSubjectAccessReview`
matrix (4 webhook behaviours × 3 endpoints × conditions-aware and unaware clients),
a test that `ValidatingAdmissionPolicy` rejects before conditions are evaluated,
and fold-down tests for a non-admission verb and for a resource excluded from
admission. Each row asserts the outcome and the number of
`AuthorizationConditionsReview` calls.

The following are not covered yet and are Beta requirements:

- `delete` and `deletecollection`
- `patch` and server-side apply
- subresources and connect requests
- `failurePolicy: Deny` (the suite uses only `NoOpinion`)
- a top-level `Union` returned by the webhook
- update/patch → create (the rows exist but are disabled until the compound
  check is conditions-aware)
- aggregated API servers

#### e2e tests

No e2e tests exist for alpha. For Beta, e2e tests will cover user-facing
functionality: `SubjectAccessReview` with `authorizationOptions`, and requests
that are conditionally allowed and then allowed or denied. One e2e test must
cover a setup with aggregated API servers.

### Graduation Criteria

#### Alpha

- The authorizer interface is refactored, as a split into
  `UnconditionalAuthorizer` and `Authorizer` (see Core interface changes).
- The feature is implemented behind the `ConditionalAuthorization` feature gate.
  A few related changes are not gated; they are listed under
  [Were upgrade and rollback tested?](#were-upgrade-and-rollback-tested-was-the-upgrade-downgrade-upgrade-path-tested).
- Integration tests are implemented and enabled, with the gaps listed under
  Integration tests.
- The in-process CEL evaluator ([#143024](https://github.com/kubernetes/kubernetes/pull/143024))
  is pending merge.

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
- All known pre-release issues and gaps resolved, in particular:
  - Webhook `failurePolicy` applies to every invalid conditions map in a webhook
    response, including an empty map, duplicate IDs across lists and more than
    128 conditions in total, which today pass validation and fail closed in the
    constructor.
  - The classifier does not mark requests to aggregated API groups as conditional
    unless the aggregated server can enforce them.
  - The update/patch → create compound authorization check is conditions-aware.
  - The in-process CEL evaluator does not require a `conditionsReview` endpoint.

    > **TODO(decision D-5):** It is undecided whether the in-process CEL evaluator stays tied to `webhook.conditionsReview`, is built whenever the gate is on, or gets an explicit configuration knob.

  - Conditions are evaluated by the same authorizer chain snapshot that authored
    them, also across authorization configuration reloads.
  - Compiled CEL programs are cached.
  - A CEL cost budget per request, across all conditions of a decision.
  - Latency and error metrics for condition evaluation (enforcer, in-process,
    `AuthorizationConditionsReview`).
  - The authorization filter and the enforcer read the feature gate from the
    same source.
  - The unsafe delete of corrupt objects does not complete a conditionally
    authorized `delete` without enforcement.
  - Audit annotations reflect the final decision when admission runs more than
    once for a request (retries, `deletecollection`).
  - A webhook `denied` status that fails validation stays Deny on the
    conditions-aware path.
  - A width and depth limit on `Union` trees.
  - Declarative validation enforces 128 conditions in total per `ConditionsMap`.
  - Connect requests that arrive over HTTP `GET`.
  - Aggregated API servers are supported, or explicitly documented as not
    supported.
  - Integration coverage for the gaps listed under Integration tests, gate-off
    equivalence with the previous release, the legacy webhook path receiving a
    conditional decision, the `AuthorizationConditionsReview` UID check, and the
    guard on the refined decision.
  - e2e tests, including aggregated API servers.

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

Old clients can safely talk to new conditional authorizers. A client opts in by
setting `spec.authorizationOptions.handledDecisionTypes` to a superset of all five
decision types; a client that sends no `authorizationOptions` has not opted in.
The authorizer must then fold its answer to `FailureDecision()`: Deny if Deny is a
possible outcome, otherwise NoOpinion.

The kube-apiserver webhook authorizer only sends `authorizationOptions` when the
webhook has `conditionsReview` configured. If a webhook returns
`status.conditionalDecision` anyway, the legacy `Authorize` path returns
`FailureDecision()` together with an error, which the authorization filter turns
into an HTTP 500 when no later authorizer in the union decides (with a
`NoOpinion` failure decision, a later `Allow` admits the request and a later
`Deny` gives that authorizer's own result, normally a 403). On the
conditions-aware path the same status fails validation
and is handled by the webhook's `failurePolicy`.

> **TODO(decision D-2):** It is undecided whether an unrequested conditional answer on the legacy path stays a 500, becomes a 403 everywhere, or becomes a 500 for the protocol violation with a descriptive 403 at the filter.

Each `AuthorizationConditionsReview` carries a fresh UID in
`request.admissionRequest.uid`, generated per call, and the response must echo
it. There is no correlation with the authorization phase, so in a multi-replica
setup conditions authored by one webhook replica can be evaluated by another.
Webhooks must be able to evaluate any condition they authored, independent of
replica.

The built-in condition type `authorizer.kubernetes.io/cel` is unversioned. Its
environment grows only additively. If an authorizer uses a newer environment than
the API server's in-process evaluator knows (a skewed API server), in-process
evaluation fails, the condition is treated as unevaluatable, and it is sent to the
webhook in the `AuthorizationConditionsReview`.

Conditions are evaluated by the same authorizer configuration that authored them,
also across authorization configuration reloads.
*Alpha status (v1.38): not yet implemented; see Beta criteria.* The request
context stores the reloadable authorizer, so if the configuration is reloaded
between authorization and admission, `EvaluateConditions` runs against the new
chain.

Rollouts of new `AuthorizationConfiguration` configurations in multi-API server
scenarios (or similar), such as shown in this picture, need special care.

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
    `AuthorizationConditionsReview` requests pending to be sent to it.
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
  - Components depending on the feature gate: `kube-apiserver`. The gate is
    defined in `k8s.io/apiserver`, so generic API servers built on that library
    also have it.
- [x] Other
  - Describe the mechanism: conditional authorization is in effect only when all
    of the following hold:
    1. the feature gate is on;
    2. the API server sets a `ConditionalAuthorizationRequestClassifier` (only
       kube-apiserver does);
    3. the `AuthorizationConditionsEnforcer` admission plugin is enabled (it is
       default-on in kube-apiserver);
    4. a webhook authorizer in `AuthorizationConfiguration` has
       `webhook.conditionsReview` configured.

    `SubjectAccessReview`, `SelfSubjectAccessReview` and
    `LocalSubjectAccessReview` return conditions when the gate is on and the
    client opts in through `spec.authorizationOptions`.
  - Will enabling / disabling the feature require downtime of the control
    plane? The gate and the admission plugin require an API server restart.
    `webhook.conditionsReview` is part of the structured authorization
    configuration and can be added or removed without API server downtime.
    Disabling the enforcer plugin with the gate on turns enforcement off: the
    legacy authorization filter is used and a warning is logged. The
    `SubjectAccessReview` APIs still return conditions to opted-in clients.
  - Will enabling / disabling the feature require downtime or reprovisioning of
    a node? No.

###### Does enabling the feature change any default behavior?

<!--
Any change of default behavior may be surprising to users or break existing
automations, so be extremely careful here.
-->

Yes. With the gate on, kube-apiserver authorizes requests that the classifier
marks as conditional (resource requests with verb `create`, `update`, `patch`,
`delete` or `deletecollection` on a resource that admission handles) through
`ConditionsAwareAuthorize`, even if no authorizer is conditional. For these
requests:

1. The reason text in 403 responses has a different format. On the
   conditions-aware path, aggregated reasons are formatted as
   `<authorizerName>: {<reason>}` and joined with `", "`, and the single deciding
   `Allow` or `Deny` reason is wrapped the same way (`a: b: {<reason>}` for
   nested unions); errors are prefixed with `<authorizerName>: `. The legacy
   union formats aggregated `NoOpinion` reasons as `<authorizerName>: <reason>`
   joined with `"\n"`, and returns the deciding `Allow` or `Deny` reason and
   error unprefixed. So every 403 reason for these requests changes, not only
   aggregated `NoOpinion` reasons.

   > **TODO(decision D-4):** It is undecided how the authorizer-name reason prefixes ship: with a release note, reverted on the legacy path, or behind the feature gate.

2. A webhook status with a non-empty `evaluationError` gives an HTTP 500 instead
   of a 403 when it is `denied: true`, and also when it is a `NoOpinion` and no
   later authorizer allows or denies, because the conditions-aware filter returns
   an internal error for a non-allowing decision that carries an error. The
   legacy `Authorize` drops `evaluationError` on every branch.
3. Webhook `SubjectAccessReview` statuses are validated. An invalid status is
   handled by the webhook's `failurePolicy`.
4. The `AuthorizationConditionsEnforcer` admission plugin runs for every admitted
   request. It passes requests that were unconditionally allowed.

###### Can the feature be disabled once it has been enabled (i.e. can we roll back the enablement)?

<!--
Describe the consequences on existing workloads (e.g., if this is a runtime
feature, can it break the existing applications?).

Feature gates are typically disabled by setting the flag to `false` and
restarting the component. No other changes should be necessary to disable the
feature.

NOTE: Also set `disable-supported` to `true` or `false` in `kep.yaml`.
-->

Yes. With the gate off, the API server clears `spec.authorizationOptions` on
incoming `(Local|Self)SubjectAccessReview` requests, declarative validation forbids
`authorizationOptions` and `status.conditionalDecision`, and
`webhook.conditionsReview` is rejected by configuration validation, so it must be
removed from the `AuthorizationConfiguration` before the gate is turned off.

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

Yes. The integration tests `TestConditionalAuthorizationEnabled`,
`TestConditionalAuthorizationDisabled` and
`TestConditionalAuthorizationEnforcerDisabled` run the same suite with the gate
on, with the gate off, and with the gate on but the enforcer plugin disabled. They
assert the request outcome in each mode and that no
`AuthorizationConditionsReview` is sent when the feature is not in effect. They do
not assert byte-for-byte equality of responses with the previous release. Unit
tests in the SAR registries, declarative validation and configuration validation
cover the gate-off clearing and forbidding of the new fields.

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

- If an administrator configures `webhook.conditionsReview` for a webhook
  authorizer (either a separate kubeconfig context through
  `kubeConfigContextName`, or the same endpoint as the `SubjectAccessReview`), but
  the authorizer server does not serve `AuthorizationConditionsReview` (correctly),
  conditionally authorized requests that otherwise could succeed fail. Before
  pointing the API server at a conditional endpoint, all replicas of the
  authorizer must support conditions.
- Errors from the `AuthorizationConditionsReview` call (unreachable endpoint,
  invalid response, UID mismatch, an outcome outside `PossibleDecisions`) fail
  closed to `FailureDecision()` of the decision being evaluated. The webhook's
  `failurePolicy` does not apply to these errors; it applies to the
  `SubjectAccessReview` call only.
- A reload of the authorization configuration while a request is between
  authorization and admission changes the chain that evaluates the conditions
  (see Version Skew Strategy).

###### What specific metrics should inform a rollback?

<!--
What signals should users be paying attention to when the feature is young
that might indicate a serious problem?
-->

- High p50 and p99 latency of authorizer-handled and in-process conditions
  evaluation, and the rate of evaluation errors.

*Alpha status (v1.38): not yet implemented; see Beta criteria.* The only
feature-specific signal is the `conditional` value of the `decision` label on
`apiserver_authorization_decisions_total` (an authorizer returned a conditional
decision), and the `conditional` value of the `result` label on the
authorization filter's attempts counter and latency histogram (the request was
conditionally allowed). Operators can also watch the API server's 5xx rate and
admission latency for write requests.

###### Were upgrade and rollback tested? Was the upgrade->downgrade->upgrade path tested?

<!--
Describe manual testing that was done and the outcomes.
Longer term, we may want to require automated upgrade/rollback tests, but we
are missing a bunch of machinery and tooling and can't do that now.
-->

This has not been tested yet. Most of the code is feature-gated, but the
following changes apply regardless of the gate:

| Change | Introduced in |
|---|---|
| The union authorizer's `Authorize` prefixes aggregated NoOpinion reasons with `<authorizerName>: `, which changes the reason text in 403 responses and `SubjectAccessReview` statuses. Short-circuit Allow/Deny reasons stay unprefixed | [#137513](https://github.com/kubernetes/kubernetes/pull/137513) |
| Built-in authorizer names are renamed to `*.authorizer.kubernetes.io` (e.g. `system-privileged-group.authorizer.kubernetes.io`) and are visible in those reasons | [#140715](https://github.com/kubernetes/kubernetes/pull/140715) |
| A warning is logged for user-configured authorizer names under `kubernetes.io` or `k8s.io` | [#140715](https://github.com/kubernetes/kubernetes/pull/140715) |
| The webhook authorizer's `Authorize` returns `FailureDecision()` plus an error for an unrequested `status.conditionalDecision`, which gives an HTTP 500 | [#137633](https://github.com/kubernetes/kubernetes/pull/137633) |
| `(*VersionedAttributes).GetOldObject()` returns the old object converted to the request version | [#142493](https://github.com/kubernetes/kubernetes/pull/142493) |
| `AuthorizationConditionsEnforcer` is in the default-on admission plugin list and the recommended order (it is inert with the gate off) | [#141959](https://github.com/kubernetes/kubernetes/pull/141959) |
| Go library changes (see the next question) | several |
| `union.New` fails on empty or duplicate authorizer names, which is a startup error | [#137513](https://github.com/kubernetes/kubernetes/pull/137513) |

> **TODO(decision D-4):** It is undecided whether the union reason prefix ships ungated with a release note, is reverted on the legacy `Authorize` path, or is put behind the feature gate.

###### Is the rollout accompanied by any deprecations and/or removals of features, APIs, fields of API types, flags, etc.?

<!--
Even if applying deprecation policies, they may still surprise some users.
-->

No Kubernetes API, field or flag is deprecated or removed. The Go library API of
`k8s.io/apiserver` changes incompatibly for out-of-tree consumers:

- `authorizer.Authorizer` has two more methods (`ConditionsAwareAuthorize`,
  `EvaluateConditions`); the previous method set is now
  `authorizer.UnconditionalAuthorizer`.
- `union.New` takes `...union.NamedAuthorizer` and returns an error.
- `webhook.New` and `webhook.NewFromInterface` have new signatures.
- The `SubjectAccessReview` registries' `NewREST` functions have new signatures.
- `SubjectAccessReview` validation moved to
  `k8s.io/apiserver/pkg/apis/authorization/validation`.
- `admission.Operation` is an alias of `authorizer.AdmissionOperation`.
- In-tree admission plugins receive an `UnconditionalAuthorizer` through
  `WantsUnconditionalAuthorizer`; `WantsAuthorizer` still hands out the full
  `Authorizer`.

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

- [x] Metrics: the `decision` label value `conditional` on
  `apiserver_authorization_decisions_total`, and the `result` label value
  `conditional` (conditionally allowed) on the authorization filter's attempts
  counter and latency histogram.
- [x] Audit annotations: `authorization.k8s.io/is-conditional-decision: "true"` on
  requests that were conditionally allowed at the filter. The enforcer then writes
  the final `authorization.k8s.io/decision` and `authorization.k8s.io/reason`.

###### How can someone using this feature know that it is working for their instance?

<!--
For instance, if this is a pod-related feature, it should be possible to determine if the feature is functioning properly
for each individual pod.
Pick one more of these and delete the rest.
Please describe all items visible to end users below with sufficient detail so that they can verify correct enablement
and operation of this feature.
Recall that end users cannot usually observe component logs or access metrics.
-->

- [x] API .status
  - Other field: `status.conditionalDecision` of a `SubjectAccessReview`,
    `SelfSubjectAccessReview` or `LocalSubjectAccessReview` whose response is known
    to be conditional, created with `spec.authorizationOptions.handledDecisionTypes`
    set to `Allow`, `Deny`, `NoOpinion`, `ConditionsMap` and `Union`.
    `kubectl auth can-i` does not send `authorizationOptions`, so it only shows the
    folded result.

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

Evaluation time of built-in CEL authorization conditions is of the same magnitude
as for `ValidatingAdmissionPolicy`.
*Alpha status (v1.38): not yet implemented; see Beta criteria.* The in-process
evaluator compiles every condition expression on each evaluation, whereas
`ValidatingAdmissionPolicy` evaluates precompiled programs.

###### What are the SLIs (Service Level Indicators) an operator can use to determine the health of the service?

<!--
Pick one more of these and delete the rest.
-->

- [x] Metrics
  - Metric name: latency and error rate of condition evaluation (in-process and
    `AuthorizationConditionsReview`); both should be low and steady.
  - Components exposing the metric: kube-apiserver
- [x] Other (treat as last resort)
  - Details: instrumentation of conditional authorizer implementations external
    to Kubernetes.

*Alpha status (v1.38): not yet implemented; see Beta criteria.* No evaluation
latency or error metric exists. Operators can use the existing authorization and
admission latency metrics, the API server's 5xx rate, and the `conditional` label
described above.

###### Are there any missing metrics that would be useful to have to improve observability of this feature?

<!--
Describe the metrics themselves and the reasons why they weren't added (e.g., cost,
implementation difficulties, etc.).
-->

Yes, all planned for Beta:

- Latency of condition evaluation: in the enforcer, in-process, and the
  `AuthorizationConditionsReview` call.
- Errors of the `AuthorizationConditionsReview` call.
- The number of conditions that in-process evaluation deferred to the webhook
  because of an evaluation error (today this is not logged either).

### Dependencies

<!--
This section must be completed when targeting beta to a release.
-->

The existing CEL libraries of Kubernetes. The in-process CEL evaluator uses the
namespace informer and client to populate `namespaceObject`, as
`ValidatingAdmissionPolicy` does.

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

- A webhook authorizer with `webhook.conditionsReview` configured. There is no
  built-in conditional authorizer yet.
  - Usage description: returns conditional decisions in `SubjectAccessReview`
    responses, and evaluates conditions that the API server cannot evaluate
    in-process through `AuthorizationConditionsReview`.
    - Impact of its outage on the feature: `SubjectAccessReview` errors follow
      the webhook's `failurePolicy`; `AuthorizationConditionsReview` errors fail
      closed to `FailureDecision()`.
    - Impact of its degraded performance or high-error rates on the feature:
      increased authorization and admission latency for write requests, and
      failed conditionally authorized requests.

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

- One `AuthorizationConditionsReview` webhook call from kube-apiserver to the
  authorizer per admission invocation of a conditionally allowed request, unless
  in-process evaluation reaches an unconditional decision. `deletecollection`
  invokes admission once per object.
- For in-process CEL evaluation, one namespace lookup for `namespaceObject` on
  every webhook `EvaluateConditions` call that has a built-in evaluator, even
  when all conditions are opaque to it, for namespaced requests. It is served
  from the informer cache; on a cache miss it falls back to a live
  `GET namespaces/<ns>` API call.

###### Will enabling / using this feature result in introducing new API types?

<!--
Describe them, providing:
  - API type
  - Supported number of objects per cluster
  - Supported number of objects per namespace (for namespace-scoped objects)
-->

`AuthorizationConditionsReview` (`authorization.k8s.io/v1alpha1`) is registered in
the schemes and in client-go, but it is not served by any API server and not
stored in etcd. It is only the wire format between the API server and webhook
authorizers.

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

- API type(s): `SubjectAccessReview`, `SelfSubjectAccessReview`,
  `LocalSubjectAccessReview` (not persisted).
- Estimated increase in size: `spec.authorizationOptions` (at most 32 entries)
  and, for opted-in clients, a `status.conditionalDecision` tree. Each
  `ConditionsMap` holds at most 128 conditions of at most 10 KiB each, plus
  descriptions of at most 1 KiB each. A `Union` can nest any number of entries.

A `Union` tree is bounded in width and depth.
*Alpha status (v1.38): not yet implemented; see Beta criteria.* The API sets no
limit on the number of `union` entries or on nesting depth.

###### Will enabling / using this feature result in increasing time taken by any operations covered by existing SLIs/SLOs?

<!--
Look at the [existing SLIs/SLOs].

Think about adding additional work or introducing new steps in between
(e.g. need to do X to start a container), etc. Please describe the details.

[existing SLIs/SLOs]: https://git.k8s.io/community/sig-scalability/slos/slos.md#kubernetes-slisslos
-->

Authorization latency can increase, and conditionally allowed write requests
spend additional time in admission: in-process condition evaluation in the
enforcer and, when needed, the `AuthorizationConditionsReview` webhook call.

###### Will enabling / using this feature result in non-negligible increase of resource usage (CPU, RAM, disk, IO, ...) in any components?

<!--
Things to keep in mind include: additional in-memory state, additional
non-trivial computations, excessive access to disks (including increased log
volume), significant amount of data sent and/or received over network, etc.
This through this both in small and large cases, again with respect to the
[supported limits].

[supported limits]: https://git.k8s.io/community//sig-scalability/configs-and-limits/thresholds.md
-->

Potentially, in kube-apiserver:

- Decoding a webhook's `status.conditionalDecision`: the `Union` tree has no width
  or depth limit yet (see the previous answer).
- In-process CEL evaluation compiles each condition expression on every
  evaluation (see the SLO answer).
- The CEL cost budget is enforced per condition, not per request.
  *Alpha status (v1.38): not yet implemented; see Beta criteria.* A per-request
  budget across all conditions of a decision is a Beta criterion; today each
  condition gets the full runtime budget.

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

Not applicable, the feature resides completely within the API server.

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

- `AuthorizationConditionsReview` endpoint unreachable or misbehaving
  - Detection: conditionally allowed requests fail with HTTP 500 from admission
    when the fail-closed decision (`FailureDecision()` with the error) is final;
    if that decision is `NoOpinion`, a later authorizer (e.g. RBAC) that allows
    admits the request, and a later `Deny` gives a 403. Audit events carry
    `authorization.k8s.io/is-conditional-decision`.
  - Mitigations: fix the authorizer, or remove `webhook.conditionsReview` from the
    configuration so the webhook stops returning conditions.
  - Diagnostics: the API server logs `Failed to make webhook authorizer condition
    evaluation request`.
  - Testing: unit tests in `webhook_conditional_test.go`.
- A webhook returns a conditional decision to a request that did not opt in
  - Detection: HTTP 500 on requests authorized through the legacy path.
  - Mitigations: fix the webhook to honour `authorizationOptions`.
  - Testing: unit tests (`TestAuthorize_FoldDown` for the legacy path,
    `TestConditionsAwareAuthorize` for the conditions-aware path); no
    integration test.
- Invalid conditions in a webhook response (bad ID or type, too many or too large
  conditions, duplicate IDs)
  - Detection: the webhook's answer becomes a `failed closed` decision with an
    error; requests either fall through to later authorizers or fail with HTTP
    500.

    The webhook's `failurePolicy` decides the outcome. Declarative validation of
    the status rejects bad IDs or types, oversized conditions or descriptions,
    more than 128 conditions in one list, and duplicate IDs within one list, and
    these follow `failurePolicy`.
    *Alpha status (v1.38): not yet implemented; see Beta criteria.* An empty map,
    duplicate IDs across lists, and more than 128 conditions in total pass
    validation; the constructor then fails closed to Deny if the map contains a
    deny condition and to NoOpinion otherwise, regardless of `failurePolicy`.
  - Testing: unit tests in `conditions_test.go` and `webhook_conditional_test.go`.
- Condition evaluation errors
  - Detection: HTTP 500 from admission (the enforcer returns an internal error when
    evaluation does not allow and carries an error).

    > **TODO(decision D-3):** It is undecided whether errors of Allow-effect conditions are ignored, keep surfacing as an error (500), or become a non-fatal error class.

  - Testing: unit tests in `evaluate_internal_test.go`.
- `AuthorizationConditionsEnforcer` disabled while the gate is on
  - Detection: the feature is silently off; the API server logs a warning at
    startup, and no request carries `authorization.k8s.io/is-conditional-decision`.
  - Mitigations: enable the plugin.
  - Testing: `TestConditionalAuthorizationEnforcerDisabled`.
- In-process CEL evaluation fails (e.g. version skew in the CEL environment)
  - Detection: more `AuthorizationConditionsReview` calls than expected; the
    deferral is not logged.
  - Mitigations: none needed, the condition is evaluated by the webhook.
  - Testing: the `if-in-process-fails-call-webhook` integration variant.
- Writes to aggregated API groups
  - Detection: kube-apiserver classifies them as conditional and annotates them,
    but does not enforce conditions for proxied requests. The aggregated API
    server authorizes them again through `Authorize` only, so a conditional answer
    fails closed there.

    > **TODO(decision D-1):** It is undecided how aggregated API groups (and the unsafe corrupt-object delete) are handled: classify them as not conditional, refuse unless the decision is an unconditional Allow, or implement the pass-through model.

  - Testing: none.

###### What steps should be taken if SLOs are not being met to determine the problem?

- Check the `AuthorizationConfiguration`, in particular `webhook.conditionsReview`
  and `failurePolicy`
- Troubleshoot any webhook authorizers' `SubjectAccessReview` and
  `AuthorizationConditionsReview` responses
- Check audit logs for `authorization.k8s.io/is-conditional-decision`,
  `authorization.k8s.io/decision` and `authorization.k8s.io/reason`, and the
  `conditional` value of the `decision` label of `apiserver_authorization_decisions_total`

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

In other words, only the authorizer itself evaluates its own conditions in the
admission phase, apart from the conditions of well-known types that the API
server evaluates in-process before handing the refined decision to the
authorizer (see [Built-in CEL conditions evaluator](#built-in-cel-conditions-evaluator)).

### Propagate an API server-generated request UID to both authorization and admission

This would have helped solve the atomicity concern, but it is not a full
long-term solution, as it still relies on people setting up webhooks.

The shipped `AuthorizationConditionsReview` does carry a UID, but for a
different purpose: the API server generates a fresh UID for every
`AuthorizationConditionsReview` call (in `request.admissionRequest.uid`), and
the webhook must echo it in `response.uid`. The UID correlates one request with
its response; it does not link the authorization phase to the admission phase.

### Only one ConditionsMap exposed as part of SubjectAccessReview status

However, if only one `ConditionsMap` is exposed, it might be impossible for a
user to understand what conditions it is subject to for a given request through
a (Self/Local/Standard) SubjectAccessReview, as the first conditional decision
might be just a “deny dangerous operations”-type of `ConditionsMap` (one with
only `denyConditions`).

The user should thus see every authorizer's decision, including all
`ConditionsMap`s, until an authorizer returns an unconditional `Allow` or
`Deny`. This is why `status.conditionalDecision` is a `ConditionsAwareDecision`
tree whose top level is either a `ConditionsMap` or a `Union` of named
sub-decisions.

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

Consider the following fictional `Union` of two authorizers' `ConditionsMap`
decisions:

- Authorizer 1:
  - `denyConditions`: `metadata.labels.owner != "lucas"`
  - `noOpinionConditions`: `metadata.labels.visible != "true"`
  - `allowConditions`: `object.type == "k8s.io/basic-auth"`,
    `metadata.labels.public == "true"`
- Authorizer 2:
  - `allowConditions`: `metadata.labels.env == "dev"`

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

Note that authorizer 1's deny condition must evaluate to false for an object to
be matched. However, the no-opinion condition is scoped only to authorizer 1: if an object
was such that `metadata.labels.owner == "lucas"` and
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

