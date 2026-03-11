package v1alpha1

import (
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// +genclient
// +genclient:nonNamespaced
// +genclient:onlyVerbs=create
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:prerelease-lifecycle-gen:introduced=1.36

// AuthorizationConditionsReview describes a request to evaluate authorization conditions.
type AuthorizationConditionsReview struct {
	metav1.TypeMeta `json:",inline"`
	// metadata is the standard list metadata.
	// In AuthorizationConditionsReview, it must be an empty struct.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// Request describes the attributes for the authorization conditions request.
	// +optional
	Request *AuthorizationConditionsRequest `json:"request,omitempty" protobuf:"bytes,2,opt,name=request"`
	// Response describes the attributes for the authorization conditions response.
	// +optional
	Response *AuthorizationConditionsResponse `json:"response,omitempty" protobuf:"bytes,3,opt,name=response"`
}

// AuthorizationConditionsRequest describes the authorization conditions request.
type AuthorizationConditionsRequest struct {
	Decision ConditionsAwareDecision `json:"decision" protobuf:"bytes,1,opt,name=decision"`

	Target AuthorizationConditionsTarget `json:"target" protobuf:"bytes,2,opt,name=target"`
}

type AuthorizationConditionsTarget struct {
	Type ConditionsTarget `json:"type" protobuf:"bytes,1,opt,name=type"`

	AdmissionControl *AuthorizationConditionsTargetAdmissionControl `json:"admissionControl,omitempty" protobuf:"bytes,2,opt,name=admissionControl"`
}

type AuthorizationConditionsTargetAdmissionControl struct {
	// UID is an identifier for the individual request/response. It allows us to distinguish instances of requests which are
	// otherwise identical (parallel requests, requests when earlier requests did not modify etc)
	// The UID is meant to track the round trip (request/response) between the KAS and the WebHook, not the user request.
	// It is suitable for correlating log entries between the webhook and apiserver, for either auditing or debugging.
	// TODO: Does this need to be here?
	// UID types.UID `json:"uid" protobuf:"bytes,1,opt,name=uid"`
	// Kind is the fully-qualified type of object being submitted (for example, v1.Pod or autoscaling.v1.Scale)
	// Kind metav1.GroupVersionKind `json:"kind" protobuf:"bytes,2,opt,name=kind"`
	// Resource is the fully-qualified resource being requested (for example, v1.pods)
	// Resource metav1.GroupVersionResource `json:"resource" protobuf:"bytes,3,opt,name=resource"`
	// SubResource is the subresource being requested, if any (for example, "status" or "scale")
	// +optional
	// SubResource string `json:"subResource,omitempty" protobuf:"bytes,4,opt,name=subResource"`

	// RequestKind is the fully-qualified type of the original API request (for example, v1.Pod or autoscaling.v1.Scale).
	// If this is specified and differs from the value in "kind", an equivalent match and conversion was performed.
	//
	// For example, if deployments can be modified via apps/v1 and apps/v1beta1, and a webhook registered a rule of
	// `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]` and `matchPolicy: Equivalent`,
	// an API request to apps/v1beta1 deployments would be converted and sent to the webhook
	// with `kind: {group:"apps", version:"v1", kind:"Deployment"}` (matching the rule the webhook registered for),
	// and `requestKind: {group:"apps", version:"v1beta1", kind:"Deployment"}` (indicating the kind of the original API request).
	//
	// See documentation for the "matchPolicy" field in the webhook configuration type for more details.
	// +optional
	// RequestKind *metav1.GroupVersionKind `json:"requestKind,omitempty" protobuf:"bytes,14,opt,name=requestKind"`
	// RequestResource is the fully-qualified resource of the original API request (for example, v1.pods).
	// If this is specified and differs from the value in "resource", an equivalent match and conversion was performed.
	//
	// For example, if deployments can be modified via apps/v1 and apps/v1beta1, and a webhook registered a rule of
	// `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]` and `matchPolicy: Equivalent`,
	// an API request to apps/v1beta1 deployments would be converted and sent to the webhook
	// with `resource: {group:"apps", version:"v1", resource:"deployments"}` (matching the resource the webhook registered for),
	// and `requestResource: {group:"apps", version:"v1beta1", resource:"deployments"}` (indicating the resource of the original API request).
	//
	// See documentation for the "matchPolicy" field in the webhook configuration type.
	// +optional
	// RequestResource *metav1.GroupVersionResource `json:"requestResource,omitempty" protobuf:"bytes,15,opt,name=requestResource"`
	// RequestSubResource is the name of the subresource of the original API request, if any (for example, "status" or "scale")
	// If this is specified and differs from the value in "subResource", an equivalent match and conversion was performed.
	// See documentation for the "matchPolicy" field in the webhook configuration type.
	// +optional
	// RequestSubResource string `json:"requestSubResource,omitempty" protobuf:"bytes,16,opt,name=requestSubResource"`

	// Name is the name of the object as presented in the request.  On a CREATE operation, the client may omit name and
	// rely on the server to generate the name.  If that is the case, this field will contain an empty string.
	// +optional
	// Name string `json:"name,omitempty" protobuf:"bytes,5,opt,name=name"`
	// Namespace is the namespace associated with the request (if any).
	// +optional
	// Namespace string `json:"namespace,omitempty" protobuf:"bytes,6,opt,name=namespace"`
	// Operation is the operation being performed. This may be different than the operation
	// requested. e.g. a patch can result in either a CREATE or UPDATE Operation.
	Operation admissionv1.Operation `json:"operation" protobuf:"bytes,7,opt,name=operation"`
	// AuthorizationVerb string                `json:"authorizationVerb" protobuf:"bytes,8,opt,name=authorizationVerb"`

	// UserInfo is information about the requesting user
	// UserInfo authenticationv1.UserInfo `json:"userInfo" protobuf:"bytes,9,opt,name=userInfo"`
	// Object is the object from the incoming request.
	// +optional
	Object runtime.RawExtension `json:"object,omitempty" protobuf:"bytes,10,opt,name=object"`
	// OldObject is the existing object. Only populated for DELETE and UPDATE requests.
	// +optional
	OldObject runtime.RawExtension `json:"oldObject,omitempty" protobuf:"bytes,11,opt,name=oldObject"`
	// DryRun indicates that modifications will definitely not be persisted for this request.
	// Defaults to false.
	// +optional
	DryRun *bool `json:"dryRun,omitempty" protobuf:"varint,12,opt,name=dryRun"`
	// Options is the operation option structure of the operation being performed.
	// e.g. `meta.k8s.io/v1.DeleteOptions` or `meta.k8s.io/v1.CreateOptions`. This may be
	// different than the options the caller provided. e.g. for a patch request the performed
	// Operation might be a CREATE, in which case the Options will a
	// `meta.k8s.io/v1.CreateOptions` even though the caller provided `meta.k8s.io/v1.PatchOptions`.
	// +optional
	Options runtime.RawExtension `json:"options,omitempty" protobuf:"bytes,13,opt,name=options"`
}

// AuthorizationConditionsResponse describes an authorization conditions response.
type AuthorizationConditionsResponse struct {
	Decision ConditionsAwareDecision `json:"decision" protobuf:"bytes,1,opt,name=decision"`

	// UID is an identifier for the individual request/response.
	// This must be copied over from the corresponding AuthorizationConditionsRequest.
	// TODO: Does this need to be here?
	// UID types.UID `json:"uid" protobuf:"bytes,2,opt,name=uid"`

	// Result contains extra details into why an authorization conditions request was denied.
	// This field IS NOT consulted in any way if "Allowed" is "true".
	// +optional
	// Result *metav1.Status `json:"status,omitempty" protobuf:"bytes,3,opt,name=status"`

	// AuditAnnotations is an unstructured key value map set by remote admission controller (e.g. error=image-blacklisted).
	// MutatingAdmissionWebhook and ValidatingAdmissionWebhook admission controller will prefix the keys with
	// admission webhook name (e.g. imagepolicy.example.com/error=image-blacklisted). AuditAnnotations will be provided by
	// the admission webhook to add additional context to the audit log for this request.
	// TODO: Does this need to be here?
	// +optional
	// AuditAnnotations map[string]string `json:"auditAnnotations,omitempty" protobuf:"bytes,4,opt,name=auditAnnotations"`

	// warnings is a list of warning messages to return to the requesting API client.
	// Warning messages describe a problem the client making the API request should correct or be aware of.
	// Limit warnings to 120 characters if possible.
	// Warnings over 256 characters and large numbers of warnings may be truncated.
	// TODO: Does this need to be here?
	// +optional
	// +listType=atomic
	// Warnings []string `json:"warnings,omitempty" protobuf:"bytes,5,rep,name=warnings"`
}

// ConditionEffect specifies how a condition evaluating to
// true should be treated.
// +enum
type ConditionEffect string

const (
	// ConditionEffectAllow means that if this condition
	// evaluates to true, the ConditionsMap evaluates to Allow, unless any
	// Deny/NoOpinion condition also evaluates to true.
	ConditionEffectAllow ConditionEffect = "Allow"

	// ConditionEffectDeny means that if this condition
	// evaluates to true, the ConditionsMap necessarily evaluates to Deny.
	// No further authorizers are consulted.
	ConditionEffectDeny ConditionEffect = "Deny"

	// ConditionEffectNoOpinion means that if this condition
	// evaluates to true, the given authorizer's ConditionsMap cannot evaluate
	// to Allow anymore, but necessarily Deny or NoOpinion.
	ConditionEffectNoOpinion ConditionEffect = "NoOpinion"
)

// ConditionsTarget represents a target data set a condition should be evaluated against.
// +enum
type ConditionsTarget string

const (
	// ConditionsTargetAdmissionControl represents that a condition can be written against
	// the data available in admission, for example, Object and OldObject.
	ConditionsTargetAdmissionControl ConditionsTarget = "AdmissionControl"
)

// Condition represents a single authorization condition to be evaluated against
// data available later in the request chain, e.g. objects available in admission.
type Condition struct {
	// id uniquely identifies this condition within the scope of the authorizer
	// that authored it. Validated as a Kubernetes label key.
	// +required
	ID string `json:"id" protobuf:"bytes,1,opt,name=id"`

	// effect specifies how the condition evaluating to "true" should be treated.
	// +required
	Effect ConditionEffect `json:"effect" protobuf:"bytes,2,opt,name=effect"`

	// condition is an opaque string that represents the condition to be evaluated.
	// It is a pure, deterministic function from condition data to a boolean.
	// +required
	Condition string `json:"condition" protobuf:"bytes,3,opt,name=condition"`

	// description is an optional human-friendly description that can be shown
	// as an error message or for debugging.
	// +optional
	Description string `json:"description,omitempty" protobuf:"bytes,4,opt,name=description"`
}

// ConditionsMap represents a map of conditions.
type ConditionsMap struct {
	// conditionsTarget describes the target data the conditions are written against.
	// +required
	ConditionsTarget ConditionsTarget `json:"conditionsTarget" protobuf:"bytes,1,opt,name=conditionsTarget,casttype=ConditionsTarget"`

	// conditionsType describes the type (format/encoding/language) of all conditions in the map.
	// +required
	ConditionsType string `json:"conditionsType" protobuf:"bytes,2,opt,name=conditionsType"`

	// conditions is an unordered map of conditions, keyed by ID, that should be evaluated
	// against the specified, to determine whether the authorizer that authored the conditions
	// allows the request.
	// If any ConditionsEffect=Deny condition evaluates to true or errors, the evaluated decision must be Deny.
	// Else if any ConditionsEffect=NoOpinion condition evaluates to true or errors, the evaluated decision must be NoOpinion.
	// Else if any ConditionsEffect=Allow condition evaluates to true, the evaluated decision must be Allow.
	// Else, the evaluated decision must be NoOpinion.
	// +listType=map
	// +listMapKey=id
	// +required
	Conditions []Condition `json:"conditions" protobuf:"bytes,3,rep,name=conditions"`
}

// ConditionsAwareDecisionType is an enum representing what kind of authorization decision
// the ConditionsAwareDecision represents. The zero value represents the Deny type.
// +enum
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
	// +required
	Type ConditionsAwareDecisionType `json:"type" protobuf:"bytes,1,opt,name=type,casttype=ConditionsAwareDecisionType"`

	// reason is optional. It indicates why a request was allowed or denied.
	// +optional
	Reason string `json:"reason,omitempty" protobuf:"bytes,2,opt,name=reason"`

	// evaluationError is an indication that some error occurred during the authorization check.
	// It is entirely possible to get an error and be able to continue determine authorization status in spite of it.
	// For instance, RBAC can be missing a role, but enough roles are still present and bound to reason about the request.
	// +optional
	EvaluationError string `json:"evaluationError,omitempty" protobuf:"bytes,3,opt,name=evaluationError"`

	// conditionsMap represents a conditional decision, modelled as a map of conditions.
	// Must be non-null when type == "ConditionsMap", otherwise this field must be unset.
	// +optional
	ConditionsMap *ConditionsMap `json:"conditionsMap,omitempty" protobuf:"bytes,4,opt,name=conditionsMap"`

	// union forms an ordered tree of decisions, where the union decision is represented by
	// an internal node, and all other decision types are leaf nodes. During evaluation, the
	// leaf decisions are evaluated in depth-first order, until an Allow or Deny decision is found.
	// The order of the decisions must match exactly the order of the authorizers in the union authorizer.
	// At least one of the leaves must be of type ConditionsMap, as otherwise the union could be trivially
	// reduced to just a single Allow/Deny/NoOpinion.
	//
	// Must have at least one element when type == "Union", otherwise this field must be unset.
	//
	// +optional
	// +listType=atomic
	Union []ConditionsAwareDecision `json:"union,omitempty" protobuf:"bytes,5,rep,name=union"`
}
