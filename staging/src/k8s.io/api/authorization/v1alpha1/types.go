package v1alpha1

import (
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:prerelease-lifecycle-gen:introduced=1.19

// AuthorizationConditionsReview describes a request to evaluate authorization conditions.
type AuthorizationConditionsReview struct {
	metav1.TypeMeta `json:",inline"`
	// Request describes the attributes for the authorization conditions request.
	// +optional
	Request *AuthorizationConditionsRequest `json:"request,omitempty" protobuf:"bytes,1,opt,name=request"`
	// Response describes the attributes for the authorization conditions response.
	// +optional
	Response *AuthorizationConditionsResponse `json:"response,omitempty" protobuf:"bytes,2,opt,name=response"`
}

// AuthorizationConditionsRequest describes the authorization conditions request.
type AuthorizationConditionsRequest struct {
	// UID is an identifier for the individual request/response. It allows us to distinguish instances of requests which are
	// otherwise identical (parallel requests, requests when earlier requests did not modify etc)
	// The UID is meant to track the round trip (request/response) between the KAS and the WebHook, not the user request.
	// It is suitable for correlating log entries between the webhook and apiserver, for either auditing or debugging.
	// TODO: Does this need to be here?
	UID types.UID `json:"uid" protobuf:"bytes,1,opt,name=uid"`
	// Kind is the fully-qualified type of object being submitted (for example, v1.Pod or autoscaling.v1.Scale)
	Kind metav1.GroupVersionKind `json:"kind" protobuf:"bytes,2,opt,name=kind"`
	// Resource is the fully-qualified resource being requested (for example, v1.pods)
	Resource metav1.GroupVersionResource `json:"resource" protobuf:"bytes,3,opt,name=resource"`
	// SubResource is the subresource being requested, if any (for example, "status" or "scale")
	// +optional
	SubResource string `json:"subResource,omitempty" protobuf:"bytes,4,opt,name=subResource"`

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
	RequestKind *metav1.GroupVersionKind `json:"requestKind,omitempty" protobuf:"bytes,14,opt,name=requestKind"`
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
	RequestResource *metav1.GroupVersionResource `json:"requestResource,omitempty" protobuf:"bytes,15,opt,name=requestResource"`
	// RequestSubResource is the name of the subresource of the original API request, if any (for example, "status" or "scale")
	// If this is specified and differs from the value in "subResource", an equivalent match and conversion was performed.
	// See documentation for the "matchPolicy" field in the webhook configuration type.
	// +optional
	RequestSubResource string `json:"requestSubResource,omitempty" protobuf:"bytes,16,opt,name=requestSubResource"`

	// Name is the name of the object as presented in the request.  On a CREATE operation, the client may omit name and
	// rely on the server to generate the name.  If that is the case, this field will contain an empty string.
	// +optional
	Name string `json:"name,omitempty" protobuf:"bytes,5,opt,name=name"`
	// Namespace is the namespace associated with the request (if any).
	// +optional
	Namespace string `json:"namespace,omitempty" protobuf:"bytes,6,opt,name=namespace"`
	// Operation is the operation being performed. This may be different than the operation
	// requested. e.g. a patch can result in either a CREATE or UPDATE Operation.
	Operation         admissionv1.Operation `json:"operation" protobuf:"bytes,7,opt,name=operation"`
	AuthorizationVerb string                `json:"authorizationVerb" protobuf:"bytes,8,opt,name=authorizationVerb"`

	// UserInfo is information about the requesting user
	UserInfo authenticationv1.UserInfo `json:"userInfo" protobuf:"bytes,9,opt,name=userInfo"`
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

	ConditionSet authorizationv1.SubjectAccessReviewConditionSet `json:"conditionSet,omitempty" protobuf:"bytes,17,opt,name=conditionSet"`
}

// AuthorizationConditionsResponse describes an authorization conditions response.
type AuthorizationConditionsResponse struct {
	// UID is an identifier for the individual request/response.
	// This must be copied over from the corresponding AuthorizationConditionsRequest.
	// TODO: Does this need to be here?
	UID types.UID `json:"uid" protobuf:"bytes,1,opt,name=uid"`

	// Allowed indicates whether or not the request is authorized according to the authorization conditions.
	// Mutually exclusive with Denied.
	// Allowed=false and Denied=false means that the authorizer has no NoOpinion on the request.
	Allowed bool `json:"allowed" protobuf:"varint,2,opt,name=allowed"`

	// Denied indicates whether or not the request is denied according to the authorization conditions.
	// Mutually exclusive with Allowed.
	// Allowed=false and Denied=false means that the authorizer has no NoOpinion on the request.
	Denied bool `json:"denied,omitempty" protobuf:"varint,3,opt,name=denied"`

	// Result contains extra details into why an authorization conditions request was denied.
	// This field IS NOT consulted in any way if "Allowed" is "true".
	// +optional
	Result *metav1.Status `json:"status,omitempty" protobuf:"bytes,4,opt,name=status"`

	// AuditAnnotations is an unstructured key value map set by remote admission controller (e.g. error=image-blacklisted).
	// MutatingAdmissionWebhook and ValidatingAdmissionWebhook admission controller will prefix the keys with
	// admission webhook name (e.g. imagepolicy.example.com/error=image-blacklisted). AuditAnnotations will be provided by
	// the admission webhook to add additional context to the audit log for this request.
	// TODO: Does this need to be here?
	// +optional
	AuditAnnotations map[string]string `json:"auditAnnotations,omitempty" protobuf:"bytes,5,opt,name=auditAnnotations"`

	// warnings is a list of warning messages to return to the requesting API client.
	// Warning messages describe a problem the client making the API request should correct or be aware of.
	// Limit warnings to 120 characters if possible.
	// Warnings over 256 characters and large numbers of warnings may be truncated.
	// TODO: Does this need to be here?
	// +optional
	// +listType=atomic
	Warnings []string `json:"warnings,omitempty" protobuf:"bytes,6,rep,name=warnings"`
}
