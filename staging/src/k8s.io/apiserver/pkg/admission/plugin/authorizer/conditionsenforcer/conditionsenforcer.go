package conditionsenforcer

import (
	"context"
	"fmt"
	"io"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/filters"
	"k8s.io/apiserver/pkg/endpoints/handlers/responsewriters"
	"k8s.io/apiserver/pkg/endpoints/request"
	genericfeatures "k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/klog/v2"
)

const (
	// PluginName indicates the name of admission plug-in
	PluginName = "AuthorizationConditionsEnforcer"
)

// Register registers a plugin
func Register(plugins *admission.Plugins) {
	plugins.Register(PluginName, func(config io.Reader) (admission.Interface, error) {
		return NewConditionalAuthorizationEnforcer(), nil
	})
}

// TODO: Should we opt out of enforcing conditions for authorization-related resources?
// Or actually, it could be useful as well, to say that someone can only request some specific SAR requests.
/*var optOutGVRs = sets.New(
	schema.GroupVersionResource{Group: authorizationv1.SchemeGroupVersion.Group, Version: authorizationv1.SchemeGroupVersion.Version, Resource: "selfsubjectaccessreviews"},
)*/

var _ admission.Interface = &ConditionalAuthorizationEnforcer{}
var _ admission.ValidationInterface = &ConditionalAuthorizationEnforcer{}

func NewConditionalAuthorizationEnforcer() *ConditionalAuthorizationEnforcer {
	return &ConditionalAuthorizationEnforcer{}
}

type ConditionalAuthorizationEnforcer struct{}

func (c *ConditionalAuthorizationEnforcer) Handles(operation admission.Operation) bool {
	return utilfeature.DefaultFeatureGate.Enabled(genericfeatures.ConditionalAuthorization)
}

func (c *ConditionalAuthorizationEnforcer) Validate(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) error {
	enforcer, ok := request.ConditionalAuthorizationContextFrom(ctx)
	if !ok {
		return nil
	}

	versionedAttributes, err := admission.NewVersionedAttributes(a, a.GetKind(), o)
	if err != nil {
		return fmt.Errorf("failed to convert object version: %w", err)
	}

	authzAttrs, err := filters.GetAuthorizerAttributes(ctx)
	if err != nil {
		return fmt.Errorf("failed to get authorizer attributes: %w", err)
	}

	//admissionRequest := plugincel.CreateAdmissionRequest(a, metav1.GroupVersionResource(a.GetResource()), metav1.GroupVersionKind(a.GetKind()))

	unionedAttrs := &unionedAttributes{
		VersionedAttributes: versionedAttributes,
		authorizationVerb:   authzAttrs.GetVerb(),
	}

	decision, reason, err := enforcer.EnforceConditions(ctx, unionedAttrs)
	if decision == authorizer.DecisionAllow {
		return nil
	}

	if err != nil {
		//audit.AddAuditAnnotation(ctx, reasonAnnotationKey, reasonError)
		return apierrors.NewInternalError(err) // TODO: Check if this is the same as responsewriters.InternalError(w, req, err)
	}

	klog.V(4).InfoS("Forbidden (after conditional authorization)", "URI", authzAttrs.GetPath(), "reason", reason)
	//audit.AddAuditAnnotations(ctx,
	//	decisionAnnotationKey, decisionForbid,
	//	reasonAnnotationKey, reason)

	return apierrors.NewForbidden(versionedAttributes.GetResource().GroupResource(), versionedAttributes.GetName(), responsewriters.ForbiddenStatusError(authzAttrs, reason))
}

type unionedAttributes struct {
	*admission.VersionedAttributes
	authorizationVerb string
}

func (u *unionedAttributes) GetAuthorizationVerb() string {
	return u.authorizationVerb
}

func (u *unionedAttributes) GetOperation() string {
	return string(u.Attributes.GetOperation())
}
