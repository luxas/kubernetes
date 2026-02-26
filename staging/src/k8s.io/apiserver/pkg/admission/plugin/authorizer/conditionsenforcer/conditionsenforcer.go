package conditionsenforcer

import (
	"context"
	"errors"
	"fmt"
	"io"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apiserver/pkg/admission"
	genericadmissioninit "k8s.io/apiserver/pkg/admission/initializer"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/filters"
	"k8s.io/apiserver/pkg/endpoints/handlers/responsewriters"
	"k8s.io/apiserver/pkg/endpoints/request"
	genericfeatures "k8s.io/apiserver/pkg/features"
	"k8s.io/client-go/kubernetes"
	"k8s.io/component-base/featuregate"
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
var _ genericadmissioninit.WantsExternalKubeClientSet = &ConditionalAuthorizationEnforcer{}
var _ genericadmissioninit.WantsFeatures = &ConditionalAuthorizationEnforcer{}

func NewConditionalAuthorizationEnforcer() *ConditionalAuthorizationEnforcer {
	return &ConditionalAuthorizationEnforcer{
		enableBuiltinCEL: true,
	}
}

type ConditionalAuthorizationEnforcer struct {
	builtinConditionSetEvaluators  []authorizer.BuiltinConditionSetEvaluator
	featureEnabled                 bool
	setExternalKubeClientSetCalled bool
	enableBuiltinCEL               bool
}

func (c *ConditionalAuthorizationEnforcer) InspectFeatureGates(features featuregate.FeatureGate) {
	c.featureEnabled = features.Enabled(genericfeatures.ConditionalAuthorization)
}

func (c *ConditionalAuthorizationEnforcer) SetExternalKubeClientSet(cs kubernetes.Interface) {
	/*if c.enableBuiltinCEL {
		c.builtinConditionSetEvaluators = append(c.builtinConditionSetEvaluators, &celConditionsEnforcer{
			conditionCompiler: &ConditionCompiler{
				SchemaResolver: resolver.NewDefinitionsSchemaResolver(openapi.GetOpenAPIDefinitions).
					Combine(&resolver.ClientDiscoveryResolver{Discovery: cs.Discovery()}),
			},
		})
	}*/
	c.setExternalKubeClientSetCalled = true
}

func (c *ConditionalAuthorizationEnforcer) ValidateInitialization() error {
	if c.enableBuiltinCEL && !c.setExternalKubeClientSetCalled {
		return errors.New("SetExternalKubeClientSet was not called on the ConditionalAuthorizationEnforcer")
	}
	return nil
}

func (c *ConditionalAuthorizationEnforcer) Handles(operation admission.Operation) bool {
	return c.featureEnabled
}

func (c *ConditionalAuthorizationEnforcer) Validate(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) error {
	authorizer, unevaluatedDecision, ok := request.ConditionallyAuthorizedDecisionFrom(ctx)
	if !ok {
		// In the unconditionally authorized path, nothing is added to the context, hence this means "directly authorized"
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

	data := conditionsData{
		unionedAttributes: unionedAttributes{
			VersionedAttributes: versionedAttributes,
			authorizationVerb:   authzAttrs.GetVerb(),
		},
	}

	// The logic here should match the WithAuthorization filter logic.
	evaluatedDecision, err := authorizer.EvaluateConditions(ctx, unevaluatedDecision, data)
	if evaluatedDecision.IsAllowed() {
		return nil
	}

	if err != nil {
		//audit.AddAuditAnnotation(ctx, reasonAnnotationKey, reasonError)
		return apierrors.NewInternalError(err) // TODO: Check if this is the same as responsewriters.InternalError(w, req, err)
	}

	reason := evaluatedDecision.Reason()
	klog.V(4).InfoS("Forbidden (after conditional authorization)", "URI", authzAttrs.GetPath(), "reason", reason)
	//audit.AddAuditAnnotations(ctx,
	//	decisionAnnotationKey, decisionForbid,
	//	reasonAnnotationKey, reason)

	return apierrors.NewForbidden(versionedAttributes.GetResource().GroupResource(), versionedAttributes.GetName(), responsewriters.ForbiddenStatusError(authzAttrs, reason))
}

type conditionsData struct {
	unionedAttributes
}

func (d conditionsData) WriteRequest() authorizer.WriteRequestConditionData {
	return &d.unionedAttributes
}

func (d conditionsData) ImpersonationRequest() authorizer.ImpersonationRequestConditionData {
	return nil
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
