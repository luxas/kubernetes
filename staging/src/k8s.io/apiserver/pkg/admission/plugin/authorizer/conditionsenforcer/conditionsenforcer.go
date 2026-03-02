package conditionsenforcer

import (
	"context"
	"fmt"
	"io"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apiserver/pkg/admission"
	genericadmissioninit "k8s.io/apiserver/pkg/admission/initializer"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/filters"
	"k8s.io/apiserver/pkg/endpoints/handlers/responsewriters"
	"k8s.io/apiserver/pkg/endpoints/request"
	genericfeatures "k8s.io/apiserver/pkg/features"
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

// TODO: Add an integration test that it's not possible to intercept SAR or ACR using this admission controller

var _ admission.Interface = &ConditionalAuthorizationEnforcer{}
var _ admission.ValidationInterface = &ConditionalAuthorizationEnforcer{}

// var _ genericadmissioninit.WantsExternalKubeClientSet = &ConditionalAuthorizationEnforcer{}
var _ genericadmissioninit.WantsFeatures = &ConditionalAuthorizationEnforcer{}

func NewConditionalAuthorizationEnforcer() *ConditionalAuthorizationEnforcer {
	return &ConditionalAuthorizationEnforcer{
		builtinConditionSetEvaluators: []authorizer.ConditionSetEvaluator{&celConditionsEnforcer{}},
	}
}

type ConditionalAuthorizationEnforcer struct {
	builtinConditionSetEvaluators []authorizer.ConditionSetEvaluator
	featureEnabled                bool
	//setExternalKubeClientSetCalled bool
	//enableBuiltinCEL               bool
}

func (c *ConditionalAuthorizationEnforcer) InspectFeatureGates(features featuregate.FeatureGate) {
	c.featureEnabled = features.Enabled(genericfeatures.ConditionalAuthorization)
}

/*func (c *ConditionalAuthorizationEnforcer) SetExternalKubeClientSet(cs kubernetes.Interface) {
	if c.enableBuiltinCEL {
		c.builtinConditionSetEvaluators = append(c.builtinConditionSetEvaluators, &celConditionsEnforcer{
			conditionCompiler: &ConditionCompiler{
				SchemaResolver: resolver.NewDefinitionsSchemaResolver(openapi.GetOpenAPIDefinitions).
					Combine(&resolver.ClientDiscoveryResolver{Discovery: cs.Discovery()}),
			},
		})
	}
	c.setExternalKubeClientSetCalled = true
}*/

func (c *ConditionalAuthorizationEnforcer) ValidateInitialization() error {
	/*if c.enableBuiltinCEL && !c.setExternalKubeClientSetCalled {
		return errors.New("SetExternalKubeClientSet was not called on the ConditionalAuthorizationEnforcer")
	}*/
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

	authzAttrs, err := filters.GetAuthorizerAttributes(ctx)
	if err != nil {
		return fmt.Errorf("failed to get authorizer attributes: %w", err)
	}

	//admissionRequest := plugincel.CreateAdmissionRequest(a, metav1.GroupVersionResource(a.GetResource()), metav1.GroupVersionKind(a.GetKind()))
	// TODO(luxas): CEL evaluation
	return EnforceConditions(ctx, a, o, authorizer, authzAttrs, unevaluatedDecision)
}

// TODO(luxas): This function should probably be under the authorizer package, and then this concrete admission plugin just returns it?
func EnforceConditions(ctx context.Context, admissionAttrs admission.Attributes, o admission.ObjectInterfaces, authorizer authorizer.Authorizer, authzAttrs authorizer.Attributes, unevaluatedDecision authorizer.Decision, builtinEvaluators ...authorizer.ConditionSetEvaluator) error {
	// TODO: Does this convert to the request GVR version?
	versionedAttributes, err := admission.NewVersionedAttributes(admissionAttrs, admissionAttrs.GetKind(), o)
	if err != nil {
		return fmt.Errorf("failed to convert object version: %w", err)
	}

	data := conditionsData{
		attrsShim: attrsShim{
			VersionedAttributes: versionedAttributes,
		},
	}

	errlist := []error{}
	evaluatedDecision := unevaluatedDecision
	// TODO: This logic should also exist in the union authorizer, so we should probably share the code.
	for _, builtinEvaluator := range builtinEvaluators {
		evaluatedDecisionAfter, err := builtinEvaluator.EvaluateConditions(ctx, evaluatedDecision, data)
		if err != nil {
			errlist = append(errlist, err)
		}
		if evaluatedDecisionAfter.IsConcrete() {
			break
		}
		evaluatedDecision = evaluatedDecisionAfter
	}

	if !evaluatedDecision.IsConcrete() {
		evaluatedDecision, err = authorizer.EvaluateConditions(ctx, unevaluatedDecision, data)
		errlist = append(errlist, err)
	}

	// At this point, we require an unconditional allow in order to proceed.
	if evaluatedDecision.IsAllowed() {
		return nil
	}

	err = utilerrors.NewAggregate(errlist)
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
	attrsShim
}

func (d conditionsData) WriteRequest() authorizer.WriteRequestConditionData {
	return &d.attrsShim
}

func (d conditionsData) ImpersonationRequest() authorizer.ImpersonationRequestConditionData {
	return nil
}

type attrsShim struct {
	*admission.VersionedAttributes
}

// TODO: Can the authorizer package depend on the admission package? If not, we need to add this cast.
func (u *attrsShim) GetOperation() string {
	return string(u.Attributes.GetOperation())
}
