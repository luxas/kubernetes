/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package conditionsenforcer

import (
	"context"
	"fmt"
	"io"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apiserver/pkg/admission"
	genericadmissioninit "k8s.io/apiserver/pkg/admission/initializer"
	"k8s.io/apiserver/pkg/audit"
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
		return NewConditionalAuthorizationEnforcer(false), nil // Default off, can be overridden by InspectFeatureGates
	})
}

// TODO(luxas): Add an integration test that it's not possible to intercept SAR or ACR using this admission controller
// TODO(luxas): Should VAP-related objects be added to the exclusion list for conditions? Most likely yes.

var _ admission.Interface = &conditionsEnforcer{}
var _ admission.ValidationInterface = &conditionsEnforcer{}
var _ genericadmissioninit.WantsFeatures = &conditionsEnforcer{}

// NewConditionalAuthorizationEnforcer instantiates a new authorization conditions enforcer admission plugin
func NewConditionalAuthorizationEnforcer(featureEnabled bool) *conditionsEnforcer {
	return &conditionsEnforcer{
		featureEnabled: featureEnabled,
	}
}

type conditionsEnforcer struct {
	featureEnabled bool
}

func (c *conditionsEnforcer) InspectFeatureGates(features featuregate.FeatureGate) {
	c.featureEnabled = features.Enabled(genericfeatures.ConditionalAuthorization)
}

func (c *conditionsEnforcer) ValidateInitialization() error {
	return nil
}

func (c *conditionsEnforcer) Handles(operation admission.Operation) bool {
	return c.featureEnabled
}

func (c *conditionsEnforcer) Validate(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) error {
	// Safety check, never operate when not enabled.
	if !c.featureEnabled {
		return nil
	}

	authz, decisionToEnforce, ok := request.ConditionallyAuthorizedDecisionFrom(ctx)
	if !ok {
		// If there no decision in the context, WithConditionsAwareAuthorization was not used, and thus there is nothing to enforce.
		return nil
	}

	// TODO(luxas): This should be admission.NewVersionedAttributes when it correctly overrides GetOldObject()
	versionedAttributes, err := newVersionedAttributes(a, a.GetKind(), o)
	if err != nil {
		return fmt.Errorf("failed to convert objects to request version: %w", err)
	}

	var decision authorizer.Decision
	var reason string
	if decisionToEnforce.IsUnconditional() {
		decision, reason, err = decisionToEnforce.UnconditionalParts()
	} else {
		decision, reason, err = authz.EvaluateConditions(ctx, decisionToEnforce, versionedAttributes)
	}

	// The code flow here should exactly match filters.WithAuthorization.
	// an authorizer could encounter evaluation errors and still allow the request, so authorizer decision is checked before error here.
	if decision == authorizer.DecisionAllow {
		audit.AddAuditAnnotations(ctx,
			filters.DecisionAnnotationKey, filters.DecisionAllow,
			filters.ReasonAnnotationKey, reason)
		return nil
	}

	if err != nil {
		audit.AddAuditAnnotation(ctx, filters.ReasonAnnotationKey, filters.ReasonError)
		return apierrors.NewInternalError(err)
	}

	authzAttrs, err := filters.GetAuthorizerAttributes(ctx)
	if err != nil {
		return fmt.Errorf("failed to get authorizer attributes: %w", err)
	}

	klog.V(4).InfoS("Forbidden (during conditional authorization)", "URI", authzAttrs.GetPath(), "reason", reason)
	audit.AddAuditAnnotations(ctx,
		filters.DecisionAnnotationKey, filters.DecisionForbid,
		filters.ReasonAnnotationKey, reason)

	return apierrors.NewForbidden(versionedAttributes.GetResource().GroupResource(), versionedAttributes.GetName(), responsewriters.ForbiddenStatusError(authzAttrs, reason))
}
