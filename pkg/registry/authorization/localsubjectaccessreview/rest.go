/*
Copyright 2016 The Kubernetes Authors.

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

package localsubjectaccessreview

import (
	"context"
	"fmt"

	authorizationv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	authorizationvalidation "k8s.io/apiserver/pkg/apis/authorization/validation"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	genericfeatures "k8s.io/apiserver/pkg/features"
	"k8s.io/apiserver/pkg/registry/rest"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	authorizationapi "k8s.io/kubernetes/pkg/apis/authorization"
	authorizationutil "k8s.io/kubernetes/pkg/registry/authorization/util"
)

type REST struct {
	authorizer authorizer.Authorizer
	scheme     *runtime.Scheme
}

func NewREST(authorizer authorizer.Authorizer, scheme *runtime.Scheme) *REST {
	return &REST{authorizer, scheme}
}

func (r *REST) NamespaceScoped() bool {
	return true
}

func (r *REST) New() runtime.Object {
	return &authorizationapi.LocalSubjectAccessReview{}
}

// Destroy cleans up resources on shutdown.
func (r *REST) Destroy() {
	// Given no underlying store, we don't destroy anything
	// here explicitly.
}

var _ rest.SingularNameProvider = &REST{}

func (r *REST) GetSingularName() string {
	return "localsubjectaccessreview"
}

func (r *REST) Create(ctx context.Context, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions) (runtime.Object, error) {
	localSubjectAccessReview, ok := obj.(*authorizationapi.LocalSubjectAccessReview)
	if !ok {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("not a LocalSubjectAccessReview: %#v", obj))
	}

	// Clear status so it's not taken into account during input validation.
	// This is important, as we cannot make validation stricter; in k8s 1.36 and before, the client was able to pass a bogus status without a validation error.
	localSubjectAccessReview.Status = authorizationapi.SubjectAccessReviewStatus{}

	// Clear the options for opting into conditions-awareness when the feature gate is off.
	// This means that we fallback to the conditions-unaware Authorize when the feature gate is
	// off, even though both the client and authorizer might have supported conditions.
	if !utilfeature.DefaultFeatureGate.Enabled(genericfeatures.ConditionalAuthorization) {
		localSubjectAccessReview.Spec.AuthorizationOptions = nil
	}

	ri, ok := request.RequestInfoFrom(ctx)
	if !ok {
		return nil, apierrors.NewBadRequest("expected a RequestInfo in the context")
	}

	// The hand-written validations are written only once, for the most recent external API version, so that also k8s.io/apiserver
	// importers can make use of the validations.
	localSubjectAccessReviewV1 := &authorizationv1.LocalSubjectAccessReview{}
	if err := r.scheme.Convert(localSubjectAccessReview, localSubjectAccessReviewV1, nil); err != nil {
		return nil, fmt.Errorf("unexpected, could not convert internal LocalSubjectAccessReview to v1: %w", err)
	}

	if errs := authorizationvalidation.ValidateLocalSubjectAccessReviewCreate(ctx, r.scheme, localSubjectAccessReviewV1, ri.APIVersion); len(errs) > 0 {
		return nil, apierrors.NewInvalid(authorizationapi.Kind(localSubjectAccessReview.Kind), "", errs)
	}
	namespace := genericapirequest.NamespaceValue(ctx)
	if len(namespace) == 0 {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("namespace is required on this type: %v", namespace))
	}
	if namespace != localSubjectAccessReview.Namespace {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("spec.resourceAttributes.namespace must match namespace: %v", namespace))
	}

	if createValidation != nil {
		if err := createValidation(ctx, obj.DeepCopyObject()); err != nil {
			return nil, err
		}
	}

	authorizationAttributes := authorizationutil.AuthorizationAttributesFrom(localSubjectAccessReview.Spec)

	// Only activate Conditional Authorization if both the server and client supports it
	if utilfeature.DefaultFeatureGate.Enabled(genericfeatures.ConditionalAuthorization) && localSubjectAccessReviewV1.Spec.AuthorizationOptions.SupportsConditionalAuthorization() {
		conditionsAwareDecision := r.authorizer.ConditionsAwareAuthorize(ctx, authorizationAttributes)
		localSubjectAccessReview.Status = authorizationutil.ConditionsAwareDecisionToSARStatus(ctx, authorizationAttributes, conditionsAwareDecision)

	} else if localSubjectAccessReviewV1.Spec.AuthorizationOptions.SupportsUnconditionalAuthorization() {
		// conditions-unaware flow, feature gate is off or client does not support conditions
		decision, reason, evaluationErr := r.authorizer.Authorize(ctx, authorizationAttributes)

		localSubjectAccessReview.Status = authorizationapi.SubjectAccessReviewStatus{
			Allowed:         (decision == authorizer.DecisionAllow),
			Denied:          (decision == authorizer.DecisionDeny),
			Reason:          reason,
			EvaluationError: authorizationutil.BuildEvaluationError(evaluationErr, authorizationAttributes),
		}
	} else {
		// the HandledDecisionTypes was neither [Allow, ConditionsMap, Deny, NoOpinion, Union] or [Allow, Deny, NoOpinion], reject it.
		return nil, apierrors.NewBadRequest(fmt.Sprintf("unsupported client-handled decision types: %v", sets.List(localSubjectAccessReviewV1.Spec.AuthorizationOptions.GetHandledDecisionTypes())))
	}

	return localSubjectAccessReview, nil
}
