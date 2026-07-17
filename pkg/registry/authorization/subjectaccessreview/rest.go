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

package subjectaccessreview

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
	return false
}

func (r *REST) New() runtime.Object {
	return &authorizationapi.SubjectAccessReview{}
}

// Destroy cleans up resources on shutdown.
func (r *REST) Destroy() {
	// Given no underlying store, we don't destroy anything
	// here explicitly.
}

var _ rest.SingularNameProvider = &REST{}

func (r *REST) GetSingularName() string {
	return "subjectaccessreview"
}

func (r *REST) Create(ctx context.Context, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions) (runtime.Object, error) {
	subjectAccessReview, ok := obj.(*authorizationapi.SubjectAccessReview)
	if !ok {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("not a SubjectAccessReview: %#v", obj))
	}

	// Clear status so it's not taken into account during input validation.
	subjectAccessReview.Status = authorizationapi.SubjectAccessReviewStatus{}

	// Clear the options for opting into conditions-awareness when the feature gate is off.
	// This means that we fallback to the conditions-unaware Authorize when the feature gate is
	// off, even though both the client and authorizer might have supported conditions.
	if !utilfeature.DefaultFeatureGate.Enabled(genericfeatures.ConditionalAuthorization) {
		subjectAccessReview.Spec.AuthorizationOptions = nil
	}

	subjectAccessReviewV1 := &authorizationv1.SubjectAccessReview{}
	if err := r.scheme.Convert(subjectAccessReview, subjectAccessReviewV1, nil); err != nil {
		return nil, fmt.Errorf("unexpected, could not convert internal SubjectAccessReview to v1: %w", err)
	}

	if errs := authorizationvalidation.ValidateSubjectAccessReviewCreate(ctx, r.scheme, subjectAccessReviewV1); len(errs) > 0 {
		return nil, apierrors.NewInvalid(authorizationapi.Kind(subjectAccessReview.Kind), "", errs)
	}

	if createValidation != nil {
		if err := createValidation(ctx, obj.DeepCopyObject()); err != nil {
			return nil, err
		}
	}

	authorizationAttributes := authorizationutil.AuthorizationAttributesFrom(subjectAccessReview.Spec)

	// Find out what decision types the client and server support, and below match against their intersection.
	serverHandledDecisionTypes := authorizationutil.ServerHandledDecisionTypes(utilfeature.DefaultFeatureGate.Enabled(genericfeatures.ConditionalAuthorization))
	clientHandledDecisionTypes := authorizationutil.ClientHandledDecisionTypes(subjectAccessReview.Spec.AuthorizationOptions)
	bothHandledDecisionTypes := serverHandledDecisionTypes.Intersection(clientHandledDecisionTypes)

	// Exact matches are performed against bothHandledDecisionTypes. If none of them match, the client provided an unsupported set,
	// for example [Allow], which we shall reject as a bad request, as this is HandledDecisionTypes is not covered by validation above.
	// The extra utilfeature.DefaultFeatureGate.Enabled(genericfeatures.ConditionalAuthorization) check here is technically redundant,
	// but should help the reader see that the conditional path only triggers when the feature gate is on.
	if authorizationutil.SupportsConditionalAuthorization(bothHandledDecisionTypes) && utilfeature.DefaultFeatureGate.Enabled(genericfeatures.ConditionalAuthorization) {
		// conditions-aware flow, feature gate is on and client supports conditions
		conditionsAwareDecision := r.authorizer.ConditionsAwareAuthorize(ctx, authorizationAttributes)
		subjectAccessReview.Status = authorizationutil.ConditionsAwareDecisionToSARStatus(ctx, authorizationAttributes, conditionsAwareDecision)

	} else if authorizationutil.SupportsUnconditionalAuthorization(bothHandledDecisionTypes) {
		// conditions-unaware flow, feature gate is off or client does not support conditions
		decision, reason, evaluationErr := r.authorizer.Authorize(ctx, authorizationAttributes)

		subjectAccessReview.Status = authorizationapi.SubjectAccessReviewStatus{
			Allowed:         (decision == authorizer.DecisionAllow),
			Denied:          (decision == authorizer.DecisionDeny),
			Reason:          reason,
			EvaluationError: authorizationutil.BuildEvaluationError(evaluationErr, authorizationAttributes),
		}
	} else {
		// bothHandledDecisionTypes was neither [Allow, ConditionsMap, Deny, NoOpinion, Union] or [Allow, Deny, NoOpinion], reject it.
		return nil, apierrors.NewBadRequest(fmt.Sprintf("unsupported client-handled decision types: %v", sets.List(clientHandledDecisionTypes)))
	}

	return subjectAccessReview, nil
}
