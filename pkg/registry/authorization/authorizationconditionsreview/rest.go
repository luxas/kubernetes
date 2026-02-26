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

package authorizationconditionsreview

import (
	"context"
	"fmt"
	"iter"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/registry/rest"
	authorizationapi "k8s.io/kubernetes/pkg/apis/authorization"
	authorizationutil "k8s.io/kubernetes/pkg/registry/authorization/util"
)

type REST struct {
	serializer runtime.Serializer
}

func NewREST(serializer runtime.Serializer) *REST {
	return &REST{serializer}
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
	return "authorizationconditionsreview"
}

func (r *REST) Create(ctx context.Context, acr runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions) (runtime.Object, error) {
	authorizationConditionsReview, ok := acr.(*authorizationapi.AuthorizationConditionsReview)
	if !ok {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("not a AuthorizationConditionsReview: %#v", acr))
	}
	/*if errs := authorizationvalidation.ValidateSubjectAccessReview(subjectAccessReview); len(errs) > 0 {
		return nil, apierrors.NewInvalid(authorizationapi.Kind(subjectAccessReview.Kind), "", errs)
	}*/

	if createValidation != nil {
		if err := createValidation(ctx, acr.DeepCopyObject()); err != nil {
			return nil, err
		}
	}

	// TODO: should this be a pointer? Should we reset on answer to write less?
	if authorizationConditionsReview.Request == nil {
		// nothing to evaluate TODO: should this set NoOpinion specifically or return bad request?
		return acr, nil
	}

	authorizationAttributes := authorizationutil.AuthorizationAttributesFrom(subjectAccessReview.Spec)
	decision, evaluationErr := r.authorizer.Authorize(ctx, authorizationAttributes)

	subjectAccessReview.Status = authorizationutil.AuthorizerDecisionToSARStatus(authorizationAttributes, decision, evaluationErr)

	return subjectAccessReview, nil
}

func (r *REST) toConditionsData(acr *authorizationapi.AuthorizationConditionsReview) (authorizer.ConditionData, error) {
	// TODO: nil pointer for WriteRequest

	wr := &conditionsDataWriteRequest{
		operation: string(acr.Request.WriteRequest.Operation),
	}

	var err error
	// TODO: Verify this encodes into runtime.RawExtension if we don't know what type it is
	// TODO: Or does
	wr.object, _, err = r.serializer.Decode(acr.Request.WriteRequest.Object.Raw, nil, nil)
	if err != nil {
		return nil, err
	}

	wr.oldObject, _, err = r.serializer.Decode(acr.Request.WriteRequest.OldObject.Raw, nil, nil)
	if err != nil {
		return nil, err
	}

	// TODO: How to decode options?
}

var _ authorizer.ConditionData = &conditionsData{}

type conditionsData struct {
	writeReq *conditionsDataWriteRequest
}

func (d *conditionsData) WriteRequest() authorizer.WriteRequestConditionData {
	if d.writeReq == nil {
		return nil
	}
	return d.writeReq
}

func (d *conditionsData) ImpersonationRequest() authorizer.ImpersonationRequestConditionData {
	return nil
}

var _ authorizer.WriteRequestConditionData = &conditionsDataWriteRequest{}

type conditionsDataWriteRequest struct {
	object    runtime.Object
	oldObject runtime.Object
	options   runtime.Object // TODO: how are these encoded?
	operation string
}

func (r *conditionsDataWriteRequest) GetOperation() string                { return r.operation }
func (r *conditionsDataWriteRequest) GetOperationOptions() runtime.Object { return r.options }
func (r *conditionsDataWriteRequest) GetObject() runtime.Object           { return r.object }
func (r *conditionsDataWriteRequest) GetOldObject() runtime.Object        { return r.oldObject }

// TODO: Figure out how to de-duplicate this logic with the webhook authorizer
func toAuthorizerConditions(conditionList []authorizationapi.SubjectAccessReviewCondition) iter.Seq2[string, authorizer.Condition] {
	return func(yield func(string, authorizer.Condition) bool) {
		for _, condition := range conditionList {
			cond := authorizer.Condition{
				Effect:      authorizer.ConditionEffect(condition.Effect),
				Condition:   condition.Condition,
				Description: condition.Description,
			}
			if !yield(condition.ID, cond) {
				return
			}
		}
	}
}

func deserializeDecision(attrs authorizer.Attributes, serializedDecision authorizationapi.SubjectAccessReviewAuthorizationDecision) (authorizer.Decision, error) {
	if serializedDecision.Denied && serializedDecision.Allowed {
		return authorizer.DecisionDeny(serializedDecision.Reason), fmt.Errorf("webhook subject access review returned both allow and deny response")
	}

	hasConditionSet := len(serializedDecision.Conditions) != 0
	hasDecisionChain := len(serializedDecision.ConditionalDecisionChain) != 0

	// check all newly-introduced mutual exclusion possibilities
	// this function is only ever called when the conditional authorization feature gate is enabled
	if serializedDecision.Denied && hasConditionSet {
		return authorizer.DecisionDeny(), fmt.Errorf("webhook subject access review: mutually exclusive Denied and Conditions are both specified")
	}
	if serializedDecision.Denied && hasDecisionChain {
		return authorizer.DecisionDeny(), fmt.Errorf("webhook subject access review: mutually exclusive Denied and ConditionalDecisionChain are both specified")
	}
	if serializedDecision.Allowed && hasConditionSet {
		return authorizer.DecisionDeny(), fmt.Errorf("webhook subject access review: mutually exclusive Allowed and Conditions are both specified")
	}
	if serializedDecision.Allowed && hasDecisionChain {
		return authorizer.DecisionDeny(), fmt.Errorf("webhook subject access review: mutually exclusive Allowed and ConditionalDecisionChain are both specified")
	}
	if hasConditionSet && hasDecisionChain {
		return authorizer.DecisionDeny(), fmt.Errorf("webhook subject access review: mutually exclusive Conditions and ConditionalDecisionChain are both specified")
	}

	if serializedDecision.Denied {
		return authorizer.DecisionDeny(serializedDecision.Reason), nil
	}

	if serializedDecision.Allowed {
		return authorizer.DecisionAllow(serializedDecision.Reason), nil
	}

	if hasConditionSet {
		return authorizer.DecisionConditional(attrs, serializedDecision.ConditionsType, toAuthorizerConditions(serializedDecision.Conditions))
	}

	if hasDecisionChain {
		subDecisions := make([]authorizer.Decision, 0, len(serializedDecision.ConditionalDecisionChain))
		for _, serializedSubDecision := range serializedDecision.ConditionalDecisionChain {
			subDecision, err := deserializeDecision(attrs, serializedSubDecision)
			if err != nil {
				return authorizer.DecisionDeny(), err
			}
			subDecisions = append(subDecisions, subDecision)
		}
		return authorizer.DecisionConditionalChain(subDecisions...), nil
	}

	return authorizer.DecisionNoOpinion(serializedDecision.Reason), nil
}
