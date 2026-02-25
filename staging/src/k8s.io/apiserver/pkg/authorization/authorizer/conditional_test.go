/*
Copyright 2025 The Kubernetes Authors.

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

package authorizer

import (
	"context"
	"errors"
	"fmt"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
)

func TestDecisionZeroValueIsDeny(t *testing.T) {
	d := Decision{}
	if !d.IsDenied() {
		t.Fatal("Expected the zero value of Decision{} to be a Deny")
	}
	if d.String() != "Deny" {
		t.Fatal("Expected the zero value to string encode to 'Deny'")
	}
}

// TODO: Check that the Decision can only return true for one of the Is.. methods

type sampleAuthorizer struct{}

func (a sampleAuthorizer) Authorize(ctx context.Context, attrs Attributes) (Decision, error) {
	switch attrs.GetUser().GetName() {
	case "alice":
		return DecisionAllow(), nil
	case "bob":
		return DecisionDeny(), nil
	case "carol":
		// allow carol to read anything, but require seting the owner=carol label on writes
		switch attrs.GetVerb() {
		case "get", "list", "watch":
			return DecisionAllow(), nil
		case "create", "update", "delete":
			conditions, err := NewConditionSet("labelSelectorApplies", []Condition{
				{
					ID:        "owner-label-is-set",
					Condition: "owner=carol",
					Effect:    ConditionEffectAllow,
				},
			})
			if err != nil {
				return DecisionNoOpinion(), err
			}
			return DecisionConditional(*conditions, a, attrs), nil
		default:
			return DecisionNoOpinion(), nil
		}
	case "dave":
		// allow dave to read anything, but never set the classified label on writes
		switch attrs.GetVerb() {
		case "get", "list", "watch":
			return DecisionAllow(), nil
		case "create", "update", "delete":
			conditions, err := NewConditionSet("labelSelectorApplies", []Condition{
				{
					ID:        "owner-label-is-set",
					Condition: "supersecret",
					Effect:    ConditionEffectDeny,
				},
			})
			if err != nil {
				return DecisionNoOpinion(), err
			}
			return DecisionConditional(*conditions, a, attrs), nil
		default:
			return DecisionNoOpinion(), nil
		}
	default:
		return DecisionNoOpinion(), nil
	}
}

func (a sampleAuthorizer) EvaluateConditions(ctx context.Context, conditionSet *ConditionSet, data ConditionData) (Decision, error) {
	// TODO: improve this
	if data.WriteRequest() == nil {
		return conditionSet.FailClosedDecision(), errors.New("only supports conditions for write requests")
	}

	enforceObjects := []runtime.Object{
		data.WriteRequest().GetObject(),
		data.WriteRequest().GetOldObject(),
	}

	return EvaluateConditionSet(conditionSet, "labelSelectorApplies", func(condition string) (bool, error) {
		for _, runtimeObj := range enforceObjects {
			if runtimeObj == nil {
				continue
			}
			obj, ok := runtimeObj.(metav1.Object)
			if !ok {
				return false, errors.New("only supports objects with metadata")
			}
			selector, err := labels.Parse(condition)
			if err != nil {
				return false, err
			}
			if !selector.Matches(labels.Set(obj.GetLabels())) {
				return false, nil
			}
		}
		return true, nil
	})
}

func EvaluateConditionSet(conditionSet *ConditionSet, supportedConditionType string, eval func(string) (bool, error)) (Decision, error) {
	if conditionSet.Type() != supportedConditionType {
		return conditionSet.FailClosedDecision(), fmt.Errorf("unsupported condition type: %q", conditionSet.Type())
	}

	for cond := range conditionSet.DenyConditions() {
		applies, err := eval(cond.Condition)
		if err != nil {
			// TODO: should we leak the error to the user?
			return DecisionDeny("an error occurred"), err
		}
		if applies {
			reason := fmt.Sprintf("condition %q denied the request", cond.ID)
			if len(cond.Description) != 0 {
				reason += fmt.Sprintf(" with description %q", cond.Description)
			}
			return DecisionDeny(reason), nil
		}
	}

	for cond := range conditionSet.NoOpinionConditions() {
		applies, err := eval(cond.Condition)
		if err != nil {
			// TODO: should we leak the error to the user?
			return DecisionNoOpinion("an error occurred"), err
		}
		if applies {
			reason := fmt.Sprintf("condition %q evaluated to NoOpinion", cond.ID)
			if len(cond.Description) != 0 {
				reason += fmt.Sprintf(" with description %q", cond.Description)
			}
			return DecisionNoOpinion(reason), nil
		}
	}

	var errlist []error
	for cond := range conditionSet.AllowConditions() {
		applies, err := eval(cond.Condition)
		if err != nil {
			// errors from Allow conditions don't affect the Decision, but
			// are returned as the non-critical error in aggregate form
			errlist = append(errlist, err)
			continue
		}
		if applies {
			reason := fmt.Sprintf("condition %q allowed the request", cond.ID)
			if len(cond.Description) != 0 {
				reason += fmt.Sprintf(" with description %q", cond.Description)
			}
			return DecisionAllow(reason), utilerrors.NewAggregate(errlist)
		}
	}
	return DecisionNoOpinion("no conditions matched"), utilerrors.NewAggregate(errlist)
}
