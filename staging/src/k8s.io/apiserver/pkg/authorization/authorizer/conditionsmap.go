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

package authorizer

import (
	"context"
	"fmt"
	"iter"
	"reflect"
	"strings"

	"k8s.io/apimachinery/pkg/api/validate/content"
	"k8s.io/apimachinery/pkg/util/sets"
)

// ConditionsMap is a map of conditions of a given type, and represents
// the conditional decision from the
// It must be constructed through ConditionsAwareDecisionConditionsMap.
// During construction, all Conditions are validated and ensured to be non-nil.
type ConditionsMap struct {
	// invariant: len(denyConditions) != 0 || len(allowConditions) != 0
	//
	// slices are used here instead of actual maps, as the ConditionsMap does
	// not need to lookup single elements. It's called a "map" as uniqueness of
	// the IDs (keys) across all conditions (values) in the map is enforced.
	denyConditions      []Condition
	noOpinionConditions []Condition
	allowConditions     []Condition
}

// FailureDecision returns either a Deny or NoOpinion decision to fail closed
// whenever processing a decision fails. If the decision contains one or
// more Deny decisions or conditions, one must fail closed with Deny, as that could or would
// have been the if the condition evaluation did not error. Otherwise, NoOpinion is returned.
func (c ConditionsMap) FailureDecision() Decision {
	if len(c.denyConditions) > 0 {
		return DecisionDeny
	}
	return DecisionNoOpinion
}

// Length returns the number of elements in the map.
func (c ConditionsMap) Length() int {
	return len(c.denyConditions) + len(c.noOpinionConditions) + len(c.allowConditions)
}

// DenyConditions returns the Deny conditions in this map.
// The order in which elements are returned is deterministic but undefined.
func (c ConditionsMap) DenyConditions() iter.Seq[Condition] {
	return func(yield func(Condition) bool) {
		for _, cond := range c.denyConditions {
			if !yield(cond) {
				return
			}
		}
	}
}

// NoOpinionConditions returns the NoOpinion conditions in this map.
// The order in which elements are returned is deterministic but undefined.
func (c ConditionsMap) NoOpinionConditions() iter.Seq[Condition] {
	return func(yield func(Condition) bool) {
		for _, cond := range c.noOpinionConditions {
			if !yield(cond) {
				return
			}
		}
	}
}

// AllowConditions returns the Allow conditions in this map.
// The order in which elements are returned is deterministic but undefined.
func (c ConditionsMap) AllowConditions() iter.Seq[Condition] {
	return func(yield func(Condition) bool) {
		for _, cond := range c.allowConditions {
			if !yield(cond) {
				return
			}
		}
	}
}

func (c ConditionsMap) PossibleDecisions() sets.Set[Decision] {
	possibleDecisions := sets.New(DecisionNoOpinion)
	if len(c.allowConditions) > 0 {
		possibleDecisions.Insert(DecisionAllow)
	}
	if len(c.denyConditions) > 0 {
		possibleDecisions.Insert(DecisionDeny)
	}
	return possibleDecisions
}

// MaxConditionsPerMap is the maximum number of conditions allowed in a single ConditionsMap.
const MaxConditionsPerMap = 128

// ConditionsAwareDecisionConditionsMap creates a ConditionsMap decision.
// The conditions are grouped by their effects: Deny, NoOpinion and Allow, that function as follows:
//   - Deny: If a Deny condition evaluates to true, the ConditionsMap necessarily evaluates to Deny.
//     In this case, no further authorizers are consulted.
//   - NoOpinion: If a NoOpinion condition evaluates to true, the given authorizer's ConditionsMap cannot
//     evaluate to Allow anymore, but necessarily Deny or NoOpinion, depending on whether there are any true
//     Deny conditions. However, later authorizers in the chain can still Allow or Deny.
//     It is effectively a softer deny that just overrides the authorizer's own allow policies.
//   - Allow: If any Allow condition evaluates to true, the ConditionsMap evaluates to Allow,
//     unless any Deny/NoOpinion condition also evaluates to true (in which case the Deny/NoOpinion conditions
//     have precedence).
func ConditionsAwareDecisionConditionsMap(denyConditions []Condition, noOpinionConditions []Condition, allowConditions []Condition) ConditionsAwareDecision {

	hasDenyEffect := len(denyConditions) > 0
	makeFailClosedError := func(err error) ConditionsAwareDecision {
		if hasDenyEffect {
			return ConditionsAwareDecisionDeny("failed closed", err)
		}
		return ConditionsAwareDecisionNoOpinion("failed closed", err)
	}

	// enforce minimum 1 and maximum amount of conditions per map
	conditionsAmount := len(denyConditions) + len(noOpinionConditions) + len(allowConditions)
	if conditionsAmount > MaxConditionsPerMap {
		return makeFailClosedError(fmt.Errorf("too many conditions: %d exceeds maximum of %d", conditionsAmount, MaxConditionsPerMap))
	}
	if conditionsAmount <= 0 {
		// Does not use makeFailClosedError, but NoOpinion directly, as in this branch there are no deny conditions, so NoOpinion is safe
		return ConditionsAwareDecisionNoOpinion("no conditions", fmt.Errorf("at least one condition must be passed to ConditionsAwareDecisionConditionsMap(), got none"))
	}
	// short-circuit case: if only NoOpinion conditions exist, we can short-circuit to a NoOpinion directly, as no matter
	// what the conditions evaluate to, the output will be NoOpinion
	if len(denyConditions) == 0 && len(noOpinionConditions) != 0 && len(allowConditions) == 0 {
		return ConditionsAwareDecisionNoOpinion("", nil)
	}

	seenIDs := sets.New[string]()

	if err := validateConditions(seenIDs, denyConditions); err != nil {
		return makeFailClosedError(err)
	}
	if err := validateConditions(seenIDs, noOpinionConditions); err != nil {
		return makeFailClosedError(err)
	}
	if err := validateConditions(seenIDs, allowConditions); err != nil {
		return makeFailClosedError(err)
	}

	return ConditionsAwareDecision{
		decisionType: conditionsAwareDecisionTypeConditionsMap,
		conditionsMap: ConditionsMap{
			denyConditions:      denyConditions,
			noOpinionConditions: noOpinionConditions,
			allowConditions:     allowConditions,
		},
	}
}
func validateConditions(seenIDs sets.Set[string], conditions []Condition) error {
	for _, condition := range conditions {
		if isNilValue(condition) {
			return fmt.Errorf("encountered nil condition")
		}

		id := condition.GetID()
		if seenIDs.Has(id) {
			return fmt.Errorf("duplicate condition ID %q", id)
		}
		seenIDs.Insert(id)

		// Validate ID as a label key.
		if errs := content.IsLabelKey(id); len(errs) > 0 {
			return fmt.Errorf("invalid condition ID %q: %s", id, strings.Join(errs, "; "))
		}

		// Validate type as a label key, if set.
		if conditionType := condition.GetType(); len(conditionType) != 0 {
			if errs := content.IsLabelKey(conditionType); len(errs) > 0 {
				return fmt.Errorf("invalid condition type %q: %s", conditionType, strings.Join(errs, "; "))
			}
		}
		// TODO(luxas): Add condition and description byte limits here or in authorizationapivalidation?
	}
	return nil
}

func isNilValue(i any) bool {
	if i == nil {
		return true // both type and data nil
	}
	v := reflect.ValueOf(i)
	switch v.Kind() {
	// v.IsNil() panics if the kind is anything else than these,
	// the list is taken from the IsNil source code
	case reflect.Chan, reflect.Func, reflect.Map,
		reflect.Pointer, reflect.UnsafePointer,
		reflect.Interface, reflect.Slice:
		return v.IsNil() // type non-nil, but data nil
	}
	return false // data non-nil
}

// GenericCondition is a generic implementation of the Condition interface,
// with optional support for fast in-process conditions evaluation, by
// setting EvaluateFunc non-nil.
type GenericCondition struct {
	ID           string
	Condition    string
	Type         string
	Description  string
	EvaluateFunc func(ctx context.Context, data ConditionsData) PartialConditionEvaluationResult
}

var _ Condition = GenericCondition{}

func (c GenericCondition) GetID() string {
	return c.ID
}
func (c GenericCondition) GetCondition() string {
	return c.Condition
}
func (c GenericCondition) GetType() string {
	return c.Type
}
func (c GenericCondition) GetDescription() string {
	return c.Description
}
func (c GenericCondition) Evaluate(ctx context.Context, data ConditionsData) PartialConditionEvaluationResult {
	if c.EvaluateFunc == nil {
		return ConditionsEvaluationResultUnevaluatable()
	}
	return c.EvaluateFunc(ctx, data)
}

func (c GenericCondition) DeepCopy() Condition {
	return c // no values passed by reference
}

// EvaluateConditionFunc is a function that is able to concretely evaluate a condition to a boolean or error.
type EvaluateConditionFunc func(ctx context.Context, condition Condition, data ConditionsData) (bool, error)

// Evaluate evaluates the ConditionsMap primarily using the Conditions' own Evaluate() function,
// and secondarily using evaluateFunc, if set.
func (c ConditionsMap) Evaluate(ctx context.Context, data ConditionsData, evaluateConditionFn EvaluateConditionFunc) (Decision, string, error) {
	// This is a translation between the generic, private function, and the interface we want to expose to callers. Because we never return "unevaluatable", the returned ConditionsAwareDecision
	// is always one of Allow/Deny/NoOpinion, and thus can we split it into UnconditionalParts
	return partiallyEvaluateConditionsMapInternal(ctx, c, data, func(ctx context.Context, cond Condition, condData ConditionsData) PartialConditionEvaluationResult {
		applied, err := evaluateConditionFn(ctx, cond, condData)
		if err != nil {
			return ConditionEvaluationResultError(err)
		}
		return ConditionEvaluationResultBoolean(applied)
	}).UnconditionalParts()
}
