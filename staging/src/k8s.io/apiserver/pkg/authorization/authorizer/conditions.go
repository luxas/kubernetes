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
	"errors"
	"fmt"
	"iter"
	"reflect"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/api/validate/content"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/user"
)

// ErrorConditionEvaluationNotSupported is returned by authorizer implementations
// that do not support condition evaluation.
var ErrorConditionEvaluationNotSupported = errors.New("condition evaluation not supported")

// conditionsAwareDecisionType is a small enum-like type for keeping track of what type a ConditionsAwareDecision is.
// These values must never be exposed to users outside of this package, and should not be used for anything else than
// keeping track of what type of a ConditionsAwareDecision is.
type conditionsAwareDecisionType int

const (
	// conditionsAwareDecisionTypeDeny represents the unconditional Deny decision.
	// It is zero such that ConditionsAwareDecision{}.IsDeny() == true
	conditionsAwareDecisionTypeDeny conditionsAwareDecisionType = 0
	// conditionsAwareDecisionTypeAllow represents the unconditional Allow decision.
	// It has a different value from DecisionAllow to never be conflated with that.
	conditionsAwareDecisionTypeAllow conditionsAwareDecisionType = 11
	// conditionsAwareDecisionTypeNoOpinion represents the unconditional NoOpinion decision.
	// It has a different value from DecisionNoOpinion to never be conflated with that.
	conditionsAwareDecisionTypeNoOpinion conditionsAwareDecisionType = 12
	// conditionsAwareDecisionTypeConditionsMap represents the conditional ConditionsMap decision.
	conditionsAwareDecisionTypeConditionsMap conditionsAwareDecisionType = 13
	// conditionsAwareDecisionTypeUnion represents a conditional Union decision.
	conditionsAwareDecisionTypeUnion conditionsAwareDecisionType = 14
)

// ConditionsAwareDecision models an authorization decision that is conditions-aware.
// It is an enum type of the following five variants:
// - Allow: unconditional Allow.
// - Deny: unconditional Deny.
// - NoOpinion: unconditional NoOpinion.
// - Conditional: conditional on some previously-unseen data.
// - Union: an ordered list of sub-decisions, which forms a tree of decisions.
//
// The zero value (ConditionsAwareDecision{}) is equivalent to ConditionsAwareDecisionDeny().
// A ConditionsAwareDecision is passed by value.
type ConditionsAwareDecision struct {
	decisionType conditionsAwareDecisionType

	conditionsMap ConditionsMap
	union         ConditionsAwareDecisionUnion

	reason string
	err    error
}

// ConditionsAwareDecisionDeny constructs a Deny decision with the given reason and error.
func ConditionsAwareDecisionDeny(reason string, err error) ConditionsAwareDecision {
	return ConditionsAwareDecision{
		// conditionsAwareDecisionTypeDeny == 0 == zero value
		// => ConditionsAwareDecision{} == ConditionsAwareDecisionDeny()
		decisionType: conditionsAwareDecisionTypeDeny,
		reason:       reason,
		err:          err,
	}
}

// ConditionsAwareDecisionAllow constructs an Allow decision with the given reason and error.
func ConditionsAwareDecisionAllow(reason string, err error) ConditionsAwareDecision {
	return ConditionsAwareDecision{
		decisionType: conditionsAwareDecisionTypeAllow,
		reason:       reason,
		err:          err,
	}
}

// ConditionsAwareDecisionNoOpinion constructs a NoOpinion decision with the given reason and error.
func ConditionsAwareDecisionNoOpinion(reason string, err error) ConditionsAwareDecision {
	return ConditionsAwareDecision{
		decisionType: conditionsAwareDecisionTypeNoOpinion,
		reason:       reason,
		err:          err,
	}
}

// ConditionsAwareDecisionFromParts is meant to be used by conditions-unaware Authorizer implementations
// in order to implement ConditionsAwareAuthorize as:
// "return ConditionsAwareDecisionFromParts(self.Authorize(ctx, a))"
func ConditionsAwareDecisionFromParts(unconditional Decision, reason string, err error) ConditionsAwareDecision {
	switch unconditional {
	case DecisionAllow:
		return ConditionsAwareDecisionAllow(reason, err)
	case DecisionNoOpinion:
		return ConditionsAwareDecisionNoOpinion(reason, err)
	case DecisionDeny:
		return ConditionsAwareDecisionDeny(reason, err)
	default:
		return ConditionsAwareDecisionDeny(reason, utilerrors.NewAggregate(
			[]error{
				err,
				fmt.Errorf("unknown unconditional decision type: %d", unconditional),
			},
		))
	}
}

// IsAllow returns true if the decision is an unconditional Allow.
func (d ConditionsAwareDecision) IsAllow() bool {
	return d.decisionType == conditionsAwareDecisionTypeAllow
}

// IsNoOpinion returns true if the decision is an unconditional NoOpinion.
func (d ConditionsAwareDecision) IsNoOpinion() bool {
	return d.decisionType == conditionsAwareDecisionTypeNoOpinion
}

// IsDeny returns true if the decision is an unconditional Deny.
func (d ConditionsAwareDecision) IsDeny() bool {
	return d.decisionType == conditionsAwareDecisionTypeDeny // == 0 == zero value
}

// IsUnion returns true if the decision consists of other sub-decisions
// unioned together in a tree-like structure.
func (d ConditionsAwareDecision) IsUnion() bool {
	return d.decisionType == conditionsAwareDecisionTypeUnion
}

// ConditionsMap returns the ConditionsMap, which is non-empty
// if and only if IsConditionsMap is true.
func (d ConditionsAwareDecision) ConditionsMap() ConditionsMap {
	return d.conditionsMap
}

// IsConditionsMap returns true if the decision is a conditional response
// with a map of conditions to evaluate.
func (d ConditionsAwareDecision) IsConditionsMap() bool {
	return d.decisionType == conditionsAwareDecisionTypeConditionsMap
}

// IsUnconditional is true if d is Allow, Deny or NoOpinion.
func (d ConditionsAwareDecision) IsUnconditional() bool {
	return d.IsAllow() || d.IsDeny() || d.IsNoOpinion()
}

// UnconditionalParts turns a ConditionsAwareDecision into the
// triple that Authorize expects. If the decision is
// conditional, the returned condition is Deny if there were at least
// some Deny condition, otherwise NoOpinion.
// This function is meant to be called when IsUnconditional() == true.
//
// If the authorizer is conditions-aware, it can choose to only implement
// real business logic in the ConditionsAwareAuthorize method, and implement
// Authorize() as "return self.ConditionsAwareAuthorize(ctx, attrs).UnconditionalParts()"
func (d ConditionsAwareDecision) UnconditionalParts() (Decision, string, error) {
	switch {
	case d.IsAllow():
		return DecisionAllow, d.Reason(), d.Error()
	case d.IsDeny():
		return DecisionDeny, d.Reason(), d.Error()
	case d.IsNoOpinion():
		return DecisionNoOpinion, d.Reason(), d.Error()
	default:
		// An error is not returned here, as that could yield a HTTP response code of 500 instead of 403.
		// For the use-case described above with regards to calling this function in Authorize, not returning
		// an error is important, as it is valid to always fail closed, as if this happens, no unconditional
		// permissions were given the requestor.
		return d.FailureDecision(), "failed closed: tried to return conditional decision to conditions-unaware authorizer", nil
	}
}

// FailureDecision returns either a Deny or NoOpinion decision to fail closed
// whenever processing a decision fails. If the decision contains one or
// more Deny decisions or conditions, one must fail closed with Deny, as that could or would
// have been the if the condition evaluation did not error. Otherwise, NoOpinion is returned.
func (d ConditionsAwareDecision) FailureDecision() Decision {
	if d.IsAllow() || d.IsNoOpinion() {
		return DecisionNoOpinion
	}
	if d.IsConditionsMap() {
		return d.conditionsMap.FailureDecision()
	}
	if d.IsUnion() {
		return d.union.FailureDecision()
	}
	// => d.IsDenied() == true
	return DecisionDeny
}

// ContainsAllowOrDeny returns true whether there union contains at least one
// Allow or Deny decision within the tree of decisions.
func (d ConditionsAwareDecision) ContainsAllowOrDeny() bool {
	if d.IsAllow() || d.IsDeny() {
		return true
	}
	if d.IsNoOpinion() || d.IsConditionsMap() {
		return false
	}
	return d.union.ContainsAllowOrDeny()
}

// UnionedDecisions returns an iterator for unioned sub-decisions.
// This iterator is non-empty if and only if IsUnion() == true.
// The sub-decisions are iterated in their priority order.
func (d ConditionsAwareDecision) UnionedDecisions() iter.Seq2[string, ConditionsAwareDecision] {
	return func(yield func(string, ConditionsAwareDecision) bool) {
		for _, subDecision := range d.union.inner {
			if !yield(subDecision.authorizerName, subDecision.d) {
				return
			}
		}
	}
}

// Reason returns the reason supplied when constructing the decision
// (if Allow/Deny/NoOpinion/ConditionsMap), or an aggregated reason (if Union).
func (d ConditionsAwareDecision) Reason() string {
	if d.IsUnion() {
		b := strings.Builder{}
		b.WriteByte('[')
		for i, sub := range d.union.inner {
			if i != 0 {
				b.WriteString(", ")
			}
			reason := sub.d.Reason()
			if len(reason) != 0 {
				b.WriteString(reason)
			} else {
				b.WriteString(`""`)
			}
		}
		b.WriteByte(']')
		return b.String()
	}
	return d.reason
}

// Error returns the error supplied when constructing the decision
// (if Allow/Deny/NoOpinion/ConditionsMap), or an aggregated error (if Union).
func (d ConditionsAwareDecision) Error() error {
	if d.IsUnion() {
		errlist := make([]error, len(d.union.inner))
		for i, sub := range d.union.inner {
			errlist[i] = sub.d.Error()
		}
		return utilerrors.NewAggregate(errlist)
	}
	return d.err
}

// String returns a human-readable representation of the decision.
func (d ConditionsAwareDecision) String() string {
	if d.IsUnion() {
		// No need to take d.reason or d.err into account, as they are always zero for the union.
		b := strings.Builder{}
		b.WriteString("Union[")
		for i, sub := range d.union.inner {
			if i != 0 {
				b.WriteString(", ")
			}
			b.WriteString(sub.d.String())
		}
		b.WriteByte(']')
		return b.String()
	}

	params := []string{}
	if len(d.reason) != 0 {
		params = append(params, fmt.Sprintf("reason=%q", d.reason))
	}
	if d.err != nil {
		params = append(params, fmt.Sprintf("err=%q", d.err.Error()))
	}
	paramsStr := func() string {
		if len(params) == 0 {
			return ""
		}
		return fmt.Sprintf("(%s)", strings.Join(params, ", "))
	}
	if d.IsAllow() {
		return fmt.Sprintf("Allow%s", paramsStr())
	}
	if d.IsNoOpinion() {
		return fmt.Sprintf("NoOpinion%s", paramsStr())
	}
	if d.IsConditionsMap() {
		params = append(params, fmt.Sprintf("len=%d", d.conditionsMap.Length()))
		/*
			if len(d.conditionsMap.denyConditions) != 0 {
				params = append(params, fmt.Sprintf("denies=%d", len(d.conditionsMap.denyConditions)))
			}
			if len(d.conditionsMap.noOpinionConditions) != 0 {
				params = append(params, fmt.Sprintf("noopinions=%d", len(d.conditionsMap.noOpinionConditions)))
			}
			if len(d.conditionsMap.allowConditions) != 0 {
				params = append(params, fmt.Sprintf("allows=%d", len(d.conditionsMap.allowConditions)))
			}
		*/
		return fmt.Sprintf("ConditionsMap%s", paramsStr())
	}
	// Deny is written such that if none of the other modes apply,
	// IsDenied() is true.
	return fmt.Sprintf("Deny%s", paramsStr())
}

func (d ConditionsAwareDecision) PossibleDecisions() sets.Set[Decision] {
	switch {
	case d.IsAllow():
		return sets.New(DecisionAllow)
	case d.IsNoOpinion():
		return sets.New(DecisionNoOpinion)
	case d.IsConditionsMap():
		return d.ConditionsMap().PossibleDecisions()
	case d.IsUnion():
		return d.union.PossibleDecisions()
	default:
		return sets.New(DecisionDeny)
	}
}

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

// conditionEvaluationResultType is a small enum for the type of ConditionEvaluationResult
type conditionEvaluationResultType int

const (
	conditionEvaluationResultTypeUnevaluatable conditionEvaluationResultType = iota
	conditionEvaluationResultTypeTrue
	conditionEvaluationResultTypeFalse
	conditionEvaluationResultTypeError
)

// ConditionEvaluationResult is an enum type with four variants:
// - true and false: Evaluation was successful, and evaluated to this value
// - error: The condition could be evaluated, but errored during eval.
// - unevaluatable: The condition cannot readily be evaluated. This is the struct zero value.
type ConditionEvaluationResult struct {
	resultType conditionEvaluationResultType
	err        error
}

// ConditionEvaluationResultBoolean constructs an evaluation result with a boolean value.
func ConditionEvaluationResultBoolean(evalResult bool) ConditionEvaluationResult {
	if evalResult {
		return ConditionEvaluationResult{resultType: conditionEvaluationResultTypeTrue}
	}
	return ConditionEvaluationResult{resultType: conditionEvaluationResultTypeFalse}
}

// ConditionEvaluationResultError indicates that the condition could be evaluated, but failed.
func ConditionEvaluationResultError(err error) ConditionEvaluationResult {
	if err == nil {
		return ConditionEvaluationResult{
			resultType: conditionEvaluationResultTypeError,
			err:        errors.New("unknown evaluation error: got err == nil in ConditionEvaluationResultError"),
		}
	}
	return ConditionEvaluationResult{
		resultType: conditionEvaluationResultTypeError,
		err:        err,
	}
}

// ConditionsEvaluationResultUnevaluatable indicates direct conditions evaluation is not possible.
func ConditionsEvaluationResultUnevaluatable() ConditionEvaluationResult {
	return ConditionEvaluationResult{
		resultType: conditionEvaluationResultTypeUnevaluatable, // == 0 (which matches the zero value of the struct)
	}
}

// IsTrue indicates that the conditions evaluation was successful, and evaluated to true, which means it influences the ConditionsMap decision.
func (r ConditionEvaluationResult) IsTrue() bool {
	return r.resultType == conditionEvaluationResultTypeTrue
}

// IsFalse indicates that the conditions evaluation was successful, but evaluated to false, and it not thus taken into account.
func (r ConditionEvaluationResult) IsFalse() bool {
	return r.resultType == conditionEvaluationResultTypeFalse
}

// IsError indicates whether conditions evaluation failed.
func (r ConditionEvaluationResult) IsError() bool {
	return r.resultType == conditionEvaluationResultTypeError
}

// Error returns the evaluation error, if any.
func (r ConditionEvaluationResult) Error() error { return r.err }

// IsUnevaluatable is true whenever none of the other variants is, that is, the zero value.
func (r ConditionEvaluationResult) IsUnevaluatable() bool {
	return r.resultType == conditionEvaluationResultTypeUnevaluatable
}

// Condition represents one authorization condition that is part of a ConditionsMap.
// The effect of a condition is defined by whether it is part of the Deny/NoOpinion/Allow
// conditions list in the ConditionsMap.
type Condition interface {
	// GetID uniquely identifies this condition within the scope of the authorizer
	// that authored it. Validated as a Kubernetes label key.
	// Any domain of form *.k8s.io or *.kubernetes.io is reserved for Kubernetes use.
	// Required.
	GetID() string

	// GetType describes the type of the condition, if there are multiple possibilities.
	// Should be formatted as a Kubernetes label key.
	// Any domain of form *.k8s.io or *.kubernetes.io is reserved for Kubernetes use.
	// Optional. Can be omitted if the authorizer already knows how to evaluate the condition.
	GetType() string

	// GetCondition returns a string encoding of the condition to be evaluated.
	// It is a pure, deterministic function from ConditionsData to a boolean (or error).
	// Might or might not be human-readable.
	// Optional, if the ID alone is enough for the authorizer to know how to evaluate the condition.
	GetCondition() string

	// GetDescription is an optional human-friendly description that can be shown
	// as an error message or for debugging. Optional.
	GetDescription() string

	// DeepCopy returns a deep copy of the Condition.
	DeepCopy() Condition

	// Evaluate evaluates the condition to a boolean, returns an error, or returns "unevaluatable".
	// If an authorizer already has a pre-compiled condition, this avoids one serialization roundtrip,
	// with potentially expensive deserialization/parsing. However, if the condition underwent a
	// serialize/deserialize roundtrip (e.g. when the caller is an aggregated API server), the authorizer
	// might have to evaluate the condition from its serialized form using evaluateFunc in
	// ConditionsMap.Evaluate.
	Evaluate(ctx context.Context, data ConditionsData) ConditionEvaluationResult
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
	EvaluateFunc func(ctx context.Context, data ConditionsData) ConditionEvaluationResult
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
func (c GenericCondition) Evaluate(ctx context.Context, data ConditionsData) ConditionEvaluationResult {
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
	return evaluateConditionsMapInternal(ctx, c, data, func(ctx context.Context, cond Condition, condData ConditionsData) ConditionEvaluationResult {
		applied, err := evaluateConditionFn(ctx, cond, condData)
		if err != nil {
			return ConditionEvaluationResultError(err)
		}
		return ConditionEvaluationResultBoolean(applied)
	}).UnconditionalParts()
}

// evaluateConditionsMapInternal evaluates the ConditionsMap primarily using the Conditions' own Evaluate() function,
// and secondarily using evaluateFunc, if set. If evaluateFunc is non-nil and never returns
// ConditionsEvaluationResultUnevaluatable, the returned decision is guaranteed to be Allow/Deny/NoOpinion.
// However, this method can also be used to evaluate a subset of the conditions (e.g. for builtin
// conditions evaluators that support a certain conditions type), returning ConditionsEvaluationResultUnevaluatable
// for conditions that the evaluator does not recognize. In the latter case, a partially evaluated, deep copied
// ConditionsMap might be returned.
func evaluateConditionsMapInternal(ctx context.Context, c ConditionsMap, data ConditionsData, evaluateConditionFn PartialEvaluateConditionFunc) ConditionsAwareDecision {
	evalCond := func(cond Condition) ConditionEvaluationResult {
		// First, try to use the condition's own evaluate function.
		// Fallback to evaluateConditionFn if set and unevaluatable
		result := cond.Evaluate(ctx, data)
		if result.IsUnevaluatable() && evaluateConditionFn != nil {
			return evaluateConditionFn(ctx, cond, data)
		}
		return result
	}

	if len(c.denyConditions) != 0 {
		appliedDenyReasons, denyErrors, unevaluatedDenyConditions := evaluateConditions(c.DenyConditions(), evalCond, "Deny", "denied the request")
		// If any deny conditions evaluated to true, return Deny
		// Deny conditions that apply take precedence over deny conditions that error, as even if the erroring
		// deny conditions wouldn't have errored, the applied deny conditions would have produced the same Deny decision.
		if len(appliedDenyReasons) != 0 {
			// A nil error must be returned here, in order for the WithAuthorization handler to return 403 and not 500.
			return ConditionsAwareDecisionDeny(strings.Join(appliedDenyReasons, ", "), nil)
		}
		// If any deny errors were encountered, fail closed
		if len(denyErrors) != 0 {
			return ConditionsAwareDecisionDeny("one or more conditional evaluation errors occurred", utilerrors.NewAggregate(denyErrors))
		}

		// When len(unevaluatedDenyConditions) != 0, the possible outcomes are [Deny, NoOpinion] or [Deny, Allow] (depending on whether)
		// there is some matching NoOpinion/Allow condition or not. This means that we need to return another, possibly refined ConditionsMap
		if len(unevaluatedDenyConditions) != 0 {
			return ConditionsAwareDecisionConditionsMap(
				unevaluatedDenyConditions,
				deepCopyConditions(c.noOpinionConditions),
				deepCopyConditions(c.allowConditions))
		}
	}
	// If we got here, all Deny conditions could be evaluated, and evaluated to false, nil
	if len(c.noOpinionConditions) != 0 {
		appliedNoOpinionReasons, noOpinionErrors, unevaluatedNoOpinionConditions := evaluateConditions(c.NoOpinionConditions(), evalCond, "NoOpinion", "evaluated to NoOpinion")
		// If any NoOpinion conditions evaluated to true, return NoOpinion
		if len(appliedNoOpinionReasons) != 0 {
			return ConditionsAwareDecisionNoOpinion(strings.Join(appliedNoOpinionReasons, ", "), nil)
		}
		// If any NoOpinion errors were encountered, fail closed to NoOpinion as if the conditions would have matched
		if len(noOpinionErrors) != 0 {
			return ConditionsAwareDecisionNoOpinion("one or more conditional evaluation errors occurred", utilerrors.NewAggregate(noOpinionErrors))
		}
		// When len(unevaluatedNoOpinionConditions) != 0, the possible outcomes are [NoOpinion] or [NoOpinion, Allow]. (depending on whether)
		// there is some matching Allow condition or not. This means that we need to return another, possibly refined ConditionsMap, unless
		// there are no Allow conditions, in which the decision is always NoOpinion.
		if len(unevaluatedNoOpinionConditions) != 0 {
			// If there are no allow conditions, then either some unevaluated NoOpinion applies, in which the decision is NoOpinion, or all unevaluated
			// NoOpinion conditions evaluate to false, no allow condition applies (as there are none), so the default NoOpinion is returned. In either
			// case under that assumption, the return value is NoOpinion.
			if len(c.allowConditions) == 0 {
				return ConditionsAwareDecisionNoOpinion("at least one NoOpinion condition matched, or no conditions matched", nil)
			}

			// Otherwise, the possible outcomes are [NoOpinion, Allow]. Return a possibly refined ConditionsMap.
			return ConditionsAwareDecisionConditionsMap(
				nil,
				unevaluatedNoOpinionConditions,
				deepCopyConditions(c.allowConditions))
		}
	}
	// If we got here, all Deny and NoOpinion conditions could be evaluated, and evaluated to false, nil
	if len(c.allowConditions) != 0 {
		appliedAllowReasons, allowErrors, unevaluatedAllowConditions := evaluateConditions(c.AllowConditions(), evalCond, "Allow", "allowed the request")
		// If there were at least one Allow condition that applied, then evaluation is successful, even if there
		// were some errors that happened. Those are in this case considered warnings.
		if len(appliedAllowReasons) != 0 {
			return ConditionsAwareDecisionAllow(strings.Join(appliedAllowReasons, ", "), utilerrors.NewAggregate(allowErrors))
		}
		// However, if no Allow condition evaluated to true, but at least one errored, return that as an error to the caller
		if len(allowErrors) != 0 {
			return ConditionsAwareDecisionNoOpinion("one or more conditional evaluation errors occurred", utilerrors.NewAggregate(allowErrors))
		}
		// When len(unevaluatedAllowConditions) != 0, the possible outcomes are [NoOpinion, Allow].
		// Return a possibly refined ConditionsMap with the Allow conditions that could not be evaluated.
		if len(unevaluatedAllowConditions) != 0 {
			return ConditionsAwareDecisionConditionsMap(nil, nil, unevaluatedAllowConditions)
		}
	}

	// All conditions evaluated to false. This means a simple default NoOpinion.
	return ConditionsAwareDecisionNoOpinion("no conditions matched", nil)
}

func evaluateConditions(conditions iter.Seq[Condition], evalCond func(cond Condition) ConditionEvaluationResult, effect, appliedDescription string) ([]string, []error, []Condition) {
	errs := []error{}
	appliedCondReasons := []string{}
	unevaluatedConditions := []Condition{}
	for cond := range conditions {
		id := cond.GetID()
		evalResult := evalCond(cond)
		switch {
		case evalResult.IsUnevaluatable():
			unevaluatedConditions = append(unevaluatedConditions, cond)
			continue
		case evalResult.IsError():
			errs = append(errs, fmt.Errorf("condition %q with effect=%s produced error: %w", id, effect, evalResult.Error()))
			continue
		case evalResult.IsTrue():
			reason := fmt.Sprintf("condition %q %s", id, appliedDescription)
			if desc := cond.GetDescription(); len(desc) != 0 {
				reason += fmt.Sprintf(" with description %q", desc)
			}
			appliedCondReasons = append(appliedCondReasons, reason)
			continue
		default: // => evalResult.IsFalse() == true
			continue
		}
	}
	// Arguments are returned in the order that they should be considered.
	return appliedCondReasons, errs, unevaluatedConditions
}

func deepCopyConditions(originals []Condition) []Condition {
	copied := make([]Condition, len(originals))
	for i, original := range originals {
		copied[i] = original.DeepCopy()
	}
	return copied
}

// PartialEvaluateConditionFunc allows partially evaluating a condition, returning Unevaluatable if a truth value or error cannot be assigned.
type PartialEvaluateConditionFunc func(ctx context.Context, condition Condition, data ConditionsData) ConditionEvaluationResult

// PartiallyEvaluateConditionsAwareDecision evaluates the ConditionsAwareDecision primarily using any conditions' own Evaluate() function,
// and secondarily using evaluateConditionFn, if set. If evaluateConditionFn is non-nil and never returns
// ConditionsEvaluationResultUnevaluatable, the returned decision is guaranteed to be Allow/Deny/NoOpinion.
// However, this method can also be used to evaluate a subset of the conditions (e.g. for builtin
// conditions evaluators that support a certain conditions type), returning ConditionsEvaluationResultUnevaluatable
// for conditions that the evaluator does not recognize. In the latter case, a partially evaluated, deep copied
// ConditionsAwareDecision is returned.
func PartiallyEvaluateConditionsAwareDecision(ctx context.Context, unevaluatedDecision ConditionsAwareDecision, data ConditionsData, evaluateConditionFn PartialEvaluateConditionFunc) ConditionsAwareDecision {
	if unevaluatedDecision.IsUnconditional() {
		return unevaluatedDecision // nothing to simplify
	}
	if evaluateConditionFn == nil {
		return unevaluatedDecision // no simplification possible
	}

	if unevaluatedDecision.IsUnion() {
		var newDecisionChain ConditionsAwareDecisionUnion
		// Recursively walk through the decision DAG in a depth-first manner.

		collectAndShortcircuitOnly := false
		for authorizerName, unevaluatedSubDecision := range unevaluatedDecision.UnionedDecisions() {
			// If collectAndShortcircuitOnly == true, a conditional decision that couldn't
			// be evaluated to Allow/Deny/NoOpinion was encountered during a previous
			// loop iteration. Then all latter decisions stay unevaluated.
			if collectAndShortcircuitOnly {
				newDecisionChain.Add(authorizerName, unevaluatedSubDecision)
				continue
			}

			// When !collectAndShortcircuitOnly: All decisions so far in newDecisionChain are NoOpinions.

			// Try evaluating or refining the leaf ConditionsMaps in this tree of decisions.
			possiblyEvaluatedSubDecision := PartiallyEvaluateConditionsAwareDecision(ctx, unevaluatedSubDecision, data, evaluateConditionFn)

			// Always preserve the indices and ordering of the decisions, as this ordering
			// is used by the union authorizer to pair a decision with its
			newDecisionChain.Add(authorizerName, possiblyEvaluatedSubDecision)

			// We successfully evaluated to something, and because all previously-seen
			// decisions were NoOpinions, we can simplify to Allow/Deny here.
			if possiblyEvaluatedSubDecision.IsAllow() || possiblyEvaluatedSubDecision.IsDeny() {
				return possiblyEvaluatedSubDecision
			}

			// If NoOpinion, try the next
			if possiblyEvaluatedSubDecision.IsNoOpinion() {
				continue
			}

			// If we got to here, the decision is a ConditionsMap or Union. This means that
			// there is no chance of evaluating to an unconditional decision using builtinConditionsEvaluator.
			// Thus, instead of continuing to try to evaluate later ConditionsMaps in-process,
			// whose computation might be wasted if previous authorizer's ConditionsMaps indeed
			// turn out to be Allow/Deny (and not NoOpinion), just short-circuit and do the webhook.
			//
			// collectAndShortcircuitOnly is used to preserve the tail of the union, without
			// evaluating the suffix.
			collectAndShortcircuitOnly = true
		}
		// If we got here, the first not-NoOpinion decision was Union or ConditionsMap, which means
		// we cannot simplify it. Return a possibly refined decision chain for webhooking.
		return newDecisionChain.ToDecision()
	}

	// Otherwise, the decision is a ConditionsMap. Try to evaluate it using the builtin evaluator.
	return evaluateConditionsMapInternal(ctx, unevaluatedDecision.ConditionsMap(), data, evaluateConditionFn)
}

type namedConditionsAwareDecision struct {
	authorizerName string
	d              ConditionsAwareDecision
}

// ConditionsAwareDecisionUnion is an unioned conditions-aware decision type, keyed by authorizer name.
type ConditionsAwareDecisionUnion struct {
	inner []namedConditionsAwareDecision
	errs  []error
}

func (unionMap *ConditionsAwareDecisionUnion) Add(authorizerName string, d ConditionsAwareDecision) {
	if slices.ContainsFunc(unionMap.inner, func(nd namedConditionsAwareDecision) bool { return nd.authorizerName == authorizerName }) {
		unionMap.errs = append(unionMap.errs, fmt.Errorf("duplicate authorizerName %q", authorizerName))
		return
	}
	if unionMap.ContainsAllowOrDeny() {
		return // all items after the first concrete Allow or Deny aren't anyways used in evaluation, so they are not added to inner
	}
	unionMap.inner = append(unionMap.inner, namedConditionsAwareDecision{authorizerName: authorizerName, d: d})
}

// FailureDecision returns either a Deny or NoOpinion decision to fail closed
// whenever processing a decision fails. If the decision contains one or
// more Deny decisions or conditions, one must fail closed with Deny, as that could or would
// have been the if the condition evaluation did not error. Otherwise, NoOpinion is returned.
func (unionMap ConditionsAwareDecisionUnion) FailureDecision() Decision {
	for _, subDecision := range unionMap.inner {
		if subDecision.d.FailureDecision() == DecisionDeny {
			return DecisionDeny
		}
	}
	return DecisionNoOpinion
}

// ContainsAllowOrDeny returns true whether there union contains at least one
// Allow or Deny decision within the unioned decisions.
func (unionMap ConditionsAwareDecisionUnion) ContainsAllowOrDeny() bool {
	for _, subDecision := range unionMap.inner {
		if subDecision.d.ContainsAllowOrDeny() {
			return true
		}
	}
	return false
}

func (unionMap ConditionsAwareDecisionUnion) PossibleDecisions() sets.Set[Decision] {
	union := sets.New(DecisionNoOpinion) // Default response is NoOpinion
	for _, subDecision := range unionMap.inner {
		union.Insert(subDecision.d.PossibleDecisions().UnsortedList()...)
		// Short-circuit on the first Allow or Deny, after that, decisions don't matter.
		if subDecision.d.ContainsAllowOrDeny() {
			// When there is an Allow or Deny leaf somewhere, the default response NoOpinion won't ever be returned
			union.Delete(DecisionNoOpinion)
			return union
		}
	}
	return union
}

// ConditionsAwareDecisionUnion unions some amount of decisions together into a tree structure,
// where Allow/Deny/NoOpinion/ConditionsMap decisions are leafs, and Union decisions are internal
// tree nodes.
func (unionMap ConditionsAwareDecisionUnion) ToDecision() ConditionsAwareDecision {
	// If we encountered any errors (e.g. duplicate authorizernames) while building the slice,
	// fail closed.
	if len(unionMap.errs) != 0 {
		err := utilerrors.NewAggregate(unionMap.errs)
		if unionMap.FailureDecision() == DecisionDeny {
			return ConditionsAwareDecisionDeny("failed closed", err)
		}
		return ConditionsAwareDecisionNoOpinion("failed closed", err)
	}

	// If we only have one possible decision, it can readily be evaluated without evaluation.
	if possibleDecisions := unionMap.PossibleDecisions(); possibleDecisions.Len() == 1 {
		onlyPossibleDecision := possibleDecisions.UnsortedList()[0]
		// Collect at least the certainly deciding decisions' reasons and errors. TODO: could we expand this?
		reasonlist := make([]string, 0, len(unionMap.inner))
		errlist := make([]error, 0, len(unionMap.inner))
		for i, subDecision := range unionMap.inner {
			if (onlyPossibleDecision == DecisionAllow && subDecision.d.IsAllow()) ||
				(onlyPossibleDecision == DecisionNoOpinion && subDecision.d.IsNoOpinion()) ||
				(onlyPossibleDecision == DecisionDeny && subDecision.d.IsDeny()) {
				if reason := subDecision.d.Reason(); len(reason) != 0 {
					reasonlist = append(reasonlist, fmt.Sprintf("%d: %s", i, reason))
				}
				if err := subDecision.d.Error(); err != nil {
					errlist = append(errlist, fmt.Errorf("%d: %w", i, err))
				}
			}
		}

		switch onlyPossibleDecision {
		case DecisionAllow:
			// For example, a union of decisions with possible outcomes "[Allow, NoOpinion], [NoOpinion], [Allow], [Deny]" yields possible outcome [Allow] always,
			// regardless of how the ConditionsMap in the beginning evaluates.
			return ConditionsAwareDecisionAllow(strings.Join(reasonlist, ", "), utilerrors.NewAggregate(errlist))
		case DecisionNoOpinion:
			// This happens for instance when called on the empty slice, then the only possible mode is NoOpinion
			// This can only happen if there were only NoOpinions in the chain, so we can gather them here. TODO: (formally) verify this
			return ConditionsAwareDecisionNoOpinion(strings.Join(reasonlist, ", "), utilerrors.NewAggregate(errlist))
		case DecisionDeny:
			// For example, a union of decisions with possible outcomes "[Deny, NoOpinion], [NoOpinion], [Deny], [Allow]" yields possible outcome [Deny] always,
			// regardless of how the ConditionsMap in the beginning evaluates.
			return ConditionsAwareDecisionDeny(strings.Join(reasonlist, ", "), utilerrors.NewAggregate(errlist))
		default:
			return ConditionsAwareDecisionDeny("failed closed", errors.New("should be unreachable: ConditionsAwareDecision should only contain Allow/Deny/NoOpinion"))
		}
	}

	return ConditionsAwareDecision{
		decisionType: conditionsAwareDecisionTypeUnion,
		union: ConditionsAwareDecisionUnion{
			// avoid assigning unionMap here, as then unionMap.Add could change the returned decision
			inner: slices.Clone(unionMap.inner),
		},
	}
}

// ConditionsData is an enum type for various evaluation targets conditions
// can be written against.
type ConditionsData struct {
	// AdmissionControl holds the data available during admission control.
	// Callers must verify that this is non-nil before using.
	AdmissionControl ConditionsDataAdmissionControl
}

// AdmissionOperation represents the admission operation,
// for example CREATE, UPDATE, DELETE. The constants are
// defined in k8s.io/apiserver/pkg/admission, but the
// type is defined here, because this package is more generic
// than the admission package (thus avoiding import cycles)
type AdmissionOperation string

// ConditionsDataAdmissionControl represents the data available during admission control, for conditions
// to evaluate against. This is by design a subset of admission.Attributes.
type ConditionsDataAdmissionControl interface {
	// GetName returns the name of the object as presented in the request. On a CREATE operation, the client
	// may omit name and rely on the server to generate the name. If that is the case, this method will return
	// the empty string
	GetName() string
	// GetNamespace is the namespace associated with the request (if any)
	GetNamespace() string
	// GetResource is the name of the resource being requested. This is not the kind. For example: pods
	GetResource() schema.GroupVersionResource
	// GetSubresource is the name of the subresource being requested. This is a different resource, scoped to the parent resource, but it may have a different kind.
	// For instance, /pods has the resource "pods" and the kind "Pod", while /pods/foo/status has the resource "pods", the sub resource "status", and the kind "Pod"
	// (because status operates on pods). The binding resource for a pod though may be /pods/foo/binding, which has resource "pods", subresource "binding", and kind "Binding".
	GetSubresource() string
	// GetOperation is the operation being performed
	GetOperation() AdmissionOperation
	// GetOperationOptions is the options for the operation being performed
	GetOperationOptions() runtime.Object
	// IsDryRun indicates that modifications will definitely not be persisted for this request. This is to prevent
	// admission controllers with side effects and a method of reconciliation from being overwhelmed.
	// However, a value of false for this does not mean that the modification will be persisted, because it
	// could still be rejected by a subsequent validation step.
	IsDryRun() bool
	// GetObject is the object from the incoming request prior to default values being applied
	GetObject() runtime.Object
	// GetOldObject is the existing object. Only populated for UPDATE and DELETE requests.
	GetOldObject() runtime.Object
	// GetKind is the type of object being manipulated.  For example: Pod
	GetKind() schema.GroupVersionKind
	// GetUserInfo is information about the requesting user
	GetUserInfo() user.Info
}
