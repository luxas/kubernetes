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
	"strings"

	"k8s.io/apimachinery/pkg/api/validate/content"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	genericfeatures "k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
)

// ErrorConditionEvaluationNotSupported is returned by authorizer implementations
// that do not support condition evaluation.
var ErrorConditionEvaluationNotSupported = errors.New("condition evaluation not supported")

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
	unconditionalDecision Decision

	conditionsMap ConditionsMap

	reason string
	err    error
}

// ConditionsAwareDecisionDeny constructs a Deny decision with the given reason and error.
func ConditionsAwareDecisionDeny(reason string, err error) ConditionsAwareDecision {
	return ConditionsAwareDecision{
		// DecisionDeny == int(0) == zero value
		// => ConditionsAwareDecision{} == ConditionsAwareDecisionDeny()
		unconditionalDecision: DecisionDeny,
		reason:                reason,
		err:                   err,
	}
}

// ConditionsAwareDecisionAllow constructs an Allow decision with the given reason and error.
func ConditionsAwareDecisionAllow(reason string, err error) ConditionsAwareDecision {
	return ConditionsAwareDecision{
		unconditionalDecision: DecisionAllow,
		reason:                reason,
		err:                   err,
	}
}

// ConditionsAwareDecisionNoOpinion constructs a NoOpinion decision with the given reason and error.
func ConditionsAwareDecisionNoOpinion(reason string, err error) ConditionsAwareDecision {
	return ConditionsAwareDecision{
		unconditionalDecision: DecisionNoOpinion,
		reason:                reason,
		err:                   err,
	}
}

// ConditionsAwareDecisionFromParts is meant to be used by conditions-unaware Authorizer implementations
// in order to implement Authorizer.ConditionsAwareAuthorize as:
// "return authorizer.ConditionsAwareDecisionFromParts(self.Authorize(ctx, a))"
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

// INVARIANT: Exactly one of Is* must return true at all times.

// IsAllowed returns true if the decision is an unconditional Allow.
func (d ConditionsAwareDecision) IsAllowed() bool {
	return d.unconditionalDecision == DecisionAllow
}

// IsNoOpinion returns true if the decision is an unconditional NoOpinion.
func (d ConditionsAwareDecision) IsNoOpinion() bool {
	return d.unconditionalDecision == DecisionNoOpinion
}

// IsConditionsMap returns true if the decision is a conditional response
// with a map of conditions to evaluate.
func (d ConditionsAwareDecision) IsConditionsMap() bool {
	return d.conditionsMap.Length() != 0
}

// IsDenied returns true if the decision is an unconditional Deny.
func (d ConditionsAwareDecision) IsDenied() bool {
	// The decision is a Deny whenever none of the other modes apply
	// All other Is* checks require some property of the struct to be
	// distinct from its zero value, which then implies that IsDenied
	// will be true for the zero value.
	// TODO(luxas): Add the Union mode also.
	return !d.IsAllowed() && !d.IsNoOpinion() && !d.IsConditionsMap()
}

// IsUnconditional is true if d is Allowed, Denied or NoOpinion.
func (d ConditionsAwareDecision) IsUnconditional() bool {
	return d.IsAllowed() || d.IsDenied() || d.IsNoOpinion()
}

// UnconditionalParts turns a ConditionsAwareDecision into the
// triple that Authorizer.Authorize expects.
func (d ConditionsAwareDecision) UnconditionalParts() (Decision, string, error) {
	switch {
	case d.IsAllowed():
		return DecisionAllow, d.Reason(), d.Error()
	case d.IsDenied():
		return DecisionDeny, d.Reason(), d.Error()
	case d.IsNoOpinion():
		return DecisionNoOpinion, d.Reason(), d.Error()
	default:
		// TODO(luxas): Use FailClosedDecision here instead.
		return DecisionDeny, "failed closed", fmt.Errorf("tried to return conditional decision to conditions-unaware authorizer")
	}
}

// FailClosedDecision returns either a Deny or NoOpinion Decision to fail closed
// whenever processing a decision fails. If the decision contains one or
// more Deny conditions, the Decision must be Deny, as that could have been the
// answer if the evaluation had been successful. Otherwise, NoOpinion is returned.
func (d ConditionsAwareDecision) FailClosedDecision(err error) ConditionsAwareDecision {
	if d.IsAllowed() || d.IsNoOpinion() {
		return ConditionsAwareDecisionNoOpinion("failed closed", err)
	}
	if d.IsConditionsMap() {
		return d.conditionsMap.FailClosedDecision(err)
	}
	// => d.IsDenied() == true
	return ConditionsAwareDecisionDeny("failed closed", err)
}

// ConditionsMap returns the ConditionsMap, which is non-empty
// if and only if IsConditionsMap is true.
func (d ConditionsAwareDecision) ConditionsMap() ConditionsMap {
	return d.conditionsMap
}

// Reason returns the reason associated with the decision.
func (d ConditionsAwareDecision) Reason() string {
	return d.reason
}

// Error returns the error associated with the decision.
func (d ConditionsAwareDecision) Error() error {
	return d.err
}

// String returns a human-readable representation of the decision.
func (d ConditionsAwareDecision) String() string {
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
	if d.IsAllowed() {
		return fmt.Sprintf("Allow%s", paramsStr())
	}
	if d.IsNoOpinion() {
		return fmt.Sprintf("NoOpinion%s", paramsStr())
	}
	if d.IsConditionsMap() {
		params = append(params, fmt.Sprintf("len=%d", d.conditionsMap.Length()))
		return fmt.Sprintf("ConditionsMap%s", paramsStr())
	}
	// Deny is written such that if none of the other modes apply,
	// IsDenied() is true.
	return fmt.Sprintf("Deny%s", paramsStr())
}

// ConditionEffect specifies how a condition evaluating to true should be handled.
type ConditionEffect string

const (
	// ConditionEffectDeny means that if this condition evaluates to true,
	// the ConditionsMap necessarily evaluates to Deny. No further authorizers
	// are consulted.
	ConditionEffectDeny ConditionEffect = "Deny"

	// ConditionEffectNoOpinion means that if this condition evaluates to true,
	// the given authorizer's ConditionsMap cannot evaluate to Allow anymore, but
	// necessarily Deny or NoOpinion, depending on whether there are any true
	// EffectDeny conditions.
	// However, later authorizers in the chain can still Allow or Deny.
	// It is effectively a softer deny that just overrides the authorizer's own
	// allow policies.
	ConditionEffectNoOpinion ConditionEffect = "NoOpinion"

	// ConditionEffectAllow means that if this condition evaluates to true,
	// the ConditionsMap evaluates to Allow, unless any Deny/NoOpinion condition
	// also evaluates to true (in which case the Deny/NoOpinion conditions have
	// precedence).
	ConditionEffectAllow ConditionEffect = "Allow"
)

// Validate validates that the given ConditionEffect is known to the system.
/*func (e ConditionEffect) Validate() error {
	if !supportedConditionEffects.Has(e) {
		return fmt.Errorf("condition effect %q not supported. Supported effects are: %v", e, slices.Sorted(maps.Keys(supportedConditionEffects)))
	}
	return nil
}*/

// var supportedConditionEffects = sets.New(ConditionEffectDeny, ConditionEffectNoOpinion, ConditionEffectAllow)

// ConditionType represents a type of authorization conditions.
// Should be formatted as a Kubernetes label key.
// Any domain suffix of *.k8s.io or *.kubernetes.io is reserved.
/*type ConditionType string

func (ct ConditionType) Validate() error {
	if errs := content.IsLabelKey(string(ct)); len(errs) > 0 {
		return fmt.Errorf("invalid condition type %q: %s", ct, strings.Join(errs, "; "))
	}
	return nil
}*/

// SerializedCondition represents a single condition to be evaluated against ConditionsData.
// A condition is a pure, deterministic function from ConditionsData to a boolean.
/*type SerializedCondition struct {
	// ID uniquely identifies this condition within the scope of the authorizer
	// that authored it. Validated as a Kubernetes label key.
	// Required.
	ID string

	// Condition is an opaque string that represents the condition to be evaluated.
	// It is a pure, deterministic function from ConditionsData to a boolean.
	// Might or might not be human-readable. Maximum MaxConditionBytes bytes.
	// Required.
	Condition string

	// Effect specifies how the condition evaluating to "true" should be treated.
	// Required.
	Effect ConditionEffect

	// Type describes the type of the condition, if there are multiple possibilities.
	// Should be formatted as a Kubernetes label key.
	// Any domain suffix of *.k8s.io or *.kubernetes.io is reserved for Kubernetes use.
	// Optional. Can be omitted if the condition is self-describing.
	Type string

	// Description is an optional human-friendly description that can be shown
	// as an error message or for debugging. Optional.
	Description string
}*/

// ConditionsMap is a map of conditions of a given type, and represents
// the conditional decision from the authorizer.
// It must be constructed through ConditionsAwareDecisionConditionsMap.
// During construction, all Conditions are validated and ensured to be non-nil.
type ConditionsMap struct {
	// invariant: when the decision is of type ConditionsMap, Length() != 0,
	// which means that at least one of these slices has an element in it.
	//
	// slices are used here instead of actual maps, as the ConditionsMap does
	// not need to lookup single elements. It's called a "map" as uniqueness of
	// the IDs (keys) across all conditions (values) in the map is enforced.
	denyConditions      []Condition
	noOpinionConditions []Condition
	allowConditions     []Condition
}

// FailClosedDecision returns either a Deny or NoOpinion Decision to fail closed
// whenever evaluating a ConditionSet fails. If the ConditionSet has one or
// more Deny conditions, the Decision must be Deny, as that could have been the
// answer if the evaluation had been successful. Otherwise, NoOpinion is returned.
func (c ConditionsMap) FailClosedDecision(err error) ConditionsAwareDecision {
	for cond := range c.Conditions() {
		if cond.GetEffect() == ConditionEffectDeny {
			return ConditionsAwareDecisionDeny("failed closed", err)
		}
	}
	return ConditionsAwareDecisionNoOpinion("failed closed", err)
}

// ConditionEvaluationResult is an enum type with four variants:
// - true and false: Evaluation was successful, and evaluated to this value
// - error: The condition could be evaluated, but errored during eval.
// - unevaluatable: The condition cannot readily be evaluated. This is the struct zero value.
type ConditionEvaluationResult struct {
	isTrue  bool
	isFalse bool
	err     error
}

// ConditionEvaluationResultBoolean constructs an evaluation result with a boolean value.
func ConditionEvaluationResultBoolean(evalResult bool) ConditionEvaluationResult {
	if evalResult {
		return ConditionEvaluationResult{isTrue: true}
	}
	return ConditionEvaluationResult{isFalse: true}
}

// ConditionEvaluationResultError indicates that the condition could be evaluated, but failed.
func ConditionEvaluationResultError(err error) ConditionEvaluationResult {
	return ConditionEvaluationResult{err: err}
}

// ConditionsEvaluationResultUnevaluatable indicates direct conditions evaluation is not possible.
func ConditionsEvaluationResultUnevaluatable() ConditionEvaluationResult {
	return ConditionEvaluationResult{}
}

// IsTrue indicates that the conditions evaluation was successful, and evaluated to true, which means it influences the ConditionsMap decision.
func (r ConditionEvaluationResult) IsTrue() bool { return r.isTrue }

// IsFalse indicates that the conditions evaluation was successful, but evaluated to false, and it not thus taken into account.
func (r ConditionEvaluationResult) IsFalse() bool { return r.isFalse }

// IsError indicates whether conditions evaluation failed.
func (r ConditionEvaluationResult) IsError() bool { return r.err != nil }

// Error returns the evaluation error, if any.
func (r ConditionEvaluationResult) Error() error { return r.err }

// IsUnevaluatable is true whenever none of the other variants is, that is, the zero value.
func (r ConditionEvaluationResult) IsUnevaluatable() bool {
	return !r.IsTrue() && !r.IsFalse() && !r.IsError()
}

type Condition interface {
	// GetID uniquely identifies this condition within the scope of the authorizer
	// that authored it. Validated as a Kubernetes label key.
	// Required.
	GetID() string

	// GetEffect specifies how the condition evaluating to "true" should be treated.
	// Required.
	GetEffect() ConditionEffect

	// GetType describes the type of the condition, if there are multiple possibilities.
	// Should be formatted as a Kubernetes label key.
	// Any domain suffix of *.k8s.io or *.kubernetes.io is reserved for Kubernetes use.
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
	// serialize/deserialize roundtrip (e.g. when the caller is an aggregated API server), some of the
	// conditions may not be directly evaluatable, and thus does the authorizer need to parse the condition
	// and
	Evaluate(ctx context.Context, data ConditionsData) ConditionEvaluationResult
}

// Length returns the number of elements in the map.
func (c ConditionsMap) Length() int {
	return len(c.denyConditions) + len(c.noOpinionConditions) + len(c.allowConditions)
}

// Conditions returns all conditions in this map.
// The order in which elements are returned is deterministic but undefined.
func (c ConditionsMap) Conditions() iter.Seq[Condition] {
	return func(yield func(Condition) bool) {
		for _, cond := range c.denyConditions {
			if !yield(cond) {
				return
			}
		}
		for _, cond := range c.noOpinionConditions {
			if !yield(cond) {
				return
			}
		}
		for _, cond := range c.allowConditions {
			if !yield(cond) {
				return
			}
		}
	}
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

const (
	// MaxConditionsPerMap is the maximum number of conditions allowed in a single ConditionsMap.
	MaxConditionsPerMap = 128
)

// ConditionsAwareDecisionConditionMap creates a ConditionsMap decision. One can use slices.Elements to create an iterator for a slice.
// TODO(luxas): Add condition and description byte limits in authorizationapivalidation?
func ConditionsAwareDecisionConditionMap(conditions ...Condition) ConditionsAwareDecision {

	// enforce maximum amount of conditions per map
	if len(conditions) > MaxConditionsPerMap {
		return ConditionsAwareDecisionDeny("failed closed", fmt.Errorf("too many conditions: %d exceeds maximum of %d", len(conditions), MaxConditionsPerMap))
	}

	denyConditions := []Condition{}
	noOpinionConditions := []Condition{}
	allowConditions := []Condition{}
	seenIDs := sets.New[string]()
	errlist := []error{}
	hasDenyEffect := false
	makeFailClosedError := func(err error) ConditionsAwareDecision {
		if hasDenyEffect {
			return ConditionsAwareDecisionDeny("failed closed", err)
		}
		return ConditionsAwareDecisionNoOpinion("failed closed", err)
	}
	for _, condition := range conditions {
		// ignore nil conditions.
		if isNilValue(condition) {
			continue
		}

		// Fail closed using Deny if there was at least one Deny condition in the map.
		effect := condition.GetEffect()
		if effect == ConditionEffectDeny {
			hasDenyEffect = true
		}

		id := condition.GetID()
		if seenIDs.Has(id) {
			errlist = append(errlist, fmt.Errorf("duplicate condition ID %q", id))
			continue
		}
		seenIDs.Insert(id)

		// Validate ID as a label key.
		if errs := content.IsLabelKey(id); len(errs) > 0 {
			errlist = append(errlist, fmt.Errorf("invalid condition ID %q: %s", id, strings.Join(errs, "; ")))
			continue
		}

		// Validate type as a label key, if set.
		if conditionType := condition.GetType(); len(conditionType) != 0 {
			if errs := content.IsLabelKey(conditionType); len(errs) > 0 {
				errlist = append(errlist, fmt.Errorf("invalid condition type %q: %s", conditionType, strings.Join(errs, "; ")))
				continue
			}
		}

		switch effect {
		case ConditionEffectDeny:
			denyConditions = append(denyConditions, condition)
		case ConditionEffectNoOpinion:
			noOpinionConditions = append(noOpinionConditions, condition)
		case ConditionEffectAllow:
			allowConditions = append(allowConditions, condition)
		default:
			// Fail closed if there are unknown effects
			return ConditionsAwareDecisionDeny("failed closed", fmt.Errorf("condition effect %q not supported. Supported effects are: [Deny, NoOpinion, Allow]", effect))
		}
	}

	// check errors before len(ConditionsMap) == 0, as some errors might have made the map be empty
	// although there were items in the iterator
	if err := utilerrors.NewAggregate(errlist); err != nil {
		// the error is returned first here, not in the loop, to make sure we saw all conditions,
		// and fail closed with deny if there were any deny conditions
		return makeFailClosedError(err)
	}

	// an empty ConditionsMap always evaluates to NoOpinion
	// ignore conditionType being invalid or the feature gate not being set in this case, as it does not matter
	// This must be done as the invariant of the decision's IsConditionsMap is whether the map has non-zero length.
	totalLen := len(denyConditions) + len(noOpinionConditions) + len(allowConditions)
	if totalLen == 0 {
		return ConditionsAwareDecisionNoOpinion("empty ConditionsMap", nil)
	}

	// Do not allow constructing Conditional decisions when the feature gate is off
	if !utilfeature.DefaultFeatureGate.Enabled(genericfeatures.ConditionalAuthorization) {
		return makeFailClosedError(fmt.Errorf("cannot construct conditional decision: the ConditionalAuthorization feature gate is disabled"))
	}

	return ConditionsAwareDecision{
		conditionsMap: ConditionsMap{
			denyConditions:      denyConditions,
			noOpinionConditions: noOpinionConditions,
			allowConditions:     allowConditions,
		},
	}
}

func isNilValue(i interface{}) bool {
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

type GenericCondition struct {
	ID           string
	Effect       ConditionEffect
	Condition    string
	Type         string
	Description  string
	EvaluateFunc func(ctx context.Context, data ConditionsData) ConditionEvaluationResult
}

var _ Condition = GenericCondition{}

func (c GenericCondition) GetID() string {
	return c.ID
}
func (c GenericCondition) GetEffect() ConditionEffect {
	return c.Effect
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

/*type BuiltinEvaluator interface {
	TryEvaluateCondition(ctx context.Context, condition Condition, data ConditionsData) (bool, error, bool)
}*/

// EvaluateConditionsMap evaluates the conditions in the map into a concrete Allow/Deny/NoOpinion Decision, given an
// evaluation function with a given supported condition type.
// This is a reference implementation that other conditional authorizers can use if convenient.
// The returned boolean quantifies whether the evaluation succeeded, that is, did _not_ have to fail closed
// due to a critical error. This allows the caller to take different actions depending of if evaluation was successful or not.
func (c *ConditionsMap) Evaluate(ctx context.Context, data ConditionsData, evaluateFunc func(context.Context, ConditionsData, Condition) ConditionEvaluationResult) ConditionsAwareDecision {
	evalCond := func(cond Condition) ConditionEvaluationResult {
		return cond.Evaluate(ctx, data)
	}
	if evaluateFunc != nil {
		evalCond = func(cond Condition) ConditionEvaluationResult {
			result := cond.Evaluate(ctx, data)
			if !result.IsUnevaluatable() {
				return result
			}
			return evaluateFunc(ctx, data, cond)
		}
	}

	if len(c.denyConditions) != 0 {
		denyErrors := []error{}
		appliedDenyReasons := []string{}
		unevaluatedDenyConditions := []Condition{}
		for cond := range c.DenyConditions() {
			id := cond.GetID()
			evalResult := evalCond(cond)
			switch {
			case evalResult.IsUnevaluatable():
				unevaluatedDenyConditions = append(unevaluatedDenyConditions, cond)
				continue
			case evalResult.IsError():
				denyErrors = append(denyErrors, fmt.Errorf("Deny condition %q produced error: %w", id, evalResult.Error()))
				continue
			case evalResult.IsTrue():
				reason := fmt.Sprintf("condition %q denied the request", id)
				if desc := cond.GetDescription(); len(desc) != 0 {
					reason += fmt.Sprintf(" with description %q", desc)
				}
				appliedDenyReasons = append(appliedDenyReasons, reason)
				continue
			default: // => evalResult.IsFalse() == true
				continue
			}
		}
		// If any deny conditions evaluated to true, return Deny
		// Deny conditions that apply take precedence over deny conditions that error, as even if the erroring
		// deny conditions wouldn't have errored, the applied deny conditions would have produced the same Deny decision.
		// TODO(luxas): Unit test for errors this behavior?
		if len(appliedDenyReasons) != 0 {
			// A nil error must be returned here, in order for the WithAuthorization handler to return 403 and not 500.
			return ConditionsAwareDecisionDeny(fmt.Sprintf("%v", appliedDenyReasons), nil)
		}
		// If any deny errors were encountered, fail closed
		if len(denyErrors) != 0 {
			return ConditionsAwareDecisionDeny("one or more conditional evaluation errors occurred", utilerrors.NewAggregate(denyErrors))
		}

		// When len(unevaluatedDenyConditions) != 0, the possible outcomes are [Deny, NoOpinion] or [Deny, Allow] (depending on whether)
		// there is some matching NoOpinion/Allow condition or not. This means that we need to return another, possibly refined ConditionsMap
		if len(unevaluatedDenyConditions) != 0 {
			return ConditionsAwareDecision{
				conditionsMap: ConditionsMap{
					denyConditions:      unevaluatedDenyConditions,
					noOpinionConditions: deepCopyConditions(c.noOpinionConditions),
					allowConditions:     deepCopyConditions(c.allowConditions),
				},
			}
		}
	}
	// If we got here, all Deny conditions could be evaluated, and evaluated to false, nil
	if len(c.noOpinionConditions) != 0 {
		noOpinionErrors := []error{}
		appliedNoOpinionReasons := []string{}
		unevaluatedNoOpinionConditions := []Condition{}
		for cond := range c.NoOpinionConditions() {
			id := cond.GetID()
			evalResult := evalCond(cond)
			switch {
			case evalResult.IsUnevaluatable():
				unevaluatedNoOpinionConditions = append(unevaluatedNoOpinionConditions, cond)
				continue
			case evalResult.IsError():
				noOpinionErrors = append(noOpinionErrors, fmt.Errorf("NoOpinion condition %q produced error: %w", id, evalResult.Error()))
				continue
			case evalResult.IsTrue():
				reason := fmt.Sprintf("condition %q evaluated to NoOpinion", id)
				if desc := cond.GetDescription(); len(desc) != 0 {
					reason += fmt.Sprintf(" with description %q", desc)
				}
				appliedNoOpinionReasons = append(appliedNoOpinionReasons, reason)
				continue
			default: // => evalResult.IsFalse() == true
				continue
			}
		}
		// If any NoOpinion conditions evaluated to true, return NoOpinion
		if len(appliedNoOpinionReasons) != 0 {
			return ConditionsAwareDecisionNoOpinion(fmt.Sprintf("%v", appliedNoOpinionReasons), nil)
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
			return ConditionsAwareDecision{
				conditionsMap: ConditionsMap{
					denyConditions:      nil,
					noOpinionConditions: unevaluatedNoOpinionConditions,
					// Technically, one could greedily try evaluating the Allow conditions and whether none of them evaluate to true,
					// directly fold to NoOpinion, even though there are unevaluated NoOpinion conditions.
					allowConditions: deepCopyConditions(c.allowConditions),
				},
			}
		}
	}
	// If we got here, all Deny and NoOpinion conditions could be evaluated, and evaluated to false, nil
	if len(c.allowConditions) != 0 {
		allowErrors := []error{}
		appliedAllowReasons := []string{}
		unevaluatedAllowConditions := []Condition{}
		for cond := range c.AllowConditions() {
			id := cond.GetID()
			evalResult := evalCond(cond)
			switch {
			case evalResult.IsUnevaluatable():
				unevaluatedAllowConditions = append(unevaluatedAllowConditions, cond)
				continue
			case evalResult.IsError():
				allowErrors = append(allowErrors, fmt.Errorf("Allow condition %q produced error: %w", id, evalResult.Error()))
				continue
			case evalResult.IsTrue():
				reason := fmt.Sprintf("condition %q allowed the request", id)
				if desc := cond.GetDescription(); len(desc) != 0 {
					reason += fmt.Sprintf(" with description %q", desc)
				}
				appliedAllowReasons = append(appliedAllowReasons, reason)
				continue
			default: // => evalResult.IsFalse() == true
				continue
			}
		}
		// If there were at least one Allow condition that applied, then evaluation is successful, even if there
		// were some errors that happened. Those are in this case considered warnings.
		if len(appliedAllowReasons) != 0 {
			return ConditionsAwareDecisionAllow(fmt.Sprintf("%v", appliedAllowReasons), utilerrors.NewAggregate(allowErrors))
		}
		// However, if no Allow condition evaluated to true, but at least one errored, return that as an error to the caller
		if len(allowErrors) != 0 {
			return ConditionsAwareDecisionNoOpinion("one or more conditional evaluation errors occurred", utilerrors.NewAggregate(allowErrors))
		}
		// When len(unevaluatedAllowConditions) != 0, the possible outcomes are [NoOpinion, Allow].
		// Return a possibly refined ConditionsMap with the Allow conditions that could not be evaluated.
		if len(unevaluatedAllowConditions) != 0 {
			return ConditionsAwareDecision{
				conditionsMap: ConditionsMap{
					denyConditions:      nil,
					noOpinionConditions: nil,
					allowConditions:     unevaluatedAllowConditions,
				},
			}
		}
	}

	// All conditions evaluated to false. This means a simple default NoOpinion.
	return ConditionsAwareDecisionNoOpinion("no conditions matched", nil)
}

func deepCopyConditions(originals []Condition) []Condition {
	copied := make([]Condition, len(originals))
	for i, original := range originals {
		copied[i] = original.DeepCopy()
	}
	return copied
}

// ConditionsData is an enum type for various evaluation targets conditions
// can be written against.
// TODO(luxas): Implement this in the follow-up PR.
type ConditionsData struct {
}
