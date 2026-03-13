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
	"errors"
	"fmt"
	"iter"
	"maps"
	"slices"
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
	return len(d.conditionsMap.conditions) != 0
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
		return fmt.Sprintf("ConditionsMap(type=%q, len=%d)%s", d.conditionsMap.conditionType, len(d.conditionsMap.conditions), paramsStr())
	}
	// Deny is written such that if none of the other modes apply,
	// IsDenied() is true.
	return fmt.Sprintf("Deny%s", paramsStr())
}

// Maximum limits for conditions and condition sets.
const (
	// MaxConditionsPerSet is the maximum number of conditions allowed in a single ConditionsMap.
	MaxConditionsPerSet = 128
	// MaxConditionBytes is the maximum size in bytes for a single Condition.Condition and Condition.Description string.
	MaxConditionBytes = 10240
)

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
func (e ConditionEffect) Validate() error {
	if !supportedConditionEffects.Has(e) {
		return fmt.Errorf("condition effect %q not supported. Supported effects are: %v", e, slices.Sorted(maps.Keys(supportedConditionEffects)))
	}
	return nil
}

var supportedConditionEffects = sets.New(ConditionEffectDeny, ConditionEffectNoOpinion, ConditionEffectAllow)

// ConditionType represents a type of authorization conditions.
// Should be formatted as a Kubernetes label key.
// Any domain suffix of *.k8s.io or *.kubernetes.io is reserved.
type ConditionType string

func (ct ConditionType) Validate() error {
	if errs := content.IsLabelKey(string(ct)); len(errs) > 0 {
		return fmt.Errorf("invalid condition type %q: %s", ct, strings.Join(errs, "; "))
	}
	return nil
}

// Condition represents a single condition to be evaluated against ConditionsData.
// A condition is a pure, deterministic function from ConditionsData to a boolean.
type Condition struct {
	// Condition is an opaque string that represents the condition to be evaluated.
	// It is a pure, deterministic function from ConditionsData to a boolean.
	// Might or might not be human-readable. Maximum MaxConditionBytes bytes.
	Condition string

	// Effect specifies how the condition evaluating to "true" should be treated.
	Effect ConditionEffect

	// Description is an optional human-friendly description that can be shown
	// as an error message or for debugging.
	Description string
}

// validateCondition validates a single Condition.
func (cond Condition) Validate(id string) error {
	// Validate ID as a label key.
	if errs := content.IsLabelKey(id); len(errs) > 0 {
		return fmt.Errorf("invalid condition ID %q: %s", id, strings.Join(errs, "; "))
	}

	// Validate Condition strings length.
	if len(cond.Condition) == 0 {
		return fmt.Errorf("condition %q has empty Condition string", id)
	}
	if len(cond.Condition) > MaxConditionBytes {
		return fmt.Errorf("condition %q exceeds maximum length of %d bytes (saw %d bytes)", id, MaxConditionBytes, len(cond.Condition))
	}
	if len(cond.Description) > MaxConditionBytes {
		return fmt.Errorf("condition description %q exceeds maximum length of %d bytes (saw %d bytes)", id, MaxConditionBytes, len(cond.Condition))
	}

	return cond.Effect.Validate()
}

// ConditionsMap is a map of conditions of a given type, and represents
// the conditional decision from the authorizer.
// It must be constructed through ConditionsAwareDecisionConditionMap.
type ConditionsMap struct {
	// conditionType is the format/encoding/language of the conditions in this set.
	// Any type starting with `k8s.io/` is reserved for Kubernetes condition types.
	// Validated as a label key.
	conditionType ConditionType

	// conditions is the set of conditions to evaluate.
	// The string ID uniquely identifies the condition within the scope of the authorizer
	// that authored the condition. Validated as a Kubernetes label key, i.e.
	// (<DNS1123 subdomain>/)[-A-Za-z0-9_.]{1,63}.
	// IDs with the 'k8s.io/' prefix are reserved for Kubernetes.
	conditions map[string]Condition
}

// Type returns the condition type (format/encoding/language) of the conditions
// in this set.
func (c ConditionsMap) Type() ConditionType {
	return c.conditionType
}

// Conditions returns the conditions in this set. The returned slice must not be
// modified.
func (c ConditionsMap) Conditions() iter.Seq2[string, Condition] {
	return func(yield func(string, Condition) bool) {
		for id, cond := range c.conditions {
			if !yield(id, cond) {
				return
			}
		}
	}
}

func (c ConditionsMap) DenyConditions() iter.Seq2[string, Condition] {
	return func(yield func(string, Condition) bool) {
		for id, cond := range c.conditions {
			if cond.Effect != ConditionEffectDeny {
				continue
			}
			if !yield(id, cond) {
				return
			}
		}
	}
}

func (c ConditionsMap) NoOpinionConditions() iter.Seq2[string, Condition] {
	return func(yield func(string, Condition) bool) {
		for id, cond := range c.conditions {
			if cond.Effect != ConditionEffectNoOpinion {
				continue
			}
			if !yield(id, cond) {
				return
			}
		}
	}
}

func (c ConditionsMap) AllowConditions() iter.Seq2[string, Condition] {
	return func(yield func(string, Condition) bool) {
		for id, cond := range c.conditions {
			if cond.Effect != ConditionEffectAllow {
				continue
			}
			if !yield(id, cond) {
				return
			}
		}
	}
}

// ConditionsAwareDecisionConditionMap creates a ConditionsMap decision. One can use maps.All to create an iterator from a map[string]Condition.
func ConditionsAwareDecisionConditionMap(conditionType ConditionType, conditionsIter iter.Seq2[string, Condition]) ConditionsAwareDecision {
	conditionMap := map[string]Condition{}
	seenIDs := sets.New[string]()
	errlist := []error{}
	hasDenyEffect := false
	makeFailClosedError := func(err error) ConditionsAwareDecision {
		if hasDenyEffect {
			return ConditionsAwareDecisionDeny("failed closed", err)
		}
		return ConditionsAwareDecisionNoOpinion("failed closed", err)
	}
	for id, condition := range conditionsIter {
		// Fail closed if there are unknown effects
		if err := condition.Effect.Validate(); err != nil {
			return ConditionsAwareDecisionDeny("failed closed", err)
		}
		if condition.Effect == ConditionEffectDeny {
			hasDenyEffect = true
		}
		if seenIDs.Has(id) {
			errlist = append(errlist, fmt.Errorf("duplicate condition ID %q", id))
			continue
		}
		seenIDs.Insert(id)

		if err := condition.Validate(id); err != nil {
			errlist = append(errlist, err)
			continue
		}
		conditionMap[id] = condition
		// defensively stop directly when having seen too many conditions
		if len(conditionMap) > MaxConditionsPerSet {
			return ConditionsAwareDecisionDeny("failed closed", fmt.Errorf("too many conditions: %d exceeds maximum of %d", len(conditionMap), MaxConditionsPerSet))
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
	if len(conditionMap) == 0 {
		return ConditionsAwareDecisionNoOpinion("empty ConditionsMap", nil)
	}

	// Do not allow constructing Conditional decisions when the feature gate is off
	if !utilfeature.DefaultFeatureGate.Enabled(genericfeatures.ConditionalAuthorization) {
		return makeFailClosedError(fmt.Errorf("cannot construct conditional decision: the ConditionalAuthorization feature gate is disabled"))
	}

	if err := conditionType.Validate(); err != nil {
		return makeFailClosedError(err)
	}

	return ConditionsAwareDecision{
		unconditionalDecision: 0,
		conditionsMap: ConditionsMap{
			conditionType: conditionType,
			conditions:    conditionMap,
		},
	}
}

// ConditionsData is an enum type for various evaluation targets conditions
// can be written against.
// TODO(luxas): Implement this in the follow-up PR.
type ConditionsData struct {
}
