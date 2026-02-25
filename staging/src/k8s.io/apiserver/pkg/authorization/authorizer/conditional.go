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
	"iter"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/api/validate/content"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
)

// ErrorConditionEvaluationNotSupported is returned by authorizer implementations
// that do not support condition evaluation.
var ErrorConditionEvaluationNotSupported = errors.New("condition evaluation not supported")

// Maximum limits for conditions and condition sets.
const (
	// MaxConditionsPerSet is the maximum number of conditions allowed in a single ConditionSet.
	MaxConditionsPerSet = 128
	// MaxConditionBytes is the maximum size in bytes for a single Condition.Condition string.
	MaxConditionBytes = 10240
)

// ConditionEffect specifies how a condition evaluating to true should be handled.
type ConditionEffect string

const (
	// ConditionEffectDeny means that if this condition evaluates to true,
	// the ConditionSet necessarily evaluates to Deny. No further authorizers
	// are consulted.
	ConditionEffectDeny ConditionEffect = "Deny"

	// ConditionEffectNoOpinion means that if this condition evaluates to true,
	// the given authorizer's ConditionSet cannot evaluate to Allow anymore, but
	// necessarily Deny or NoOpinion, depending on whether there are any true
	// EffectDeny conditions.
	// However, later authorizers in the chain can still Allow or Deny.
	// It is effectively a softer deny that just overrides the authorizer's own
	// allow policies.
	ConditionEffectNoOpinion ConditionEffect = "NoOpinion"

	// ConditionEffectAllow means that if this condition evaluates to true,
	// the ConditionSet evaluates to Allow, unless any Deny/NoOpinion condition
	// also evaluates to true (in which case the Deny/NoOpinion conditions have
	// precedence).
	ConditionEffectAllow ConditionEffect = "Allow"
)

// reservedConditionIDPrefix is the prefix reserved for Kubernetes-defined condition IDs.
const reservedConditionIDPrefix = "k8s.io/"

// Condition represents a single condition to be evaluated against ConditionData.
// A condition is a pure, deterministic function from ConditionData to a Boolean.
type Condition struct {
	// ID uniquely identifies the condition within the scope of the authorizer
	// that authored the condition. Validated as a Kubernetes label key, i.e.
	// (<DNS1123 subdomain>/)[-A-Za-z0-9_.]{1,63}.
	// IDs with the 'k8s.io/' prefix are reserved for Kubernetes.
	ID string

	// Condition is an opaque string that represents the condition to be evaluated.
	// It is a pure, deterministic function from ConditionData to a Boolean.
	// Might or might not be human-readable. Maximum MaxConditionBytes bytes.
	Condition string

	// Effect specifies how the condition evaluating to "true" should be treated.
	Effect ConditionEffect

	// Description is an optional human-friendly description that can be shown
	// as an error message or for debugging.
	Description string
}

// ConditionSet represents a conditional response from an authorizer.
// It must be constructed through NewConditionSet or NewUnconditionalConditionSet.
type ConditionSet struct {
	// conditionType is the format/encoding/language of the conditions in this set.
	// Any type starting with `k8s.io/` is reserved for Kubernetes condition types.
	// Validated as a label key.
	conditionType string

	// conditions is the set of conditions to evaluate.
	// TODO: implement this using a map from ID to Condition instead?
	conditions []Condition
}

// Type returns the condition type (format/encoding/language) of the conditions
// in this set.
func (c *ConditionSet) Type() string {
	return c.conditionType
}

// Conditions returns the conditions in this set. The returned slice must not be
// modified.
func (c *ConditionSet) Conditions() iter.Seq[Condition] {
	return func(yield func(Condition) bool) {
		for _, cond := range c.conditions {
			if !yield(cond) {
				return
			}
		}
	}
}

func (c *ConditionSet) DenyConditions() iter.Seq[Condition] {
	return func(yield func(Condition) bool) {
		for _, cond := range c.conditions {
			if cond.Effect != ConditionEffectDeny {
				continue
			}
			if !yield(cond) {
				return
			}
		}
	}
}

func (c *ConditionSet) NoOpinionConditions() iter.Seq[Condition] {
	return func(yield func(Condition) bool) {
		for _, cond := range c.conditions {
			if cond.Effect != ConditionEffectNoOpinion {
				continue
			}
			if !yield(cond) {
				return
			}
		}
	}
}

func (c *ConditionSet) AllowConditions() iter.Seq[Condition] {
	return func(yield func(Condition) bool) {
		for _, cond := range c.conditions {
			if cond.Effect != ConditionEffectAllow {
				continue
			}
			if !yield(cond) {
				return
			}
		}
	}
}

func (c *ConditionSet) Equal(other *ConditionSet) bool {
	if c == nil || other == nil {
		// if both are nil => true
		// if c nil, but other non-nil => false
		// if c non-nil, but other nil => false
		return (c == nil) == (other == nil)
	}
	// both non-nil
	return false // TODO implement semantic equivalence
}

// CanBecomeAllowed returns true if this ConditionSet has at least one
// effect=Allow condition, or wraps an unconditional Allow decision.
func (c *ConditionSet) CanBecomeAllowed() bool {
	for _, cond := range c.conditions {
		if cond.Effect == ConditionEffectAllow {
			return true
		}
	}
	return false
}

// FailClosedDecision returns either a Deny or NoOpinion Decision to fail closed
// whenever evaluating a ConditionSet fails. If the ConditionSet has one or
// more Deny conditions, the Decision must be Deny, as that could have been the
// answer if the evaluation had been successful. Otherwise, NoOpinion is returned.
func (c *ConditionSet) FailClosedDecision() Decision {
	hasDenyCondition := slices.ContainsFunc(c.conditions, func(cond Condition) bool {
		return cond.Effect == ConditionEffectDeny
	})
	if hasDenyCondition {
		return DecisionDeny()
	}
	return DecisionNoOpinion()
}

// NewConditionSet creates a new ConditionSet with the given condition type
// and conditions. It validates all conditions and returns an error if any
// validation fails.
func NewConditionSet(conditionType string, conditions []Condition) (*ConditionSet, error) {
	if errs := content.IsLabelKey(conditionType); len(errs) > 0 {
		return nil, fmt.Errorf("invalid condition type %q: %s", conditionType, strings.Join(errs, "; "))
	}

	if len(conditions) == 0 {
		return nil, fmt.Errorf("conditions must not be empty")
	}

	if len(conditions) > MaxConditionsPerSet {
		return nil, fmt.Errorf("too many conditions: %d exceeds maximum of %d", len(conditions), MaxConditionsPerSet)
	}

	seenIDs := make(map[string]struct{}, len(conditions))
	for i, cond := range conditions {
		if err := validateCondition(cond, i); err != nil {
			return nil, err
		}
		if _, ok := seenIDs[cond.ID]; ok {
			return nil, fmt.Errorf("duplicate condition ID %q at index %d", cond.ID, i)
		}
		seenIDs[cond.ID] = struct{}{}
	}

	// Make a defensive copy of the conditions slice.
	conditionsCopy := make([]Condition, len(conditions))
	copy(conditionsCopy, conditions)

	return &ConditionSet{
		conditionType: conditionType,
		conditions:    conditionsCopy,
	}, nil
}

// validateCondition validates a single Condition.
func validateCondition(cond Condition, index int) error {
	// Validate ID as a label key.
	if errs := content.IsLabelKey(cond.ID); len(errs) > 0 {
		return fmt.Errorf("invalid condition ID %q at index %d: %s", cond.ID, index, strings.Join(errs, "; "))
	}

	// Reject reserved k8s.io/ prefix.
	if strings.HasPrefix(cond.ID, reservedConditionIDPrefix) {
		return fmt.Errorf("condition ID %q at index %d uses reserved prefix %q", cond.ID, index, reservedConditionIDPrefix)
	}

	// Validate Condition string length.
	if len(cond.Condition) == 0 {
		return fmt.Errorf("condition at index %d has empty Condition string", index)
	}
	if len(cond.Condition) > MaxConditionBytes {
		return fmt.Errorf("condition %q at index %d exceeds maximum length of %d bytes (%d bytes)", cond.ID, index, MaxConditionBytes, len(cond.Condition))
	}

	// Validate Effect.
	switch cond.Effect {
	case ConditionEffectAllow, ConditionEffectDeny, ConditionEffectNoOpinion:
		// valid
	default:
		return fmt.Errorf("condition %q at index %d has invalid effect %q", cond.ID, index, cond.Effect)
	}

	return nil
}

// ConditionSetEvaluator evaluates a condition set given more information in ConditionData.
// The resulting Decision may be concrete (Allow/Deny/NoOpinion), or again conditional, if the
// data in ConditionData is partial.
type ConditionSetEvaluator interface {
	EvaluateConditions(ctx context.Context, decision Decision, data ConditionData) (Decision, error)
}

// EvaluateConditionSet evaluates the conditions in the set into a concrete Allow/Deny/NoOpinion Decision, given an
// evaluation function with a given supported condition type.
// This is a reference implementation that other conditional authorizers can use if convenient.
func EvaluateConditionSet(conditionSet *ConditionSet, supportedConditionType string, eval func(string) (bool, error)) (Decision, error) {
	if conditionSet == nil {
		return DecisionNoOpinion(), nil
	}

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

// BuiltinConditionSetEvaluator is a ConditionSetEvaluator that can evaluate
// conditions of a specific type in-process, without requiring a webhook call.
type BuiltinConditionSetEvaluator interface {
	ConditionSetEvaluator

	// SupportedConditionType returns the condition type that this evaluator
	// supports (e.g. "k8s.io/cel").
	SupportedConditionType() sets.Set[string]
}

// ConditionData provides the data that was unknown at authorization time but
// is now available for condition evaluation. This includes the request object,
// the old object (for updates/deletes), the operation, and options.
// All top-level getters are mutually exclusive with each other.
type ConditionData interface {
	// WriteRequest provides data for a condition that is targeting a normal write request
	// (verbs=create, update, patch, delete, deletecollection or a connect request).
	// Evaluating a ConditionSet against WriteRequest must return a concrete decision (Allow/Deny/NoOpinion).
	WriteRequest() WriteRequestConditionData

	// ImpersonationRequest provides data known at the time of impersonation. Evaluating a condition
	// against the data of ImpersonationRequest can result in a concrete decision (Allow/Deny/NoOpinion)
	// or another conditional decision, with conditions written against WriteRequest.
	ImpersonationRequest() ImpersonationRequestConditionData
}

type WriteRequestConditionData interface {
	// GetOperation returns the operation being performed (e.g. "CREATE", "UPDATE",
	// "DELETE", "CONNECT").
	GetOperation() string

	// GetOperationOptions returns the options for the operation being performed.
	GetOperationOptions() runtime.Object

	// GetObject returns the object from the incoming request prior to default
	// values being applied. Only populated for CREATE and UPDATE requests.
	GetObject() runtime.Object

	// GetOldObject returns the existing object. Only populated for UPDATE and
	// DELETE requests.
	GetOldObject() runtime.Object
}

type ImpersonationRequestConditionData interface {
	// GetVerb returns the kube verb associated with API requests (this includes get, list, watch, create, update, patch, delete, deletecollection, and proxy),
	// or the lowercased HTTP verb associated with non-API requests (this includes get, put, post, patch, and delete)
	GetVerb() string

	// When IsReadOnly() == true, the request has no side effects, other than
	// caching, logging, and other incidentals.
	IsReadOnly() bool

	// The namespace of the object, if a request is for a REST object.
	GetNamespace() string

	// The kind of object, if a request is for a REST object.
	GetResource() string

	// GetSubresource returns the subresource being requested, if present
	GetSubresource() string

	// GetName returns the name of the object as parsed off the request.  This will not be present for all request types, but
	// will be present for: get, update, delete
	GetName() string

	// The group of the resource, if a request is for a REST object.
	GetAPIGroup() string

	// GetAPIVersion returns the version of the group requested, if a request is for a REST object.
	GetAPIVersion() string

	// IsResourceRequest returns true for requests to API resources, like /api/v1/nodes,
	// and false for non-resource endpoints like /api, /healthz
	IsResourceRequest() bool

	// GetPath returns the path of the request
	GetPath() string

	// ParseFieldSelector is lazy, thread-safe, and stores the parsed result and error.
	// It returns an error if the field selector cannot be parsed.
	// The returned requirements must be treated as readonly and not modified.
	GetFieldSelector() (fields.Requirements, error)

	// ParseLabelSelector is lazy, thread-safe, and stores the parsed result and error.
	// It returns an error if the label selector cannot be parsed.
	// The returned requirements must be treated as readonly and not modified.
	GetLabelSelector() (labels.Requirements, error)
}
