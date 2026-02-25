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
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/api/validate/content"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
)

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
	// Mutually exclusive with unconditionalDecision.
	conditions []Condition

	// unconditionalDecision captures an unconditional decision from an authorizer
	// that is later in the chain than an authorizer that returned a conditional
	// response.
	// Mutually exclusive with conditions.
	unconditionalDecision *Decision
}

// Type returns the condition type (format/encoding/language) of the conditions
// in this set.
func (c *ConditionSet) Type() string {
	return c.conditionType
}

// Conditions returns the conditions in this set. The returned slice must not be
// modified.
func (c *ConditionSet) Conditions() []Condition {
	return c.conditions
}

// IsUnconditional returns true if this ConditionSet wraps an unconditional
// decision from a later authorizer in the chain.
func (c *ConditionSet) IsUnconditional() bool {
	return c.unconditionalDecision != nil
}

// UnconditionalDecision returns the unconditional decision, if this ConditionSet
// wraps one. Returns nil if this is a regular condition set.
func (c *ConditionSet) UnconditionalDecision() *Decision {
	return c.unconditionalDecision
}

// CanBecomeAllowed returns true if this ConditionSet has at least one
// effect=Allow condition, or wraps an unconditional Allow decision.
func (c *ConditionSet) CanBecomeAllowed() bool {
	if c.unconditionalDecision != nil {
		return c.unconditionalDecision.IsAllowed()
	}
	for _, cond := range c.conditions {
		if cond.Effect == ConditionEffectAllow {
			return true
		}
	}
	return false
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

// NewUnconditionalConditionSet creates a ConditionSet that wraps an unconditional
// decision from an authorizer later in the chain. This is used when composing
// conditional and unconditional responses in the authorization chain.
func NewUnconditionalConditionSet(decision Decision) *ConditionSet {
	return &ConditionSet{
		unconditionalDecision: &decision,
	}
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
	EvaluateConditions(ctx context.Context, conditionSet *ConditionSet, data ConditionData) (Decision, error)
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
type ConditionData interface {
	// WriteRequest
	WriteRequest() WriteRequestConditionData
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
