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
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
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
		if len(d.conditionsMap.denyConditions) != 0 {
			params = append(params, fmt.Sprintf("denies=%d", len(d.conditionsMap.denyConditions)))
		}
		if len(d.conditionsMap.noOpinionConditions) != 0 {
			params = append(params, fmt.Sprintf("noopinions=%d", len(d.conditionsMap.noOpinionConditions)))
		}
		if len(d.conditionsMap.allowConditions) != 0 {
			params = append(params, fmt.Sprintf("allows=%d", len(d.conditionsMap.allowConditions)))
		}
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
