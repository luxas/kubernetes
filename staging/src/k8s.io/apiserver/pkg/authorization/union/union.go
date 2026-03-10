/*
Copyright 2014 The Kubernetes Authors.

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

// Package union implements an authorizer that combines multiple subauthorizer.
// The union authorizer iterates over each subauthorizer and returns the first
// decision that is either an Allow decision or a Deny decision. If a
// subauthorizer returns a NoOpinion, then the union authorizer moves onto the
// next authorizer or, if the subauthorizer was the last authorizer, returns
// NoOpinion as the aggregate decision. I.e. union authorizer creates an
// aggregate decision and supports short-circuit allows and denies from
// subauthorizers.
package union

import (
	"context"
	"errors"
	"strings"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

// unionAuthzHandler authorizer against a chain of authorizer.Authorizer
type unionAuthzHandler []authorizer.Authorizer

// New returns an authorizer that authorizes against a chain of authorizer.Authorizer objects
func New(authorizationHandlers ...authorizer.Authorizer) authorizer.Authorizer {
	return unionAuthzHandler(authorizationHandlers)
}

// Authorizes against a chain of authorizer.Authorizer objects and returns nil if successful and returns error if unsuccessful
func (authzHandler unionAuthzHandler) Authorize(ctx context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
	var (
		errlist    []error
		reasonlist []string
	)

	for _, currAuthzHandler := range authzHandler {
		decision, reason, err := currAuthzHandler.Authorize(ctx, a)

		if err != nil {
			errlist = append(errlist, err)
		}
		if len(reason) != 0 {
			reasonlist = append(reasonlist, reason)
		}
		switch decision {
		case authorizer.DecisionAllow, authorizer.DecisionDeny:
			return decision, reason, err
		case authorizer.DecisionNoOpinion:
			// continue to the next authorizer
		}
	}

	return authorizer.DecisionNoOpinion, strings.Join(reasonlist, "\n"), utilerrors.NewAggregate(errlist)
}

// AuthorizeConditionsAware is not conditions-aware, converts the Authorize decision.
func (authzHandler unionAuthzHandler) AuthorizeConditionsAware(ctx context.Context, attrs authorizer.Attributes, encodingPreference authorizer.ConditionsEncodingPreference) authorizer.ConditionsAwareDecision {
	var decisions []authorizer.ConditionsAwareDecision

	for _, currAuthzHandler := range authzHandler {
		// Precondition: All previously seen leaf decisions were either of NoOpinion or ConditionsMap type.

		// Call the authorizer on its conditions-aware method, and add the decision to the slice,
		// regardless of type. This due to that later in EvaluateConditions, the decision index
		// in the slice is what correlates a decision with the authorizer that should be used
		// for evaluating it (if needed).
		decision := currAuthzHandler.AuthorizeConditionsAware(ctx, attrs, encodingPreference)
		decisions = append(decisions, decision)

		// If there is any Allow/Deny decision leaf, no need to walk the chain further.
		if decision.ContainsAllowOrDeny() {
			return authorizer.ConditionsAwareDecisionUnion(decisions...)
		}
		// => all leaves are NoOpinion or ConditionsMap, continue to the next authorizer
	}

	// If we reached here, all leaf decisions were either of NoOpinion or ConditionsMap type.
	// If all decisions were NoOpinions, the constructor folds into a single NoOpinion decision.
	return authorizer.ConditionsAwareDecisionUnion(decisions...)
}

// EvaluateConditions is not supported by this authorizer.
func (authzHandler unionAuthzHandler) EvaluateConditions(ctx context.Context, unevaluatedDecision authorizer.ConditionsAwareDecision, data authorizer.ConditionsData, evaluators authorizer.BuiltinConditionsMapEvaluators) authorizer.ConditionsAwareDecision {
	// Stopping condition for the recursion: Nothing to evaluate here.
	if unevaluatedDecision.IsAllowed() || unevaluatedDecision.IsDenied() || unevaluatedDecision.IsNoOpinion() {
		return unevaluatedDecision
	}
	// This should never happen, an authorizer shall only be called back on an unevaluatedDecision that was returned from
	// AuthorizeConditionsAware(). However, unionAuthzHandler.AuthorizeConditionsAware never returns a "bare" ConditionsMap,
	// but either Allow/Deny/NoOpinion (the case above), or Union[...], even if the union only contains one element.
	if unevaluatedDecision.IsConditionsMap() {
		return unevaluatedDecision.FailClosedDecision(errors.New("union authorizer never returns a bare ConditionsMap, cannot evaluate"))
	}

	var evaluatedDecisions []authorizer.ConditionsAwareDecision
	for i, unevaluatedSubDecision := range unevaluatedDecision.UnionedDecisions() {
		// Precondition: All previously seen leaf decisions were either of NoOpinion or ConditionsMap type.

		// If the decision is Allow/Deny/NoOpinion, evaluation doesn't change the response,
		// hence the default evaluated value is the unevaluated one.
		evaluatedSubDecision := unevaluatedSubDecision

		// However, ConditionsMap and Union decisions can be evaluated, so evaluate such sub-decisions
		if unevaluatedSubDecision.IsConditionsMap() || unevaluatedSubDecision.IsUnion() {
			evaluatedSubDecision = authzHandler[i].EvaluateConditions(ctx, unevaluatedSubDecision, data, evaluators)
			// TODO(luxas): We should ensure here that the evaluated leaf ConditionsMaps are a subset of their unevaluated one,
			// namely that:
			// a) the evaluated ConditionsTarget is ordered after the unevaluated ConditionsTarget,
			// b) any ConditionsMap evaluated to either Allow/Deny/NoOpinion/ConditionsMap (never Union),
			// c) if a ConditionsMap evaluated to an Allow, it had at least one effect=Allow condition,
			// d) if a ConditionsMap evaluated to an Deny, it had at least one effect=Deny condition,
			// e) any condition in a map kept their Effect as-is,
			// f) no new conditions were added, and
			// g) all leafs of a union satisfies these constraints (recursively).
		}

		// Likewise as in AuthorizeConditionsAware, always register all decisions in the slice, as there could
		// be e.g. Deny conditions before an unconditional Allow, and this setup cannot be simplified to a single decision
		evaluatedDecisions = append(evaluatedDecisions, evaluatedSubDecision)

		// If there is any Allow/Deny decision leaf, no need to walk the chain further.
		if evaluatedSubDecision.ContainsAllowOrDeny() {
			return authorizer.ConditionsAwareDecisionUnion(evaluatedDecisions...)
		}
		// => all leaves are NoOpinion or ConditionsMap, continue to the next authorizer
	}

	// If we reached here, all evaluated decision leafs were NoOpinion or ConditionsMap.
	// If all decisions were NoOpinions, the constructor folds into a single NoOpinion decision.
	return authorizer.ConditionsAwareDecisionUnion(evaluatedDecisions...)
}

// unionAuthzRulesHandler authorizer against a chain of authorizer.RuleResolver
type unionAuthzRulesHandler []authorizer.RuleResolver

// NewRuleResolvers returns an authorizer that authorizes against a chain of authorizer.Authorizer objects
func NewRuleResolvers(authorizationHandlers ...authorizer.RuleResolver) authorizer.RuleResolver {
	return unionAuthzRulesHandler(authorizationHandlers)
}

// RulesFor against a chain of authorizer.RuleResolver objects and returns nil if successful and returns error if unsuccessful
func (authzHandler unionAuthzRulesHandler) RulesFor(ctx context.Context, user user.Info, namespace string) ([]authorizer.ResourceRuleInfo, []authorizer.NonResourceRuleInfo, bool, error) {
	var (
		errList              []error
		resourceRulesList    []authorizer.ResourceRuleInfo
		nonResourceRulesList []authorizer.NonResourceRuleInfo
	)
	incompleteStatus := false

	for _, currAuthzHandler := range authzHandler {
		resourceRules, nonResourceRules, incomplete, err := currAuthzHandler.RulesFor(ctx, user, namespace)

		if incomplete {
			incompleteStatus = true
		}
		if err != nil {
			errList = append(errList, err)
		}
		if len(resourceRules) > 0 {
			resourceRulesList = append(resourceRulesList, resourceRules...)
		}
		if len(nonResourceRules) > 0 {
			nonResourceRulesList = append(nonResourceRulesList, nonResourceRules...)
		}
	}

	return resourceRulesList, nonResourceRulesList, incompleteStatus, utilerrors.NewAggregate(errList)
}
