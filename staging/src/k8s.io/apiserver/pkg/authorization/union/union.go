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
	"fmt"
	"strconv"

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

// This means that we got a concrete Allow or Deny or a conditional Allow
// Note that there may be conditional Denies before a concrete Allow, and
// a conditional Allow before a concrete Deny.

// Authorizes against a chain of authorizer.Authorizer objects and returns nil if successful and returns error if unsuccessful
func (authzHandler unionAuthzHandler) Authorize(ctx context.Context, a authorizer.Attributes) (authorizer.Decision, error) {
	var (
		errlist             []error
		noOpinionReasonList []string
		decisionChain       []authorizer.NamedDecision
	)

	for i, currAuthzHandler := range authzHandler {
		// Precondition: All previously seen decisions were either NoOpinion or Conditional.
		decision, err := currAuthzHandler.Authorize(ctx, a)

		if err != nil {
			// TODO: Wrap the errors to be of the form "authenticator 'foo' returned error: %w"
			errlist = append(errlist, err)
		}

		if !decision.IsNoOpinion() {
			decisionChain = append(decisionChain, authorizer.NamedDecision{
				AuthorizerName: fmt.Sprintf("%d", i),
				Decision:       decision,
			})
		} else { // decision.IsNoOpinion()
			reason := decision.Reason()
			if len(reason) != 0 {
				noOpinionReasonList = append(noOpinionReasonList, reason)
			}
		}

		// If we got a concrete Allow/Deny decision, no need to walk the chain further.
		if decision.IsDenied() || decision.IsAllowed() {
			// TODO: should we capture the reasons and errors from earlier conditional decisions?
			return authorizer.DecisionConditionalChain(decisionChain...), utilerrors.NewAggregate(errlist)
		}
	}

	if len(decisionChain) != 0 {
		// We reached the end of the chain and found no concrete Allow/Deny decision,
		// but at least one conditional decision. Return that here
		return authorizer.DecisionConditionalChain(decisionChain...), utilerrors.NewAggregate(errlist)
	}

	// We reached the end of the chain and all of the decisions were NoOpinions.
	return authorizer.DecisionNoOpinion(noOpinionReasonList...), utilerrors.NewAggregate(errlist)
}

func (authzHandler unionAuthzHandler) EvaluateConditions(ctx context.Context, unevaluatedDecision authorizer.Decision, data authorizer.ConditionData) (authorizer.Decision, error) {
	if unevaluatedDecision.IsAllowed() || unevaluatedDecision.IsDenied() || unevaluatedDecision.IsNoOpinion() {
		return unevaluatedDecision, nil
	}
	// TODO: better separation between IsConditional and IsConditionalChain
	if unevaluatedDecision.IsConditional() {
		return unevaluatedDecision.FailClosedDecision(), errors.New("plain ConditionSet unsupported")
	}

	errlist := []error{}
	for _, namedUnevaluatedSubDecision := range unevaluatedDecision.ConditionalChain() {
		failClosedDecision := namedUnevaluatedSubDecision.Decision.FailClosedDecision()
		i, err := strconv.Atoi(namedUnevaluatedSubDecision.AuthorizerName)
		if err != nil {
			if failClosedDecision.IsDenied() {
				return failClosedDecision, fmt.Errorf("unrecognized authorizer %q", namedUnevaluatedSubDecision.AuthorizerName)
			}
			continue
		}
		if i < 0 || i >= len(authzHandler) {
			if failClosedDecision.IsDenied() {
				return failClosedDecision, fmt.Errorf("unrecognized authorizer %q", namedUnevaluatedSubDecision.AuthorizerName)
			}
			continue
		}
		conditionsAuthorizer := authzHandler[i]
		evalResult, err := conditionsAuthorizer.EvaluateConditions(ctx, namedUnevaluatedSubDecision.Decision, data)
		if evalResult.IsAllowed() || evalResult.IsDenied() {
			return evalResult, err
		}

		if err != nil {
			errlist = append(errlist, err)
		}

		if evalResult.IsNoOpinion() {
			continue
		}

		// We do not yet support evaluating conditional to conditional
		err = errors.New("unsupported to evaluate conditional to conditional")
		if err != nil {
			errlist = append(errlist, err)
		}
		if failClosedDecision.IsDenied() {
			return failClosedDecision, err
		}
	}
	// Everything evaluated to NoOpinion
	// TODO: Aggregate the reasons here too?
	return authorizer.DecisionNoOpinion(), utilerrors.NewAggregate(errlist)
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
