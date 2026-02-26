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

package union

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
)

type mockAuthzHandler struct {
	decision authorizer.Decision
	err      error
}

func (mock *mockAuthzHandler) Authorize(ctx context.Context, a authorizer.Attributes) (authorizer.Decision, error) {
	return mock.decision, mock.err
}

func (mock *mockAuthzHandler) EvaluateConditions(ctx context.Context, decision authorizer.Decision, data authorizer.ConditionData) (authorizer.Decision, error) {
	return authorizer.DecisionDeny(), authorizer.ErrorConditionEvaluationNotSupported
}

func TestAuthorizationSecondPasses(t *testing.T) {
	handler1 := &mockAuthzHandler{decision: authorizer.DecisionNoOpinion("")}
	handler2 := &mockAuthzHandler{decision: authorizer.DecisionAllow("")}
	authzHandler := New(handler1, handler2)

	authorized, _ := authzHandler.Authorize(context.Background(), nil)
	if !authorized.IsAllowed() {
		t.Errorf("Unexpected authorization failure")
	}
}

func TestAuthorizationFirstPasses(t *testing.T) {
	handler1 := &mockAuthzHandler{decision: authorizer.DecisionAllow("")}
	handler2 := &mockAuthzHandler{decision: authorizer.DecisionNoOpinion("")}
	authzHandler := New(handler1, handler2)

	authorized, _ := authzHandler.Authorize(context.Background(), nil)
	if !authorized.IsAllowed() {
		t.Errorf("Unexpected authorization failure")
	}
}

func TestAuthorizationNonePasses(t *testing.T) {
	handler1 := &mockAuthzHandler{decision: authorizer.DecisionNoOpinion("")}
	handler2 := &mockAuthzHandler{decision: authorizer.DecisionNoOpinion("")}
	authzHandler := New(handler1, handler2)

	authorized, _ := authzHandler.Authorize(context.Background(), nil)
	if authorized.IsAllowed() {
		t.Errorf("Expected failed authorization")
	}
}

func TestAuthorizationError(t *testing.T) {
	handler1 := &mockAuthzHandler{err: fmt.Errorf("foo")}
	handler2 := &mockAuthzHandler{err: fmt.Errorf("foo")}
	authzHandler := New(handler1, handler2)

	_, err := authzHandler.Authorize(context.Background(), nil)
	if err == nil {
		t.Errorf("Expected error: %v", err)
	}
}

type mockAuthzRuleHandler struct {
	resourceRules    []authorizer.ResourceRuleInfo
	nonResourceRules []authorizer.NonResourceRuleInfo
	err              error
}

func (mock *mockAuthzRuleHandler) RulesFor(ctx context.Context, user user.Info, namespace string) ([]authorizer.ResourceRuleInfo, []authorizer.NonResourceRuleInfo, bool, error) {
	if mock.err != nil {
		return []authorizer.ResourceRuleInfo{}, []authorizer.NonResourceRuleInfo{}, false, mock.err
	}
	return mock.resourceRules, mock.nonResourceRules, false, nil
}

func TestAuthorizationResourceRules(t *testing.T) {
	handler1 := &mockAuthzRuleHandler{
		resourceRules: []authorizer.ResourceRuleInfo{
			&authorizer.DefaultResourceRuleInfo{
				Verbs:     []string{"*"},
				APIGroups: []string{"*"},
				Resources: []string{"bindings"},
			},
			&authorizer.DefaultResourceRuleInfo{
				Verbs:     []string{"get", "list", "watch"},
				APIGroups: []string{"*"},
				Resources: []string{"*"},
			},
		},
	}
	handler2 := &mockAuthzRuleHandler{
		resourceRules: []authorizer.ResourceRuleInfo{
			&authorizer.DefaultResourceRuleInfo{
				Verbs:     []string{"*"},
				APIGroups: []string{"*"},
				Resources: []string{"events"},
			},
			&authorizer.DefaultResourceRuleInfo{
				Verbs:         []string{"get"},
				APIGroups:     []string{"*"},
				Resources:     []string{"*"},
				ResourceNames: []string{"foo"},
			},
		},
	}

	expected := []authorizer.DefaultResourceRuleInfo{
		{
			Verbs:     []string{"*"},
			APIGroups: []string{"*"},
			Resources: []string{"bindings"},
		},
		{
			Verbs:     []string{"get", "list", "watch"},
			APIGroups: []string{"*"},
			Resources: []string{"*"},
		},
		{
			Verbs:     []string{"*"},
			APIGroups: []string{"*"},
			Resources: []string{"events"},
		},
		{
			Verbs:         []string{"get"},
			APIGroups:     []string{"*"},
			Resources:     []string{"*"},
			ResourceNames: []string{"foo"},
		},
	}

	authzRulesHandler := NewRuleResolvers(handler1, handler2)

	rules, _, _, _ := authzRulesHandler.RulesFor(genericapirequest.NewContext(), nil, "")
	actual := getResourceRules(rules)
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("Expected: \n%#v\n but actual: \n%#v\n", expected, actual)
	}
}

func TestAuthorizationNonResourceRules(t *testing.T) {
	handler1 := &mockAuthzRuleHandler{
		nonResourceRules: []authorizer.NonResourceRuleInfo{
			&authorizer.DefaultNonResourceRuleInfo{
				Verbs:           []string{"get"},
				NonResourceURLs: []string{"/api"},
			},
		},
	}

	handler2 := &mockAuthzRuleHandler{
		nonResourceRules: []authorizer.NonResourceRuleInfo{
			&authorizer.DefaultNonResourceRuleInfo{
				Verbs:           []string{"get"},
				NonResourceURLs: []string{"/api/*"},
			},
		},
	}

	expected := []authorizer.DefaultNonResourceRuleInfo{
		{
			Verbs:           []string{"get"},
			NonResourceURLs: []string{"/api"},
		},
		{
			Verbs:           []string{"get"},
			NonResourceURLs: []string{"/api/*"},
		},
	}

	authzRulesHandler := NewRuleResolvers(handler1, handler2)

	_, rules, _, _ := authzRulesHandler.RulesFor(genericapirequest.NewContext(), nil, "")
	actual := getNonResourceRules(rules)
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("Expected: \n%#v\n but actual: \n%#v\n", expected, actual)
	}
}

func getResourceRules(infos []authorizer.ResourceRuleInfo) []authorizer.DefaultResourceRuleInfo {
	rules := make([]authorizer.DefaultResourceRuleInfo, len(infos))
	for i, info := range infos {
		rules[i] = authorizer.DefaultResourceRuleInfo{
			Verbs:         info.GetVerbs(),
			APIGroups:     info.GetAPIGroups(),
			Resources:     info.GetResources(),
			ResourceNames: info.GetResourceNames(),
		}
	}
	return rules
}

func getNonResourceRules(infos []authorizer.NonResourceRuleInfo) []authorizer.DefaultNonResourceRuleInfo {
	rules := make([]authorizer.DefaultNonResourceRuleInfo, len(infos))
	for i, info := range infos {
		rules[i] = authorizer.DefaultNonResourceRuleInfo{
			Verbs:           info.GetVerbs(),
			NonResourceURLs: info.GetNonResourceURLs(),
		}
	}
	return rules
}

// evalTestAuthz is a configurable authorizer for testing the union evaluation flow.
type evalTestAuthz struct {
	// conditionEffect, if non-empty, makes Authorize return a Conditional decision
	// with a single condition of this effect. If empty, decision is returned instead.
	conditionEffect authorizer.ConditionEffect
	// decision is returned from Authorize when conditionEffect is empty.
	decision authorizer.Decision
	// authorizeErr is returned as the error from Authorize.
	authorizeErr error

	// evalDecision is returned from EvaluateConditions.
	evalDecision authorizer.Decision
	// evalErr is returned as the error from EvaluateConditions.
	evalErr error
}

func (a *evalTestAuthz) Authorize(ctx context.Context, attrs authorizer.Attributes) (authorizer.Decision, error) {
	if a.conditionEffect != "" {
		cs, err := authorizer.NewConditionSet("test-type", []authorizer.Condition{
			{ID: "test-cond", Condition: "test", Effect: a.conditionEffect},
		})
		if err != nil {
			return authorizer.DecisionDeny(), err
		}
		return authorizer.DecisionConditional(*cs, attrs), a.authorizeErr
	}
	return a.decision, a.authorizeErr
}

func (a *evalTestAuthz) EvaluateConditions(ctx context.Context, decision authorizer.Decision, data authorizer.ConditionData) (authorizer.Decision, error) {
	// Concrete decisions need no evaluation, return as-is.
	if decision.IsAllowed() || decision.IsDenied() || decision.IsNoOpinion() {
		return decision, nil
	}
	return a.evalDecision, a.evalErr
}

// TestUnionEvaluateConditions tests the full Authorize + EvaluateConditions flow
// through a DAG of nested union authorizers:
//
//	union0 = [union1, union2, authz5]
//	union1 = [union2, authz3]
//	union2 = [authz1, authz2]
//
// Note: union2 is shared (appears in both union0 and union1).
func TestUnionEvaluateConditions(t *testing.T) {
	type authzConfig struct {
		conditionEffect authorizer.ConditionEffect
		decision        authorizer.Decision
		authorizeErr    error
		evalDecision    authorizer.Decision
		evalErr         error
	}

	noOpinion := func() authzConfig {
		return authzConfig{decision: authorizer.DecisionNoOpinion()}
	}

	tests := []struct {
		name                  string
		authz1, authz2, authz3, authz5 authzConfig
		wantAuthorizeDecision string
		wantFinalDecision     string
		wantAuthorizeErr      bool
		wantFinalErr          bool
	}{
		// === Concrete decisions (no conditions) ===

		{
			name:                  "all noopinion",
			authz1:                noOpinion(),
			authz2:                noOpinion(),
			authz3:                noOpinion(),
			authz5:                noOpinion(),
			wantAuthorizeDecision: "NoOpinion",
			wantFinalDecision:     "NoOpinion",
		},
		{
			name:                  "authz1 allow short-circuits everything",
			authz1:                authzConfig{decision: authorizer.DecisionAllow()},
			authz2:                noOpinion(),
			authz3:                noOpinion(),
			authz5:                noOpinion(),
			wantAuthorizeDecision: "Allow",
			wantFinalDecision:     "Allow",
		},
		{
			name:                  "authz1 deny short-circuits everything",
			authz1:                authzConfig{decision: authorizer.DecisionDeny()},
			authz2:                noOpinion(),
			authz3:                noOpinion(),
			authz5:                noOpinion(),
			wantAuthorizeDecision: "Deny",
			wantFinalDecision:     "Deny",
		},
		{
			name:                  "authz1 noopinion authz2 allow",
			authz1:                noOpinion(),
			authz2:                authzConfig{decision: authorizer.DecisionAllow()},
			authz3:                noOpinion(),
			authz5:                noOpinion(),
			wantAuthorizeDecision: "Allow",
			wantFinalDecision:     "Allow",
		},
		{
			name:                  "authz1 authz2 noopinion authz3 allow",
			authz1:                noOpinion(),
			authz2:                noOpinion(),
			authz3:                authzConfig{decision: authorizer.DecisionAllow()},
			authz5:                noOpinion(),
			wantAuthorizeDecision: "Allow",
			wantFinalDecision:     "Allow",
		},
		{
			name:                  "all inner noopinion authz5 allow",
			authz1:                noOpinion(),
			authz2:                noOpinion(),
			authz3:                noOpinion(),
			authz5:                authzConfig{decision: authorizer.DecisionAllow()},
			wantAuthorizeDecision: "Allow",
			wantFinalDecision:     "Allow",
		},
		{
			name:                  "authz1 noopinion authz2 deny",
			authz1:                noOpinion(),
			authz2:                authzConfig{decision: authorizer.DecisionDeny()},
			authz3:                noOpinion(),
			authz5:                noOpinion(),
			wantAuthorizeDecision: "Deny",
			wantFinalDecision:     "Deny",
		},

		// === Conditional decisions ===

		{
			name: "authz1 conditional allow evals to allow",
			authz1: authzConfig{
				conditionEffect: authorizer.ConditionEffectAllow,
				evalDecision:    authorizer.DecisionAllow(),
			},
			authz2:                noOpinion(),
			authz3:                noOpinion(),
			authz5:                noOpinion(),
			wantAuthorizeDecision: "ConditionalChain",
			wantFinalDecision:     "Allow",
		},
		{
			name: "authz1 conditional allow evals to noopinion",
			authz1: authzConfig{
				conditionEffect: authorizer.ConditionEffectAllow,
				evalDecision:    authorizer.DecisionNoOpinion(),
			},
			authz2:                noOpinion(),
			authz3:                noOpinion(),
			authz5:                noOpinion(),
			wantAuthorizeDecision: "ConditionalChain",
			wantFinalDecision:     "NoOpinion",
		},
		{
			name: "authz1 conditional deny evals to deny",
			authz1: authzConfig{
				conditionEffect: authorizer.ConditionEffectDeny,
				evalDecision:    authorizer.DecisionDeny(),
			},
			authz2:                noOpinion(),
			authz3:                noOpinion(),
			authz5:                noOpinion(),
			wantAuthorizeDecision: "ConditionalChain",
			wantFinalDecision:     "Deny",
		},
		{
			name: "authz1 conditional deny evals to noopinion",
			authz1: authzConfig{
				conditionEffect: authorizer.ConditionEffectDeny,
				evalDecision:    authorizer.DecisionNoOpinion(),
			},
			authz2:                noOpinion(),
			authz3:                noOpinion(),
			authz5:                noOpinion(),
			wantAuthorizeDecision: "ConditionalChain",
			wantFinalDecision:     "NoOpinion",
		},

		// === Conditional + concrete mixes ===

		{
			name: "authz1 conditional noopinion authz2 allow",
			authz1: authzConfig{
				conditionEffect: authorizer.ConditionEffectAllow,
				evalDecision:    authorizer.DecisionNoOpinion(),
			},
			authz2: authzConfig{decision: authorizer.DecisionAllow()},
			authz3: noOpinion(),
			authz5: noOpinion(),
			// union2 chain includes both the Conditional and the Allow, so Authorize is ConditionalChain.
			// Eval: authz1 NoOpinion, authz2 Allow (concrete passthrough) -> Allow.
			wantAuthorizeDecision: "ConditionalChain",
			wantFinalDecision:     "Allow",
		},
		{
			name: "authz1 conditional noopinion authz3 allow",
			authz1: authzConfig{
				conditionEffect: authorizer.ConditionEffectAllow,
				evalDecision:    authorizer.DecisionNoOpinion(),
			},
			authz2: noOpinion(),
			authz3: authzConfig{decision: authorizer.DecisionAllow()},
			authz5: noOpinion(),
			// union1 chain: [ConditionalChain_union2, Allow_authz3] -> ConditionalChain.
			// Eval: authz1 NoOpinion, then authz3 Allow (concrete passthrough) -> Allow.
			wantAuthorizeDecision: "ConditionalChain",
			wantFinalDecision:     "Allow",
		},
		{
			name: "authz1 conditional noopinion authz5 allow",
			authz1: authzConfig{
				conditionEffect: authorizer.ConditionEffectAllow,
				evalDecision:    authorizer.DecisionNoOpinion(),
			},
			authz2: noOpinion(),
			authz3: noOpinion(),
			authz5: authzConfig{decision: authorizer.DecisionAllow()},
			// union0 chain: [CC_union1, CC_union2, Allow_authz5] -> ConditionalChain.
			// Eval: all conditionals NoOpinion, authz5 Allow (concrete passthrough) -> Allow.
			wantAuthorizeDecision: "ConditionalChain",
			wantFinalDecision:     "Allow",
		},

		// === Multiple conditionals ===

		{
			name: "authz1 conditional noopinion authz3 conditional allow",
			authz1: authzConfig{
				conditionEffect: authorizer.ConditionEffectAllow,
				evalDecision:    authorizer.DecisionNoOpinion(),
			},
			authz2: noOpinion(),
			authz3: authzConfig{
				conditionEffect: authorizer.ConditionEffectAllow,
				evalDecision:    authorizer.DecisionAllow(),
			},
			authz5: noOpinion(),
			// union2=ConditionalChain(authz1), union1=ConditionalChain(union2, authz3)
			// Eval: authz1 evals NoOpinion, then authz3 evals Allow
			wantAuthorizeDecision: "ConditionalChain",
			wantFinalDecision:     "Allow",
		},
		{
			name: "authz1 conditional noopinion authz3 conditional noopinion authz5 conditional allow",
			authz1: authzConfig{
				conditionEffect: authorizer.ConditionEffectAllow,
				evalDecision:    authorizer.DecisionNoOpinion(),
			},
			authz2: noOpinion(),
			authz3: authzConfig{
				conditionEffect: authorizer.ConditionEffectAllow,
				evalDecision:    authorizer.DecisionNoOpinion(),
			},
			authz5: authzConfig{
				conditionEffect: authorizer.ConditionEffectAllow,
				evalDecision:    authorizer.DecisionAllow(),
			},
			// All conditionals NoOpinion except authz5 which returns Allow
			wantAuthorizeDecision: "ConditionalChain",
			wantFinalDecision:     "Allow",
		},
		{
			name: "all conditionals eval noopinion",
			authz1: authzConfig{
				conditionEffect: authorizer.ConditionEffectAllow,
				evalDecision:    authorizer.DecisionNoOpinion(),
			},
			authz2: authzConfig{
				conditionEffect: authorizer.ConditionEffectAllow,
				evalDecision:    authorizer.DecisionNoOpinion(),
			},
			authz3: authzConfig{
				conditionEffect: authorizer.ConditionEffectAllow,
				evalDecision:    authorizer.DecisionNoOpinion(),
			},
			authz5: authzConfig{
				conditionEffect: authorizer.ConditionEffectAllow,
				evalDecision:    authorizer.DecisionNoOpinion(),
			},
			wantAuthorizeDecision: "ConditionalChain",
			wantFinalDecision:     "NoOpinion",
		},

		// === Conditional deny in the chain ===

		{
			name: "authz1 conditional deny evals deny authz3 conditional allow would eval allow",
			authz1: authzConfig{
				conditionEffect: authorizer.ConditionEffectDeny,
				evalDecision:    authorizer.DecisionDeny(),
			},
			authz2: noOpinion(),
			authz3: authzConfig{
				conditionEffect: authorizer.ConditionEffectAllow,
				evalDecision:    authorizer.DecisionAllow(),
			},
			authz5: noOpinion(),
			// union2=ConditionalChain(authz1), union1=ConditionalChain(union2, authz3)
			// Eval: authz1 evals Deny -> short-circuits immediately
			wantAuthorizeDecision: "ConditionalChain",
			wantFinalDecision:     "Deny",
		},
		{
			name: "authz1 conditional deny noopinion authz3 conditional allow evals allow",
			authz1: authzConfig{
				conditionEffect: authorizer.ConditionEffectDeny,
				evalDecision:    authorizer.DecisionNoOpinion(),
			},
			authz2: noOpinion(),
			authz3: authzConfig{
				conditionEffect: authorizer.ConditionEffectAllow,
				evalDecision:    authorizer.DecisionAllow(),
			},
			authz5: noOpinion(),
			// Eval: authz1 evals NoOpinion, authz3 evals Allow
			wantAuthorizeDecision: "ConditionalChain",
			wantFinalDecision:     "Allow",
		},

		// === Error handling ===

		{
			name: "authz1 conditional eval error",
			authz1: authzConfig{
				conditionEffect: authorizer.ConditionEffectAllow,
				evalDecision:    authorizer.DecisionNoOpinion(),
				evalErr:         errors.New("eval error"),
			},
			authz2:                noOpinion(),
			authz3:                noOpinion(),
			authz5:                noOpinion(),
			wantAuthorizeDecision: "ConditionalChain",
			wantFinalDecision:     "NoOpinion",
			wantFinalErr:          true,
		},
		{
			name: "authorize error propagated",
			authz1: authzConfig{
				decision:     authorizer.DecisionNoOpinion(),
				authorizeErr: errors.New("authz error"),
			},
			authz2:                noOpinion(),
			authz3:                noOpinion(),
			authz5:                noOpinion(),
			wantAuthorizeDecision: "NoOpinion",
			wantAuthorizeErr:      true,
			wantFinalDecision:     "NoOpinion",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authz1 := &evalTestAuthz{
				conditionEffect: tt.authz1.conditionEffect,
				decision:        tt.authz1.decision,
				authorizeErr:    tt.authz1.authorizeErr,
				evalDecision:    tt.authz1.evalDecision,
				evalErr:         tt.authz1.evalErr,
			}
			authz2 := &evalTestAuthz{
				conditionEffect: tt.authz2.conditionEffect,
				decision:        tt.authz2.decision,
				authorizeErr:    tt.authz2.authorizeErr,
				evalDecision:    tt.authz2.evalDecision,
				evalErr:         tt.authz2.evalErr,
			}
			authz3 := &evalTestAuthz{
				conditionEffect: tt.authz3.conditionEffect,
				decision:        tt.authz3.decision,
				authorizeErr:    tt.authz3.authorizeErr,
				evalDecision:    tt.authz3.evalDecision,
				evalErr:         tt.authz3.evalErr,
			}
			authz5 := &evalTestAuthz{
				conditionEffect: tt.authz5.conditionEffect,
				decision:        tt.authz5.decision,
				authorizeErr:    tt.authz5.authorizeErr,
				evalDecision:    tt.authz5.evalDecision,
				evalErr:         tt.authz5.evalErr,
			}

			union2 := New(authz1, authz2)
			union1 := New(union2, authz3)
			union0 := New(union1, union2, authz5)

			attrs := authorizer.AttributesRecord{
				User:           &user.DefaultInfo{Name: "testuser"},
				Verb:           "get",
				ConditionsMode: authorizer.ConditionsModeHumanReadable,
			}

			ctx := context.Background()
			authzDecision, authzErr := union0.Authorize(ctx, attrs)

			if (authzErr != nil) != tt.wantAuthorizeErr {
				t.Fatalf("Authorize() error = %v, wantErr %v", authzErr, tt.wantAuthorizeErr)
			}
			if authzDecision.String() != tt.wantAuthorizeDecision {
				t.Errorf("Authorize() = %s, want %s", authzDecision.String(), tt.wantAuthorizeDecision)
			}

			finalDecision, finalErr := union0.EvaluateConditions(ctx, authzDecision, nil)

			if (finalErr != nil) != tt.wantFinalErr {
				t.Fatalf("EvaluateConditions() error = %v, wantErr %v", finalErr, tt.wantFinalErr)
			}
			if finalDecision.String() != tt.wantFinalDecision {
				t.Errorf("EvaluateConditions() = %s, want %s", finalDecision.String(), tt.wantFinalDecision)
			}
		})
	}
}

func TestAuthorizationUnequivocalDeny(t *testing.T) {
	cs := []struct {
		authorizers []authorizer.Authorizer
		decision    authorizer.Decision
	}{
		{
			authorizers: []authorizer.Authorizer{},
			decision:    authorizer.DecisionNoOpinion(""),
		},
		{
			authorizers: []authorizer.Authorizer{
				&mockAuthzHandler{decision: authorizer.DecisionNoOpinion("")},
				&mockAuthzHandler{decision: authorizer.DecisionAllow("")},
				&mockAuthzHandler{decision: authorizer.DecisionDeny("")},
			},
			decision: authorizer.DecisionAllow(""),
		},
		{
			authorizers: []authorizer.Authorizer{
				&mockAuthzHandler{decision: authorizer.DecisionNoOpinion("")},
				&mockAuthzHandler{decision: authorizer.DecisionDeny("")},
				&mockAuthzHandler{decision: authorizer.DecisionAllow("")},
			},
			decision: authorizer.DecisionDeny(""),
		},
		{
			authorizers: []authorizer.Authorizer{
				&mockAuthzHandler{decision: authorizer.DecisionNoOpinion("")},
				&mockAuthzHandler{decision: authorizer.DecisionDeny(""), err: errors.New("webhook failed closed")},
				&mockAuthzHandler{decision: authorizer.DecisionAllow("")},
			},
			decision: authorizer.DecisionDeny(""),
		},
	}
	for i, c := range cs {
		t.Run(fmt.Sprintf("case %v", i), func(t *testing.T) {
			authzHandler := New(c.authorizers...)

			decision, _ := authzHandler.Authorize(context.Background(), nil)
			if !decision.Equal(c.decision) {
				t.Errorf("Unexpected authorization failure: %v, expected: %v", decision, c.decision)
			}
		})
	}
}
