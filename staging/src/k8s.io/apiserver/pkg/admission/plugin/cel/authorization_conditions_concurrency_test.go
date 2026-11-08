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

package cel

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/authorizerfactory"
	apiservercel "k8s.io/apiserver/pkg/cel"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
)

// These tests are most valuable when run with -race.

const costedCondition = "object.spec.nodeName == 'node1'"

// largeBudget fits many authorizer checks, which are expensive in terms of CEL cost.
const largeBudget = 1 << 40

func newTestEvaluator(t *testing.T, budget int64, authz authorizer.UnconditionalAuthorizer) *celAuthorizationConditionsEvaluator {
	t.Helper()
	builder := newTestAuthorizationConditionsEvaluatorBuilder(t, budget, authz, defaultNamespace)
	e, err := builder.EvaluatorForData(t.Context(), versioned(t, podCreateAttributes()))
	if err != nil {
		t.Fatalf("EvaluatorForData failed: %v", err)
	}
	return e.(*celAuthorizationConditionsEvaluator)
}

// measureCost returns the runtime cost of evaluating expr once against podCreateAttributes.
func measureCost(t *testing.T, expr string) int64 {
	t.Helper()
	e := newTestEvaluator(t, celconfig.RuntimeCELCostBudget, authorizerfactory.NewAlwaysAllowAuthorizer())
	if res := e.EvaluateCondition(t.Context(), celCond("c", expr)); res.IsError() || res.IsUnevaluatable() {
		t.Fatalf("measuring %q: got %s (err=%v)", expr, evalResultString(res), res.Error())
	}
	return celconfig.RuntimeCELCostBudget - e.remainingBudget
}

// runConcurrently runs fn(i) for i in [0, n) in n goroutines released at the same time, and waits for them.
func runConcurrently(n int, fn func(i int)) {
	var start, done sync.WaitGroup
	start.Add(1)
	for i := range n {
		done.Go(func() {
			start.Wait()
			fn(i)
		})
	}
	start.Done()
	done.Wait()
}

func isOutOfBudget(r authorizer.ConditionEvaluationResult) bool {
	return r.IsError() && errors.Is(r.Error(), apiservercel.ErrOutOfBudget)
}

func TestAuthorizationConditionsEvaluator_ConcurrentBudget(t *testing.T) {
	cost := measureCost(t, costedCondition)
	if cost <= 0 {
		t.Fatalf("expected a positive evaluation cost, got %d", cost)
	}
	const fits, goroutines, iterations = 5, 50, 20

	tests := []struct {
		name          string
		budget        int64
		wantRemaining int64
	}{
		// The leftover is too small for one more evaluation, so the next charge exhausts the budget.
		{name: "budget with leftover", budget: fits*cost + cost/2, wantRemaining: -1},
		{name: "budget fits exactly", budget: fits * cost, wantRemaining: -1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Repeat to exercise different interleavings.
			for range iterations {
				e := newTestEvaluator(t, tc.budget, authorizerfactory.NewAlwaysAllowAuthorizer())
				results := make([]authorizer.ConditionEvaluationResult, goroutines)
				runConcurrently(goroutines, func(i int) {
					results[i] = e.EvaluateCondition(t.Context(), celCond("c", costedCondition))
				})
				var trues, outOfBudget int
				for i, r := range results {
					switch {
					case r.IsTrue():
						trues++
					case isOutOfBudget(r):
						outOfBudget++
					default:
						t.Fatalf("goroutine %d: got %s (err=%v), want True or out of budget", i, evalResultString(r), r.Error())
					}
				}
				// Exactly as many conditions succeed as when evaluated sequentially.
				if trues != fits || outOfBudget != goroutines-fits {
					t.Fatalf("got %d True and %d out of budget, want %d and %d", trues, outOfBudget, fits, goroutines-fits)
				}
				if got := e.remainingBudget; got != tc.wantRemaining {
					t.Fatalf("remaining budget: got %d, want %d", got, tc.wantRemaining)
				}
			}
		})
	}
}

func TestAuthorizationConditionsEvaluator_BudgetExhaustion(t *testing.T) {
	cost := measureCost(t, costedCondition)

	t.Run("exceeding the budget in Evaluate stops further evaluation", func(t *testing.T) {
		e := newTestEvaluator(t, cost-1, authorizerfactory.NewAlwaysAllowAuthorizer())
		if r := e.EvaluateCondition(t.Context(), celCond("c", costedCondition)); !isOutOfBudget(r) {
			t.Fatalf("got %s (err=%v), want out of budget", evalResultString(r), r.Error())
		}
		if got := e.remainingBudget; got != -1 {
			t.Fatalf("remaining budget: got %d, want -1", got)
		}
		// Even conditions that would fit in the original budget are no longer evaluated.
		if r := e.EvaluateCondition(t.Context(), celCond("c", "true")); !isOutOfBudget(r) {
			t.Errorf("got %s (err=%v), want out of budget", evalResultString(r), r.Error())
		}
	})

	t.Run("unrecognized conditions are unaffected by an exhausted budget", func(t *testing.T) {
		e := newTestEvaluator(t, celconfig.RuntimeCELCostBudget, authorizerfactory.NewAlwaysAllowAuthorizer())
		e.remainingBudget = -1
		if r := e.EvaluateCondition(t.Context(), authorizer.GenericCondition{ID: "c", Type: "example.com/opaque", Condition: "true"}); !r.IsUnevaluatable() {
			t.Errorf("got %s, want Unevaluatable", evalResultString(r))
		}
	})

	t.Run("evaluation errors still consume budget", func(t *testing.T) {
		// The comparison is evaluated before failing on the missing key, so the error has a cost.
		const failing = "object.spec.nodeName == 'node1' && object.metadata.labels['missing'] == 'x'"
		e := newTestEvaluator(t, celconfig.RuntimeCELCostBudget, authorizerfactory.NewAlwaysAllowAuthorizer())
		if r := e.EvaluateCondition(t.Context(), celCond("c", failing)); !r.IsError() || isOutOfBudget(r) {
			t.Fatalf("got %s (err=%v), want a non-budget error", evalResultString(r), r.Error())
		}
		if got := e.remainingBudget; got >= celconfig.RuntimeCELCostBudget {
			t.Errorf("expected the failed evaluation to consume budget, remaining %d", got)
		}
	})
}

// countingAuthorizer counts calls per verb, and sleeps so that concurrent identical checks overlap.
type countingAuthorizer struct {
	mu    sync.Mutex
	calls map[string]int
}

func (c *countingAuthorizer) Authorize(_ context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
	c.mu.Lock()
	if c.calls == nil {
		c.calls = map[string]int{}
	}
	c.calls[a.GetVerb()]++
	c.mu.Unlock()
	time.Sleep(time.Millisecond)
	if a.GetVerb() == "get" {
		return authorizer.DecisionAllow, "", nil
	}
	return authorizer.DecisionDeny, "", nil
}

func (c *countingAuthorizer) callsFor(verb string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls[verb]
}

func authzCheck(verb string) string {
	return fmt.Sprintf("authorizer.group('').resource('pods').namespace('default').check('%s').allowed()", verb)
}

func TestAuthorizationConditionsEvaluator_ConcurrentAuthorizerChecks(t *testing.T) {
	const goroutines = 50
	verbs := []string{"get", "list", "watch"}
	authz := &countingAuthorizer{}
	builder := newTestAuthorizationConditionsEvaluatorBuilder(t, largeBudget, authz, defaultNamespace)

	for request := 1; request <= 2; request++ {
		e, err := builder.EvaluatorForData(t.Context(), versioned(t, podCreateAttributes()))
		if err != nil {
			t.Fatalf("EvaluatorForData failed: %v", err)
		}
		results := make([]authorizer.ConditionEvaluationResult, goroutines)
		runConcurrently(goroutines, func(i int) {
			results[i] = e.EvaluateCondition(t.Context(), celCond("c", authzCheck(verbs[i%len(verbs)])))
		})
		for i, r := range results {
			want := "False"
			if verbs[i%len(verbs)] == "get" {
				want = "True"
			}
			if got := evalResultString(r); got != want {
				t.Errorf("request %d, goroutine %d: got %s (err=%v), want %s", request, i, got, r.Error(), want)
			}
		}
		// Identical checks are cached within a request, but not across requests.
		for _, verb := range verbs {
			if got := authz.callsFor(verb); got != request {
				t.Errorf("after request %d: authorizer called %d times for verb %q, want %d", request, got, verb, request)
			}
		}
	}
}

func TestAuthorizationConditionsEvaluator_ConcurrentMixedConditions(t *testing.T) {
	conditions := []struct {
		expr string
		want string
	}{
		{expr: "true", want: "True"},
		{expr: "false", want: "False"},
		{expr: costedCondition, want: "True"},
		{expr: "object.metadata.labels['app'] == 'web'", want: "True"},
		{expr: "namespaceObject.metadata.labels['env'] == 'prod'", want: "True"},
		{expr: "request.operation == 'DELETE'", want: "False"},
		{expr: "oldObject == null", want: "True"},
		{expr: "1 < 'asdf'", want: "Error"},
		{expr: authzCheck("get"), want: "True"},
		{expr: authzCheck("delete"), want: "False"},
	}
	const rounds = 20
	e := newTestEvaluator(t, largeBudget, &countingAuthorizer{})
	results := make([]authorizer.ConditionEvaluationResult, rounds*len(conditions))
	runConcurrently(len(results), func(i int) {
		results[i] = e.EvaluateCondition(t.Context(), celCond("c", conditions[i%len(conditions)].expr))
	})
	for i, r := range results {
		c := conditions[i%len(conditions)]
		if got := evalResultString(r); got != c.want {
			t.Errorf("%q: got %s (err=%v), want %s", c.expr, got, r.Error(), c.want)
		}
	}
}

func TestAuthorizationConditionsEvaluatorBuilder_SetAuthorizer(t *testing.T) {
	client := fake.NewClientset(defaultNamespace)
	builder, err := NewAuthorizationConditionsEvaluatorBuilder(informers.NewSharedInformerFactory(client, 0), client, nil, celconfig.RuntimeCELCostBudget)
	if err != nil {
		t.Fatalf("NewAuthorizationConditionsEvaluatorBuilder failed: %v", err)
	}
	data := versioned(t, podCreateAttributes())
	cond := celCond("c", authzCheck("get"))

	if _, err := builder.EvaluatorForData(t.Context(), data); err == nil {
		t.Fatal("expected an error before SetAuthorizer")
	}

	builder.SetAuthorizer(authorizerfactory.NewAlwaysAllowAuthorizer())
	e, err := builder.EvaluatorForData(t.Context(), data)
	if err != nil {
		t.Fatalf("EvaluatorForData failed: %v", err)
	}
	if got := evalResultString(e.EvaluateCondition(t.Context(), cond)); got != "True" {
		t.Errorf("got %s, want True", got)
	}

	// Evaluators keep the authorizer they were built with.
	builder.SetAuthorizer(authorizerfactory.NewAlwaysDenyAuthorizer())
	if got := evalResultString(e.EvaluateCondition(t.Context(), celCond("c", authzCheck("list")))); got != "True" {
		t.Errorf("existing evaluator: got %s, want True", got)
	}
	e, err = builder.EvaluatorForData(t.Context(), data)
	if err != nil {
		t.Fatalf("EvaluatorForData failed: %v", err)
	}
	if got := evalResultString(e.EvaluateCondition(t.Context(), cond)); got != "False" {
		t.Errorf("new evaluator: got %s, want False", got)
	}

	builder.SetAuthorizer(nil)
	if _, err := builder.EvaluatorForData(t.Context(), data); err == nil {
		t.Error("expected an error after SetAuthorizer(nil)")
	}
}

func TestAuthorizationConditionsEvaluatorBuilder_ConcurrentSetAuthorizer(t *testing.T) {
	builder := newTestAuthorizationConditionsEvaluatorBuilder(t, largeBudget, authorizerfactory.NewAlwaysAllowAuthorizer(), defaultNamespace).(*AuthorizationConditionsEvaluatorBuilder)
	cond := celCond("c", authzCheck("get"))
	runConcurrently(50, func(i int) {
		if i%2 == 0 {
			if i%4 == 0 {
				builder.SetAuthorizer(authorizerfactory.NewAlwaysAllowAuthorizer())
			} else {
				builder.SetAuthorizer(authorizerfactory.NewAlwaysDenyAuthorizer())
			}
			return
		}
		e, err := builder.EvaluatorForData(t.Context(), versioned(t, podCreateAttributes()))
		if err != nil {
			t.Errorf("EvaluatorForData failed: %v", err)
			return
		}
		if r := e.EvaluateCondition(t.Context(), cond); !r.IsTrue() && !r.IsFalse() {
			t.Errorf("got %s (err=%v), want True or False", evalResultString(r), r.Error())
		}
	})
}
