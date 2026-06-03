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

package authorizer_test

import (
	"errors"
	"fmt"
	"testing"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	genericfeatures "k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
)

// genericCond builds a no-op GenericCondition with the given ID.
func genericCond(id string) authorizer.Condition {
	return authorizer.GenericCondition{ID: id, Condition: "x", Type: "test"}
}

// possibleDecisionsTestSetup enables the conditional authorization feature gate.
func possibleDecisionsTestSetup(t *testing.T) {
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, genericfeatures.ConditionalAuthorization, true)
}

// TestPossibleDecisions is the unified table-driven test for
// ConditionsAwareDecision.PossibleDecisions, ConditionsMap.PossibleDecisions, and
// ConditionsAwareDecisionUnion.PossibleDecisions. Every input is constructed as a
// ConditionsAwareDecision (the public entry point through which both ConditionsMap and
// ConditionsAwareDecisionUnion are exercised), and every row asserts both the
// PossibleDecisions output and the decision's String() representation.
//
// Semantics covered by the rows:
//   - All five ConditionsAwareDecision variants (Allow/Deny/NoOpinion/ConditionsMap/Union).
//   - Every non-empty combination of ConditionsMap effect groups (deny / noOpinion / allow).
//   - Union sub-decision sequences:
//   - The default outcome of a union is NoOpinion (when every sub-decision evaluates to NoOpinion).
//   - A union short-circuits at the first sub-decision that yields a concrete Allow or Deny.
//   - A ConditionsMap sub-decision can yield NoOpinion at runtime, in which case evaluation
//     continues to the next sub-decision; therefore later concrete Allow/Deny outcomes remain reachable.
//   - Add drops elements appended after the first concrete Allow/Deny leaf.
func TestPossibleDecisions(t *testing.T) {
	possibleDecisionsTestSetup(t)

	// ConditionsMap leaves used as building blocks below.
	condMapAllow := authorizer.ConditionsAwareDecisionConditionsMap(nil, nil, []authorizer.Condition{genericCond("allow-1")})
	condMapDeny := authorizer.ConditionsAwareDecisionConditionsMap([]authorizer.Condition{genericCond("deny-1")}, nil, nil)
	condMapDenyAndAllow := authorizer.ConditionsAwareDecisionConditionsMap(
		[]authorizer.Condition{genericCond("deny-1")},
		nil,
		[]authorizer.Condition{genericCond("allow-1")},
	)

	// Empty-reason leaves used for union sub-decisions (avoids spurious "0: " index prefixes
	// in the simplified ToDecision output that would clutter wantString comparisons).
	allow := authorizer.ConditionsAwareDecisionAllow("", nil)
	deny := authorizer.ConditionsAwareDecisionDeny("", nil)
	noOp := authorizer.ConditionsAwareDecisionNoOpinion("", nil)

	tests := []struct {
		name          string
		d             authorizer.ConditionsAwareDecision
		wantString    string
		wantDecisions sets.Set[authorizer.Decision]
	}{
		// ===== Unconditional leaves =====
		{
			name:          "Allow (error ignored)",
			d:             authorizer.ConditionsAwareDecisionAllow("ok", errors.New("warning")),
			wantString:    `Allow(reason="ok", err="warning")`,
			wantDecisions: sets.New(authorizer.DecisionAllow),
		},
		{
			name:          "Deny (error ignored)",
			d:             authorizer.ConditionsAwareDecisionDeny("no", errors.New("warning")),
			wantString:    `Deny(reason="no", err="warning")`,
			wantDecisions: sets.New(authorizer.DecisionDeny),
		},
		{
			name:          "NoOpinion (error ignored)",
			d:             authorizer.ConditionsAwareDecisionNoOpinion("meh", errors.New("warning")),
			wantString:    `NoOpinion(reason="meh", err="warning")`,
			wantDecisions: sets.New(authorizer.DecisionNoOpinion),
		},
		{
			name:          "zero value is Deny",
			d:             authorizer.ConditionsAwareDecision{},
			wantString:    `Deny`,
			wantDecisions: sets.New(authorizer.DecisionDeny),
		},

		// ===== ConditionsMap effect-group combinations =====
		{
			// The constructor short-circuits an all-empty input to NoOpinion-with-error,
			// so the resulting decision is NoOpinion (not a ConditionsMap).
			name:          "ConditionsMap: empty input folds to NoOpinion",
			d:             authorizer.ConditionsAwareDecisionConditionsMap(nil, nil, nil),
			wantString:    `NoOpinion(reason="no conditions", err="at least one condition must be passed to ConditionsAwareDecisionConditionsMap(), got none")`,
			wantDecisions: sets.New(authorizer.DecisionNoOpinion),
		},
		{
			name:          "ConditionsMap: allow-only -> {NoOpinion, Allow}",
			d:             condMapAllow,
			wantString:    `ConditionsMap(allows=1)`,
			wantDecisions: sets.New(authorizer.DecisionNoOpinion, authorizer.DecisionAllow),
		},
		{
			name:          "ConditionsMap: noOpinion-only -> folds to NoOpinion",
			d:             authorizer.ConditionsAwareDecisionConditionsMap(nil, []authorizer.Condition{genericCond("nop-1")}, nil),
			wantString:    `NoOpinion`,
			wantDecisions: sets.New(authorizer.DecisionNoOpinion),
		},
		{
			name:          "ConditionsMap: deny-only -> {NoOpinion, Deny}",
			d:             condMapDeny,
			wantString:    `ConditionsMap(denies=1)`,
			wantDecisions: sets.New(authorizer.DecisionNoOpinion, authorizer.DecisionDeny),
		},
		{
			name:          "ConditionsMap: noOpinion + allow -> {NoOpinion, Allow}",
			d:             authorizer.ConditionsAwareDecisionConditionsMap(nil, []authorizer.Condition{genericCond("nop-1")}, []authorizer.Condition{genericCond("allow-1")}),
			wantString:    `ConditionsMap(noopinions=1, allows=1)`,
			wantDecisions: sets.New(authorizer.DecisionNoOpinion, authorizer.DecisionAllow),
		},
		{
			name:          "ConditionsMap: deny + noOpinion -> {NoOpinion, Deny}",
			d:             authorizer.ConditionsAwareDecisionConditionsMap([]authorizer.Condition{genericCond("deny-1")}, []authorizer.Condition{genericCond("nop-1")}, nil),
			wantString:    `ConditionsMap(denies=1, noopinions=1)`,
			wantDecisions: sets.New(authorizer.DecisionNoOpinion, authorizer.DecisionDeny),
		},
		{
			name:          "ConditionsMap: deny + allow -> {NoOpinion, Allow, Deny}",
			d:             condMapDenyAndAllow,
			wantString:    `ConditionsMap(denies=1, allows=1)`,
			wantDecisions: sets.New(authorizer.DecisionNoOpinion, authorizer.DecisionAllow, authorizer.DecisionDeny),
		},
		{
			name:          "ConditionsMap: deny + noOpinion + allow -> {NoOpinion, Allow, Deny}",
			d:             authorizer.ConditionsAwareDecisionConditionsMap([]authorizer.Condition{genericCond("deny-1")}, []authorizer.Condition{genericCond("nop-1")}, []authorizer.Condition{genericCond("allow-1")}),
			wantString:    `ConditionsMap(denies=1, noopinions=1, allows=1)`,
			wantDecisions: sets.New(authorizer.DecisionNoOpinion, authorizer.DecisionAllow, authorizer.DecisionDeny),
		},

		// ===== Union sequences (built via Add+ToDecision through unionDecision) =====
		{
			// Empty union -> default NoOpinion.
			name:          "Union: empty -> NoOpinion",
			d:             unionDecision(),
			wantString:    `NoOpinion`,
			wantDecisions: sets.New(authorizer.DecisionNoOpinion),
		},
		{
			// Single Allow/Deny/NoOpinion leaves simplify back to the same unconditional decision.
			name:          "Union: single NoOpinion simplifies to NoOpinion",
			d:             unionDecision(noOp),
			wantString:    `NoOpinion`,
			wantDecisions: sets.New(authorizer.DecisionNoOpinion),
		},
		{
			name:          "Union: single Allow simplifies to Allow",
			d:             unionDecision(allow),
			wantString:    `Allow`,
			wantDecisions: sets.New(authorizer.DecisionAllow),
		},
		{
			name:          "Union: single Deny simplifies to Deny",
			d:             unionDecision(deny),
			wantString:    `Deny`,
			wantDecisions: sets.New(authorizer.DecisionDeny),
		},
		{
			// ConditionsMap sub-decisions are conditional, so the union stays a Union.
			name:          "Union: single ConditionsMap(allow) -> {NoOpinion, Allow}",
			d:             unionDecision(condMapAllow),
			wantString:    `Union[ConditionsMap(allows=1)]`,
			wantDecisions: sets.New(authorizer.DecisionNoOpinion, authorizer.DecisionAllow),
		},
		{
			name:          "Union: single ConditionsMap(deny) -> {NoOpinion, Deny}",
			d:             unionDecision(condMapDeny),
			wantString:    `Union[ConditionsMap(denies=1)]`,
			wantDecisions: sets.New(authorizer.DecisionNoOpinion, authorizer.DecisionDeny),
		},
		{
			name:          "Union: all NoOpinions -> NoOpinion",
			d:             unionDecision(noOp, noOp, noOp),
			wantString:    `NoOpinion`,
			wantDecisions: sets.New(authorizer.DecisionNoOpinion),
		},
		{
			// A trailing concrete Allow/Deny after NoOpinions short-circuits, so the union
			// eagerly folds to that Allow/Deny.
			name:          "Union: [NoOpinion, NoOpinion, Allow] simplifies to Allow",
			d:             unionDecision(noOp, noOp, allow),
			wantString:    `Allow`,
			wantDecisions: sets.New(authorizer.DecisionAllow),
		},
		{
			name:          "Union: [NoOpinion, NoOpinion, Deny] simplifies to Deny",
			d:             unionDecision(noOp, noOp, deny),
			wantString:    `Deny`,
			wantDecisions: sets.New(authorizer.DecisionDeny),
		},
		{
			// CM(allow) is {NoOpinion, Allow}; with a trailing Allow, both branches yield
			// Allow, so the union folds to Allow.
			name:          "Union: [CM(allow), Allow] simplifies to Allow",
			d:             unionDecision(condMapAllow, allow),
			wantString:    `Allow`,
			wantDecisions: sets.New(authorizer.DecisionAllow),
		},
		{
			// CM(allow) -> Allow yields Allow; CM(allow) -> NoOpinion falls through to Deny.
			// Both outcomes are reachable, so the union stays a Union.
			name:          "Union: [CM(allow), Deny] stays Union",
			d:             unionDecision(condMapAllow, deny),
			wantString:    `Union[ConditionsMap(allows=1), Deny]`,
			wantDecisions: sets.New(authorizer.DecisionAllow, authorizer.DecisionDeny),
		},
		{
			name:          "Union: [CM(deny), Allow] stays Union",
			d:             unionDecision(condMapDeny, allow),
			wantString:    `Union[ConditionsMap(denies=1), Allow]`,
			wantDecisions: sets.New(authorizer.DecisionAllow, authorizer.DecisionDeny),
		},
		{
			name:          "Union: [CM(deny), Deny] simplifies to Deny",
			d:             unionDecision(condMapDeny, deny),
			wantString:    `Deny`,
			wantDecisions: sets.New(authorizer.DecisionDeny),
		},
		{
			// No downstream Allow/Deny to short-circuit, so NoOpinion remains possible.
			name:          "Union: [CM(allow), NoOpinion] -> {NoOpinion, Allow}",
			d:             unionDecision(condMapAllow, noOp),
			wantString:    `Union[ConditionsMap(allows=1), NoOpinion]`,
			wantDecisions: sets.New(authorizer.DecisionNoOpinion, authorizer.DecisionAllow),
		},
		{
			name:          "Union: [CM(allow), CM(deny)] -> {NoOpinion, Allow, Deny}",
			d:             unionDecision(condMapAllow, condMapDeny),
			wantString:    `Union[ConditionsMap(allows=1), ConditionsMap(denies=1)]`,
			wantDecisions: sets.New(authorizer.DecisionNoOpinion, authorizer.DecisionAllow, authorizer.DecisionDeny),
		},
		{
			name:          "Union: [CM(deny+allow)] -> {NoOpinion, Allow, Deny}",
			d:             unionDecision(condMapDenyAndAllow),
			wantString:    `Union[ConditionsMap(denies=1, allows=1)]`,
			wantDecisions: sets.New(authorizer.DecisionNoOpinion, authorizer.DecisionAllow, authorizer.DecisionDeny),
		},
		{
			name:          "Union: [NoOpinion, CM(allow), Deny] -> {Allow, Deny}",
			d:             unionDecision(noOp, condMapAllow, deny),
			wantString:    `Union[NoOpinion, ConditionsMap(allows=1), Deny]`,
			wantDecisions: sets.New(authorizer.DecisionAllow, authorizer.DecisionDeny),
		},
		{
			name:          "Union: [CM(allow), CM(deny), Allow] -> {Allow, Deny}",
			d:             unionDecision(condMapAllow, condMapDeny, allow),
			wantString:    `Union[ConditionsMap(allows=1), ConditionsMap(denies=1), Allow]`,
			wantDecisions: sets.New(authorizer.DecisionAllow, authorizer.DecisionDeny),
		},
		{
			// After the first Allow is added, Add silently drops all subsequent entries.
			name:          "Union: after first Allow, later elements are dropped by Add",
			d:             unionDecision(noOp, allow, deny, condMapAllow),
			wantString:    `Allow`,
			wantDecisions: sets.New(authorizer.DecisionAllow),
		},
		{
			name:          "Union: after first Deny, later elements are dropped by Add",
			d:             unionDecision(noOp, deny, allow, condMapAllow),
			wantString:    `Deny`,
			wantDecisions: sets.New(authorizer.DecisionDeny),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.d.String(); got != tt.wantString {
				t.Errorf("String() = %q, want %q", got, tt.wantString)
			}
			if got := tt.d.PossibleDecisions(); !got.Equal(tt.wantDecisions) {
				t.Errorf("PossibleDecisions() = %v, want %v", sortedDecisions(got), sortedDecisions(tt.wantDecisions))
			}
		})
	}
}

// TestConditionsAwareDecisionUnionAdd exercises the Add method's bookkeeping behavior:
// it must reject duplicate authorizer names and stop appending after the first Allow/Deny leaf.
func TestConditionsAwareDecisionUnionAdd(t *testing.T) {
	possibleDecisionsTestSetup(t)

	noOp := authorizer.ConditionsAwareDecisionNoOpinion("", nil)
	allow := authorizer.ConditionsAwareDecisionAllow("a", nil)
	deny := authorizer.ConditionsAwareDecisionDeny("d", nil)
	condMapAllow := authorizer.ConditionsAwareDecisionConditionsMap(nil, nil, []authorizer.Condition{genericCond("allow-1")})

	t.Run("duplicate authorizer name fails closed", func(t *testing.T) {
		var u authorizer.ConditionsAwareDecisionUnion
		u.Add("dup", noOp)
		u.Add("dup", noOp)
		u.Add("allow", authorizer.ConditionsAwareDecisionAllow("", nil))

		d := u.ToDecision()
		if !d.IsNoOpinion() {
			t.Errorf("expected NoOpinion (no Deny leaf), got %s", d.String())
		}
		if d.Error() == nil || !containsString(d.Error().Error(), `duplicate authorizerName "dup"`) {
			t.Errorf("expected aggregated duplicate error, got %v", d.Error())
		}
	})

	t.Run("duplicate after Deny leaf fails closed with Deny", func(t *testing.T) {
		var u authorizer.ConditionsAwareDecisionUnion
		u.Add("a", deny)
		// Add another duplicate "a" - this should NOT be skipped by the Allow/Deny short-circuit,
		// because the duplicate check runs first and appends to errs.
		u.Add("a", noOp)
		u.Add("allow", authorizer.ConditionsAwareDecisionAllow("", nil))

		d := u.ToDecision()
		if !d.IsDeny() {
			t.Errorf("expected Deny (deny leaf present), got %s", d.String())
		}
		if d.Error() == nil || !containsString(d.Error().Error(), `duplicate authorizerName "a"`) {
			t.Errorf("expected aggregated duplicate error, got %v", d.Error())
		}
	})

	t.Run("Allow leaf short-circuits subsequent Adds", func(t *testing.T) {
		var u authorizer.ConditionsAwareDecisionUnion
		u.Add("0", noOp)
		u.Add("1", allow)
		// These additions must be silently dropped by the ContainsAllowOrDeny short-circuit.
		u.Add("2", deny)
		u.Add("3", condMapAllow)

		d := u.ToDecision()
		if !d.IsAllow() {
			t.Errorf("expected Allow after short-circuit, got %s", d.String())
		}

		// Iterating the resulting union should only see the entries before/at the short-circuit point.
		seen := map[string]bool{}
		for name := range d.UnionedDecisions() {
			seen[name] = true
		}
		// The wrapped decision is unconditional Allow, so UnionedDecisions is empty.
		if len(seen) != 0 {
			t.Errorf("expected unconditional Allow to expose no unioned decisions, got %v", seen)
		}
	})

	t.Run("Deny leaf short-circuits subsequent Adds", func(t *testing.T) {
		var u authorizer.ConditionsAwareDecisionUnion
		u.Add("0", noOp)
		u.Add("1", deny)
		u.Add("2", allow)
		u.Add("3", condMapAllow)

		d := u.ToDecision()
		if !d.IsDeny() {
			t.Errorf("expected Deny after short-circuit, got %s", d.String())
		}
	})

	t.Run("ConditionsMap leaves do not short-circuit Add", func(t *testing.T) {
		var u authorizer.ConditionsAwareDecisionUnion
		u.Add("0", condMapAllow)
		u.Add("1", condMapAllow) // distinct authorizerName, still appended
		u.Add("2", noOp)

		d := u.ToDecision()
		if !d.IsUnion() {
			t.Fatalf("expected Union, got %s", d.String())
		}

		var names []string
		for name := range d.UnionedDecisions() {
			names = append(names, name)
		}
		want := []string{"0", "1", "2"}
		if !stringSlicesEqual(names, want) {
			t.Errorf("UnionedDecisions names = %v, want %v", names, want)
		}
	})
}

// TestConditionsAwareDecisionUnionToDecisionPostMutation verifies that mutating the source
// ConditionsAwareDecisionUnion after calling ToDecision does NOT change the returned decision.
// (The patch explicitly clones the inner slice in ToDecision for this reason.)
func TestConditionsAwareDecisionUnionToDecisionPostMutation(t *testing.T) {
	possibleDecisionsTestSetup(t)

	condMapAllow := authorizer.ConditionsAwareDecisionConditionsMap(nil, nil, []authorizer.Condition{genericCond("allow-1")})

	var u authorizer.ConditionsAwareDecisionUnion
	u.Add("0", condMapAllow)
	u.Add("1", condMapAllow) // distinct name -> distinct entry
	snapshot := u.ToDecision()

	// Sanity: snapshot has 2 inner entries.
	var beforeNames []string
	for name := range snapshot.UnionedDecisions() {
		beforeNames = append(beforeNames, name)
	}
	if !stringSlicesEqual(beforeNames, []string{"0", "1"}) {
		t.Fatalf("setup: snapshot inner = %v, want [0 1]", beforeNames)
	}

	// Mutate u after the snapshot was taken. snapshot must remain unchanged.
	u.Add("2", condMapAllow)

	var afterNames []string
	for name := range snapshot.UnionedDecisions() {
		afterNames = append(afterNames, name)
	}
	if !stringSlicesEqual(afterNames, []string{"0", "1"}) {
		t.Errorf("post-mutation snapshot inner = %v, want [0 1]; ToDecision must clone", afterNames)
	}
}

// containsString reports whether s contains substr (replacement for strings.Contains to
// avoid adding another import).
func containsString(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// stringSlicesEqual reports whether two []string are element-wise equal.
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// sortedDecisions returns the elements of s as a stable, sorted slice for error messages.
func sortedDecisions(s sets.Set[authorizer.Decision]) []string {
	out := make([]string, 0, s.Len())
	for _, d := range s.UnsortedList() {
		out = append(out, fmt.Sprintf("%v", d))
	}
	// simple insertion sort to avoid an extra dep
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}
