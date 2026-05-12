// Package authz_oracle_test contains property-based tests (using hegel-go)
// that verify the production Go authorization code matches the formal Lean 4
// model (ConditionalAuthz.lean).
//
// Each function prefixed with "oracle" is a direct transliteration of the
// corresponding Lean function. The hegel tests generate arbitrary authorizer
// chains and verify that the production code and the oracle agree.
//
// Setup:
//   cd plan && go mod init authz-oracle && go mod tidy
//   go get hegel.dev/go/hegel@latest
//   go test -v -run TestAuthzEquivalence -count=1
//

package authz_oracle_test

import (
	"context"
	"fmt"
	"math"
	"testing"

	"hegel.dev/go/hegel"

	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/union"
)

// ============================================================================
// Part 1: Oracle — Direct transliteration of ConditionalAuthz.lean
// ============================================================================

// oracleUnconditionalDecision mirrors ConditionalAuthz.UnconditionalDecision.
// We reuse authorizer.Decision (which is the same int enum).

// oracleIdealChain mirrors ConditionalAuthz.idealChain:
// Run each authorizer with full data, short-circuit on Allow/Deny, continue on NoOpinion.
func oracleIdealChain(
	fullAuthorizers []func() authorizer.Decision, // pre-bound to (attrs, data)
) authorizer.Decision {
	for _, full := range fullAuthorizers {
		switch d := full(); d {
		case authorizer.DecisionAllow, authorizer.DecisionDeny:
			return d
		case authorizer.DecisionNoOpinion:
			continue
		}
	}
	return authorizer.DecisionNoOpinion
}

// oracleLeafDecision mirrors ConditionalAuthz.LeafDecision.
type oracleLeafDecision struct {
	unconditional *authorizer.Decision // non-nil for Allow/Deny/NoOpinion
	conditional   []oracleCondition    // non-nil for Conditional
}

func oracleLeafAllow() oracleLeafDecision {
	d := authorizer.DecisionAllow
	return oracleLeafDecision{unconditional: &d}
}
func oracleLeafDeny() oracleLeafDecision {
	d := authorizer.DecisionDeny
	return oracleLeafDecision{unconditional: &d}
}
func oracleLeafNoOpinion() oracleLeafDecision {
	d := authorizer.DecisionNoOpinion
	return oracleLeafDecision{unconditional: &d}
}
func oracleLeafConditional(conditions []oracleCondition) oracleLeafDecision {
	return oracleLeafDecision{conditional: conditions}
}

func (d oracleLeafDecision) isConditional() bool { return d.conditional != nil }

// oracleCondition mirrors a single condition in a ConditionsMap.
type oracleCondition struct {
	effect   authorizer.ConditionEffect
	evaluate bool // pre-bound evaluation result for this test scenario
}

// oracleUnionEntry mirrors ConditionalAuthz.UnionEntry.
type oracleUnionEntry struct {
	leaf             oracleLeafDecision
	canBecomeAllowed bool
	evaluateResult   authorizer.Decision // pre-computed evaluateConditions result
}

// oracleAuthzPhase mirrors ConditionalAuthz.authzPhase:
// Collect entries, short-circuit on Allow/Deny (ContainsAllowOrDeny).
func oracleAuthzPhase(entries []oracleUnionEntry) []oracleUnionEntry {
	var result []oracleUnionEntry
	for _, e := range entries {
		result = append(result, e)
		if e.leaf.unconditional != nil {
			d := *e.leaf.unconditional
			if d == authorizer.DecisionAllow || d == authorizer.DecisionDeny {
				break
			}
		}
		// Conditional and NoOpinion: continue collecting
	}
	return result
}

// oracleEvaluateUnion mirrors ConditionalAuthz.evaluateUnion:
// Walk entries in order. For Allow/Deny: return. For NoOpinion: continue.
// For Conditional: evaluate, then Allow/Deny returns, NoOpinion continues.
func oracleEvaluateUnion(entries []oracleUnionEntry) authorizer.Decision {
	for _, e := range entries {
		if e.leaf.unconditional != nil {
			switch *e.leaf.unconditional {
			case authorizer.DecisionAllow:
				return authorizer.DecisionAllow
			case authorizer.DecisionDeny:
				return authorizer.DecisionDeny
			case authorizer.DecisionNoOpinion:
				continue
			}
		}
		// Conditional: use pre-computed evaluation result
		switch e.evaluateResult {
		case authorizer.DecisionAllow:
			return authorizer.DecisionAllow
		case authorizer.DecisionDeny:
			return authorizer.DecisionDeny
		case authorizer.DecisionNoOpinion:
			continue
		}
	}
	return authorizer.DecisionNoOpinion
}

// oracleUnionCanBecomeAllowed mirrors ConditionalAuthz.unionCanBecomeAllowed.
func oracleUnionCanBecomeAllowed(entries []oracleUnionEntry) bool {
	for _, e := range entries {
		if e.leaf.unconditional != nil {
			switch *e.leaf.unconditional {
			case authorizer.DecisionAllow:
				return true
			case authorizer.DecisionDeny:
				return false
			case authorizer.DecisionNoOpinion:
				continue
			}
		}
		// Conditional
		if e.canBecomeAllowed {
			return true
		}
		// Conditional without canBecomeAllowed: continue
	}
	return false
}

// oraclePipeline mirrors ConditionalAuthz.pipeline:
// authzPhase → canBecomeAllowed check → evaluateUnion or Deny.
func oraclePipeline(entries []oracleUnionEntry) authorizer.Decision {
	phase := oracleAuthzPhase(entries)
	if !oracleUnionCanBecomeAllowed(phase) {
		return authorizer.DecisionDeny
	}
	return oracleEvaluateUnion(phase)
}

// oracleConditionsMapEvaluate mirrors ConcConditionsMap.evaluate:
// Deny > NoOpinion > Allow > NoOpinion (default).
func oracleConditionsMapEvaluate(conditions []oracleCondition) authorizer.Decision {
	// Phase 1: Deny
	for _, c := range conditions {
		if c.effect == authorizer.ConditionEffectDeny && c.evaluate {
			return authorizer.DecisionDeny
		}
	}
	// Phase 2: NoOpinion
	for _, c := range conditions {
		if c.effect == authorizer.ConditionEffectNoOpinion && c.evaluate {
			return authorizer.DecisionNoOpinion
		}
	}
	// Phase 3: Allow
	for _, c := range conditions {
		if c.effect == authorizer.ConditionEffectAllow && c.evaluate {
			return authorizer.DecisionAllow
		}
	}
	// Phase 4: default
	return authorizer.DecisionNoOpinion
}

// ============================================================================
// Part 2: Generators for hegel-go
// ============================================================================

// genDecision generates a random unconditional decision.
func genDecision() hegel.Generator[authorizer.Decision] {
	return hegel.Map(hegel.Integers[int](0, 2), func(i int) authorizer.Decision {
		return authorizer.Decision(i) // 0=Deny, 1=Allow, 2=NoOpinion
	})
}

// genConditionEffect generates a random condition effect.
func genConditionEffect() hegel.Generator[authorizer.ConditionEffect] {
	return hegel.SampledFrom([]authorizer.ConditionEffect{
		authorizer.ConditionEffectAllow,
		authorizer.ConditionEffectDeny,
		authorizer.ConditionEffectNoOpinion,
	})
}

// genCondition generates a random condition with a pre-determined evaluation result.
func genCondition() hegel.Generator[oracleCondition] {
	return hegel.Composite(func(tc *hegel.TestCase) oracleCondition {
		return oracleCondition{
			effect:   hegel.Draw(tc, genConditionEffect()),
			evaluate: hegel.Draw(tc, hegel.Booleans()),
		}
	})
}

// genConditionsList generates a list of 0..8 conditions.
func genConditionsList() hegel.Generator[[]oracleCondition] {
	return hegel.Lists(genCondition()).MinSize(0).MaxSize(8)
}

// genUnionEntry generates a random union entry (authorizer + decision).
func genUnionEntry() hegel.Generator[oracleUnionEntry] {
	return hegel.Composite(func(tc *hegel.TestCase) oracleUnionEntry {
		// 0=Allow, 1=Deny, 2=NoOpinion, 3=Conditional
		kind := hegel.Draw(tc, hegel.Integers(0, 3))
		switch kind {
		case 0:
			return oracleUnionEntry{leaf: oracleLeafAllow()}
		case 1:
			return oracleUnionEntry{leaf: oracleLeafDeny()}
		case 2:
			return oracleUnionEntry{leaf: oracleLeafNoOpinion()}
		default: // 3 = Conditional
			conditions := hegel.Draw(tc, genConditionsList())
			evalResult := oracleConditionsMapEvaluate(conditions)
			cba := false
			for _, c := range conditions {
				if c.effect == authorizer.ConditionEffectAllow {
					cba = true
					break
				}
			}
			return oracleUnionEntry{
				leaf:             oracleLeafConditional(conditions),
				canBecomeAllowed: cba,
				evaluateResult:   evalResult,
			}
		}
	})
}

// genChain generates a chain of 0..6 union entries.
func genChain() hegel.Generator[[]oracleUnionEntry] {
	return hegel.Lists(genUnionEntry()).MinSize(0).MaxSize(6)
}

// ============================================================================
// Part 3: Adapters — bridge oracle entries to production Go code
// ============================================================================

// testAuthorizer wraps an oracleUnionEntry into an authorizer.Authorizer
// that can be used with the production union authorizer.
type testAuthorizer struct {
	entry oracleUnionEntry
}

func (ta *testAuthorizer) Authorize(_ context.Context, _ authorizer.Attributes) (authorizer.Decision, string, error) {
	// The ideal (unconditional) authorize: if conditional, return the pre-computed evaluation result
	if ta.entry.leaf.isConditional() {
		return ta.entry.evaluateResult, "", nil
	}
	return *ta.entry.leaf.unconditional, "", nil
}

func (ta *testAuthorizer) ConditionsAwareAuthorize(_ context.Context, _ authorizer.Attributes) authorizer.ConditionsAwareDecision {
	if !ta.entry.leaf.isConditional() {
		return authorizer.ConditionsAwareDecisionFromParts(*ta.entry.leaf.unconditional, "", nil)
	}
	// Build a ConditionsMap from the oracle conditions
	goConditions := make([]authorizer.Condition, len(ta.entry.leaf.conditional))
	for i, c := range ta.entry.leaf.conditional {
		goConditions[i] = authorizer.GenericCondition{
			ID:     fmt.Sprintf("cond-%d", i),
			Effect: c.effect,
			EvaluateFunc: func(_ context.Context, _ authorizer.ConditionsData) authorizer.ConditionEvaluationResult {
				return authorizer.ConditionEvaluationResultBoolean(c.evaluate)
			},
		}
	}
	return authorizer.ConditionsAwareDecisionConditionsMap(goConditions...)
}

func (ta *testAuthorizer) EvaluateConditions(_ context.Context, decision authorizer.ConditionsAwareDecision, data authorizer.ConditionsData) (authorizer.Decision, string, error) {
	if decision.IsUnconditional() {
		return decision.UnconditionalParts()
	}
	if decision.IsConditionsMap() {
		cm := decision.ConditionsMap()
		evaluated := cm.Evaluate(context.Background(), data, nil)
		return evaluated.UnconditionalParts()
	}
	return authorizer.DecisionDeny, "unexpected decision type in test", nil
}

// ============================================================================
// Part 4: hegel-go property tests
// ============================================================================

// TestAuthzEquivalence_EvaluateUnion_Eq_IdealChain tests the core semantic lemma:
// evaluateUnion(authzPhase(chain)) == idealChain(chain)
// This corresponds to theorem evaluateUnion_eq_idealChain in the Lean model.
func TestAuthzEquivalence_EvaluateUnion_Eq_IdealChain(t *testing.T) {
	hegel.Test(t, func(ht *hegel.T) {
		chain := hegel.Draw(ht, genChain())

		// Oracle: idealChain (single-phase, all data available)
		fullAuthorizers := make([]func() authorizer.Decision, len(chain))
		for i, e := range chain {
			e := e
			fullAuthorizers[i] = func() authorizer.Decision {
				if e.leaf.isConditional() {
					return e.evaluateResult
				}
				return *e.leaf.unconditional
			}
		}
		idealResult := oracleIdealChain(fullAuthorizers)

		// Oracle: evaluateUnion(authzPhase(chain))
		phase := oracleAuthzPhase(chain)
		evalResult := oracleEvaluateUnion(phase)

		if idealResult != evalResult {
			t.Fatalf("evaluateUnion_eq_idealChain FAILED: idealChain=%v, evaluateUnion=%v, chain=%+v",
				idealResult, evalResult, chain)
		}
	})
}

// TestAuthzEquivalence_CBA_Sound tests the canBecomeAllowed soundness property:
// unionCanBecomeAllowed(entries) == false → evaluateUnion(entries) != Allow
// This corresponds to theorem cba_sound in the Lean model.
func TestAuthzEquivalence_CBA_Sound(t *testing.T) {
	hegel.Test(t, func(ht *hegel.T) {
		chain := hegel.Draw(ht, genChain())
		phase := oracleAuthzPhase(chain)
		cba := oracleUnionCanBecomeAllowed(phase)

		if !cba {
			evalResult := oracleEvaluateUnion(phase)
			if evalResult == authorizer.DecisionAllow {
				t.Fatalf("cba_sound FAILED: canBecomeAllowed=false but evaluateUnion=Allow, chain=%+v", chain)
			}
		}
	})
}

// TestAuthzEquivalence_Pipeline_IsAllowed tests the main theorem:
// isAllowed(idealChain) == isAllowed(pipeline)
// This corresponds to theorem authorization_allows_iff in the Lean model.
func TestAuthzEquivalence_Pipeline_IsAllowed(t *testing.T) {
	hegel.Test(t, func(ht *hegel.T) {
		chain := hegel.Draw(ht, genChain())

		idealResult := func() authorizer.Decision {
			fullAuthorizers := make([]func() authorizer.Decision, len(chain))
			for i, e := range chain {
				e := e
				fullAuthorizers[i] = func() authorizer.Decision {
					if e.leaf.isConditional() {
						return e.evaluateResult
					}
					return *e.leaf.unconditional
				}
			}
			return oracleIdealChain(fullAuthorizers)
		}()

		pipelineResult := oraclePipeline(chain)

		idealAllowed := idealResult == authorizer.DecisionAllow
		pipelineAllowed := pipelineResult == authorizer.DecisionAllow

		if idealAllowed != pipelineAllowed {
			t.Fatalf("authorization_allows_iff FAILED: isAllowed(ideal)=%v, isAllowed(pipeline)=%v, chain=%+v",
				idealAllowed, pipelineAllowed, chain)
		}
	})
}

// TestAuthzEquivalence_ConditionsMap_Evaluate_Priority tests the priority order:
// Deny > NoOpinion > Allow > NoOpinion (default)
// This corresponds to ConcConditionsMap.cba_sound and the Evaluate semantics.
func TestAuthzEquivalence_ConditionsMap_Evaluate_Priority(t *testing.T) {
	hegel.Test(t, func(ht *hegel.T) {
		conditions := hegel.Draw(ht, genConditionsList())

		oracleResult := oracleConditionsMapEvaluate(conditions)

		// Build production ConditionsMap and evaluate
		if len(conditions) == 0 {
			// Empty map → NoOpinion in both oracle and production
			if oracleResult != authorizer.DecisionNoOpinion {
				t.Fatalf("empty conditions should be NoOpinion, got %v", oracleResult)
			}
			return
		}

		goConditions := make([]authorizer.Condition, len(conditions))
		for i, c := range conditions {
			c := c
			goConditions[i] = authorizer.GenericCondition{
				ID:     fmt.Sprintf("cond-%d", i),
				Effect: c.effect,
				EvaluateFunc: func(_ context.Context, _ authorizer.ConditionsData) authorizer.ConditionEvaluationResult {
					return authorizer.ConditionEvaluationResultBoolean(c.evaluate)
				},
			}
		}

		cad := authorizer.ConditionsAwareDecisionConditionsMap(goConditions...)
		if cad.IsConditionsMap() {
			cm := cad.ConditionsMap()
			prodDecision := cm.Evaluate(context.Background(), authorizer.ConditionsData{}, nil)
			prodResult, _, _ := prodDecision.UnconditionalParts()

			if oracleResult != prodResult {
				t.Fatalf("ConditionsMap.Evaluate priority FAILED: oracle=%v, production=%v, conditions=%+v",
					oracleResult, prodResult, conditions)
			}
		}
	})
}

// TestAuthzEquivalence_Production_Union_Vs_Oracle tests that the production
// union authorizer (union.New) matches the oracle for both the old Authorize
// path and the new ConditionsAwareAuthorize + EvaluateConditions path.
func TestAuthzEquivalence_Production_Union_Vs_Oracle(t *testing.T) {
	hegel.Test(t, func(ht *hegel.T) {
		chain := hegel.Draw(ht, genChain())

		// Build production authorizer chain
		prodAuthzs := make([]authorizer.Authorizer, len(chain))
		for i, e := range chain {
			prodAuthzs[i] = &testAuthorizer{entry: e}
		}
		unionAuthz := union.New(prodAuthzs...)

		// Production: old path (Authorize)
		prodOldDecision, _, _ := unionAuthz.Authorize(context.Background(), nil)

		// Oracle: idealChain (matches old Authorize semantics)
		fullAuthorizers := make([]func() authorizer.Decision, len(chain))
		for i, e := range chain {
			e := e
			fullAuthorizers[i] = func() authorizer.Decision {
				if e.leaf.isConditional() {
					return e.evaluateResult
				}
				return *e.leaf.unconditional
			}
		}
		oracleOldResult := oracleIdealChain(fullAuthorizers)

		if prodOldDecision != oracleOldResult {
			t.Fatalf("Production Authorize vs idealChain FAILED: prod=%v, oracle=%v, chain=%+v",
				prodOldDecision, oracleOldResult, chain)
		}

		// Production: new path (ConditionsAwareAuthorize + EvaluateConditions)
		condAwareDecision := unionAuthz.ConditionsAwareAuthorize(context.Background(), nil)

		if condAwareDecision.IsUnconditional() {
			prodNewDecision, _, _ := condAwareDecision.UnconditionalParts()
			if prodNewDecision != oracleOldResult {
				t.Fatalf("Production ConditionsAwareAuthorize (unconditional) vs idealChain FAILED: prod=%v, oracle=%v",
					prodNewDecision, oracleOldResult)
			}
		} else {
			// Evaluate the conditional decision
			prodNewDecision, _, _ := unionAuthz.EvaluateConditions(
				context.Background(), condAwareDecision, authorizer.ConditionsData{})

			// This should match the oracle's evaluateUnion result
			phase := oracleAuthzPhase(chain)
			oracleEvalResult := oracleEvaluateUnion(phase)

			if prodNewDecision != oracleEvalResult {
				t.Fatalf("Production EvaluateConditions vs evaluateUnion FAILED: prod=%v, oracle=%v, chain=%+v",
					prodNewDecision, oracleEvalResult, chain)
			}
		}
	})
}

// Ensure imports are used.
var _ = fmt.Sprintf
var _ = math.MaxInt
