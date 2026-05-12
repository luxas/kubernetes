package fuzz

import (
	"encoding/json"
	"testing"

	"hegel.dev/go/hegel"

	leanauthzffi "k8s.io/kubernetes/plan/lean-authz-ffi"

	genericfeatures "k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
)

// ---------------------------------------------------------------------------
// hegel-go property test
// ---------------------------------------------------------------------------

// TestHegelDifferential uses structured generation via hegel-go to produce
// arbitrary authorizer chains and compare the Lean oracle against the
// production Go code. Unlike FuzzDifferential (which uses byte-level mutation
// on JSON), this generates valid chains directly at the type level, making it
// effective at finding bugs that require specific structural properties like
// "chain has 6+ handlers".
func TestHegelDifferential(t *testing.T) {
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, genericfeatures.ConditionalAuthorization, true)

	hegel.Test(t, func(ht *hegel.T) {
		handlers := hegel.Draw(ht, genChain())
		input := leanauthzffi.AuthzInput{Handlers: handlers}

		// Lean oracle (formally proven, called via C FFI)
		leanResult, err := leanauthzffi.CallLean(input)
		if err != nil {
			ht.Fatalf("Lean FFI error: %v", err)
		}

		// Production Go code (real union authorizer)
		goResult := goProductionOracle(input)

		inputJSON, err := json.Marshal(input)
		if err != nil {
			ht.Fatal("json marshalling error", err)
		}
		compareResults(ht, inputJSON, leanResult, goResult)
	}, hegel.WithTestCases(5000)) // At some point: might want to use the test database if we find regressions
}

// ---------------------------------------------------------------------------
// Structured generators for authorization chains
// ---------------------------------------------------------------------------

func genChain() hegel.Generator[[]leanauthzffi.HandlerInput] {
	return hegel.Lists(genHandler()).MinSize(0).MaxSize(10)
}

func genHandler() hegel.Generator[leanauthzffi.HandlerInput] {
	return hegel.Composite(func(tc *hegel.TestCase) leanauthzffi.HandlerInput {
		condAware := hegel.Draw(tc, hegel.SampledFrom([]string{"Allow", "Deny", "NoOpinion", "ConditionsMap"}))
		var authorize, evalCond string
		var canBecomeAllowed bool
		switch condAware {
		case "Allow", "Deny", "NoOpinion":
			authorize = condAware
			evalCond = condAware
			if condAware == "Allow" {
				canBecomeAllowed = true
			}
		case "ConditionsMap":
			// Assume the authorizer always fails closed for calls to Authorize when conditions are returned
			possibleEvalCondResults := []string{"NoOpinion"}
			hasDenyEffectCondition := hegel.Draw(tc, hegel.Booleans())
			if hasDenyEffectCondition {
				authorize = "Deny"
				possibleEvalCondResults = append(possibleEvalCondResults, "Deny")
			} else {
				authorize = "NoOpinion"
			}
			// when there is no Allow effect, the authorizer shall not return Allow. TODO: Actually guard against authorizers misbehaving in our framework instead of this assumption
			hasAllowEffectCondition := hegel.Draw(tc, hegel.Booleans())
			if hasAllowEffectCondition {
				possibleEvalCondResults = append(possibleEvalCondResults, "Allow")
				canBecomeAllowed = true
			}
			evalCond = hegel.Draw(tc, hegel.SampledFrom(possibleEvalCondResults))
		default:
			tc.Errorf("unexpected condAware=%s generated", condAware)
		}

		return leanauthzffi.HandlerInput{
			Authorize:                authorize,
			ConditionsAwareAuthorize: condAware,
			CmCanBecomeAllowed:       canBecomeAllowed,
			EvaluateConditions:       evalCond,
		}
	})
}
