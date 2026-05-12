package leanauthzffi

import (
	"testing"
)

func TestCallLean_EmptyChain(t *testing.T) {
	result, err := CallLean(AuthzInput{Handlers: []HandlerInput{}})
	if err != nil {
		t.Fatal(err)
	}
	if result.UnionAuthorize != "NoOpinion" {
		t.Errorf("expected NoOpinion for empty chain, got %s", result.UnionAuthorize)
	}
	if result.Pipeline != "Deny" {
		t.Errorf("expected Deny pipeline for empty chain (cba=false), got %s", result.Pipeline)
	}
}

func TestCallLean_SingleAllow(t *testing.T) {
	result, err := CallLean(AuthzInput{
		Handlers: []HandlerInput{{
			Authorize:                "Allow",
			ConditionsAwareAuthorize: "Allow",
			CmCanBecomeAllowed:       false,
			EvaluateConditions:       "Allow",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.UnionAuthorize != "Allow" {
		t.Errorf("expected Allow, got %s", result.UnionAuthorize)
	}
	if result.Pipeline != "Allow" {
		t.Errorf("expected Allow pipeline, got %s", result.Pipeline)
	}
}

func TestCallLean_ConditionalAllow(t *testing.T) {
	result, err := CallLean(AuthzInput{
		Handlers: []HandlerInput{{
			Authorize:                "Allow",
			ConditionsAwareAuthorize: "ConditionsMap",
			CmCanBecomeAllowed:       true,
			EvaluateConditions:       "Allow",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// UnionAuthorize uses the old path: handler.authorize = Allow
	if result.UnionAuthorize != "Allow" {
		t.Errorf("expected Allow, got %s", result.UnionAuthorize)
	}
	// Pipeline uses the new path: ConditionsMap → cba=true → evaluate → Allow
	if result.Pipeline != "Allow" {
		t.Errorf("expected Allow pipeline, got %s", result.Pipeline)
	}
}

func TestCallLean_ConditionalDeniedByCBA(t *testing.T) {
	result, err := CallLean(AuthzInput{
		Handlers: []HandlerInput{{
			Authorize:                "NoOpinion",
			ConditionsAwareAuthorize: "ConditionsMap",
			CmCanBecomeAllowed:       false,
			EvaluateConditions:       "NoOpinion",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.UnionAuthorize != "NoOpinion" {
		t.Errorf("expected NoOpinion, got %s", result.UnionAuthorize)
	}
	// Pipeline: cba=false → Deny
	if result.Pipeline != "Deny" {
		t.Errorf("expected Deny pipeline, got %s", result.Pipeline)
	}
	if result.SliceCBA != false {
		t.Errorf("expected sliceCBA=false")
	}
}

func TestCallLean_ChainResumption(t *testing.T) {
	// First authorizer: ConditionsMap that evaluates to NoOpinion
	// Second authorizer: Allow
	// The chain should resume after the first evaluates to NoOpinion
	result, err := CallLean(AuthzInput{
		Handlers: []HandlerInput{
			{
				Authorize:                "NoOpinion",
				ConditionsAwareAuthorize: "ConditionsMap",
				CmCanBecomeAllowed:       true,
				EvaluateConditions:       "NoOpinion",
			},
			{
				Authorize:                "Allow",
				ConditionsAwareAuthorize: "Allow",
				CmCanBecomeAllowed:       false,
				EvaluateConditions:       "Allow",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	// UnionAuthorize: first=NoOpinion → second=Allow
	if result.UnionAuthorize != "Allow" {
		t.Errorf("expected Allow, got %s", result.UnionAuthorize)
	}
	// Pipeline: first=ConditionsMap(cba=true) → short-circuit collects both →
	// EvaluateEntries: first evaluates to NoOpinion → continues → second=Allow
	if result.Pipeline != "Allow" {
		t.Errorf("expected Allow pipeline, got %s", result.Pipeline)
	}
}
