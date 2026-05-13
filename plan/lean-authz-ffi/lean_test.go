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
			AuthorizeIdeal: "Allow", AuthorizeMetadata: "Allow",
			ConditionsAwareAuthorize: "Allow",
			CmCanBecomeAllowed: false, EvaluateConditions: "Allow",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.UnionAuthorize != "Allow" {
		t.Errorf("expected Allow, got %s", result.UnionAuthorize)
	}
	if result.UnionAuthorizeMetadata != "Allow" {
		t.Errorf("expected metadata Allow, got %s", result.UnionAuthorizeMetadata)
	}
	if result.Pipeline != "Allow" {
		t.Errorf("expected Allow pipeline, got %s", result.Pipeline)
	}
}

func TestCallLean_ConditionalAllow(t *testing.T) {
	result, err := CallLean(AuthzInput{
		Handlers: []HandlerInput{{
			AuthorizeIdeal: "Allow", AuthorizeMetadata: "Allow",
			ConditionsAwareAuthorize: "ConditionsMap",
			CmCanBecomeAllowed: true, EvaluateConditions: "Allow",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// UnionAuthorize uses the ideal path: authorizeIdeal = Allow
	if result.UnionAuthorize != "Allow" {
		t.Errorf("expected Allow, got %s", result.UnionAuthorize)
	}
	// Pipeline uses the new path: ConditionsMap → cba=true → evaluate → Allow
	if result.Pipeline != "Allow" {
		t.Errorf("expected Allow pipeline, got %s", result.Pipeline)
	}
}

func TestCallLean_FailClosed(t *testing.T) {
	// ideal=NoOpinion, metadata=Deny (fail-closed)
	result, err := CallLean(AuthzInput{
		Handlers: []HandlerInput{{
			AuthorizeIdeal: "NoOpinion", AuthorizeMetadata: "Deny",
			ConditionsAwareAuthorize: "ConditionsMap",
			CmCanBecomeAllowed: false, EvaluateConditions: "NoOpinion",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.UnionAuthorize != "NoOpinion" {
		t.Errorf("expected ideal NoOpinion, got %s", result.UnionAuthorize)
	}
	if result.UnionAuthorizeMetadata != "Deny" {
		t.Errorf("expected metadata Deny (fail-closed), got %s", result.UnionAuthorizeMetadata)
	}
}

func TestCallLean_ChainResumption(t *testing.T) {
	// First authorizer: ConditionsMap that evaluates to NoOpinion
	// Second authorizer: Allow
	// The chain should resume after the first evaluates to NoOpinion
	result, err := CallLean(AuthzInput{
		Handlers: []HandlerInput{
			{
				AuthorizeIdeal: "NoOpinion", AuthorizeMetadata: "NoOpinion",
				ConditionsAwareAuthorize: "ConditionsMap",
				CmCanBecomeAllowed: true, EvaluateConditions: "NoOpinion",
			},
			{
				AuthorizeIdeal: "Allow", AuthorizeMetadata: "Allow",
				ConditionsAwareAuthorize: "Allow",
				CmCanBecomeAllowed: false, EvaluateConditions: "Allow",
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
	// UnionEvaluateConditions: first evaluates to NoOpinion → continues → second=Allow
	if result.Pipeline != "Allow" {
		t.Errorf("expected Allow pipeline, got %s", result.Pipeline)
	}
}
