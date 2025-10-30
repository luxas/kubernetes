package contextpropagation

import (
	"context"
	"testing"
)

type key int

const (
	conditionalAuthorizationContextKey key = iota
)

type ConditionalAuthorizationContext struct {
	Conditions []string
}

// WithConditionalAuthorizationContext returns a copy of parent in which the authorization UID for the request is set
func WithConditionalAuthorizationContext(parent context.Context, data *ConditionalAuthorizationContext) context.Context {
	return context.WithValue(parent, conditionalAuthorizationContextKey, data)
}

// ConditionalAuthorizationContextFrom returns the conditional authorization context associated with the ctx
func ConditionalAuthorizationContextFrom(ctx context.Context) (*ConditionalAuthorizationContext, bool) {
	context, ok := ctx.Value(conditionalAuthorizationContextKey).(*ConditionalAuthorizationContext)
	return context, ok
}

func TestPropagateContext(t *testing.T) {
	ctx := context.Background()
	authorizeCtx := WithConditionalAuthorizationContext(ctx, &ConditionalAuthorizationContext{
		Conditions: nil,
	})

	authorize(authorizeCtx)

	generalConditions, ok := ConditionalAuthorizationContextFrom(ctx)
	t.Logf("general conditions: %+v, ok: %v", generalConditions, ok)

	authorizeConditions, ok := ConditionalAuthorizationContextFrom(authorizeCtx)
	t.Logf("authorize conditions: %+v, ok: %v", authorizeConditions, ok)
}

func authorize(ctx context.Context) {
	conditions, ok := ConditionalAuthorizationContextFrom(ctx)
	if ok {
		conditions.Conditions = append(conditions.Conditions, "bar")
	}
}
