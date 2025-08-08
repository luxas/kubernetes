package request

import (
	"context"

	"github.com/google/cel-go/cel"
)

type ConditionalAuthorizationContext struct {
	Conditions []CompilationResult
}

func (e *ConditionalAuthorizationContext) Error() string {
	return "pseudo error for passing the conditions from the authorizer to the API server for enforcement"
}

func (e *ConditionalAuthorizationContext) Is(target error) bool {
	_, ok := target.(*ConditionalAuthorizationContext)
	return ok
}

func (e *ConditionalAuthorizationContext) As(i any) bool {
	ok := false
	switch x := i.(type) {
	case *ConditionalAuthorizationContext:
		*x = *e
		ok = true
	}
	return ok
}

// WithConditionalAuthorizationContext returns a copy of parent in which the authorization UID for the request is set
func WithConditionalAuthorizationContext(parent context.Context, context *ConditionalAuthorizationContext) context.Context {
	return WithValue(parent, conditionalAuthorizationContextKey, context)
}

// ConditionalAuthorizationContextFrom returns the conditional authorization context associated with the ctx
func ConditionalAuthorizationContextFrom(ctx context.Context) (*ConditionalAuthorizationContext, bool) {
	context, ok := ctx.Value(conditionalAuthorizationContextKey).(*ConditionalAuthorizationContext)
	return context, ok
}

type CompilationResult struct {
	Program            cel.Program
	ExpressionAccessor ExpressionAccessor
	OutputType         *cel.Type
}

type ExpressionAccessor interface {
	GetExpression() string
	ReturnTypes() []*cel.Type
}
