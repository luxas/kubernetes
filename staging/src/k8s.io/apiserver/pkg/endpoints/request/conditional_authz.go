package request

import (
	"context"
	"encoding/json"

	"github.com/google/cel-go/cel"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/features"
)

// ConditionalAuthorizationServerSupportedAnnotation is the annotation that the server sets during a SubjectAccessReview webhook
// to indicate that it supports conditional authorization SAR responses.
const ConditionalAuthorizationServerSupportedAnnotation = "kubernetes.io/" + string(features.SubjectAccessReviewConditions) + "ServerSupported"

// ConditionalAuthorizationConditionsAnnotation is the annotation that the client sets during a SubjectAccessReview webhook
// to indicate (to a supporting server) what conditions must be enforced during admission.
// The annotation value is a JSON-encoded array of SubjectAccessReviewCondition objects.
const ConditionalAuthorizationConditionsAnnotation = "kubernetes.io/" + string(features.SubjectAccessReviewConditions)

type ConditionalAuthorizationContext struct {
	Conditions []CompiledCondition
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

func (e *ConditionalAuthorizationContext) ApplyToAnnotations(obj metav1.Object) error {
	annotations := obj.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}
	encodableConditions := make([]SubjectAccessReviewCondition, len(e.Conditions))
	for i, cond := range e.Conditions {
		encodableConditions[i] = cond.SubjectAccessReviewCondition
	}
	encodedConditions, err := json.Marshal(encodableConditions)
	if err != nil {
		return err
	}
	annotations[ConditionalAuthorizationConditionsAnnotation] = string(encodedConditions)
	obj.SetAnnotations(annotations)
	return nil
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

type CompiledCondition struct {
	SubjectAccessReviewCondition
	Program            cel.Program
	ExpressionAccessor ExpressionAccessor
}

type ExpressionAccessor interface {
	GetExpression() string
	ReturnTypes() []*cel.Type
}

// Conditions is an array of authorization conditions. All conditions must evaluate to true for the request to be authorized.
// The conditions are evaluated in order, and in case of a false response or error, the process is short-circuited, and the request is denied.
// This field is alpha-level, and ignored if the SubjectAccessReview handler has not enabled the SubjectAccessReviewConditions feature gate,
// in which the response is treated as NoOpinion.
type Conditions []SubjectAccessReviewCondition

type SubjectAccessReviewCondition struct {
	// Effect is the effect of the condition.
	Effect ConditionEffect `json:"effect"`

	// Condition is a CEL expression that evaluates a ValidatingAdmissionPolicy-like environment into a boolean value.
	// If the condition evaluates to true, the request is authorized.
	Condition string `json:"condition"`

	// ID is an optional ID of the condition, used for error and reason messages.
	ID string `json:"id"`
}

type ConditionEffect string

const (
	ConditionEffectAllow ConditionEffect = "Allow"
	ConditionEffectDeny  ConditionEffect = "Deny"
)
