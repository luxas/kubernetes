package request

import (
	"context"
	"fmt"

	"github.com/google/cel-go/cel"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/features"
)

// WithConditionalAuthorizationRequest returns a copy of parent in which the request supports propagating conditions from authorizers to
// later in the request chain when the conditions can be evaluated (e.g. in admission).
func WithConditionalAuthorizationRequest(parent context.Context, context ConditionalAuthorizationRequest) context.Context {
	return WithValue(parent, conditionalAuthorizationRequestKey, context)
}

// ConditionalAuthorizationRequestFrom returns the conditional authorization context associated with the ctx
func ConditionalAuthorizationRequestFrom(ctx context.Context) (ConditionalAuthorizationRequest, bool) {
	context, ok := ctx.Value(conditionalAuthorizationRequestKey).(ConditionalAuthorizationRequest)
	return context, ok
}

type ConditionalAuthorizationRequest interface {
	AuthorizationChains() []AuthorizationChain

	// registerAuthorizationChain is called by the ConditionalAuthorizationRegistrar to register a new authorization chain.
	registerAuthorizationChain(chain AuthorizationChain)
}

type AuthorizationChain interface {
	AttributesOrigin() AttributesOrigin
	AuthorizerConditions() []AuthorizerCondition
}

type AuthorizerCondition interface {
	AuthorizerName() string
	FailurePolicy() FailurePolicy
	Conditions() []Condition
}

type Condition interface {
	Effect() ConditionEffect
	// TODO: Parse the program already earlier, so we can know if there are syntactical errors up front,
	// which could lead to an error, or short-circuit earlier.
	Condition() string
	ID() string
}

// WithConditionalAuthorizationRegistrar returns a copy of parent in which the request supports propagating conditions from authorizers to
// later in the request chain when the conditions can be evaluated (e.g. in admission).
func WithConditionalAuthorizationRegistrar(parent context.Context, context ConditionalAuthorizationRequest) context.Context {
	return WithValue(parent, conditionalAuthorizationRequestKey, context)
}

// ConditionalAuthorizationRegistrarFrom returns the conditional authorization registrar for
func ConditionalAuthorizationRegistrarFrom(ctx context.Context) (ConditionalAuthorizationRequest, bool) {
	context, ok := ctx.Value(conditionalAuthorizationRequestKey).(ConditionalAuthorizationRequest)
	return context, ok
}

// ConditionalAuthorizationServerSupportedAnnotation is the annotation that the server sets during a SubjectAccessReview webhook
// to indicate that it supports conditional authorization SAR responses.
const ConditionalAuthorizationServerSupportedAnnotation = "kubernetes.io/" + string(features.SubjectAccessReviewConditions) + "ServerSupported"

// ConditionalAuthorizationConditionsAnnotation is the annotation that the client sets during a SubjectAccessReview webhook
// to indicate (to a supporting server) what conditions must be enforced during admission.
// The annotation value is a JSON-encoded array of SubjectAccessReviewCondition objects.
const ConditionalAuthorizationConditionsAnnotation = "kubernetes.io/" + string(features.SubjectAccessReviewConditions)

/*func (e *ConditionalAuthorizationContext) ApplyToAnnotations(obj metav1.Object) error {
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
}*/

type CompiledCondition struct {
	SubjectAccessReviewCondition
	Program            cel.Program
	ExpressionAccessor ExpressionAccessor
}

type ExpressionAccessor interface {
	GetExpression() string
	ReturnTypes() []*cel.Type
}

func NewConditionalAuthorizationRegistrar(origin AttributesOrigin, target ConditionalAuthorizationRequest) ConditionalAuthorizationRegistrar {
	c := &chain{origin: origin}
	target.registerAuthorizationChain(c)
	return &registrar{
		chain: c,
	}
}

type ConditionalAuthorizationRegistrar interface {
	// Register registers a set of conditions for a specific resource request.
	// This function should ONLY be called by the authorizer if it could not determine an unconditional answer (Allowed or Denied).
	// The conditions are validated and converted to a set of validatedConditions.
	// The failurePolicy indicates what to do if the condition fails to evaluate.
	// Register can only be called once.
	// A chain of conditions is built like follows:
	// If len(AllowConditions) == 0, len(DenyRequestConditions) == 0, and len(DenyNoOpinionConditions) == 0, then the Authorize() response is NoOpinion.
	// If len(AllowConditions) > 0, len(DenyRequestConditions) == 0, and len(DenyNoOpinionConditions) == 0, then the Authorize() response is NoOpinion.
	Register(conditions []SubjectAccessReviewCondition, authorizerName string, failurePolicy FailurePolicy) error

	dontImplementOutsideThisPackage()
}

type chain struct {
	origin      AttributesOrigin
	authorizers []AuthorizerCondition
}

func (c *chain) AttributesOrigin() AttributesOrigin {
	return c.origin
}

func (c *chain) AuthorizerConditions() []AuthorizerCondition {
	return c.authorizers
}

type registrar struct {
	chain            *chain
	canBecomeAllowed bool
}

var validEffects = sets.New(
	ConditionEffectAllow,
	ConditionEffectDenyNoOpinion,
	ConditionEffectDenyRequest,
)

func (p *registrar) CanBecomeAllowed() bool {
	return p.canBecomeAllowed
}

func (p *registrar) Register(conditions []SubjectAccessReviewCondition, authorizerName string, failurePolicy FailurePolicy) error {
	validatedConditions := make([]Condition, len(conditions))
	for i, condition := range conditions {
		if !validEffects.Has(condition.Effect) {
			return fmt.Errorf("invalid effect: %q, supported: %v", condition.Effect, validEffects)
		}
		// TODO: Parse the condition using the environment already up front?
		// If failurePolicy is FailurePolicyFail, and either all Allow conditions failed to parse, or any Deny condition failed to parse,
		// return an error.
		validatedConditions[i] = &validatedCondition{
			effect:    condition.Effect,
			id:        condition.ID,
			condition: condition.Condition,
		}
		if condition.Effect == ConditionEffectAllow {
			p.canBecomeAllowed = true
		}
	}

	p.chain.authorizers = append(p.chain.authorizers, &authorizerConditions{
		name:          authorizerName,
		failurePolicy: failurePolicy,
		conditions:    validatedConditions,
	})
	return nil
}

func (p *registrar) dontImplementOutsideThisPackage() {}

type AttributesOrigin struct {
	Group       string
	Version     string
	Resource    string
	Subresource string
	Verb        string
}

// TODO: Only allow conditions for specific resource requests.
// TODO: Respect only such condition sets where there is at least one Allow condition (and by extension, at least one condition overall).

// Conditions is an array of authorization conditions. All conditions must evaluate to true for the request to be authorized.
// The conditions are evaluated in order, and in case of a false response or error, the process is short-circuited, and the request is denied.
// This field is alpha-level, and ignored if the SubjectAccessReview handler has not enabled the SubjectAccessReviewConditions feature gate,
// in which the response is treated as NoOpinion.
//type Conditions []SubjectAccessReviewCondition

type authorizerConditions struct {
	conditions    []Condition
	failurePolicy FailurePolicy
	name          string
}

func (a *authorizerConditions) AuthorizerName() string {
	return a.name
}
func (a *authorizerConditions) FailurePolicy() FailurePolicy {
	return a.failurePolicy
}
func (a *authorizerConditions) Conditions() []Condition {
	return a.conditions
}

type FailurePolicy string

const (
	// FailurePolicyIgnore indicates that the authorizer will ignore the failure of the condition,
	// and continue evaluating the next condition.
	FailurePolicyIgnore FailurePolicy = "Ignore"

	// FailurePolicyFail indicates that the authorizer will fail the condition,
	// and the request will be denied.
	FailurePolicyFail FailurePolicy = "Fail"
)

type validatedCondition struct {
	effect    ConditionEffect
	condition string
	id        string
}

func (c *validatedCondition) Effect() ConditionEffect {
	return c.effect
}
func (c *validatedCondition) Condition() string {
	return c.condition
}
func (c *validatedCondition) ID() string {
	return c.id
}

// SubjectAccessReviewCondition is a encodable/decodable structure for passing condition data between a webhook authorizer and Kubernetes
type SubjectAccessReviewCondition struct {
	// Effect is the effect of the condition.
	Effect ConditionEffect `json:"effect"`

	// Condition is a CEL expression that evaluates a ValidatingAdmissionPolicy-like environment into a boolean value.
	// If the condition evaluates to true, the request is authorized.
	Condition string `json:"condition"`

	// ID is an optional ID of the condition, used for error and reason messages.
	ID string `json:"id"`
}

// ConditionEffect is an enum that indicates the effect of a condition evaluating to true.
type ConditionEffect string

const (
	// ConditionEffectAllow indicates that when the condition evaluates to true, the request is will be allowed,
	// unless there is any deny condition that evaluates to true.
	ConditionEffectAllow ConditionEffect = "Allow"

	// ConditionEffectDenyNoOpinion indicates that when the condition evaluates to true,
	// the response for the authorizer will be NoOpinion; and the conditions of the next authorizer in the chain will
	// be evaluated. If there are no more authorizers in the chain, the request will be denied.
	ConditionEffectDenyNoOpinion ConditionEffect = "DenyNoOpinion"

	// ConditionEffectDenyRequest indicates that when the condition evaluates to true, the request is will be denied,
	// unless there is any allow condition that evaluates to true.
	ConditionEffectDenyRequest ConditionEffect = "DenyRequest"
)
