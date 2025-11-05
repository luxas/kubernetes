package authorizer

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/user"
	genericfeatures "k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/utils/ptr"
)

/*
  TODO:
  - Implement conditional authz for the patch -> create/update authorization flow.
  - Add the field to the AuthorizationConfiguration to determine which context to use for the conditions review webhook.
  - Better error handling
  - More efficient CEL implementation
  - Should the webhook SAR cache its responses?
  - Would it make sense to use a bidirectional gRPC stream to authorizers instead, in order to reduce the cost of these checks?
  - Should we try to make it possible for a webhook authorizer to return multiple condition sets?
    - If so, should the resolution still be chunked per physical or logical authorizer?'
  - Built webhook authorizer from a normal client-go client instead of a kubeconfig.
  - Scope down the ConditionAttributes interface to only the fields that are needed.
    - If too much information is given, it increases the temptation to not do partial evaluation,
	  but to just put the whole policy in the condition, which is wrong.
	- Needed are:
	  - Operation (e.g. in case of authorizationVerb=patch, we don't know what the operation will be)
	  - New + old object
	  - Operation options
	  - Namespace??
  - Build the NodeRestriction plugin using the conditional authorization framework, where all conditions resolution is still done in code.
  - Enable automatically the admission plugin if the feature is enabled.
*/

// Attributes is an interface used by AdmissionController to get information about a request
// that is used to make an admission decision.
// TODO: Decide on naming, e.g. ConditionData? RequestData? ConditionRequestData? ConditionAttributes? ResidualData?
type ConditionAttributes interface {
	// GetName returns the name of the object as presented in the request.  On a CREATE operation, the client
	// may omit name and rely on the server to generate the name.  If that is the case, this method will return
	// the empty string
	GetName() string
	// GetNamespace is the namespace associated with the request (if any)
	GetNamespace() string
	// GetResource is the name of the resource being requested.  This is not the kind.  For example: pods
	GetResource() schema.GroupVersionResource
	// GetSubresource is the name of the subresource being requested.  This is a different resource, scoped to the parent resource, but it may have a different kind.
	// For instance, /pods has the resource "pods" and the kind "Pod", while /pods/foo/status has the resource "pods", the sub resource "status", and the kind "Pod"
	// (because status operates on pods). The binding resource for a pod though may be /pods/foo/binding, which has resource "pods", subresource "binding", and kind "Binding".
	GetSubresource() string
	// GetOperation is the operation being performed
	GetOperation() string
	// GetOperationOptions is the options for the operation being performed
	GetOperationOptions() runtime.Object
	// IsDryRun indicates that modifications will definitely not be persisted for this request. This is to prevent
	// admission controllers with side effects and a method of reconciliation from being overwhelmed.
	// However, a value of false for this does not mean that the modification will be persisted, because it
	// could still be rejected by a subsequent validation step.
	IsDryRun() bool
	// GetObject is the object from the incoming request prior to default values being applied.
	// Only populated for CREATE and UPDATE requests.
	GetObject() runtime.Object
	// GetOldObject is the existing object. Only populated for UPDATE and DELETE requests.
	GetOldObject() runtime.Object
	// GetKind is the type of object being manipulated.  For example: Pod
	GetKind() schema.GroupVersionKind
	// GetUserInfo is information about the requesting user
	GetUserInfo() user.Info

	// GetAuthorizationVerb returns the authorization verb of the request (e.g. "create", "update", "delete", "patch").
	GetAuthorizationVerb() string
}

func toAuthorizationAttributes(admissionAttrs ConditionAttributes) Attributes {
	return AttributesRecord{
		User: admissionAttrs.GetUserInfo(),

		APIGroup:    admissionAttrs.GetResource().Group,
		APIVersion:  admissionAttrs.GetResource().Version,
		Resource:    admissionAttrs.GetResource().Resource,
		Subresource: admissionAttrs.GetSubresource(),

		Verb:            admissionAttrs.GetAuthorizationVerb(),
		Namespace:       admissionAttrs.GetNamespace(),
		Name:            admissionAttrs.GetName(),
		ResourceRequest: true,
		// TODO: add path? field and label selectors?
	}
}

type Condition struct {
	ID          string
	Type        ConditionType
	Effect      ConditionEffect
	Condition   string
	Description string
}

// ConditionType is the type of condition. Types starting with "k8s.io/" are reserved for Kubernetes core conditions.
type ConditionType string

func (c ConditionType) IsBuiltin() bool {
	return strings.HasPrefix(string(c), "k8s.io/")
}

// ConditionEffect controls what a condition evaluating to true should be interpreted as.
type ConditionEffect string

const (
	ConditionEffectAllow         ConditionEffect = "Allow"
	ConditionEffectDenyRequest   ConditionEffect = "DenyRequest"
	ConditionEffectDenyNoOpinion ConditionEffect = "DenyNoOpinion"
)

// TODO: Rename to ConditionSetEvaluator
type ConditionsResolver interface {
	// ResolveConditions resolve a set of conditions into a concrete decision (Allow, Deny, NoOpinion),
	// given full information about the request (ConditionAttributes, which includes e.g. the old and new objects).
	ResolveConditions(ctx context.Context, admissionAttrs ConditionAttributes, conditionSet *ConditionSet) (Decision, string, error)
}

type BuiltinConditionsResolver interface {
	ConditionsResolver
	SupportedConditionTypes() sets.Set[ConditionType]
}

type ConditionalAuthorizer interface {
	Authorizer
	ConditionsResolver
	// FailureMode determines how to treat an error from ResolveConditions
	FailureMode() FailureMode
}

// FailureMode determines how to treat an error from ResolveConditions.
// TODO: Don't have this externally, just use DecisionOnError() authorizer.Decision instead?
type FailureMode string

const (
	// FailureModeNoOpinion means that an erroring conditional response should be treated as the authorizer initially returned NoOpinion.
	// This is the default mode.
	FailureModeNoOpinion FailureMode = "NoOpinion"
	// FailureModeDeny means that an erroring conditional response should be treated as the authorizer initially returned Deny.
	FailureModeDeny FailureMode = "Deny"
)

type ConditionsEnforcer interface {
	EnforceConditions(ctx context.Context, admissionAttrs ConditionAttributes) (Decision, string, error)

	OrderedConditionSets(ctx context.Context, authzAttrs Attributes) []*ConditionSet

	WithBuiltinConditionsResolvers(builtinConditionsResolvers ...BuiltinConditionsResolver) ConditionsEnforcer
}

type ConditionSet struct {
	conditions            []Condition
	unconditionalDecision *Decision
}

func NewConditionSet(conditions ...Condition) (*ConditionSet, error) {
	// TODO: Validate the conditions here.
	return &ConditionSet{conditions: conditions}, nil
}

func NewAlwaysAllowConditionSet() *ConditionSet {
	return &ConditionSet{unconditionalDecision: ptr.To(DecisionAllow)}
}

func NewAlwaysDenyConditionSet() *ConditionSet {
	return &ConditionSet{unconditionalDecision: ptr.To(DecisionDeny)}
}

func (c *ConditionSet) UnconditionallyAllowed() bool {
	return c.unconditionalDecision != nil && *c.unconditionalDecision == DecisionAllow
}
func (c *ConditionSet) UnconditionallyDenied() bool {
	return c.unconditionalDecision != nil && *c.unconditionalDecision == DecisionDeny
}

func (c *ConditionSet) CanBecomeAuthorized() bool {
	if c.UnconditionallyAllowed() {
		return true
	}
	if c.UnconditionallyDenied() {
		return false
	}
	for _, condition := range c.conditions {
		if condition.Effect == ConditionEffectAllow {
			return true
		}
	}
	return false
}

func (c *ConditionSet) IsEmpty() bool {
	return len(c.conditions) == 0
}

func (c *ConditionSet) GetConditions() []Condition {
	return c.conditions
}

// The key type is unexported to prevent collisions
type key int

const (
	// conditionsEnforcerKey is the context key for the conditions enforcer.
	conditionsEnforcerKey key = iota
)

var (
	conditionalAuthorizationVerbs = sets.New(
		"create",
		"patch",
		"update",
		"delete",
	)
)

// AuthorizeWithConditionalSupport authorizes the request just like authorizer.Authorize, but also supports returning
// conditions that might need to be enforced.
//
// If DecisionConditional is returned, the ConditionsEnforcer is guaranteed to be non-nil.
//
// Note: Authorizers must not call this function, this is meant as a top-level helper to be called e.g. by
// HTTP handlers or similar entrypoint functions.
func AuthorizeWithConditionalSupport(ctx context.Context, attrs Attributes, authorizer Authorizer) (Decision, string, ConditionsEnforcer, error) {
	// This method must not be called recursively (outside of this package).
	if _, ok := conditionsEnforcerFrom(ctx); ok {
		return DecisionNoOpinion, "", nil, ErrAuthorizeWithConditionalSupportCalledRecursively
	}

	// Populate the context with an empty conditions enforcer.
	// During the Authorize call, an authorizer that wishes to return conditions can
	// write into this pointer by calling NewConditionalDecision.
	// TODO: Feed the original attributes into the conditions enforcer, so that they can be used for serialization.
	enforcer := &conditionsEnforcer{}
	ctx = withConditionsEnforcer(ctx, enforcer)

	decision, reason, err := authorizer.Authorize(ctx, attrs)
	// Pass through all non-conditional responses as-is.
	if !decision.IsConditional() {
		return decision, reason, nil, err
	}
	// Only allow conditional authorization if the feature is enabled.
	// TODO: Should this automatically result in a Deny decision?
	if !utilfeature.DefaultFeatureGate.Enabled(genericfeatures.ConditionalAuthorization) {
		return DecisionNoOpinion, "", nil, ErrConditionalAuthorizationFeatureNotEnabled
	}
	// Only allow conditional authorization for create, patch, update, delete requests, and
	// whenever the GVR is fully-qualified. This avoids problematic situations that could arise
	// if the WithAuthorization filter allowed the request to proceed (because the decision was Conditional),
	// but admission never running for the request (e.g. for read requests).
	if !conditionalAuthorizationVerbs.Has(attrs.GetVerb()) {
		return DecisionNoOpinion, "", nil, fmt.Errorf("%w: verb=%s, supported verbs=%v", ErrConditionalAuthorizationNotSupported, attrs.GetVerb(), conditionalAuthorizationVerbs.UnsortedList())
	}
	if attrs.GetAPIGroup() == "*" || attrs.GetAPIVersion() == "" || attrs.GetAPIVersion() == "*" ||
		attrs.GetResource() == "" || attrs.GetResource() == "*" || attrs.GetSubresource() == "*" {
		return DecisionNoOpinion, "", nil, fmt.Errorf("%w: GVR is not fully-qualified", ErrConditionalAuthorizationNotSupported)
	}

	// TODO: If there are no Allow rules, we know it's either a Deny or NoOpinion decision.
	// In this case, we are not sure whether it makes sense to proceed with the request.
	// Technically, we _should_ check out the next authorizer as well, to make sure there is some chance of becoming authorized.
	// One could split the response into two: ConditionalAllow and ConditionalDeny.
	// TODO:

	// Conditional decision path. Check if any conditions actually were set through NewConditionalDecision.
	// If not, that is a programmer error (returning decision=Conditional* without calling NewConditionalDecision)
	if !enforcer.hasConditions() {
		return DecisionNoOpinion, "", nil, ErrConditionalResponseWithoutConditions
	}

	// There are two conditional types: ConditionalAllow and ConditionalDeny.
	if enforcer.canBecomeAuthorized() {
		return DecisionConditionalAllow, "conditionally authorized", enforcer, nil
	}

	return DecisionConditionalDeny, "", enforcer, nil
}

// withConditionsEnforcer returns a copy of parent in which the conditional authorization enabled value is set
func withConditionsEnforcer(parent context.Context, enforcer *conditionsEnforcer) context.Context {
	return context.WithValue(parent, conditionsEnforcerKey, enforcer)
}

// conditionsEnforcerFrom returns the value of the conditions enforcer key on the ctx
// If ok is true, the returned enforcer is guaranteed to be non-nil.
func conditionsEnforcerFrom(ctx context.Context) (*conditionsEnforcer, bool) {
	enforcer, ok := ctx.Value(conditionsEnforcerKey).(*conditionsEnforcer)
	if !ok || enforcer == nil {
		return nil, false
	}
	return enforcer, true
}

func RegisterAuthorizerChainAfterConditionalResponse(ctx context.Context, authorizerChain ...Authorizer) {
	enforcer, ok := conditionsEnforcerFrom(ctx)
	if !ok {
		return
	}
	enforcer.authorizerChain = append(enforcer.authorizerChain, authorizerChain...)
}

var (
	ErrAuthorizeWithConditionalSupportCalledRecursively = errors.New("AuthorizeWithConditionalSupport called recursively")
	ErrConditionalResponseWithoutConditions             = errors.New("conditional response without conditions; a conditional response must be built with NewConditionalDecision")
	ErrConditionalAuthorizationFeatureNotEnabled        = errors.New("conditional authorization feature is not enabled")
	ErrConditionalResponseAlreadyBuilt                  = errors.New("conditional response already built; a conditional response must be built exactly oncewith NewConditionalDecision")
	ErrConditionalAuthorizationNotSupported             = errors.New("conditional authorization is not supported for this request")
)

func NewConditionalDecision(ctx context.Context, self ConditionalAuthorizer, conditions *ConditionSet) (Decision, string, error) {
	enforcer, ok := conditionsEnforcerFrom(ctx)
	if !ok {
		// A conditional response is treated as NoOpinion when the feature is not enabled.
		// TODO: Just use utilruntime.HandleError here instead?
		// TODO: Is there a risk in that someone would use a conditional authorizer without calling AuthorizeWithConditionalSupport,
		// and then some part of the chain would the error take precedence over the NoOpinion semantics?
		return DecisionNoOpinion, "", ErrConditionalAuthorizationFeatureNotEnabled
	}

	// Conditional with no conditions is the same as NoOpinion (as no conditions are true).
	if conditions.IsEmpty() {
		return DecisionNoOpinion, "", nil
	}

	// TODO: Remember to encode the conditions in the SAR response of the API server self-check endpoints.

	enforcer.precomputedConditionSets = append(enforcer.precomputedConditionSets, precomputedConditionSet{
		conditions: conditions,
		self:       self,
	})

	if conditions.CanBecomeAuthorized() {
		return DecisionConditionalAllow, "conditionally authorized", nil
	}
	return DecisionConditionalDeny, "", nil
}

func UnconditionalAllowAfterConditionalDeny(ctx context.Context) (Decision, string, error) {
	enforcer, ok := conditionsEnforcerFrom(ctx)
	if !ok {
		return DecisionNoOpinion, "", ErrConditionalAuthorizationFeatureNotEnabled
	}

	enforcer.precomputedConditionSets = append(enforcer.precomputedConditionSets, precomputedConditionSet{
		conditions: NewAlwaysAllowConditionSet(),
		self:       nil,
	})

	return DecisionConditionalAllow, "conditionally authorized", nil
}

type precomputedConditionSet struct {
	conditions *ConditionSet
	self       ConditionalAuthorizer
}

type conditionsEnforcer struct {
	precomputedConditionSets   []precomputedConditionSet
	builtinConditionsResolvers []BuiltinConditionsResolver
	authorizerChain            []Authorizer
}

func (e *conditionsEnforcer) canBecomeAuthorized() bool {
	for _, precomputedConditionSet := range e.precomputedConditionSets {
		if precomputedConditionSet.conditions.CanBecomeAuthorized() {
			return true
		}
	}
	return false
}

func (e *conditionsEnforcer) hasConditions() bool {
	return len(e.precomputedConditionSets) != 0
}

func (e *conditionsEnforcer) EnforceConditions(ctx context.Context, admissionAttrs ConditionAttributes) (Decision, string, error) {
	var (
		errlist    []error
		reasonlist []string
	)

	for _, precomputedConditionSet := range e.precomputedConditionSets {
		// This only happens if the authorization chain got responses like ConditionalDeny,ConditionalDeny,Allow.
		// UnconditionallyAllowed is true for the last item in precomputedConditionSets in that example. If he code
		// reaches this point, it means that the previous ConditionalDeny responses were evaluated to NoOpinion,
		// and thus is it safe to return Allow here.
		if precomputedConditionSet.conditions.UnconditionallyAllowed() {
			return DecisionAllow, "", nil
		}

		// First, try to enforce the conditions of the self authorizer.
		decision, reason, err := e.enforceConditions(ctx, precomputedConditionSet.self, admissionAttrs, precomputedConditionSet.conditions)
		// If we got a concrete decision, use it.
		if decision == DecisionAllow || decision == DecisionDeny {
			return decision, reason, err
		}

		if err != nil {
			errlist = append(errlist, err)
		}
		if len(reason) != 0 {
			reasonlist = append(reasonlist, reason)
		}

		// If we got a NoOpinion, continue to the next authorizer.
	}

	authzAttrs := toAuthorizationAttributes(admissionAttrs)

	for _, authorizer := range e.authorizerChain {

		decision, reason, conditionsEnforcer, err := AuthorizeWithConditionalSupport(ctx, authzAttrs, authorizer)
		if decision == DecisionAllow || decision == DecisionDeny {
			return decision, reason, err
		}

		if err != nil {
			errlist = append(errlist, err)
		}
		if len(reason) != 0 {
			reasonlist = append(reasonlist, reason)
		}

		if decision.IsConditional() { // TODO: Force err == nil here?
			decision, reason, err = conditionsEnforcer.
				WithBuiltinConditionsResolvers(e.builtinConditionsResolvers...).
				EnforceConditions(ctx, admissionAttrs)
			if decision == DecisionAllow || decision == DecisionDeny {
				return decision, reason, err
			}
			// Otherwise, treat like NoOpinion.
			// TODO: Should we error here if decision.IsConditional() == true
			// TODO: And/or respect the FailureMode of the authorizer?
			if err != nil {
				errlist = append(errlist, err)
			}
			if len(reason) != 0 {
				reasonlist = append(reasonlist, reason)
			}
		}
	}
	// If we reached the end of the chain, that means we got a NoOpinion decision from all authorizers.
	return DecisionNoOpinion, strings.Join(reasonlist, "\n"), utilerrors.NewAggregate(errlist)
}

// enforceConditions enforces the conditions of the given authorizer, using the builtin conditions resolvers if available.
// The function guarantees that the decision is a concrete one (Allow, Deny, NoOpinion).
func (e *conditionsEnforcer) enforceConditions(ctx context.Context, authorizer ConditionalAuthorizer, admissionAttrs ConditionAttributes, conditionSet *ConditionSet) (Decision, string, error) {
	resolveConditions := authorizer.ResolveConditions

	for _, builtinConditionsResolver := range e.builtinConditionsResolvers {
		resolvableWithBuiltin := true
		for _, condition := range conditionSet.GetConditions() {
			if !builtinConditionsResolver.SupportedConditionTypes().Has(condition.Type) {
				resolvableWithBuiltin = false
				break
			}
		}
		// If all conditions are resolvable with a builtin conditions resolver, use it, as that
		// is the most efficient way to enforce conditions.
		// authorizer would likely have to webhook to enforce the conditions.
		if resolvableWithBuiltin {
			resolveConditions = builtinConditionsResolver.ResolveConditions
			break
		}
	}

	decision, reason, err := resolveConditions(ctx, admissionAttrs, conditionSet)
	if decision == DecisionAllow || decision == DecisionDeny {
		return decision, reason, err
	}
	// The decision must be a concrete one (Allow, Deny, NoOpinion); a conditional response is not valid here.
	if decision != DecisionNoOpinion {
		err = utilerrors.NewAggregate([]error{err, fmt.Errorf("invalid decision returned by ResolveConditions: %d", decision)})
		decision = DecisionNoOpinion
	}
	if err != nil {
		err = fmt.Errorf("error enforcing conditions: %w", err)
		if authorizer.FailureMode() == FailureModeDeny {
			return DecisionDeny, reason, err
		}
		return DecisionNoOpinion, reason, err
	}
	return decision, reason, nil
}

func (e *conditionsEnforcer) WithBuiltinConditionsResolvers(builtinConditionsResolvers ...BuiltinConditionsResolver) ConditionsEnforcer {
	e.builtinConditionsResolvers = append(e.builtinConditionsResolvers, builtinConditionsResolvers...)
	return e
}

func (e *conditionsEnforcer) OrderedConditionSets(ctx context.Context, authzAttrs Attributes) []*ConditionSet {
	conditionSets := make([]*ConditionSet, 0, len(e.precomputedConditionSets))
	for _, precomputedConditionSet := range e.precomputedConditionSets {
		conditionSets = append(conditionSets, precomputedConditionSet.conditions)
	}

	for _, authorizer := range e.authorizerChain {
		// TODO: Figure out error handling here.
		decision, _, conditionsEnforcer, _ := AuthorizeWithConditionalSupport(ctx, authzAttrs, authorizer)
		if decision == DecisionAllow {
			conditionSets = append(conditionSets, NewAlwaysAllowConditionSet())
			break
		}
		if decision == DecisionDeny {
			conditionSets = append(conditionSets, NewAlwaysDenyConditionSet())
			break
		}

		if decision.IsConditional() {
			conditionSets = append(conditionSets, conditionsEnforcer.OrderedConditionSets(ctx, authzAttrs)...)
		}
	}
	return conditionSets
}
