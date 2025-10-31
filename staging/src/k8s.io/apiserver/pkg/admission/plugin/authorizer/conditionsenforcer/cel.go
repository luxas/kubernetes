package conditionsenforcer

import (
	"context"
	"fmt"
	"math"
	"reflect"
	"time"

	celtypes "github.com/google/cel-go/common/types"
	"github.com/google/cel-go/interpreter"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/admission"
	plugincel "k8s.io/apiserver/pkg/admission/plugin/cel"
	apiscel "k8s.io/apiserver/pkg/apis/cel"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/cel"
)

const (
	ConditionTypeAuthorizationCEL authorizer.ConditionType = "k8s.io/authorization-cel"
)

var _ authorizer.BuiltinConditionsResolver = &celConditionsEnforcer{}

type celConditionsEnforcer struct {
	conditionCompiler *ConditionCompiler
}

func (e *celConditionsEnforcer) SupportedConditionTypes() sets.Set[authorizer.ConditionType] {
	return sets.New(ConditionTypeAuthorizationCEL)
}

func (e *celConditionsEnforcer) ResolveConditions(ctx context.Context, a authorizer.ConditionAttributes, conditionSet *authorizer.ConditionSet) (authorizer.Decision, string, error) {
	unionedAttrs := a.(*unionedAttributes)
	admissionAttrs := unionedAttrs.VersionedAttributes

	compiledConditions, err := e.conditionCompiler.Compile(admissionAttrs.GetKind(), conditionSet)
	if err != nil {
		return authorizer.DecisionNoOpinion, "", err
	}

	admissionRequest := plugincel.CreateAdmissionRequest(admissionAttrs, metav1.GroupVersionResource(admissionAttrs.GetResource()), metav1.GroupVersionKind(admissionAttrs.GetKind()))

	results, _, err := forInput(ctx, admissionAttrs, admissionRequest, compiledConditions)
	if err != nil {
		return authorizer.DecisionNoOpinion, "", err
	}

	var errlist []error

	allowed := false
	// TODO: Could optimize this by evaluating all deny policies first.
	// TODO: Does it make sense to separate evaluation from authorization wrt authorizing the decisions?
	for i, result := range results {
		condition := &conditionSet.GetConditions()[i]
		if result.Error != nil {
			// If the policy is a deny policy, we return an error immediately, as it's not safe to ignore deny policies
			// we do not know the value of.
			if condition.Effect == authorizer.ConditionEffectDenyRequest || condition.Effect == authorizer.ConditionEffectDenyNoOpinion {

				// TODO: Add information about what source policy failed
				return authorizer.DecisionNoOpinion, "", fmt.Errorf("conditional authorization policy %q produced an evaluation error: %v", condition.ID, result.Error)
			}
			// In case of an allow policy, we can still aggregate the error in case no allow policy matches.
			// If no allow policy matches, and at least one allow policy produced an error, the FailureMode of the authorizer
			// determines whether to continue (NoOpinion) or fail the request (Deny).
			// However, if any allow policy matches, erroring allow policies are ignored.
			// TODO: We could add some logging here if we wanted though.
			errlist = append(errlist, result.Error)
		}
		if condition.Effect == authorizer.ConditionEffectDenyRequest && result.EvalResult == celtypes.True {
			reason := fmt.Sprintf("conditional authorization policy %q denied the request", condition.ID)
			return authorizer.DecisionDeny, reason, nil
		}

		if condition.Effect == authorizer.ConditionEffectDenyNoOpinion && result.EvalResult == celtypes.True {
			reason := fmt.Sprintf("conditional authorization policy %q made the conditionset evaluate to NoOpinion", condition.ID)
			return authorizer.DecisionNoOpinion, reason, nil
		}

		if condition.Effect == authorizer.ConditionEffectAllow && result.EvalResult == celtypes.True {
			allowed = true
			// flag that we found an allowing policy, but loop through all conditions, as there might be a denying policy,
			// which has higher precedence to deny the request
		}
	}
	if allowed {
		return authorizer.DecisionAllow, "", nil
	}

	return authorizer.DecisionNoOpinion, "no conditional authorization policy allowed the request", nil
}

func forInput(ctx context.Context, versionedAttr *admission.VersionedAttributes, request *admissionv1.AdmissionRequest, compilationResults []*plugincel.CompilationResult) ([]plugincel.EvaluationResult, int64, error) {
	// TODO: replace unstructured with ref.Val for CEL variables when native type support is available
	evaluations := make([]plugincel.EvaluationResult, len(compilationResults))
	var err error

	activation, err := newActivation(versionedAttr, request)
	if err != nil {
		return nil, -1, err
	}

	remainingBudget := int64(apiscel.RuntimeCELCostBudget)
	for i, compilationResult := range compilationResults {
		evaluations[i], remainingBudget, err = activation.Evaluate(ctx, compilationResult, remainingBudget)
		if err != nil {
			return nil, -1, err
		}
	}

	return evaluations, remainingBudget, nil
}

// newActivation creates an activation for CEL admission plugins from the given request, admission chain and
// variable binding information.
func newActivation(versionedAttr *admission.VersionedAttributes, request *admissionv1.AdmissionRequest) (*evaluationActivation, error) {
	oldObjectVal, err := objectToResolveVal(versionedAttr.VersionedOldObject)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare oldObject variable for evaluation: %w", err)
	}
	objectVal, err := objectToResolveVal(versionedAttr.VersionedObject)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare object variable for evaluation: %w", err)
	}
	requestVal, err := convertObjectToUnstructured(request)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare request variable for evaluation: %w", err)
	}
	va := &evaluationActivation{
		object:    objectVal,
		oldObject: oldObjectVal,
		request:   requestVal.Object,
	}
	return va, nil
}

type evaluationActivation struct {
	object, oldObject, params, request, namespace, authorizer, requestResourceAuthorizer, variables interface{}
}

// ResolveName returns a value from the activation by qualified name, or false if the name
// could not be found.
func (a *evaluationActivation) ResolveName(name string) (interface{}, bool) {
	switch name {
	case plugincel.ObjectVarName:
		return a.object, true
	case plugincel.OldObjectVarName:
		return a.oldObject, true
	case plugincel.RequestVarName:
		return a.request, true
	default:
		return nil, false
	}
}

// Parent returns the parent of the current activation, may be nil.
// If non-nil, the parent will be searched during resolve calls.
func (a *evaluationActivation) Parent() interpreter.Activation {
	return nil
}

// Evaluate runs a compiled CEL admission plugin expression using the provided activation and CEL
// runtime cost budget.
func (a *evaluationActivation) Evaluate(ctx context.Context, compilationResult *plugincel.CompilationResult, remainingBudget int64) (plugincel.EvaluationResult, int64, error) {
	var evaluation = plugincel.EvaluationResult{}
	if compilationResult.ExpressionAccessor == nil { // in case of placeholder
		return evaluation, remainingBudget, nil
	}

	evaluation.ExpressionAccessor = compilationResult.ExpressionAccessor
	if compilationResult.Program == nil {
		evaluation.Error = &cel.Error{
			Type:   cel.ErrorTypeInternal,
			Detail: "unexpected internal error compiling expression",
		}
		return evaluation, remainingBudget, nil
	}
	t1 := time.Now()
	evalResult, evalDetails, err := compilationResult.Program.ContextEval(ctx, a)
	elapsed := time.Since(t1)
	evaluation.Elapsed = elapsed
	if evalDetails == nil {
		return evaluation, -1, &cel.Error{
			Type:   cel.ErrorTypeInternal,
			Detail: fmt.Sprintf("runtime cost could not be calculated for expression: %v, no further expression will be run", compilationResult.ExpressionAccessor.GetExpression()),
		}
	} else {
		rtCost := evalDetails.ActualCost()
		if rtCost == nil {
			return evaluation, -1, &cel.Error{
				Type:   cel.ErrorTypeInvalid,
				Detail: fmt.Sprintf("runtime cost could not be calculated for expression: %v, no further expression will be run", compilationResult.ExpressionAccessor.GetExpression()),
				Cause:  cel.ErrOutOfBudget,
			}
		} else {
			if *rtCost > math.MaxInt64 || int64(*rtCost) > remainingBudget {
				return evaluation, -1, &cel.Error{
					Type:   cel.ErrorTypeInvalid,
					Detail: "validation failed due to running out of cost budget, no further validation rules will be run",
					Cause:  cel.ErrOutOfBudget,
				}
			}
			remainingBudget -= int64(*rtCost)
		}
	}
	if err != nil {
		evaluation.Error = &cel.Error{
			Type:   cel.ErrorTypeInvalid,
			Detail: fmt.Sprintf("expression '%v' resulted in error: %v", compilationResult.ExpressionAccessor.GetExpression(), err),
		}
	} else {
		evaluation.EvalResult = evalResult
	}
	return evaluation, remainingBudget, nil
}

func convertObjectToUnstructured(obj interface{}) (*unstructured.Unstructured, error) {
	if obj == nil || reflect.ValueOf(obj).IsNil() {
		return &unstructured.Unstructured{Object: nil}, nil
	}
	ret, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return nil, err
	}
	return &unstructured.Unstructured{Object: ret}, nil
}

func objectToResolveVal(r runtime.Object) (interface{}, error) {
	if r == nil || reflect.ValueOf(r).IsNil() {
		return nil, nil
	}
	v, err := convertObjectToUnstructured(r)
	if err != nil {
		return nil, err
	}
	return v.Object, nil
}
