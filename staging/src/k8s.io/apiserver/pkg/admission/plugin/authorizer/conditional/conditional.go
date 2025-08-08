package conditional

import (
	"context"
	"fmt"
	"io"
	"math"
	"reflect"
	"time"

	celtypes "github.com/google/cel-go/common/types"
	"github.com/google/cel-go/interpreter"
	admissionv1 "k8s.io/api/admission/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/admission"
	plugincel "k8s.io/apiserver/pkg/admission/plugin/cel"
	apiscel "k8s.io/apiserver/pkg/apis/cel"
	"k8s.io/apiserver/pkg/cel"
	"k8s.io/apiserver/pkg/endpoints/request"
	genericfeatures "k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
)

const (
	// PluginName indicates the name of admission plug-in
	PluginName = "ConditionalAuthorizationEnforcer"
)

// Register registers a plugin
func Register(plugins *admission.Plugins) {
	plugins.Register(PluginName, func(config io.Reader) (admission.Interface, error) {
		return NewConditionalAuthorizationEnforcer(), nil
	})
}

var _ admission.Interface = &ConditionalAuthorizationEnforcer{}
var _ admission.ValidationInterface = &ConditionalAuthorizationEnforcer{}

func NewConditionalAuthorizationEnforcer() *ConditionalAuthorizationEnforcer {
	return &ConditionalAuthorizationEnforcer{}
}

type ConditionalAuthorizationEnforcer struct{}

func (c *ConditionalAuthorizationEnforcer) Handles(operation admission.Operation) bool {
	return utilfeature.DefaultFeatureGate.Enabled(genericfeatures.SubjectAccessReviewConditions)
}

func (c *ConditionalAuthorizationEnforcer) Validate(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) error {
	authorizationConditions, ok := request.ConditionalAuthorizationContextFrom(ctx)
	if !ok {
		return nil
	}

	versionedAttributes, err := admission.NewVersionedAttributes(a, a.GetKind(), o)
	if err != nil {
		return fmt.Errorf("failed to convert object version: %w", err)
	}

	admissionRequest := plugincel.CreateAdmissionRequest(a, metav1.GroupVersionResource(a.GetResource()), metav1.GroupVersionKind(a.GetKind()))

	results, _, err := forInput(ctx, versionedAttributes, admissionRequest, authorizationConditions.Conditions)
	if err != nil {
		return err
	}

	for i, result := range results {
		if result.Error != nil {
			// TODO: Add information about what source policy failed
			resultErr := fmt.Errorf("conditional authorization policy %d produced an evaluation error", i)
			err := admission.NewForbidden(a, resultErr).(*k8serrors.StatusError)
			err.ErrStatus.Details.Causes = append(err.ErrStatus.Details.Causes, metav1.StatusCause{
				Type:    metav1.CauseTypeFieldValueInvalid,
				Message: result.Error.Error(),
			})
			return err
		}

		if result.EvalResult != celtypes.True {
			resultErr := fmt.Errorf("conditional authorization policy %d denied the request", i)
			return admission.NewForbidden(a, resultErr)
		}
	}

	return nil
}

func forInput(ctx context.Context, versionedAttr *admission.VersionedAttributes, request *admissionv1.AdmissionRequest, compilationResults []request.CompilationResult) ([]plugincel.EvaluationResult, int64, error) {
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
func (a *evaluationActivation) Evaluate(ctx context.Context, compilationResult request.CompilationResult, remainingBudget int64) (plugincel.EvaluationResult, int64, error) {
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
