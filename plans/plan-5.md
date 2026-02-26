 Plan: Add conditionalDecisionChain to SubjectAccessReviewStatus                                                                                                                                                                          

 Context

 KEP-5681 (Conditional Authorization) extends the authorizer.Decision type with a recursive structure (ConditionalDecisionChain []Decision). The SAR API needs a serializable representation of this recursive decision tree so
 clients (e.g. kubectl auth can-i) can discover what conditions they are subject to. The internal authorizer.Decision struct uses unexported fields and cannot be directly serialized, so dedicated API types are needed.

 Naming

 The KEP specifies conditionalDecisionChain and SubjectAccessReviewAuthorizationDecision for the API field/type names. The user mentioned "conditionalDecisionChain" but the KEP naming is canonical for API types. The structural mapping is:

 ┌─────────────────────────────────────────┬───────────────────────────────────────┐
 │        authorizer.Decision state        │ SubjectAccessReviewAuthorizationDecision field │
 ├─────────────────────────────────────────┼───────────────────────────────────────┤
 │ Allow                                   │ Allowed: true                         │
 ├─────────────────────────────────────────┼───────────────────────────────────────┤
 │ Deny                                    │ Denied: true                          │
 ├─────────────────────────────────────────┼───────────────────────────────────────┤
 │ NoOpinion                               │ Omitted from chain (elided)           │
 ├─────────────────────────────────────────┼───────────────────────────────────────┤
 │ Conditional (conditionSet != nil)       │ ConditionsType + Conditions[]         │
 ├─────────────────────────────────────────┼───────────────────────────────────────┤
 │ ConditionalChain (decisionChain != nil) │ ConditionalDecisionChain[] (recursive)       │
 └─────────────────────────────────────────┴───────────────────────────────────────┘

 Changes

 1. staging/src/k8s.io/api/authorization/v1/types.go — Add new types + field

 Add after ConditionalAuthorizationOptions (line ~216):

 type SubjectAccessReviewConditionEffect string
 const (
     SubjectAccessReviewConditionEffectAllow     SubjectAccessReviewConditionEffect = "Allow"
     SubjectAccessReviewConditionEffectDeny      SubjectAccessReviewConditionEffect = "Deny"
     SubjectAccessReviewConditionEffectNoOpinion SubjectAccessReviewConditionEffect = "NoOpinion"
 )

 type SubjectAccessReviewCondition struct {
     ID          string                              `json:"id" protobuf:"bytes,1,opt,name=id"`
     Effect      SubjectAccessReviewConditionEffect  `json:"effect" protobuf:"bytes,2,opt,name=effect"`
     Condition   string                              `json:"condition" protobuf:"bytes,3,opt,name=condition"`
     Description string                              `json:"description,omitempty" protobuf:"bytes,4,opt,name=description"`
 }

 type SubjectAccessReviewAuthorizationDecision struct {
     Allowed           bool                                `json:"allowed,omitempty" protobuf:"varint,1,opt,name=allowed"`
     Denied            bool                                `json:"denied,omitempty" protobuf:"varint,2,opt,name=denied"`
     FailureMode       string                              `json:"failureMode,omitempty" protobuf:"bytes,3,opt,name=failureMode"`
     AuthorizerName    string                              `json:"authorizerName,omitempty" protobuf:"bytes,4,opt,name=authorizerName"`
     ConditionsType    string                              `json:"conditionsType,omitempty" protobuf:"bytes,5,opt,name=conditionsType"`
     Conditions        []SubjectAccessReviewCondition      `json:"conditions,omitempty" protobuf:"bytes,6,rep,name=conditions"`
     ConditionalDecisionChain []SubjectAccessReviewAuthorizationDecision   `json:"conditionalDecisionChain,omitempty" protobuf:"bytes,7,rep,name=conditionalDecisionChain"`
     Reason            string                              `json:"reason,omitempty" protobuf:"bytes,8,opt,name=reason"`
 }

 Add field to SubjectAccessReviewStatus (protobuf tag 5, next available after 1-4):

 ConditionalDecisionChain []SubjectAccessReviewAuthorizationDecision `json:"conditionalDecisionChain,omitempty" protobuf:"bytes,5,rep,name=conditionalDecisionChain"`

 2. pkg/apis/authorization/types.go — Add internal types + field

 Add matching types without json/protobuf tags:

 type SubjectAccessReviewConditionEffect string
 const (...)

 type SubjectAccessReviewCondition struct {
     ID, Effect, Condition, Description  // same fields, no tags
 }

 type SubjectAccessReviewAuthorizationDecision struct {
     Allowed, Denied, FailureMode, AuthorizerName, ConditionsType string
     Conditions []SubjectAccessReviewCondition
     ConditionalDecisionChain []SubjectAccessReviewAuthorizationDecision
     Reason string
 }

 Add ConditionalDecisionChain []SubjectAccessReviewAuthorizationDecision to internal SubjectAccessReviewStatus.

 3. staging/src/k8s.io/api/authorization/v1beta1/types.go — Add field referencing v1

 Add field to v1beta1 SubjectAccessReviewStatus (protobuf tag 5), referencing the v1 type:

 ConditionalDecisionChain []authorizationv1.SubjectAccessReviewAuthorizationDecision `json:"conditionalDecisionChain,omitempty" protobuf:"bytes,5,rep,name=conditionalDecisionChain"`

 This follows the established pattern where v1beta1 reuses v1 types for FieldSelectorAttributes, LabelSelectorAttributes, and ConditionalAuthorizationOptions.

 4. Run codegen

 hack/update-codegen.sh

 This regenerates deepcopy, conversion (v1/v1beta1 <-> internal), protobuf, and openapi.

 Verification

 make                    # compile check
 hack/test-changed.sh    # unit tests
