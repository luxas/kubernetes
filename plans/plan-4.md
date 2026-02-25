# Unit tests for authorizer/conditional.go

write unit tests for all cases supported in sampleAuthorizer in staging/src/k8s.io/apiserver/pkg/authorization/authorizer/conditional_test.go. the test case matrix should use an outermost layer which specifies the given            
  attributes, and then a list of inner cases with the object specified, and the wanted final decision (from the Authorize + decision.EvaluateConditions combination). use unstructured.Unstructured for specifying an implementation    
   of the objects in conditiondata