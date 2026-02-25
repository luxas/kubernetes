# Add ConditionsMode to SubjectAccessReview

Currently, the following test fails:

```
Running tool: /usr/local/go/bin/go test -test.fullpath=true -timeout 120s -run ^TestResourceAttributesFrom$ k8s.io/kubernetes/pkg/registry/authorization/util

--- FAIL: TestResourceAttributesFrom (0.00s)
    /Users/luxas/upbound/kubernetes/pkg/registry/authorization/util/helpers_test.go:94: authorizer.AttributesRecord has a new field: "ConditionsMode". Add to ResourceAttributesFrom/NonResourceAttributesFrom as appropriate, then add to knownAttributesRecordFieldNames
FAIL
FAIL	k8s.io/kubernetes/pkg/registry/authorization/util	0.705s
FAIL
```

Fix it by adding the structs

```go
type ConditionalAuthorizationOptions struct {
    ConditionsMode ConditionsMode // with json tags etc as appropriate
}

type SubjectAccessReviewSpec struct {
    ConditionalAuthorization *ConditionalAuthorizationOptions // with json tags etc as appropriate
}

type ConditionsMode string // plus well-defined modes
```

to all external and internal types (and variants such as `SelfSubjectAccessReview`) of `SubjectAccessReview`.

Map the field as appropriate to make the failing unit test pass.