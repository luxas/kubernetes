import Lake
open Lake DSL

/-!
Lean model of the Kubernetes Conditional Authorization (KEP-5681) implementation.

Each top-level directory mirrors one Go package (flattened):

| Lean dir              | Go package                                                        |
|-----------------------|-------------------------------------------------------------------|
| `authorizer/`         | `staging/src/k8s.io/apiserver/pkg/authorization/authorizer`       |
| `union/`              | `staging/src/k8s.io/apiserver/pkg/authorization/union`            |
| `webhook/`            | `staging/src/k8s.io/apiserver/plugin/pkg/authorizer/webhook`      |
| `encoding/`           | `staging/src/k8s.io/apiserver/pkg/apis/authorization/v1`          |
| `filters/`            | `staging/src/k8s.io/apiserver/pkg/endpoints/filters`              |
| `conditionsenforcer/` | `staging/src/k8s.io/apiserver/pkg/admission/plugin/authorizer/conditionsenforcer` |
| `cel/`                | `staging/src/k8s.io/apiserver/pkg/admission/plugin/cel`           |

Inside a directory, `foo.lean` mirrors `foo.go` and `foo_properties.lean` holds the
theorems (the counterpart of `foo_test.go`). See `README.md`.
-/

package «conditional-authz» where
  leanOptions := #[⟨`autoImplicit, false⟩]

@[default_target]
lean_lib ConditionalAuthz where
  roots := #[`authorizer, `union, `webhook, `encoding, `filters, `conditionsenforcer, `cel]
  globs := #[.submodules `authorizer, .submodules `union, .submodules `webhook,
             .submodules `encoding, .submodules `filters, .submodules `conditionsenforcer,
             .submodules `cel]
