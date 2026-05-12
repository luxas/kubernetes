import Lake
open Lake DSL

package «lean-authz» where
  leanOptions := #[⟨`autoImplicit, false⟩]

@[default_target]
lean_lib TranspiledAuthz where
  srcDir := ".."
  roots := #[`TranspiledAuthz]

lean_lib TranspiledAuthzFFI where
  roots := #[`TranspiledAuthzFFI]
