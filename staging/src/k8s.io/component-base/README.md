## component-base

**WARNING:** This staging repo is still in the experimental stage.
The code structure as-is now is not guaranteed to be have a stable interface quite yet.

### Goal

Implement KEP 32: https://github.com/kubernetes/enhancements/blob/master/keps/sig-cluster-lifecycle/0032-create-a-k8s-io-component-repo.md

The proposal is essentially about refactoring the Kubernetes core package structure in a way that all core components may share common code around:
 - ComponentConfig implementation
 - flag and command handling
 - HTTPS serving
 - delegated authn/z
 - logging.

### OWNERS

WG Component Standard is working on this refactoring process, which is happening incrementally, starting in the v1.14 cycle.
SIG API Machinery and SIG Cluster Lifecycle owns the code.
