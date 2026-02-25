#!/bin/bash

# Get changed packages
CHANGED=$(git diff --name-only HEAD | grep '\.go$' | sed 's|/[^/]*\.go$||' | sort -u)

# For each changed package, grep for imports of it
for pkg in $CHANGED; do
  # Convert filesystem path to import path fragment
  import_path=$(echo "$pkg" | sed 's|staging/src/||')
  # echo "=== rdeps of $import_path ==="
  grep -r "\"${import_path}\"" \
    --include='*.go' \
    staging/ pkg/ plugin/ cmd/ test/ \
    --exclude-dir=vendor \
    -l 2>/dev/null \
    | sed -e 's|^cmd/|k8s.io/kubernetes/cmd/|' -e 's|^plugin/|k8s.io/kubernetes/plugin/|' -e 's|^pkg/|k8s.io/kubernetes/pkg/|' -e 's|^test/|k8s.io/kubernetes/test/|' -e 's|^staging/src/||' \
    | sed 's|/[^/]*\.go$||' | sort -u
done