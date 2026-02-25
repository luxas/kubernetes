#!/bin/bash

KUBE_ROOT=$(dirname "${BASH_SOURCE[0]}")/..

UPDATE_COMPATIBILITY_FIXTURE_DATA=true make -C "${KUBE_ROOT}" test WHAT="$(${KUBE_ROOT}/hack/changed-packages.sh | grep -v test/integration | tr '\n' ' ')" > ${KUBE_ROOT}/plans/last-test-run.txt
