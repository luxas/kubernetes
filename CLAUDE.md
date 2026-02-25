# Claude usage with Kubernetes

## Building

Always set the following environment variables when building the code:

- TMPDIR=/Users/luxas/upbound/kubernetes/.cache/tmp
- GOCACHE=/Users/luxas/upbound/kubernetes/.cache/go-build
- GOPATH=/Users/luxas/upbound/kubernetes/.cache/gopath

in order to make sure the compilation uses just local files in the sandbox.

In order to verify that the project compiles, run `make` with the env vars set.

## Unit testing

In order to run unit tests, run `hack/test-changed.sh`. The script automatically
writes the test output log to `plans/last-test-run.txt`, so run the command
as-is, without grepping or tailing the output. After the invocation, you can
grep the `plans/last-test-run.txt` file to understand next steps.

## Permissions for tool calling

No need to ask for permission to use the following tools:

- grep
- go build
- make
- tail
- sed
