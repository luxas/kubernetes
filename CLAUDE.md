# Claude usage with Kubernetes

## Building

In order to verify that the project compiles, run `make`. DO NOT set any
environment variables when running this command.

## Unit testing

After each major coding step, unit tests should be run, to make sure tests are passing.

In order to run unit tests, run `hack/test-changed.sh`. The script automatically
writes the test output log to `plans/last-test-run.txt`, so run the command
as-is, without grepping or tailing the output. After the invocation, you can
grep the `plans/last-test-run.txt` file to understand next steps. DO NOT set any
environment variables when running this command.

## Updating automatically-generated conversion, deepcopy, defaulting and validation code

Some code in Kubernetes is automatically generated (all files that have the
`zz_generated.*` prefix). After making a change that touches API types, run
`hack/update-codegen.sh` to make update these files, before running unit tests
or trying to compile the code. DO NOT try to edit `zz_generated` files yourself.

## Permissions for tool calling

No need to ask for permission to use the following tools:

- grep
- go build
- make
- tail
- sed
