# Continuation: add per-commit `## Tests` sections to the KEP‑5681 reviews

## Context

The commit-by-commit review of the 25-commit `impl-conditional-authz-3` branch
is already complete: `review/00-summary.md` plus `review/<letter>-<sha>.md`
for each commit exist at `/Users/luxas/upbound/kubernetes-push/review/`. Each
per-commit review already covers: What this commit does / Files touched /
Findings / What's well done / Verdict.

The user now wants a deeper test-focused pass. For every commit, add a new
`## Tests` section that evaluates:

- **Coverage** — do the added / modified unit + integration tests exercise
  every notable codepath the commit introduces? Which branches are missed?
- **Structure** — could the tests be simplified (table-driven refactoring,
  helper extraction, deduplication, use of `iter.Seq2`/subtests)?
- **Stale comments** — in the test file or in the production code the
  tests are exercising, does anything read as outdated after this commit
  (references to renamed methods, TODOs already resolved, misleading
  invariant comments)?

## Scope and constraints

- **Files edited: only** `review/<letter>-<sha>.md` (25 files) — no code
  changes to the Kubernetes tree.
- **Insertion point:** a new `## Tests` section placed immediately *before*
  the existing `## Verdict` heading in each file. Keeps `Verdict` as the
  concluding line as it is today.
- **Depth by commit:** substantive when the commit adds hand-written tests;
  brief when the commit touches only codegen / mechanical stubs. See the
  inventory below.
- **Reachable via SHA:** every commit is either on the current branch
  (`impl-conditional-authz-3`) or on `impl-conditional-authz-2` /
  dangling. All SHAs are readable via `git show`.

## Method per commit

1. `git show <sha> -- <test-file>` for each test file listed in the
   commit's stat.
2. Read the current state of the test file at HEAD when non-obvious
   (e.g. Phase B commits have been superseded by later refactors — the
   HEAD state may look different, which is a coverage-relevant fact).
3. Compare against the production diff (already summarised in the
   existing review's "Files touched" section) to identify:
   - Branches only reachable via error paths that aren't tested.
   - Boundary conditions (empty slice, nil pointer, max limits) missing.
   - Concurrency/thread-safety claims in the docstring — never tested.
4. Look for structural nits:
   - Test tables with copy-paste rows differing in one field → parameterise.
   - Repeated fixture setup → helper.
   - Assertions using string equality on multi-line output → prefer
     structured comparison.
5. Look for outdated comments in the test file *and* in the production
   code the tests exercise:
   - Method names in comments that no longer match after a rename.
   - TODO markers now resolved by later commits.
   - "Private for now" or "will change" hedges that are now stable.
6. Draft the `## Tests` section using the section template below.
7. `Edit` the review file to insert the section before `## Verdict`.

## `## Tests` section template

```markdown
## Tests

### Test files touched
- `<file>_test.go` (+A/−D lines) — one-liner about scope.
- `<other>_test.go` (+A/−D) — …

### Coverage
- What is well-covered: <specific behaviours>.
- Missing / thin: <specific branches or edge cases>. Reference the
  production `file.go:line` that is untested.
- Feature-gate on/off both exercised? Yes/no with reference.

### Structure
- Suggestions for simplification (parameterisation, helpers, subtests).
- Repeated fixtures worth extracting.
- Any tests that are slow / flaky / non-deterministic to flag.

### Stale comments
- Test file: `<file>:line` — outdated wording.
- Production file: `<file>:line` — outdated wording.
- Or: "None found."
```

For commits with only codegen or mechanical test edits, use a shorter form:

```markdown
## Tests

Codegen commit (or: purely mechanical rename in existing tests). No
substantive test surface to review. `<one-line explanation>`.
```

## Per-commit inventory (in file/execution order)

Depth categorisation from the git-stat inventory:

**Deep test analysis warranted** (11 files, hand-written tests > 100 lines
added or 200+ lines modified):
- `a-6d78dfd60cf` — conditions_test.go +194 (new file, the initial
  ConditionsAwareDecision tests).
- `g-98eab691156` — conditions_test.go +127/−46 (added
  PossibleDecisions / FailureDecision / ContainsUnconditionalAllowOrDeny
  columns).
- `h-9d7f6593151` — conditions_test.go +150 (new ConditionsMap tests).
- `i-666dea045e8` — conditions_test.go +487, evaluate_internal_test.go
  +686 (the reference-evaluator test surface — largest single-commit
  test addition).
- `j-d725c326bcd` — conditions_test.go +698, conditionsunion_test.go
  +173, union_test.go +777 (the union authorizer's massive test
  addition).
- `k-7a6938b39f1` — evaluate_test.go +442 (new file, partial-evaluation
  tests).
- `n-3033213ea26` — conditions_test.go +215, conditionsunion_test.go
  +56, evaluate_test.go +46 (pre-factor tests: validation, DNS-1123,
  UnconditionalParts).
- `o-be2f64e38a9` — conditions_test.go +163 (UnconditionalParts with
  expectConditional).
- `q-cce400c33ab` — util_test.go +209, conversion_test.go +232 v1beta1,
  +307 apiserver conversion, validation_test.go +444, four
  declarative_validation_test.go files.
- `t-67896e14ab4` — conditionsenforcer_test.go +542, filter
  authorization_test.go +239, metrics_test.go +91, context_test.go +66.
- `u-f0f9a3ed310` — subjectaccessreview/rest_test.go +597,
  util/helpers_test.go +216, encoding_test.go +143.
- `v-f1e726ca22c` — webhook_conditional_test.go +1023,
  encoding_test.go +252, apis/apiserver/validation_test.go +321.
- `w-67711704058` — config_test.go +181 (classifier tests).
- `x-6013eb05df2` — the whole integration test suite: 4 files, ~2907
  lines. Meta-analysis; not test-of-tests.

**Medium** (moderate test surface — Phase A adapter, feature-gate reference
files, small tests):
- `b-7e3c7349470` — many one-line renames in `*_test.go` files across
  the tree; check that no assertion depends on the renamed identifier
  substantively.
- `c-69a8b4dd7a9` — metrics_test.go +72, union_test.go +20, plus small
  updates to several integration test files (`auth_test.go`,
  `accessreview_test.go`, `rbac_test.go`).
- `d-27e0fa95ff9` — conditions_test.go +79/−… (mostly deletions after
  removing `FailClosedDecision` / `UnconditionalParts`), metrics_test.go
  +11.
- `l-5c9a3d7744d` — validation_test.go +188 (move; verify same tests
  still run against the moved-file location).
- `s-f2982e77497` — compile_test.go +15 (single new test entry for the
  CEL matcher-env extension).

**Brief** (codegen, references, or 1-line touches):
- `e-a42663cc26c` — no tests touched.
- `f-40d1ff2444b` — no tests touched (only the private-enum
  representation change).
- `m-72400feff77` — codegen commit, no hand-written tests.
- `p-db947349618` — only `feature_list.md` documentation update; no test.
- `r-dedec1a12ef` — three `declarative_validation_test.go` files, 1
  line each (a version bump).
- `y-2f14e9c3e7d` — codegen commit; regenerates
  `zz_generated.validations.*_test.go` files (declarative validation
  test infrastructure); no hand-written tests to analyse.

## Execution sequence

1. Loop through the reviews alphabetically (a → y), which matches the
   commit-order of the branch.
2. For each file:
   a. Read the review to reconfirm the "Files touched" list and the
      existing coverage notes.
   b. `git show <sha> -- <test-file>` for each listed test file.
   c. When useful (large test files, or tests I haven't fully mapped in
      the initial review), read the current state at HEAD:
      `read <test-file>`.
   d. Draft the `## Tests` section following the template.
   e. `Edit` the review to insert the section right before
      `## Verdict`.
3. After all 25 files are updated, cross-reference key findings in
   `review/00-summary.md` if new blocking issues surface (only if they
   change verdicts; otherwise leave the summary as-is).

## Verification

- `grep -c "^## Tests" review/*.md` should show `1` for every
  `<letter>-<sha>.md` file (and `0` for `00-summary.md`).
- Every `## Tests` section should sit exactly above `## Verdict`
  (verify with `grep -B1 "^## Verdict" review/*.md`).
- Every `## Tests` section should cite at least one specific
  `file.go:line` or `<file>_test.go:line` reference (grep for
  `\.go:` occurrences).
- Every review file grew relative to the previous state (line count
  strictly larger).
- No code files under `staging/`, `pkg/`, `plugin/`, `test/` are
  modified (`git status --short` shows only `review/*.md`).

## Non-goals

- **Not** rewriting existing sections of the reviews (verdicts stay; if
  a `## Tests` finding contradicts a prior verdict, note it in the new
  section rather than editing the old sections).
- **Not** touching `kep.md`, `changes.md`, or any production code.
- **Not** writing missing tests in the tree — this pass only reports
  coverage gaps, it does not fix them.
- **Not** repeating the roll-up in `00-summary.md` unless a truly new
  Critical issue is discovered by the test-focused pass.
