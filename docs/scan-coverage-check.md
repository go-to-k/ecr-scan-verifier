# Scan coverage check (fail-fast) specification

When the construct waits for scan results it does not start itself, a misconfigured
repository (e.g. not covered by any Enhanced scanning filter) would previously poll
until the `pollingTimeout` (14 minutes by default) before failing. The scan coverage
check detects "this scan will never run" states from the registry / repository
scanning configuration and fails the deployment immediately with a descriptive error.

Tracking issue: [#23](https://github.com/go-to-k/ecr-scan-verifier/issues/23)

## When the check runs

The check runs **once**, when the **first** `DescribeImageScanFindings` call raises
`ScanNotFoundException` (i.e. no scan results exist yet), and only in modes where the
construct does not start the scan itself:

- `ScanConfig.enhanced()`
- `ScanConfig.basic({ startScan: false })`

It calls two ECR APIs:

- `GetRegistryScanningConfiguration` — the registry (account + region) scan type
  (`BASIC` / `ENHANCED`)
- `BatchGetRepositoryScanningConfiguration` — the configuration **as evaluated by ECR
  for this repository**: `scanOnPush`, `scanFrequency`, `appliedScanFilters` (the
  registry filter rules that matched). Wildcard matching is done server-side by ECR;
  the construct never reimplements filter matching.

## Field semantics

`BatchGetRepositoryScanningConfiguration` returns, per repository:

- **`scanOnPush`** — the *effective* (evaluated) scan-on-push status for this
  repository. Historically scan-on-push was configured per repository via
  `imageScanningConfiguration.scanOnPush` (the legacy mechanism); the registry-level
  scanning configuration supersedes it, and this field reflects the evaluated result
  regardless of which mechanism set it.
- **`appliedScanFilters`** — the registry-level filter rules (configured per AWS
  account **and region**) that matched this repository. ECR evaluates the wildcard
  matching server-side.
- **`scanFrequency`** — one of `SCAN_ON_PUSH`, `CONTINUOUS_SCAN`, `MANUAL`.
  `MANUAL` means *no automatic scanning applies* — the repository is only scanned if
  a scan is triggered manually via `StartImageScan`. Since Enhanced scanning disables
  `StartImageScan` entirely, `MANUAL` in an ENHANCED registry means the repository
  will never be scanned.

Field combinations worth spelling out:

| Combination | Registry | Meaning |
|---|---|---|
| `appliedScanFilters` empty + `scanFrequency: MANUAL` | ENHANCED | Not covered by any filter → never scanned. **This is the fail-fast trigger** (verified against the real API, see below). |
| `appliedScanFilters` non-empty + `scanFrequency: MANUAL` | ENHANCED | Contradiction — Enhanced filter rules can only be `SCAN_ON_PUSH` / `CONTINUOUS_SCAN`, so a matched rule implies an automatic frequency. Should not occur; treated as covered (keep polling). |
| `appliedScanFilters` non-empty + `scanFrequency: MANUAL` | BASIC | **Legitimate state**: BASIC filter rules can be `SCAN_ON_PUSH` or `MANUAL`, and a matched `MANUAL` rule means "manual scanning only". The BASIC branch does not read `appliedScanFilters`; it reads the effective `scanOnPush` (`false` here), which handles this state correctly. |
| `appliedScanFilters` empty + `scanFrequency: SCAN_ON_PUSH` / `CONTINUOUS_SCAN` | ENHANCED | Contradiction — the frequency is derived from matched rules, so "no matched rules + automatic frequency" cannot legitimately coexist. Should not occur; treated as covered (keep polling). |

The two "should not occur" rows are why the fail condition requires **both** signals
(empty filters *and* non-automatic frequency): a transient propagation state or a
future API change that corrupts one field alone can then never trigger a wrong
fail-fast — it degrades to the old polling behavior instead.

## When the check does NOT run

| Case | Behavior (unchanged from previous versions) |
|---|---|
| Scan results already exist | First poll succeeds; the check never executes. A repository scanned manually in the past therefore keeps working even with `scanOnPush: false`. |
| `ScanConfig.basic()` (`startScan: true`, default) | The construct starts the scan itself via `StartImageScan`; a transient `ScanNotFoundException` right after starting is just propagation lag. |
| `ScanConfig.signatureOnly()` | No scanning at all. |
| Repository / image does not exist | `RepositoryNotFoundException` / `ImageNotFoundException` are rethrown immediately on the first poll (fails fast already, before this feature). |

## Decision table

| # | ScanConfig | Registry scan type | Repository state | Behavior |
|---|---|---|---|---|
| 1 | `enhanced()` | ENHANCED | Covered: `appliedScanFilters` non-empty, or `scanFrequency` is `SCAN_ON_PUSH` / `CONTINUOUS_SCAN` | **Keep polling** — "scan has not started yet" is the normal case for a fresh push |
| 2 | `enhanced()` | ENHANCED | Not covered: `appliedScanFilters` empty **and** `scanFrequency` is neither `SCAN_ON_PUSH` nor `CONTINUOUS_SCAN` (observed: `MANUAL`) | **Fail immediately**: `Repository 'X' is not covered by any Enhanced scanning filter...` |
| 3 | `enhanced()` | BASIC | — (registry scan type alone is decisive) | **Fail immediately**: `Enhanced scanning (Amazon Inspector) is not enabled for this registry...` |
| 4 | `basic({startScan: false})` | BASIC | `scanOnPush: true` | **Keep polling** |
| 5 | `basic({startScan: false})` | BASIC | `scanOnPush: false` | **Fail immediately**: `Scan on push is not enabled for repository 'X'...` |
| 6 | `basic({startScan: false})` | ENHANCED | Covered (as in #1) | **Keep polling** — Inspector results are readable through the same `DescribeImageScanFindings` API |
| 7 | `basic({startScan: false})` | ENHANCED | Not covered (as in #2) | **Fail immediately** (same error as #2) |

Only #2, #3, #5 and #7 fail fast — exactly the states where the configuration proves
the scan can never run.

## Inconclusive states — always fall back to polling

Any state that does not *definitively* prove non-coverage falls back to the previous
behavior (keep polling; eventually the pre-existing `polling timeout` error):

| Situation | Behavior |
|---|---|
| Configuration API call fails (throttling, permissions, ...) | Warn log + keep polling |
| `BatchGetRepositoryScanningConfiguration` returns a `failures` entry | Warn log + keep polling |
| Registry scan type missing / unknown value | Warn log + keep polling |
| Contradictory response (e.g. `appliedScanFilters` empty but `scanFrequency: CONTINUOUS_SCAN`) | Treated as covered; keep polling |

## Design principles

1. **Fail only on definitive non-coverage.** A false fail-fast would block a
   deployment that would otherwise succeed; an undetected misconfiguration merely
   falls back to the old timeout error. Because these costs are asymmetric, every
   ambiguous state resolves to "keep polling".
2. **Two-signal corroboration in the ENHANCED branch.** The fail condition requires
   both `appliedScanFilters` empty *and* a non-automatic `scanFrequency`. In an
   ENHANCED registry `scanFrequency` is derived from the matched rules, so the two
   fields cannot legitimately disagree ("empty + `CONTINUOUS_SCAN`" or "non-empty +
   `MANUAL`" are contradictions) — requiring both protects against transient
   propagation states and future API changes.
3. **Each branch uses the field that directly answers "will a scan ever start" for
   that scan type.** For ENHANCED registries that is filter coverage
   (`appliedScanFilters` / `scanFrequency`) — Enhanced scanning has no per-repository
   scan-on-push setting, and the `scanOnPush` field there is a derived view whose
   value for `CONTINUOUS_SCAN`-only coverage is not clearly documented. For BASIC
   registries it is the effective `scanOnPush` value (BASIC filter rules are
   `SCAN_ON_PUSH` / `MANUAL`, and their evaluation result is exactly this field).
4. **No interaction with `failOnVulnerability`.** That flag only controls whether
   detected *vulnerabilities* fail the deployment. The coverage error is on the same
   rail as the pre-existing timeout / scan-`FAILED` errors: it always fails the
   deployment, regardless of `failOnVulnerability`, and is not suppressed by
   `suppressErrorOnRollback` (which covers signature verification and vulnerability
   errors only).

## Verified API response shape

Captured against the real API on 2026-07-29 (us-east-2, ENHANCED registry with a
filter rule matching nothing, `BatchGetRepositoryScanningConfiguration` on a
non-covered repository):

```json
{
  "scanningConfigurations": [
    {
      "repositoryArn": "arn:aws:ecr:us-east-2:<account>:repository/<repo>",
      "repositoryName": "<repo>",
      "scanOnPush": false,
      "scanFrequency": "MANUAL",
      "appliedScanFilters": []
    }
  ],
  "failures": []
}
```

The filter change was visible in the response ~5 seconds after
`put-registry-scanning-configuration` (no propagation lag observed).

Note: a full end-to-end "deployment fails immediately" test cannot be expressed in
the `integ-runner` suites (they cannot assert an expected deployment failure), which
is why the shape verification above plus unit tests covering every branch of the
decision table stand in for it.

## IAM permissions

Granted by the construct only when the check can run
(`startScan: false` and not `SIGNATURE_ONLY`):

| Action | Resource |
|---|---|
| `ecr:BatchGetRepositoryScanningConfiguration` | repository ARN |
| `ecr:GetRegistryScanningConfiguration` | `*` (registry-level API) |

## Implementation

- Handler logic: `verifyScanCoverage` in
  [`assets/lambda/lib/ecr-scan.ts`](../assets/lambda/lib/ecr-scan.ts)
- Permission grants: [`src/ecr-scan-verifier.ts`](../src/ecr-scan-verifier.ts)
- Unit tests (all decision-table branches):
  [`assets/lambda/test/ecr-scan.test.ts`](../assets/lambda/test/ecr-scan.test.ts)
