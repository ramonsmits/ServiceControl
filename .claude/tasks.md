# Task: Fix failed-message sort by "Time of failure" — DONE

Customer bug: ServicePulse "Time of failure" ASC/DESC sort of failed messages
actually ordered by "Time sent". Root cause: Primary `SortInfoModelBinder`
allowlist missing `time_of_failure`/`modified`; binder silently rewrote the
token to `time_sent` before the (capable) RavenDB layer saw it.

Branch: fix/failed-messages-sort-by-time-of-failure

## Steps

- [x] Investigate root cause across ServicePulse / API / RavenDB
- [x] Create branch
- [x] RED: failing binder test (time_of_failure, modified) — 0c9da188e
- [x] GREEN: add the two keys to Primary binder allowlist — 6bbabc3cd
- [x] REFACTOR: SortInfo.AllowedSortOptions single source of truth, Primary
      (binder + RavenDB) + Audit (binder) + characterization tests — c433ffaed
- [x] Verify: Primary 214 pass, Audit 80 pass; new binder tests 5+4 pass.
      Only pre-existing unrelated `PlatformSampleSettings` approval test fails
      (fails identically with changes stashed — not caused by this work).

## Issues / PR filed
- Public bug: https://github.com/Particular/ServiceControl/issues/5475
- PlatformBugs triage: https://github.com/Particular/PlatformBugs/issues/1519
- PR (master): https://github.com/Particular/ServiceControl/pull/5477
  (references #5475 without auto-close)
- Backport PR (release-6.14): https://github.com/Particular/ServiceControl/pull/5479
  (RED+GREEN only, no refactor; Resolves #5475 / Backport of #5477;
  reviewer dvdstelt)
  ([3.1] Priority; Support case 00105211; `Priority` label + validation
  pending a second staff member per triage process)

## Smoke test (pr-5479 deployment)
- Generated dummy data via ServiceControl.SmokeTest v1.6.0 (87 failed msgs +
  audits/sagas/custom-checks/fanout across Endpoint0-3)
- Verified backport end-to-end: GET /api/errors?sort=time_of_failure asc/desc
  correctly ordered AND independent of time_sent (no fallback) → fix confirmed
  on the deployed pr-5479 image

## Not done (left for user decision)
- Push branch / open PR (not requested)
- Triage validation by a second staff member + post-triage Priority comment
  on #5475 (human step, per bug-triage-scoring.md)
- ServicePulse: no change needed (it was already correct)
- docs.particular.net: no API surface change (behaviour fix only)
