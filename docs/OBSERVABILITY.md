# Read-only bridge observations

`GET /observations` supplies versioned inputs for monitoring policies on the
existing bridge service. It does not sign, publish, replace or reconcile a
payout. Keep this service on its approved internal network. Responses use
`Cache-Control: no-store`; collectors must enforce their own age budget for
`observedAt` and reject unavailable samples. One installed handler admits one
collection at a time, with a shared maximum duration of fifteen seconds.
Concurrent collections receive 503 immediately. Other methods receive 405.

The response has `schema: 1`, `observedAt`, `queue` and `peg`. HTTP 200 means
both observations were collected; a positive deficit can still be present.
HTTP 503 means at least one required observation is unavailable. Never turn a
missing field, reader error, unknown state or partial sample into zero debt.
Errors use fixed reason codes and omit endpoints, credentials and raw replies.

## Queue age

`queue` uses one SQLite read transaction and releases it before any network
request. It reports counts by persisted payout state, `outstanding`, the oldest
unpaid `seen_at` as `oldestSeenAt`, and its age in seconds. A paid row is excluded.
Failed, reserved and uncertain rows still need attention and remain outstanding;
monitoring does not authorize retrying them. Invalid/future times, unknown
states and database errors make the sample unavailable.

The age starts when the coordinator first recorded the withdrawal. It is not
an independently authenticated chain timestamp or the time funds became
spendable. A withdrawal missing from this local database cannot be counted here.

## Peg observations

The collector checks the configured L2 chain ID and genesis, selects a
reader-reported finalized block, and uses its exact hash for every contract
call. It reads `pendingZNN()`, `pendingQSR()` and WrappedQSR `totalSupply()`.
No latest-block or numeric-height fallback is used for those calls.

The NoM vault balance must name the configured vault and match a stable,
confirmed account frontier. The frontier's confirming momentum must already be
inside the selected finalized L2 derivation. Unconfirmed vault blocks,
unreceived deposits, missing RPC fields and malformed amounts refuse the sample.
The collector rechecks the vault frontier and queues, canonical L2 block and
finalized horizon before publishing amounts. It reports these source points and
the SHA-256 of the typed rollup configuration serialized by Go's `encoding/json`.
Provision that configuration digest independently in the consuming policy.

All amounts are decimal strings in NoM base units. For each token,
`payoutLiquidityDeficitBaseUnits` is `max(pending - liquid, 0)`. For QSR,
`userLiabilityBaseUnits` is wrapped supply plus pending withdrawals, and
`backingDeficitBaseUnits` is `max(user liability - liquid, 0)`. Fee revenue is not
added to user liability. Arithmetic is exact and bounded to 256-bit inputs.

Native ZNN circulating supply is not exposed by these interfaces. Its
`totalBackingState` remains `not_established`; a zero pending-liquidity deficit
does not establish full ZNN backing. QSR values are consistent observations
reported by the configured readers, not independent canonicality or reserve
proofs. Concurrent events after the rechecks remain possible.

## Optional member observation contract

The response now includes the typed bridge configuration digest at the top level
and `signers`. A vault signer can implement `SignerMonitoringSource` to provide
public member node points, checked times, threshold and a separately accepted
committee configuration digest. Sources must bind replies to their independently
provisioned member authority and omit keys, credentials, URLs and raw errors.

This package defines the interface and a bounded required-field momentum reader.
It does not adopt an authenticated committee/member implementation. Unsupported
and single-key signers explicitly return `not_configured`; that state cannot
qualify a complete committee freshness check. A consumer must validate member
inventory, sample and node ages, chain identity and lag using an accepted policy.
Fresh response time alone does not make an old node fresh.

Peg and optional member reads run concurrently after the queue read transaction
ends, share the collection deadline, and both join before the response returns.
These points remain reader observations. Authentication, complete alert policies
and real operator/custody acceptance require their separate implementations and
qualification.

## Operator triage and remaining alert work

An unavailable sample requires investigation of its fixed reason and source
points before economic conclusions. Preserve the existing payout journal and
original hashes. Restore reader availability, investigate unreceived deposits
or derivation lag, and repeat the observation through the approved monitor.
Do not re-sign, replace, mark paid or rewrite old timestamps to clear an alert.

An old outstanding row requires checking the exact withdrawal and original
attempt in the normal recovery procedure. A positive liquidity or backing
deficit requires custody/operator investigation and independently accepted
chain and balance observations. The endpoint cannot authorize moving funds.

The complete S02 requirement remains open: exercise common-height block/config
mismatch, deficit, stale-signer, old-pending-withdrawal, publication-error and
queue-saturation thresholds through the actual incident and notification path,
with accepted policies and runbooks. This provider is the missing data input;
it does not install thresholds, probe signers, send alerts or prove real operator
acceptance. Full native ZNN liability accounting also needs a separately
specified authoritative source. Local HTTP/SQLite fixtures do not establish
real chain state, recipient delivery, deployment or production readiness.

## Native CI result scope

The Linux component and race commands emit named Go JSON test events and run
without cached test results. Component tests have a three-minute package
deadline and race tests a five-minute package deadline; the existing job has
a ten-minute overall deadline. Build, vet, all packages, the Core gitlink and
the existing observation fixtures remain included. Individual passes, skips,
failures and actual command completion must be retained before qualification.

These component fixtures do not establish independent NoM authority, a deployed
monitor, recipient delivery, operator acceptance or production readiness. A
source change or successful workflow status alone is not runtime evidence.

## Complete sweep health

The aggregate health flag is false before and during a sweep. It becomes true
only after receiving deposits, scanning withdrawals, paying withdrawals,
confirming payouts and funding plasma all succeed in that sweep. A later no-op
cannot erase an earlier failure. Operational failures allow independent later
work; cancellation stops the remaining steps. No payout, receive, queue or
journal semantics change in this health-only update.

The status response includes sweepInProgress, lastSweepAt and five named step
records with state, startedAt, finishedAt and an optional error. lastOkAt remains
the previous complete success until a new complete success. Returned maps are
independent snapshots. The Status consumer must be upgraded with this producer:
an old aggregate-only response does not establish complete-step health. This
wire contract uses process wall-clock timestamps, not independently verified
chain or custody evidence. Actual external monitoring deployment remains an
operator acceptance gate.
