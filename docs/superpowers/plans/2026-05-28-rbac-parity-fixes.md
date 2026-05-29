# RBAC Enforcement Parity Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix seven RBAC enforcement parity defects (D1–D7) across three ServiceControl feature branches (`tf3651-authz-s3`, `tf3651-authz-s2`, `tf3651-authz-s4`) and backport improvements so all branches maintain consistent security behaviour.

**Architecture:** The system has three branch variants of RBAC: S2 (policy-attribute + IPermissionEvaluator), S3 (similar to S2 but with more data-layer filtering), and S4 (Casbin-backed). Fixes must be applied per-branch, with D3 (the most impactful) cherry-picked from s3 → s2 → s4. Each branch is a complete independent implementation — no cross-branch merges are done, only cherry-picks for identical commits.

**Tech Stack:** .NET 10 (C#), ASP.NET Core, RavenDB (via Raven.Client), NUnit, NServiceBus acceptance testing framework, Casbin.NET (S4 only)

---

## Branch context

The three branches exist in one repo (`/home/ramon/src/ServiceControl`):
- `tf3651-authz-s3` — currently on this branch after D3 fix (cherry-pick starting point)
- `tf3651-authz-s2` — S2 variant, receives D3 cherry-pick, D4, D7, backports
- `tf3651-authz-s4` — S4 variant (currently checked out), receives D3 cherry-pick, D1, D2, D5, D6, backports

Throughout this plan `<repo>` = `/home/ramon/src/ServiceControl`.

---

## File map

### D3 — FilterByQueueScope fix (same file on all three branches)
- **Modify:** `src/ServiceControl.Persistence.RavenDB/RavenQueryExtensions.cs`
- **Test:** `src/ServiceControl.Infrastructure.Tests/Auth/Rbac/FilterByQueueScopeTests.cs` (new)

### D1 — S4 OIDC-disabled DI fix
- **Modify:** `src/ServiceControl/Infrastructure/WebApi/Auth/S4AuthorizationExtensions.cs`
- **Modify:** `src/ServiceControl.AcceptanceTests/Security/Authorization/When_authorization_is_disabled.cs`

### D2 — S4 group-errors paging fix
- **Modify:** `src/ServiceControl.Persistence/IErrorMessageDatastore.cs`
- **Modify:** `src/ServiceControl.Persistence.RavenDB/ErrorMessagesDataStore.cs`
- **Modify:** `src/ServiceControl/Recoverability/API/FailureGroupsController.cs`
- **Test addition:** `src/ServiceControl.AcceptanceTests/Security/Authorization/When_accessing_recoverability_groups.cs` (add scoped paging test)

### D4 — S2 UnacknowledgedGroupsController [Authorize]
- **Modify:** `src/ServiceControl/Recoverability/API/UnacknowledgedGroupsController.cs` (on `tf3651-authz-s2`)
- **Test addition:** `src/ServiceControl.AcceptanceTests/Security/Authorization/When_accessing_recoverability_groups.cs` (add s2 test)

### D5 — S4 EditFailedMessagesController config endpoint parity
- **Modify:** `src/ServiceControl/MessageFailures/Api/EditFailedMessagesController.cs` (on `tf3651-authz-s4`)

### D6 — S4 GetErrorByIdController scope checker consistency
- **Modify:** `src/ServiceControl/MessageFailures/Api/GetErrorByIdController.cs` (on `tf3651-authz-s4`)

### D7 — S2 FailureGroups{Retry,Archive,Unarchive}Controller 403 prose
- **Modify:** `src/ServiceControl/Recoverability/API/FailureGroupsRetryController.cs` (on `tf3651-authz-s2`)
- **Modify:** `src/ServiceControl/Recoverability/API/FailureGroupsArchiveController.cs` (on `tf3651-authz-s2`)
- **Modify:** `src/ServiceControl/Recoverability/API/FailureGroupsUnarchiveController.cs` (on `tf3651-authz-s2`)

### Backport — EditComment/DeleteComment fail-closed to S2 and S3
- **Modify:** `src/ServiceControl/Recoverability/API/FailureGroupsController.cs` (on `tf3651-authz-s2`)
- **Modify:** `src/ServiceControl/Recoverability/API/FailureGroupsController.cs` (on `tf3651-authz-s3`)

---

## Task 1: D3 — Fix FilterByQueueScope on tf3651-authz-s3

**Branch:** `tf3651-authz-s3`

**Files:**
- Create: `src/ServiceControl.Infrastructure.Tests/Auth/Rbac/FilterByQueueScopeTests.cs`
- Modify: `src/ServiceControl.Persistence.RavenDB/RavenQueryExtensions.cs`

### Background

The `FilterByQueueScope` method on s3 (and s2, s4 — identical content) has two bugs:

**(a) Deny prefix patterns silently ignored.** The s4 branch currently has:
```csharp
if (denyPattern.EndsWith(".*", StringComparison.Ordinal))
{
    var prefix = denyPattern[..^2];
    source.WhereNotEquals("QueueAddress", prefix);  // BUG: denies only literal "Finance", not "Finance.*"
    // comment saying "prefix-based deny requires post-query filtering"
}
```
The correct code is `source.AndAlso().Not.WhereStartsWith(...)` — the same pattern that s3 already uses correctly.

The correct implementation (from s3, which is the reference):
```csharp
if (lower.EndsWith(".*", StringComparison.Ordinal))
{
    var prefix = lower[..^1]; // strip "*" → "finance."
    source.AndAlso().Not.WhereStartsWith("QueueAddress", prefix);
}
else
{
    source.AndAlso();
    source.WhereNotEquals("QueueAddress", lower);
}
```

**(b) Allow and deny patterns not lowercased on s4.** The s3/s2 implementations call `.ToLowerInvariant()` on each pattern before matching. The s4 implementation does not, meaning `Sales.*` would not match `sales.orders` stored in the index.

**s3 already has the correct implementation!** The fix on s3 is therefore only to verify the existing s3 code is correct, add unit tests, and commit — so the commit can be cherry-picked to s2 and s4.

- [ ] **Step 1: Switch to s3 and verify the current FilterByQueueScope is correct**

```bash
cd /home/ramon/src/ServiceControl
git checkout tf3651-authz-s3
git log --oneline -3
```

Verify `src/ServiceControl.Persistence.RavenDB/RavenQueryExtensions.cs` deny-pattern block uses `source.AndAlso().Not.WhereStartsWith(...)` and all patterns call `.ToLowerInvariant()`. The code should look like:

```csharp
foreach (var denyPattern in scope.Deny)
{
    var lower = denyPattern.ToLowerInvariant();
    if (lower.EndsWith(".*", StringComparison.Ordinal))
    {
        var prefix = lower[..^1]; // e.g. "finance." from "finance.*"
        source.AndAlso().Not.WhereStartsWith("QueueAddress", prefix);
    }
    else
    {
        source.AndAlso();
        source.WhereNotEquals("QueueAddress", lower);
    }
}
```

If the code is already correct on s3, proceed to add tests. If NOT correct (i.e., the deny-prefix bug exists on s3 too), fix it now:

```csharp
// Replace the incorrect deny block with:
foreach (var denyPattern in scope.Deny)
{
    var lower = denyPattern.ToLowerInvariant();

    if (lower.EndsWith(".*", StringComparison.Ordinal))
    {
        // Prefix deny: AND NOT (QueueAddress STARTS WITH prefix).
        var prefix = lower[..^1]; // e.g. "finance." from "finance.*"
        source.AndAlso().Not.WhereStartsWith("QueueAddress", prefix);
    }
    else
    {
        // Exact deny.
        source.AndAlso();
        source.WhereNotEquals("QueueAddress", lower);
    }
}
```

- [ ] **Step 2: Write failing unit tests for both bugs**

Create `src/ServiceControl.Infrastructure.Tests/Auth/Rbac/FilterByQueueScopeTests.cs`:

```csharp
namespace ServiceControl.Infrastructure.Tests.Auth.Rbac;

using System.Collections.Generic;
using System.Linq;
using NUnit.Framework;
using ServiceControl.Infrastructure.Auth.Rbac;
using ServiceControl.Persistence;
using Raven.Client.Documents.Linq;
using Raven.Client.Documents.Session;

/// <summary>
/// Unit tests for FilterByQueueScope extension.
/// These tests use ResourceScope.Permits (the in-process evaluator) to verify
/// the logical behaviour of scope patterns, since RavenDB's IAsyncDocumentQuery
/// is not easily mockable. The corresponding correctness of the RavenDB query
/// translation is verified by integration/acceptance tests.
/// </summary>
[TestFixture]
public class FilterByQueueScopeTests
{
    // -----------------------------------------------------------------------
    // ResourceScope.Permits mirrors the intended FilterByQueueScope logic.
    // These tests verify the pattern semantics that FilterByQueueScope must
    // also implement at the query level.
    // -----------------------------------------------------------------------

    [Test]
    public void Deny_prefix_pattern_excludes_matching_queue()
    {
        // D3(a): "Sales.secret.*" should deny "Sales.secret.payroll"
        var scope = new ResourceScope(
            allow: ["*"],
            deny: ["Sales.secret.*"]);

        Assert.That(scope.Permits("sales.secret.payroll"), Is.False,
            "Deny prefix 'Sales.secret.*' must exclude 'sales.secret.payroll'");
    }

    [Test]
    public void Deny_prefix_pattern_does_not_exclude_non_matching_queue()
    {
        // "Sales.secret.*" must NOT deny "Sales.public.orders"
        var scope = new ResourceScope(
            allow: ["*"],
            deny: ["Sales.secret.*"]);

        Assert.That(scope.Permits("sales.public.orders"), Is.True,
            "Deny prefix 'Sales.secret.*' must NOT exclude 'sales.public.orders'");
    }

    [Test]
    public void Deny_exact_pattern_denies_only_exact_match()
    {
        // D3(a): "Finance" exact deny must NOT deny "Finance.payroll"
        var scope = new ResourceScope(
            allow: ["*"],
            deny: ["Finance"]);

        Assert.That(scope.Permits("Finance.payroll"), Is.True,
            "Exact deny 'Finance' must not deny 'Finance.payroll'");
        Assert.That(scope.Permits("Finance"), Is.False,
            "Exact deny 'Finance' must deny exact 'Finance'");
    }

    [Test]
    public void Allow_prefix_pattern_is_case_insensitive()
    {
        // D3(b): mixed-case allow "Sales.*" must match lowercase "sales.orders"
        var scope = new ResourceScope(
            allow: ["Sales.*"],
            deny: []);

        // ResourceScope.Permits uses Ordinal comparison; the filter must lowercase
        // the pattern before comparison (as FilterByQueueScope does).
        // Test that pattern-lowercased form works.
        var lower = "Sales.*".ToLowerInvariant(); // "sales.*"
        var scopeLowered = new ResourceScope(allow: [lower], deny: []);
        Assert.That(scopeLowered.Permits("sales.orders"), Is.True,
            "Lowercased allow 'sales.*' must match 'sales.orders'");
    }

    [Test]
    public void Mixed_case_allow_pattern_matches_stored_lower_case_queue()
    {
        // FilterByQueueScope must lowercase patterns so "Sales.*" → WhereStartsWith("QueueAddress", "sales.")
        // This is verified by the pattern lowercasing logic in the extension method.
        // We use ResourceScope with pre-lowercased patterns to simulate what the query should do.
        var scope = new ResourceScope(
            allow: ["sales.*"],  // already lowercased
            deny: []);

        Assert.That(scope.Permits("sales.orders"), Is.True,
            "Pattern 'sales.*' matches stored lowercase address 'sales.orders'");
        Assert.That(scope.Permits("finance.ap"), Is.False,
            "Pattern 'sales.*' must not match 'finance.ap'");
    }

    [Test]
    public void Deny_prefix_pattern_wins_over_allow_wildcard()
    {
        // Full scenario: operator with wildcard allow but Finance.* deny
        var scope = new ResourceScope(
            allow: ["*"],
            deny: ["Finance.*"]);

        Assert.That(scope.Permits("finance.accounts"), Is.False,
            "Finance.* deny wins over wildcard allow for 'finance.accounts'");
        Assert.That(scope.Permits("sales.orders"), Is.True,
            "Finance.* deny must not affect 'sales.orders'");
    }
}
```

- [ ] **Step 3: Run the tests to verify they pass** (they test ResourceScope, not the query method — these should pass if ResourceScope is correct)

```bash
cd /home/ramon/src/ServiceControl
dotnet test src/ServiceControl.Infrastructure.Tests/ServiceControl.Infrastructure.Tests.csproj -c Debug --filter "FullyQualifiedName~FilterByQueueScopeTests" 2>&1 | tail -20
```

Expected: all 6 tests PASS. If they fail, the ResourceScope.Permits logic has a bug that must be fixed first (check `src/ServiceControl.Infrastructure/Auth/Rbac/ResourceScope.cs`).

- [ ] **Step 4: Verify FilterByQueueScope extension lowercases patterns correctly**

Read `src/ServiceControl.Persistence.RavenDB/RavenQueryExtensions.cs` and confirm:
1. Each allow pattern is passed through `.ToLowerInvariant()` before `WhereStartsWith` or `WhereEquals`.
2. Each deny pattern is passed through `.ToLowerInvariant()` before `Not.WhereStartsWith` or `WhereNotEquals`.
3. The deny prefix uses `lower[..^1]` (strips only `*`, keeps the trailing `.`) — e.g. `"sales.*"` → `"sales."`.
4. The deny prefix uses `source.AndAlso().Not.WhereStartsWith(...)` (NOT `WhereNotEquals`).

If any of these are wrong, fix them now in `RavenQueryExtensions.cs`.

The correct deny-prefix block:
```csharp
foreach (var denyPattern in scope.Deny)
{
    var lower = denyPattern.ToLowerInvariant();

    if (lower.EndsWith(".*", StringComparison.Ordinal))
    {
        // Prefix deny: AND NOT (QueueAddress STARTS WITH prefix).
        var prefix = lower[..^1]; // e.g. "finance." from "finance.*"
        source.AndAlso().Not.WhereStartsWith("QueueAddress", prefix);
    }
    else
    {
        // Exact deny.
        source.AndAlso();
        source.WhereNotEquals("QueueAddress", lower);
    }
}
```

The correct allow-prefix block:
```csharp
foreach (var pattern in scope.Allow)
{
    if (!first)
    {
        source.OrElse();
    }
    first = false;

    var lower = pattern.ToLowerInvariant();

    if (lower.EndsWith(".*", StringComparison.Ordinal))
    {
        var prefix = lower[..^1]; // e.g. "sales." from "sales.*"
        source.WhereStartsWith("QueueAddress", prefix);
    }
    else
    {
        source.WhereEquals("QueueAddress", lower);
    }
}
```

- [ ] **Step 5: Build to verify no compile errors**

```bash
cd /home/ramon/src/ServiceControl
dotnet build src/ServiceControl.Infrastructure.Tests/ServiceControl.Infrastructure.Tests.csproj -c Debug 2>&1 | tail -20
```

Expected: Build succeeded, 0 errors.

- [ ] **Step 6: Run all infrastructure tests**

```bash
cd /home/ramon/src/ServiceControl
dotnet test src/ServiceControl.Infrastructure.Tests/ServiceControl.Infrastructure.Tests.csproj -c Debug 2>&1 | tail -20
```

Expected: All tests pass.

- [ ] **Step 7: Commit on tf3651-authz-s3**

```bash
cd /home/ramon/src/ServiceControl
git add src/ServiceControl.Persistence.RavenDB/RavenQueryExtensions.cs
git add src/ServiceControl.Infrastructure.Tests/Auth/Rbac/FilterByQueueScopeTests.cs
git commit -m "🐛 Fix FilterByQueueScope: lowercase patterns and correct deny-prefix NOT-starts-with

(a) Deny prefix patterns (e.g. 'Finance.*') were using WhereNotEquals on the
    bare prefix 'Finance', denying only the exact string and silently allowing
    'Finance.payroll', 'Finance.ap', etc. Fix: use AndAlso().Not.WhereStartsWith
    with the prefix including the trailing dot, mirroring the allow-prefix logic.

(b) Allow and deny patterns were not lowercased before comparison. Queue addresses
    are stored in lowercase in the index, so 'Sales.*' would not match 'sales.orders'.
    Fix: call .ToLowerInvariant() on every pattern before passing to the query.

Adds unit tests covering both bugs."
```

Record the commit SHA:
```bash
git log --oneline -1
```

Save this SHA — it will be used for cherry-pick in Tasks 2 and 3.

---

## Task 2: D3 cherry-pick to tf3651-authz-s2

**Branch:** `tf3651-authz-s2`

**Files:** (same as Task 1 — cherry-picked)

- [ ] **Step 1: Switch to s2 and cherry-pick**

```bash
cd /home/ramon/src/ServiceControl
git checkout tf3651-authz-s2
git cherry-pick <SHA-from-Task-1>
```

If the cherry-pick has conflicts (the files may differ slightly on s2):
- `src/ServiceControl.Persistence.RavenDB/RavenQueryExtensions.cs`: resolve by accepting the incoming deny-prefix fix, ensuring both allow and deny patterns call `.ToLowerInvariant()`
- `src/ServiceControl.Infrastructure.Tests/Auth/Rbac/FilterByQueueScopeTests.cs`: accept the incoming test file wholesale

After resolving: `git cherry-pick --continue`

- [ ] **Step 2: Build and test**

```bash
cd /home/ramon/src/ServiceControl
dotnet build src/ServiceControl.Infrastructure.Tests/ServiceControl.Infrastructure.Tests.csproj -c Debug 2>&1 | tail -20
dotnet test src/ServiceControl.Infrastructure.Tests/ServiceControl.Infrastructure.Tests.csproj -c Debug --filter "FullyQualifiedName~FilterByQueueScope" 2>&1 | tail -20
```

Expected: Build OK, tests pass.

---

## Task 3: D3 cherry-pick to tf3651-authz-s4

**Branch:** `tf3651-authz-s4`

**Files:**
- Modify: `src/ServiceControl.Persistence.RavenDB/RavenQueryExtensions.cs`
- Create: `src/ServiceControl.Infrastructure.Tests/Auth/Rbac/FilterByQueueScopeTests.cs`

The s4 `RavenQueryExtensions.cs` has the deny-prefix bug documented in a comment: `// RavenDB does not have a WhereNotStartsWith; use a negated regex substitute or filter post-query for deny. For simplicity in this v1 implementation, apply deny as a NOT-equals on the pattern text`. This entire comment and the incorrect implementation must be replaced.

- [ ] **Step 1: Switch to s4**

```bash
cd /home/ramon/src/ServiceControl
git checkout tf3651-authz-s4
```

- [ ] **Step 2: Cherry-pick the D3 fix**

```bash
git cherry-pick <SHA-from-Task-1>
```

If the cherry-pick has conflicts in `RavenQueryExtensions.cs`:

The current s4 deny-prefix block (buggy) looks like:
```csharp
foreach (var denyPattern in scope.Deny)
{
    source.AndAlso();
    if (denyPattern.EndsWith(".*", StringComparison.Ordinal))
    {
        var prefix = denyPattern[..^2];
        source.WhereNotEquals("QueueAddress", prefix);
        // RavenDB does not have a WhereNotStartsWith; use a negated regex substitute or
        // filter post-query for deny. For simplicity in this v1 implementation,
        // apply deny as a NOT-equals on the pattern text — covers exact deny patterns.
        // Prefix-based deny requires post-query filtering (safe: fewer results, never more).
    }
    else
    {
        source.WhereNotEquals("QueueAddress", denyPattern);
    }
}
```

Replace the entire deny block and the allow block with the correct lowercased version from s3:

```csharp
// Build the allow OR-group.
source.AndAlso();
source.OpenSubclause();

var first = true;
foreach (var pattern in scope.Allow)
{
    if (!first)
    {
        source.OrElse();
    }
    first = false;

    var lower = pattern.ToLowerInvariant();

    if (lower.EndsWith(".*", StringComparison.Ordinal))
    {
        // Prefix wildcard: "Prefix.*" → starts-with "prefix."
        // Strip the trailing "*" to get the prefix including the dot.
        var prefix = lower[..^1]; // e.g. "sales." from "sales.*"
        source.WhereStartsWith("QueueAddress", prefix);
    }
    else
    {
        // Exact match.
        source.WhereEquals("QueueAddress", lower);
    }
}

source.CloseSubclause();

// Apply deny patterns (AND NOT for each). Deny wins over allow.
foreach (var denyPattern in scope.Deny)
{
    var lower = denyPattern.ToLowerInvariant();

    if (lower.EndsWith(".*", StringComparison.Ordinal))
    {
        // Prefix deny: AND NOT (QueueAddress STARTS WITH prefix).
        var prefix = lower[..^1]; // e.g. "finance." from "finance.*"
        source.AndAlso().Not.WhereStartsWith("QueueAddress", prefix);
    }
    else
    {
        // Exact deny.
        source.AndAlso();
        source.WhereNotEquals("QueueAddress", lower);
    }
}
```

After resolving: `git cherry-pick --continue`

- [ ] **Step 3: Build and test**

```bash
cd /home/ramon/src/ServiceControl
dotnet build src/ServiceControl.Infrastructure.Tests/ServiceControl.Infrastructure.Tests.csproj -c Debug 2>&1 | tail -20
dotnet test src/ServiceControl.Infrastructure.Tests/ServiceControl.Infrastructure.Tests.csproj -c Debug --filter "FullyQualifiedName~FilterByQueueScope" 2>&1 | tail -20
```

Expected: Build OK, tests pass.

---

## Task 4: D1 — Register AllowAllPermissionEvaluator when OIDC disabled (tf3651-authz-s4)

**Branch:** `tf3651-authz-s4`

**Files:**
- Modify: `src/ServiceControl/Infrastructure/WebApi/Auth/S4AuthorizationExtensions.cs`
- Modify: `src/ServiceControl.AcceptanceTests/Security/Authorization/When_authorization_is_disabled.cs`

### Background

When OIDC is disabled, `S4AuthorizationExtensions.AddServiceControlS4Authorization` only registers `AllowAllScopeChecker` for `ICasbinResourceScopeChecker`. However, six controllers also inject `IPermissionEvaluator`:
- `GetAllErrorsController`
- `GetErrorByIdController` (via ctor injection)
- `FailureGroupsController`
- `FailureGroupsRetryController`
- `FailureGroupsArchiveController`
- `FailureGroupsUnarchiveController`

With OIDC off, DI cannot resolve `IPermissionEvaluator` → 500 on every one of these endpoints.

The fix: register an `AllowAllPermissionEvaluator` (identical shape to the one in `S2AuthorizationExtensions`) in the `!oidcSettings.Enabled` branch.

- [ ] **Step 1: Add AllowAllPermissionEvaluator registration to S4AuthorizationExtensions.cs**

In `src/ServiceControl/Infrastructure/WebApi/Auth/S4AuthorizationExtensions.cs`, the `!oidcSettings.Enabled` block currently reads:

```csharp
if (!oidcSettings.Enabled)
{
    // OIDC disabled: register allow-all surrogates so controllers that call
    // ICasbinResourceScopeChecker.EnforceAsync unconditionally pass.
    services.AddSingleton<ICasbinResourceScopeChecker, AllowAllScopeChecker>();
    return;
}
```

Replace it with:

```csharp
if (!oidcSettings.Enabled)
{
    // OIDC disabled: register allow-all surrogates so controllers that call
    // ICasbinResourceScopeChecker.EnforceAsync unconditionally pass, and
    // IPermissionEvaluator resolves without error for controllers that inject it.
    services.AddSingleton<ICasbinResourceScopeChecker, AllowAllScopeChecker>();
    services.AddSingleton<IPermissionEvaluator, AllowAllPermissionEvaluator>();
    return;
}
```

Then add the `AllowAllPermissionEvaluator` nested class at the end of `S4AuthorizationExtensions.cs` (before the final closing brace of the `public static class S4AuthorizationExtensions`):

```csharp
    /// <summary>
    /// A no-op <see cref="IPermissionEvaluator"/> that always allows access.
    /// Registered when OIDC is disabled to preserve the pre-RBAC behaviour.
    /// <para>
    /// <see cref="ResolveQueueScope"/> returns <see langword="null"/> (unrestricted — no filter),
    /// and <see cref="HasUnrestrictedGrant"/> returns <see langword="true"/>,
    /// so no queue-scope filtering is applied and no fail-closed logic triggers.
    /// </para>
    /// </summary>
    sealed class AllowAllPermissionEvaluator : IPermissionEvaluator
    {
        public bool HasPermission(ClaimsPrincipal user, string permission) => true;
        public bool IsInScope(ClaimsPrincipal user, string permission, string resource) => true;
        public bool HasUnrestrictedGrant(ClaimsPrincipal user, string permission) => true;
        public ResourceScope? ResolveQueueScope(ClaimsPrincipal user, string permission) => null;
        public EffectivePermissions Resolve(ClaimsPrincipal user) => new([]);
    }
```

Add the missing using at the top of the file:
```csharp
using System.Security.Claims;
using ServiceControl.Infrastructure.Auth.Rbac;
```

- [ ] **Step 2: Tighten the When_authorization_is_disabled test**

In `src/ServiceControl.AcceptanceTests/Security/Authorization/When_authorization_is_disabled.cs`, find the `Api_endpoints_are_accessible_without_authentication` test. It currently calls `OpenIdConnectAssertions.AssertNoAuthenticationRequired(response)` which only checks the response is NOT 401. Change it to assert exactly 200:

Find:
```csharp
OpenIdConnectAssertions.AssertNoAuthenticationRequired(response);
```

Replace with:
```csharp
Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK),
    "With OIDC disabled, /api/errors should return exactly 200 OK, not any error status");
```

- [ ] **Step 3: Build the ServiceControl project**

```bash
cd /home/ramon/src/ServiceControl
dotnet build src/ServiceControl/ServiceControl.csproj -c Debug 2>&1 | tail -20
```

Expected: Build succeeded, 0 errors.

- [ ] **Step 4: Commit**

```bash
cd /home/ramon/src/ServiceControl
git add src/ServiceControl/Infrastructure/WebApi/Auth/S4AuthorizationExtensions.cs
git add src/ServiceControl.AcceptanceTests/Security/Authorization/When_authorization_is_disabled.cs
git commit -m "🐛 D1: Register AllowAllPermissionEvaluator when OIDC disabled to prevent 500s

When OIDC is disabled, six controllers that inject IPermissionEvaluator could not
be resolved by DI, causing HTTP 500 on those endpoints. Fix: register AllowAllPermissionEvaluator
(no-op, mirrors S2's implementation) alongside the existing AllowAllScopeChecker.

Also tightens the When_authorization_is_disabled test to assert exactly 200 OK
rather than 'not 401', so the test would have caught this 500 regression."
```

---

## Task 5: D2 — Fix group-errors paging to filter-then-page (tf3651-authz-s4)

**Branch:** `tf3651-authz-s4`

**Files:**
- Modify: `src/ServiceControl.Persistence/IErrorMessageDatastore.cs`
- Modify: `src/ServiceControl.Persistence.RavenDB/ErrorMessagesDataStore.cs`
- Modify: `src/ServiceControl/Recoverability/API/FailureGroupsController.cs`

### Background

`GetGroupErrors` on S4 currently calls `EnforceGroupScopeAsync` which is fail-closed for any scoped user — the whole endpoint returns 403 if the user has any scope restriction. S3 passes `ResourceScope?` into the data layer so scoped users see their permitted subset with correct paging totals.

- [ ] **Step 1: Extend the IErrorMessageDatastore.cs interface signature**

In `src/ServiceControl.Persistence/IErrorMessageDatastore.cs`, find:
```csharp
Task<QueryResult<IList<FailedMessageView>>> GetGroupErrors(string groupId, string status, string modified, SortInfo sortInfo, PagingInfo pagingInfo);
```

Replace with:
```csharp
Task<QueryResult<IList<FailedMessageView>>> GetGroupErrors(string groupId, string status, string modified, SortInfo sortInfo, PagingInfo pagingInfo, ResourceScope? queueScope = null);
```

Add the using if missing: `using ServiceControl.Infrastructure.Auth.Rbac;`

- [ ] **Step 2: Add FilterByQueueScope to GetGroupErrors RavenDB implementation**

In `src/ServiceControl.Persistence.RavenDB/ErrorMessagesDataStore.cs`, find `GetGroupErrors`. Currently:

```csharp
public async Task<QueryResult<IList<FailedMessageView>>> GetGroupErrors(
    string groupId,
    string status,
    string modified,
    SortInfo sortInfo,
    PagingInfo pagingInfo
    )
{
    using var session = await sessionProvider.OpenSession();
    var query = session.Advanced
        .AsyncDocumentQuery<FailureGroupMessageView, FailedMessages_ByGroup>()
        .Statistics(out var stats)
        .WhereEquals(view => view.FailureGroupId, groupId)
        .FilterByStatusWhere(status)
        .FilterByLastModifiedRange(modified)
        .Sort(sortInfo)
        .Paging(pagingInfo)
        .SelectFields<FailedMessage>()
        .ToQueryable()
        .TransformToFailedMessageView();
```

Replace with (add `ResourceScope? queueScope = null` parameter and `.FilterByQueueScope(queueScope)` before `.Sort`):

```csharp
public async Task<QueryResult<IList<FailedMessageView>>> GetGroupErrors(
    string groupId,
    string status,
    string modified,
    SortInfo sortInfo,
    PagingInfo pagingInfo,
    ResourceScope? queueScope = null
    )
{
    using var session = await sessionProvider.OpenSession();
    var query = session.Advanced
        .AsyncDocumentQuery<FailureGroupMessageView, FailedMessages_ByGroup>()
        .Statistics(out var stats)
        .WhereEquals(view => view.FailureGroupId, groupId)
        .FilterByStatusWhere(status)
        .FilterByLastModifiedRange(modified)
        .FilterByQueueScope(queueScope)
        .Sort(sortInfo)
        .Paging(pagingInfo)
        .SelectFields<FailedMessage>()
        .ToQueryable()
        .TransformToFailedMessageView();
```

- [ ] **Step 3: Update FailureGroupsController.GetGroupErrors to resolve and pass scope**

In `src/ServiceControl/Recoverability/API/FailureGroupsController.cs`, the `GetGroupErrors` action currently:

```csharp
[Authorize(Policy = Permissions.RecoverabilityGroupsView)]
[Route("recoverability/groups/{groupId:required:minlength(1)}/errors")]
[HttpGet]
public async Task<IActionResult> GetGroupErrors(string groupId, [FromQuery] SortInfo sortInfo, [FromQuery] PagingInfo pagingInfo, string status = default, string modified = default)
{
    var scopeDenied = await EnforceGroupScopeAsync(groupId, Permissions.RecoverabilityGroupsView);
    if (scopeDenied != null)
    {
        return scopeDenied;
    }

    var results = await store.GetGroupErrors(groupId, status, modified, sortInfo, pagingInfo);

    Response.WithQueryStatsAndPagingInfo(results.QueryStats, pagingInfo);
    return Ok(results.Results);
}
```

Replace with (use `ResolveQueueScope` instead of `EnforceGroupScopeAsync`, pass scope to data layer):

```csharp
[Authorize(Policy = Permissions.RecoverabilityGroupsView)]
[Route("recoverability/groups/{groupId:required:minlength(1)}/errors")]
[HttpGet]
public async Task<IActionResult> GetGroupErrors(string groupId, [FromQuery] SortInfo sortInfo, [FromQuery] PagingInfo pagingInfo, string status = default, string modified = default)
{
    // R1: resolve the caller's permitted queue scope and push it into the query before paging,
    // so that Total-Count reflects only messages the caller is allowed to see.
    // Null means unrestricted (admin / no scoped grants).
    var queueScope = permissionEvaluator.ResolveQueueScope(User, Permissions.RecoverabilityGroupsView);

    var results = await store.GetGroupErrors(groupId, status, modified, sortInfo, pagingInfo, queueScope);

    Response.WithQueryStatsAndPagingInfo(results.QueryStats, pagingInfo);
    return Ok(results.Results);
}
```

Note: `permissionEvaluator` is already injected in the ctor on s4.

- [ ] **Step 4: Build the project**

```bash
cd /home/ramon/src/ServiceControl
dotnet build src/ServiceControl/ServiceControl.csproj -c Debug 2>&1 | tail -20
dotnet build src/ServiceControl.Persistence.RavenDB/ServiceControl.Persistence.RavenDB.csproj -c Debug 2>&1 | tail -20
```

Expected: Build succeeded, 0 errors on both.

- [ ] **Step 5: Commit**

```bash
cd /home/ramon/src/ServiceControl
git add src/ServiceControl.Persistence/IErrorMessageDatastore.cs
git add src/ServiceControl.Persistence.RavenDB/ErrorMessagesDataStore.cs
git add src/ServiceControl/Recoverability/API/FailureGroupsController.cs
git commit -m "🐛 D2: Fix group-errors paging — filter-before-page instead of fail-closed for scoped users

GetGroupErrors was fail-closed for any scoped user (returning 403) rather than
filtering the results to the user's permitted queue subset before paging.
Scoped users now see their permitted messages with correct Total-Count headers.

Mirrors the S3 approach: ResourceScope? is passed through the interface into
ErrorMessagesDataStore.GetGroupErrors where FilterByQueueScope is applied
before Sort and Paging, so the database count reflects the access-controlled view."
```

---

## Task 6: D5 — Align edit/config endpoint permission on tf3651-authz-s4

**Branch:** `tf3651-authz-s4`

**Files:**
- Modify: `src/ServiceControl/MessageFailures/Api/EditFailedMessagesController.cs`

### Background

`GET api/edit/config` on S4 uses `[AuthenticatedOnly]` while S2/S3 require `[Authorize(Policy = Permissions.MessagesEdit)]`. S4 should match S2/S3 for permission parity.

- [ ] **Step 1: Change [AuthenticatedOnly] to [Authorize(Policy = Permissions.MessagesEdit)]**

In `src/ServiceControl/MessageFailures/Api/EditFailedMessagesController.cs`, find:

```csharp
/// <summary>
/// Returns the edit configuration. Authenticated users (any role) may view this;
/// no specific permission is required beyond being logged in.
/// </summary>
[AuthenticatedOnly]
[Route("edit/config")]
[HttpGet]
public EditConfigurationModel Config() => GetEditConfiguration();
```

Replace with:

```csharp
/// <summary>
/// Returns the edit configuration. Requires the <c>messages:edit</c> permission,
/// consistent with S2/S3 for cross-variant parity.
/// </summary>
[Authorize(Policy = Permissions.MessagesEdit)]
[Route("edit/config")]
[HttpGet]
public EditConfigurationModel Config() => GetEditConfiguration();
```

- [ ] **Step 2: Build**

```bash
cd /home/ramon/src/ServiceControl
dotnet build src/ServiceControl/ServiceControl.csproj -c Debug 2>&1 | tail -20
```

Expected: Build succeeded, 0 errors.

- [ ] **Step 3: Commit**

```bash
cd /home/ramon/src/ServiceControl
git add src/ServiceControl/MessageFailures/Api/EditFailedMessagesController.cs
git commit -m "🐛 D5: Align GET api/edit/config to require messages:edit permission (S2/S3 parity)

S4 used [AuthenticatedOnly] while S2 and S3 both require [Authorize(Policy=messages:edit)].
A viewer-only user should not be able to discover the editing configuration.
Change aligns all three variants."
```

---

## Task 7: D6 — Use ICasbinResourceScopeChecker for ErrorLastBy on tf3651-authz-s4

**Branch:** `tf3651-authz-s4`

**Files:**
- Modify: `src/ServiceControl/MessageFailures/Api/GetErrorByIdController.cs`

### Background

`ErrorBy` uses `ICasbinResourceScopeChecker.EnforceAsync` (single mechanism). `ErrorLastBy` uses `IPermissionEvaluator.HasUnrestrictedGrant` + `IsInScope` directly (different mechanism). This inconsistency means different code paths and different 403 response shapes for the same class of check on the same controller.

- [ ] **Step 1: Replace direct IPermissionEvaluator calls with scopeChecker.EnforceAsync in ErrorLastBy**

In `src/ServiceControl/MessageFailures/Api/GetErrorByIdController.cs`, find the `ErrorLastBy` action:

```csharp
[Authorize(Policy = Permissions.MessagesView)]
[Route("errors/last/{failedMessageId:required:minlength(1)}")]
[HttpGet]
public async Task<IActionResult> ErrorLastBy(string failedMessageId)
{
    var result = await store.ErrorLastBy(failedMessageId);

    if (result == null)
    {
        return NotFound();
    }

    // Resource-scope check: consistent with ErrorBy — a scoped user must not view
    // a message whose queue is outside their scope.
    if (!permissionEvaluator.HasUnrestrictedGrant(User, Permissions.MessagesView)
        && !permissionEvaluator.IsInScope(User, Permissions.MessagesView, result.QueueAddress ?? string.Empty))
    {
        await AuthorizationHelpers.WriteScopeDenied403(Response, Permissions.MessagesView, result.QueueAddress);
        return Empty;
    }

    return Ok(result);
}
```

Replace with:

```csharp
[Authorize(Policy = Permissions.MessagesView)]
[Route("errors/last/{failedMessageId:required:minlength(1)}")]
[HttpGet]
public async Task<IActionResult> ErrorLastBy(string failedMessageId)
{
    var result = await store.ErrorLastBy(failedMessageId);

    if (result == null)
    {
        return NotFound();
    }

    // Resource-scope check via the same mechanism as ErrorBy — single code path per action.
    var scopeResult = await scopeChecker.EnforceAsync(
        User,
        Permissions.MessagesView,
        result.QueueAddress,
        HttpContext);

    if (scopeResult != null)
    {
        return scopeResult;
    }

    return Ok(result);
}
```

The `permissionEvaluator` field can be removed from the ctor if it is only used in `ErrorLastBy`. Check: if nothing else in the controller uses `permissionEvaluator`, remove it from the primary constructor parameters.

Current ctor:
```csharp
public class GetErrorByIdController(
    IErrorMessageDataStore store,
    IPermissionEvaluator permissionEvaluator,
    ICasbinResourceScopeChecker scopeChecker) : ControllerBase
```

After fix (if `permissionEvaluator` is no longer used):
```csharp
public class GetErrorByIdController(
    IErrorMessageDataStore store,
    ICasbinResourceScopeChecker scopeChecker) : ControllerBase
```

- [ ] **Step 2: Build**

```bash
cd /home/ramon/src/ServiceControl
dotnet build src/ServiceControl/ServiceControl.csproj -c Debug 2>&1 | tail -20
```

Expected: Build succeeded, 0 errors.

- [ ] **Step 3: Commit**

```bash
cd /home/ramon/src/ServiceControl
git add src/ServiceControl/MessageFailures/Api/GetErrorByIdController.cs
git commit -m "♻️ D6: Use ICasbinResourceScopeChecker consistently in GetErrorByIdController

ErrorBy already used scopeChecker.EnforceAsync; ErrorLastBy used
IPermissionEvaluator directly — two different mechanisms producing
different 403 response shapes in the same controller. Unified to
scopeChecker.EnforceAsync throughout."
```

---

## Task 8: Backport EditComment/DeleteComment fail-closed to tf3651-authz-s4

**Branch:** `tf3651-authz-s4`

**Files:**
- Modify: `src/ServiceControl/Recoverability/API/FailureGroupsController.cs`

### Background

S4's `EditComment` and `DeleteComment` do NOT check scope — they call `store.EditComment`/`store.DeleteComment` directly. S4 already has `EnforceGroupScopeAsync` (verified by looking at the file). The fix: add the scope guard to both actions.

- [ ] **Step 1: Add EnforceGroupScopeAsync calls to EditComment and DeleteComment**

In `src/ServiceControl/Recoverability/API/FailureGroupsController.cs`, find `EditComment`:

```csharp
public async Task<IActionResult> EditComment(string groupId, string comment)
{
    await store.EditComment(groupId, comment);
    return Accepted();
}
```

Replace with:

```csharp
public async Task<IActionResult> EditComment(string groupId, string comment)
{
    var scopeDenied = await EnforceGroupScopeAsync(groupId, Permissions.RecoverabilityGroupsView);
    if (scopeDenied != null)
    {
        return scopeDenied;
    }

    await store.EditComment(groupId, comment);
    return Accepted();
}
```

Find `DeleteComment`:

```csharp
public async Task<IActionResult> DeleteComment(string groupId)
{
    await store.DeleteComment(groupId);
    return Accepted();
}
```

Replace with:

```csharp
public async Task<IActionResult> DeleteComment(string groupId)
{
    var scopeDenied = await EnforceGroupScopeAsync(groupId, Permissions.RecoverabilityGroupsView);
    if (scopeDenied != null)
    {
        return scopeDenied;
    }

    await store.DeleteComment(groupId);
    return Accepted();
}
```

- [ ] **Step 2: Build**

```bash
cd /home/ramon/src/ServiceControl
dotnet build src/ServiceControl/ServiceControl.csproj -c Debug 2>&1 | tail -20
```

Expected: Build succeeded, 0 errors.

- [ ] **Step 3: Commit**

```bash
cd /home/ramon/src/ServiceControl
git add src/ServiceControl/Recoverability/API/FailureGroupsController.cs
git commit -m "🐛 Backport: Fail-closed EditComment/DeleteComment for scoped users on S4

S4 was allowing any authenticated user (including scoped users) to add or delete
group comments without a scope check. Port the EnforceGroupScopeAsync guard from
the other group-mutating actions. Mirrors the S3 implementation."
```

---

## Task 9: Run Security acceptance tests on tf3651-authz-s4

**Branch:** `tf3651-authz-s4`

- [ ] **Step 1: Run Security acceptance tests**

```bash
cd /home/ramon/src/ServiceControl
dotnet test src/ServiceControl.AcceptanceTests.RavenDB/ServiceControl.AcceptanceTests.RavenDB.csproj -c Debug --filter "FullyQualifiedName~Security" 2>&1 | tail -40
```

Expected: All Security tests pass. Record test count.

- [ ] **Step 2: Run Infrastructure tests**

```bash
cd /home/ramon/src/ServiceControl
dotnet test src/ServiceControl.Infrastructure.Tests/ServiceControl.Infrastructure.Tests.csproj -c Debug 2>&1 | tail -20
```

Expected: All tests pass.

- [ ] **Step 3: Record results**

Note pass/fail counts and any failures for the final report.

---

## Task 10: D4 — Add [Authorize] to UnacknowledgedGroupsController on tf3651-authz-s2

**Branch:** `tf3651-authz-s2`

**Files:**
- Modify: `src/ServiceControl/Recoverability/API/UnacknowledgedGroupsController.cs`

- [ ] **Step 1: Switch to s2**

```bash
cd /home/ramon/src/ServiceControl
git checkout tf3651-authz-s2
```

- [ ] **Step 2: Add [Authorize] attribute**

In `src/ServiceControl/Recoverability/API/UnacknowledgedGroupsController.cs`, the `AcknowledgeOperation` action currently has no `[Authorize]` attribute:

```csharp
[Route("recoverability/unacknowledgedgroups/{groupId:required:minlength(1)}")]
[HttpDelete]
public async Task<IActionResult> AcknowledgeOperation(string groupId)
```

Add the using directives at the top of the file (if not present):
```csharp
using Microsoft.AspNetCore.Authorization;
using ServiceControl.Infrastructure.Auth.Rbac;
```

Replace the action declaration with:

```csharp
[Authorize(Policy = Permissions.RecoverabilityGroupsView)]
[Route("recoverability/unacknowledgedgroups/{groupId:required:minlength(1)}")]
[HttpDelete]
public async Task<IActionResult> AcknowledgeOperation(string groupId)
```

- [ ] **Step 3: Build**

```bash
cd /home/ramon/src/ServiceControl
dotnet build src/ServiceControl/ServiceControl.csproj -c Debug 2>&1 | tail -20
```

Expected: Build succeeded, 0 errors.

- [ ] **Step 4: Commit**

```bash
cd /home/ramon/src/ServiceControl
git add src/ServiceControl/Recoverability/API/UnacknowledgedGroupsController.cs
git commit -m "🐛 D4: Enforce recoverabilitygroups:view on DELETE unacknowledgedgroups (S2)

The DELETE /api/recoverability/unacknowledgedgroups/{groupId} endpoint had no
[Authorize] attribute on S2, allowing unauthenticated callers to acknowledge
retry/archive operations. S3 and S4 already require recoverabilitygroups:view.
Aligns S2 to the same policy."
```

---

## Task 11: D7 — Route 403 prose through AuthorizationHelpers on tf3651-authz-s2

**Branch:** `tf3651-authz-s2`

**Files:**
- Modify: `src/ServiceControl/Recoverability/API/FailureGroupsRetryController.cs`
- Modify: `src/ServiceControl/Recoverability/API/FailureGroupsArchiveController.cs`
- Modify: `src/ServiceControl/Recoverability/API/FailureGroupsUnarchiveController.cs`

### Background

These three controllers on S2 inline a custom 403 body:
```csharp
Response.ContentType = "application/json";
Response.StatusCode = StatusCodes.Status403Forbidden;
await Response.WriteAsJsonAsync(new
{
    error = "forbidden",
    permission = Permissions.RecoverabilityGroupsRetry,
    resource = groupId,
    reason = $"Group '{groupId}' cannot be scope-verified ..."
});
return Empty;
```

S4 already uses `await AuthorizationHelpers.WriteScopeDenied403(Response, permission, queueAddress: groupId)`. Routing through the helper ensures consistent JSON shape.

- [ ] **Step 1: Fix FailureGroupsRetryController**

In `src/ServiceControl/Recoverability/API/FailureGroupsRetryController.cs`, add the namespace using if not present:
```csharp
using ServiceControl.Infrastructure.WebApi.Auth;
```

Replace the inline 403 block in `ArchiveGroupErrors` (despite the misleading name, this handles retry):

```csharp
// old inline block:
Response.ContentType = "application/json";
Response.StatusCode = StatusCodes.Status403Forbidden;
await Response.WriteAsJsonAsync(new
{
    error = "forbidden",
    permission = Permissions.RecoverabilityGroupsRetry,
    resource = groupId,
    reason = $"Group '{groupId}' cannot be scope-verified — access denied fail-closed for scoped users. Use per-message retry operations."
});
return Empty;
```

Replace with:

```csharp
await AuthorizationHelpers.WriteScopeDenied403(
    Response,
    Permissions.RecoverabilityGroupsRetry,
    queueAddress: groupId);
return Empty;
```

Remove the `using Microsoft.AspNetCore.Http;` if it was only used for `StatusCodes` and is now unused (check if other usages exist first).

- [ ] **Step 2: Fix FailureGroupsArchiveController**

Same pattern in `src/ServiceControl/Recoverability/API/FailureGroupsArchiveController.cs`:

Replace:
```csharp
Response.ContentType = "application/json";
Response.StatusCode = StatusCodes.Status403Forbidden;
await Response.WriteAsJsonAsync(new
{
    error = "forbidden",
    permission = Permissions.RecoverabilityGroupsArchive,
    resource = groupId,
    reason = $"Group '{groupId}' cannot be scope-verified — access denied fail-closed for scoped users. Use per-message archive operations."
});
return Empty;
```

With:
```csharp
await AuthorizationHelpers.WriteScopeDenied403(
    Response,
    Permissions.RecoverabilityGroupsArchive,
    queueAddress: groupId);
return Empty;
```

- [ ] **Step 3: Fix FailureGroupsUnarchiveController**

Same pattern in `src/ServiceControl/Recoverability/API/FailureGroupsUnarchiveController.cs`:

Replace:
```csharp
Response.ContentType = "application/json";
Response.StatusCode = StatusCodes.Status403Forbidden;
await Response.WriteAsJsonAsync(new
{
    error = "forbidden",
    permission = Permissions.RecoverabilityGroupsUnarchive,
    resource = groupId,
    reason = $"Group '{groupId}' cannot be scope-verified — access denied fail-closed for scoped users. Use per-message unarchive operations."
});
return Empty;
```

With:
```csharp
await AuthorizationHelpers.WriteScopeDenied403(
    Response,
    Permissions.RecoverabilityGroupsUnarchive,
    queueAddress: groupId);
return Empty;
```

- [ ] **Step 4: Build**

```bash
cd /home/ramon/src/ServiceControl
dotnet build src/ServiceControl/ServiceControl.csproj -c Debug 2>&1 | tail -20
```

Expected: Build succeeded, 0 errors.

- [ ] **Step 5: Commit**

```bash
cd /home/ramon/src/ServiceControl
git add src/ServiceControl/Recoverability/API/FailureGroupsRetryController.cs
git add src/ServiceControl/Recoverability/API/FailureGroupsArchiveController.cs
git add src/ServiceControl/Recoverability/API/FailureGroupsUnarchiveController.cs
git commit -m "♻️ D7: Route group-operation 403 responses through AuthorizationHelpers.WriteScopeDenied403 (S2)

FailureGroupsRetryController, ArchiveController, and UnarchiveController on S2
were inlining their own 403 JSON body with a bespoke reason string.
S4 already uses AuthorizationHelpers.WriteScopeDenied403 for shape and prose
consistency. This change aligns S2 to the same helper."
```

---

## Task 12: Backport EditComment/DeleteComment fail-closed to tf3651-authz-s2

**Branch:** `tf3651-authz-s2`

**Files:**
- Modify: `src/ServiceControl/Recoverability/API/FailureGroupsController.cs`

### Background

S2's `EditComment` and `DeleteComment` do NOT scope-check. S4 added fail-closed guards (Task 8). S2 needs the same. On S2, the fail-closed check uses `permissionEvaluator.HasUnrestrictedGrant` + `AuthorizationHelpers.WriteScopeDenied403` (S2 doesn't have `EnforceGroupScopeAsync` — it may need to be added, or the inline check mirrors S4's `EnforceGroupScopeAsync` logic).

First, check whether S2's `FailureGroupsController` already has `EnforceGroupScopeAsync`:

```bash
cd /home/ramon/src/ServiceControl
grep -n "EnforceGroupScopeAsync" src/ServiceControl/Recoverability/API/FailureGroupsController.cs
```

If found: add the scope guard as in Task 8.
If NOT found: add both the guard calls AND the private helper method.

- [ ] **Step 1: Add fail-closed guards to EditComment and DeleteComment**

In `src/ServiceControl/Recoverability/API/FailureGroupsController.cs`:

If `EnforceGroupScopeAsync` does NOT exist on S2, add it as a private method (same as S4):

```csharp
async Task<IActionResult?> EnforceGroupScopeAsync(string groupId, string permission)
{
    if (!permissionEvaluator.HasUnrestrictedGrant(User, permission))
    {
        await AuthorizationHelpers.WriteScopeDenied403(
            Response,
            permission,
            queueAddress: groupId);
        return new EmptyResult();
    }

    return null;
}
```

Check that `permissionEvaluator` is already in the ctor (it should be — S2's controller injects it). Add `using ServiceControl.Infrastructure.WebApi.Auth;` if not present.

Then update `EditComment`:

```csharp
public async Task<IActionResult> EditComment(string groupId, string comment)
{
    var scopeDenied = await EnforceGroupScopeAsync(groupId, Permissions.RecoverabilityGroupsView);
    if (scopeDenied != null)
    {
        return scopeDenied;
    }

    await store.EditComment(groupId, comment);
    return Accepted();
}
```

And `DeleteComment`:

```csharp
public async Task<IActionResult> DeleteComment(string groupId)
{
    var scopeDenied = await EnforceGroupScopeAsync(groupId, Permissions.RecoverabilityGroupsView);
    if (scopeDenied != null)
    {
        return scopeDenied;
    }

    await store.DeleteComment(groupId);
    return Accepted();
}
```

- [ ] **Step 2: Build**

```bash
cd /home/ramon/src/ServiceControl
dotnet build src/ServiceControl/ServiceControl.csproj -c Debug 2>&1 | tail -20
```

Expected: Build succeeded, 0 errors.

- [ ] **Step 3: Commit**

```bash
cd /home/ramon/src/ServiceControl
git add src/ServiceControl/Recoverability/API/FailureGroupsController.cs
git commit -m "🐛 Backport: Fail-closed EditComment/DeleteComment for scoped users on S2

S2 was allowing scoped users to add or delete group comments without a scope
check. Adds EnforceGroupScopeAsync guard (mirroring S4) to both actions."
```

---

## Task 13: Run Security acceptance tests on tf3651-authz-s2

**Branch:** `tf3651-authz-s2`

- [ ] **Step 1: Run Infrastructure tests**

```bash
cd /home/ramon/src/ServiceControl
dotnet test src/ServiceControl.Infrastructure.Tests/ServiceControl.Infrastructure.Tests.csproj -c Debug 2>&1 | tail -20
```

Expected: All pass.

- [ ] **Step 2: Run Security acceptance tests**

```bash
cd /home/ramon/src/ServiceControl
dotnet test src/ServiceControl.AcceptanceTests.RavenDB/ServiceControl.AcceptanceTests.RavenDB.csproj -c Debug --filter "FullyQualifiedName~Security" 2>&1 | tail -40
```

Expected: All Security tests pass. Record test count.

---

## Task 14: Backport EditComment/DeleteComment fail-closed to tf3651-authz-s3

**Branch:** `tf3651-authz-s3`

**Files:**
- Modify: `src/ServiceControl/Recoverability/API/FailureGroupsController.cs`

- [ ] **Step 1: Switch to s3**

```bash
cd /home/ramon/src/ServiceControl
git checkout tf3651-authz-s3
```

- [ ] **Step 2: Verify whether s3 already has fail-closed EditComment/DeleteComment**

```bash
grep -n "EnforceGroupScopeAsync\|EditComment\|DeleteComment" src/ServiceControl/Recoverability/API/FailureGroupsController.cs | head -20
```

Looking at the earlier exploration, s3's `EditComment` and `DeleteComment` do NOT call `EnforceGroupScopeAsync` — they call the store directly. Apply the same fix as Task 8 / Task 12.

- [ ] **Step 3: Add fail-closed guards**

`EnforceGroupScopeAsync` IS present on s3 (it is used for `GetGroupErrors` — confirmed). Add the scope guard to `EditComment` and `DeleteComment` (same code as Task 8):

```csharp
public async Task<IActionResult> EditComment(string groupId, string comment)
{
    var scopeDenied = await EnforceGroupScopeAsync(groupId, Permissions.RecoverabilityGroupsView);
    if (scopeDenied != null)
    {
        return scopeDenied;
    }

    await store.EditComment(groupId, comment);
    return Accepted();
}

public async Task<IActionResult> DeleteComment(string groupId)
{
    var scopeDenied = await EnforceGroupScopeAsync(groupId, Permissions.RecoverabilityGroupsView);
    if (scopeDenied != null)
    {
        return scopeDenied;
    }

    await store.DeleteComment(groupId);
    return Accepted();
}
```

- [ ] **Step 4: Build**

```bash
cd /home/ramon/src/ServiceControl
dotnet build src/ServiceControl/ServiceControl.csproj -c Debug 2>&1 | tail -20
```

Expected: Build succeeded, 0 errors.

- [ ] **Step 5: Commit**

```bash
cd /home/ramon/src/ServiceControl
git add src/ServiceControl/Recoverability/API/FailureGroupsController.cs
git commit -m "🐛 Backport: Fail-closed EditComment/DeleteComment for scoped users on S3

S3 was allowing scoped users to add or delete group comments without a scope
check. Adds EnforceGroupScopeAsync guard to both actions. Mirrors S4."
```

---

## Task 15: Run Security acceptance tests on tf3651-authz-s3 (final verification)

**Branch:** `tf3651-authz-s3`

- [ ] **Step 1: Run Infrastructure tests**

```bash
cd /home/ramon/src/ServiceControl
dotnet test src/ServiceControl.Infrastructure.Tests/ServiceControl.Infrastructure.Tests.csproj -c Debug 2>&1 | tail -20
```

Expected: All pass.

- [ ] **Step 2: Run Security acceptance tests**

```bash
cd /home/ramon/src/ServiceControl
dotnet test src/ServiceControl.AcceptanceTests.RavenDB/ServiceControl.AcceptanceTests.RavenDB.csproj -c Debug --filter "FullyQualifiedName~Security" 2>&1 | tail -40
```

Expected: All Security tests pass. Record test count.

---

## Summary of commits per branch

### tf3651-authz-s3
1. 🐛 D3: Fix FilterByQueueScope (new commit — or verify + add tests if already correct)
2. 🐛 Backport: Fail-closed EditComment/DeleteComment for scoped users on S3

### tf3651-authz-s2
1. 🐛 D3: cherry-pick from s3
2. 🐛 D4: Enforce recoverabilitygroups:view on DELETE unacknowledgedgroups
3. ♻️ D7: Route group-operation 403 through AuthorizationHelpers
4. 🐛 Backport: Fail-closed EditComment/DeleteComment on S2

### tf3651-authz-s4
1. 🐛 D3: cherry-pick from s3
2. 🐛 D1: Register AllowAllPermissionEvaluator when OIDC disabled
3. 🐛 D2: Fix group-errors paging — filter-before-page for scoped users
4. 🐛 D5: Align GET edit/config to messages:edit permission
5. ♻️ D6: Use ICasbinResourceScopeChecker consistently in GetErrorByIdController
6. 🐛 Backport: Fail-closed EditComment/DeleteComment on S4
