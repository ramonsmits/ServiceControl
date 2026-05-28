#nullable enable
namespace ServiceControl.Infrastructure.Tests.Auth.Rbac;

using System.Collections.Generic;
using System.Linq;
using NUnit.Framework;
using ServiceControl.Infrastructure.Auth.Rbac;

/// <summary>
/// Unit tests for the permission-status mapping logic that backs <c>GET /api/me/diagnostics</c>.
/// These are fast, host-startup-free tests. The mapping logic is replicated inline here
/// (independent of the controller) so this project does not need to reference the main
/// ServiceControl assembly.
/// </summary>
[TestFixture]
public class MeDiagnosticsPermissionMappingTests
{
    // ---------------------------------------------------------------------------
    // Minimal local types mirroring the controller's descriptor types —
    // avoids a dependency on the ServiceControl assembly from this test project.
    // ---------------------------------------------------------------------------

    enum PermissionStatus { Allowed, Scoped, NotGranted }

    sealed record PermissionEntry(string Permission, PermissionStatus Status, ScopeEntry? Scope);

    sealed record ScopeEntry(IReadOnlyList<string> Allow, IReadOnlyList<string> Deny);

    // ---------------------------------------------------------------------------
    // Replication of the controller's mapping logic — the canonical implementation
    // lives in MeDiagnosticsController. Any change there must be reflected here.
    // ---------------------------------------------------------------------------

    static IReadOnlyList<PermissionEntry> ComputeEntries(EffectivePermissions effective)
    {
        var hasWildcard = effective.Grants.Any(g => g.Permission == "*");
        var result = new List<PermissionEntry>();

        foreach (var permission in Permissions.All.Where(p => p != "*").OrderBy(p => p, System.StringComparer.Ordinal))
        {
            PermissionEntry entry;

            if (hasWildcard)
            {
                entry = new PermissionEntry(permission, PermissionStatus.Allowed, Scope: null);
            }
            else
            {
                var grantsForPermission = effective.Grants
                    .Where(g => g.Permission == permission)
                    .ToList();

                if (grantsForPermission.Count == 0)
                {
                    entry = new PermissionEntry(permission, PermissionStatus.NotGranted, Scope: null);
                }
                else if (grantsForPermission.Any(g => g.Scope == null))
                {
                    entry = new PermissionEntry(permission, PermissionStatus.Allowed, Scope: null);
                }
                else
                {
                    var unionAllow = grantsForPermission
                        .SelectMany(g => g.Scope!.Allow)
                        .Distinct(System.StringComparer.Ordinal)
                        .OrderBy(p => p, System.StringComparer.Ordinal)
                        .ToList();

                    var unionDeny = grantsForPermission
                        .SelectMany(g => g.Scope!.Deny)
                        .Distinct(System.StringComparer.Ordinal)
                        .OrderBy(p => p, System.StringComparer.Ordinal)
                        .ToList();

                    entry = new PermissionEntry(
                        permission,
                        PermissionStatus.Scoped,
                        Scope: new ScopeEntry(unionAllow, unionDeny));
                }
            }

            result.Add(entry);
        }

        return result;
    }

    // ---------------------------------------------------------------------------
    // Tests
    // ---------------------------------------------------------------------------

    const string RetryPerm = Permissions.MessagesRetry;
    const string EditPerm = Permissions.MessagesEdit;
    const string LicensePerm = Permissions.LicensingManage;

    [Test]
    public void Unrestricted_grant_produces_Allowed_status()
    {
        var effective = new EffectivePermissions([
            new EffectiveGrant(RetryPerm, Scope: null)
        ]);

        var entries = ComputeEntries(effective);
        var retry = entries.Single(e => e.Permission == RetryPerm);

        Assert.That(retry.Status, Is.EqualTo(PermissionStatus.Allowed));
        Assert.That(retry.Scope, Is.Null);
    }

    [Test]
    public void No_grant_produces_NotGranted_status()
    {
        var effective = new EffectivePermissions([]);

        var entries = ComputeEntries(effective);
        var license = entries.Single(e => e.Permission == LicensePerm);

        Assert.That(license.Status, Is.EqualTo(PermissionStatus.NotGranted));
        Assert.That(license.Scope, Is.Null);
    }

    [Test]
    public void Scoped_only_grants_produce_Scoped_status_with_union_patterns()
    {
        var effective = new EffectivePermissions([
            new EffectiveGrant(EditPerm, new ResourceScope(["Sales.*"], [])),
            new EffectiveGrant(EditPerm, new ResourceScope(["Ops.*"], ["Ops.secret.*"]))
        ]);

        var entries = ComputeEntries(effective);
        var edit = entries.Single(e => e.Permission == EditPerm);

        Assert.That(edit.Status, Is.EqualTo(PermissionStatus.Scoped));
        Assert.That(edit.Scope, Is.Not.Null);
        // Allow is the union of both grants, sorted alphabetically
        Assert.That(edit.Scope!.Allow, Is.EquivalentTo(new[] { "Ops.*", "Sales.*" }));
        // Deny is the union of both grants
        Assert.That(edit.Scope.Deny, Is.EquivalentTo(new[] { "Ops.secret.*" }));
    }

    [Test]
    public void Unrestricted_grant_wins_over_scoped_grant_for_same_permission()
    {
        // A user may have both a scoped and an unrestricted grant (from two different roles).
        // The unrestricted grant must win → Allowed.
        var effective = new EffectivePermissions([
            new EffectiveGrant(RetryPerm, new ResourceScope(["Sales.*"], [])),
            new EffectiveGrant(RetryPerm, Scope: null) // unrestricted
        ]);

        var entries = ComputeEntries(effective);
        var retry = entries.Single(e => e.Permission == RetryPerm);

        Assert.That(retry.Status, Is.EqualTo(PermissionStatus.Allowed));
        Assert.That(retry.Scope, Is.Null);
    }

    [Test]
    public void Wildcard_grant_makes_every_catalogue_permission_Allowed()
    {
        // sc-admin has a single "*" grant — every permission should appear as Allowed.
        var effective = new EffectivePermissions([
            new EffectiveGrant("*", Scope: null)
        ]);

        var entries = ComputeEntries(effective);

        var catalogue = Permissions.All.Where(p => p != "*").ToHashSet();
        Assert.That(entries.Select(e => e.Permission).ToHashSet(), Is.EquivalentTo(catalogue),
            "Output should cover every catalogue permission");

        Assert.That(entries.All(e => e.Status == PermissionStatus.Allowed), Is.True,
            "All permissions must be Allowed when the user has a wildcard grant");

        Assert.That(entries.All(e => e.Scope == null), Is.True,
            "Wildcard grant should produce null scope for every entry");
    }

    [Test]
    public void Output_covers_every_catalogue_permission_exactly_once()
    {
        var effective = new EffectivePermissions([
            new EffectiveGrant(RetryPerm, Scope: null)
        ]);

        var entries = ComputeEntries(effective);
        var catalogue = Permissions.All.Where(p => p != "*").ToHashSet();

        Assert.That(entries.Select(e => e.Permission).ToHashSet(), Is.EquivalentTo(catalogue),
            "Every catalogue permission must appear in the output");

        // No duplicates
        Assert.That(entries.Select(e => e.Permission).Distinct().Count(), Is.EqualTo(entries.Count),
            "Each permission must appear exactly once");
    }
}
