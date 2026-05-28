#nullable enable
namespace ServiceControl.Infrastructure.Auth.Rbac;

using System.Collections.Generic;

/// <summary>
/// Translates a loaded <see cref="RbacPolicy"/> (from <c>rbac.yaml</c>) into Casbin policy lines
/// that can be fed into a <c>TextAdapter</c> at startup.
///
/// <para>
/// <b>Format:</b> each line is a Casbin CSV policy row:
/// <list type="bullet">
///   <item><c>p, role:X, perm, res, allow|deny</c> — a permission policy line</item>
///   <item><c>g, binding, role:X</c>               — a role-membership line</item>
/// </list>
/// </para>
///
/// <para>
/// <b>Design contract:</b> operators edit <c>rbac.yaml</c> only — they never write Casbin syntax.
/// This compiler is the single point that converts the YAML model into Casbin's format.
/// </para>
///
/// <para>
/// <b>Wildcard permission (<c>*</c>):</b> compiled as <c>p, role:X, *, *, allow</c> — the
/// wildcard both in the permission column and the resource column so a single allow line
/// satisfies any <c>Enforce(user, anyPerm, anyRes)</c> call for that role.
/// </para>
///
/// <para>
/// <b>Scoped permissions:</b>
/// <list type="bullet">
///   <item>Each <c>allow</c> pattern becomes one allow line.</item>
///   <item>Each <c>deny</c> pattern becomes one deny line.</item>
///   <item>The deny-override effect in the model ensures a deny wins over any allow.</item>
/// </list>
/// </para>
///
/// <para>
/// <b>Unrestricted permissions</b> (no <see cref="PermissionGrant.Scope"/>):
/// compiled as <c>p, role:X, perm, *, allow</c> — resource wildcard covers everything.
/// </para>
/// </summary>
public static class RbacPolicyToCasbinCompiler
{
    /// <summary>
    /// Compiles the given <paramref name="policy"/> to a list of Casbin policy lines.
    /// The returned list is ordered: all <c>p</c> lines first, then all <c>g</c> lines.
    /// </summary>
    /// <param name="policy">The RBAC policy loaded from <c>rbac.yaml</c>.</param>
    /// <returns>A list of Casbin policy lines suitable for use with a <c>TextAdapter</c>.</returns>
    public static IReadOnlyList<string> Compile(RbacPolicy policy)
    {
        var pLines = new List<string>();
        var gLines = new List<string>();

        foreach (var (_, role) in policy.Roles)
        {
            // The policy subject for this role is always "role:<roleName>".
            // This is the Casbin convention that distinguishes role names from user names.
            var rolePolicySub = $"role:{role.Name}";

            // --- Permission policy lines (p) ---
            foreach (var grant in role.Permissions)
            {
                if (grant.Scope is null)
                {
                    // Unrestricted permission: applies to every resource.
                    // Resource wildcard "*" matches anything via globMatch.
                    pLines.Add($"p, {rolePolicySub}, {grant.Permission}, *, allow");
                }
                else
                {
                    // Scoped permission: one allow line per allow pattern, one deny line per deny pattern.
                    foreach (var allowPattern in grant.Scope.Allow)
                    {
                        pLines.Add($"p, {rolePolicySub}, {grant.Permission}, {allowPattern}, allow");
                    }

                    foreach (var denyPattern in grant.Scope.Deny)
                    {
                        pLines.Add($"p, {rolePolicySub}, {grant.Permission}, {denyPattern}, deny");
                    }
                }
            }

            // --- Role membership lines (g) ---
            // Each binding maps a user/group claim value to the role's policy subject.
            // This allows Casbin's g(r.sub, p.sub) function to resolve the user's role.
            foreach (var binding in role.Bindings)
            {
                gLines.Add($"g, {binding}, {rolePolicySub}");
            }
        }

        var result = new List<string>(pLines.Count + gLines.Count);
        result.AddRange(pLines);
        result.AddRange(gLines);
        return result;
    }
}
