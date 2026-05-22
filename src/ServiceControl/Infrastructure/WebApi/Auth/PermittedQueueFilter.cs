#nullable enable
namespace ServiceControl.Infrastructure.WebApi.Auth;

using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using ServiceControl.Infrastructure.Auth.Rbac;
using ServiceControl.MessageFailures;
using ServiceControl.MessageFailures.Api;

/// <summary>
/// R1 scope filter: removes messages from list results that are outside the user's permitted
/// queue scope for a given permission.
/// <para>
/// For users with an unrestricted grant (no scope restriction) the full result set is returned
/// unchanged. For users with only scoped grants, messages whose queue address does not match
/// any permitted scope pattern are excluded.
/// </para>
/// <para>
/// This filter is applied at the controller level (post-query) for list endpoints where
/// per-row authorization is required. It is the S3 equivalent of the R1 data-layer filter
/// described in §S3.4 of the implementation plan. A data-layer implementation would be more
/// efficient for large result sets but requires threading <see cref="ClaimsPrincipal"/> through
/// the persistence interface — deferred to a later phase.
/// </para>
/// </summary>
public static class PermittedQueueFilter
{
    /// <summary>
    /// Filters a list of <see cref="FailedMessageView"/> to those whose queue address is in scope
    /// for the current user's <paramref name="permission"/> grant.
    /// </summary>
    public static IList<FailedMessageView> FilterByPermittedQueues(
        this IList<FailedMessageView> results,
        ClaimsPrincipal user,
        string permission,
        IPermissionEvaluator permissionEvaluator)
    {
        var effective = permissionEvaluator.Resolve(user);

        // Check whether the user holds at least one unrestricted grant for this permission.
        var hasUnrestrictedGrant = effective.Grants.Any(g =>
            (g.Permission == "*" || g.Permission == permission) && g.Scope == null);

        // Unrestricted users see everything.
        if (hasUnrestrictedGrant)
        {
            return results;
        }

        // No grants at all → empty (the verb gate should have already blocked this case,
        // but we keep the filter safe).
        if (!effective.Grants.Any(g => g.Permission == "*" || g.Permission == permission))
        {
            return [];
        }

        // Scoped users: keep only messages whose queue address is in scope for any of their grants.
        return results
            .Where(m =>
            {
                var queueAddress = m.QueueAddress;
                if (string.IsNullOrEmpty(queueAddress))
                {
                    // No queue address → exclude (fail-closed).
                    return false;
                }

                return permissionEvaluator.IsInScope(user, permission, queueAddress);
            })
            .ToList();
    }
}
