#nullable enable
namespace ServiceControl.Infrastructure.CustomIndexes;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using Microsoft.Extensions.Logging;

/// <summary>
/// Default <see cref="ICustomIndexAuthzResolver"/>. Supports source <c>idp-claim</c>
/// (reads named claim values straight off the principal) and logs a one-time warning
/// for any other source (e.g. <c>role</c>) — currently treated as "no narrowing"
/// while role-based attribute scopes remain a future enhancement.
/// </summary>
public sealed class CustomIndexAuthzResolver(ILogger<CustomIndexAuthzResolver> logger) : ICustomIndexAuthzResolver
{
    readonly HashSet<string> warnedSources = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyList<string>? GetAuthorizedValues(ClaimsPrincipal user, CustomIndex index)
    {
        if (index.Authz is null)
        {
            return null;
        }

        var source = index.Authz.Source ?? string.Empty;

        if (string.Equals(source, "idp-claim", StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(index.Authz.Claim))
            {
                return Array.Empty<string>();
            }

            return user.FindAll(index.Authz.Claim)
                .Select(c => c.Value)
                .Where(v => !string.IsNullOrWhiteSpace(v))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        // Unknown source — warn once per source name to avoid log spam, return null
        // (no narrowing) so an unknown source doesn't accidentally lock people out.
        if (warnedSources.Add(source))
        {
            logger.LogWarning(
                "CustomIndex '{Key}' has authz source '{Source}' which is not implemented — treating as no narrowing. Implemented sources: idp-claim.",
                index.Key, source);
        }
        return null;
    }
}
