namespace ServiceControl.MessageFailures.Api
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Infrastructure.WebApi;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;
    using Persistence.Infrastructure;
    using ServiceControl.Infrastructure.Auth.Rbac;
    using ServiceControl.Infrastructure.CustomIndexes;
    using ServiceControl.Persistence;

    /// <summary>
    /// Filters failed messages by custom-attribute predicates resolved against the
    /// dynamic-field <c>FailedMessage/Attributes/v&lt;hash&gt;</c> RavenDB index, with
    /// authz narrowing on dimensions whose <see cref="CustomIndex"/> carries an
    /// <see cref="CustomIndexAuthz"/> binding.
    /// </summary>
    /// <remarks>
    /// Query convention:
    /// <list type="bullet">
    ///   <item><c>?attr.NServiceBus.Tenant=acme</c> — equality</item>
    ///   <item><c>?attr.NServiceBus.FailedQ.starts-with=Sales.</c> — starts-with</item>
    /// </list>
    /// Authz narrowing applies per index:
    /// <list type="bullet">
    ///   <item>Index has no <c>authz</c> binding — caller's predicate is passed through unchanged.</item>
    ///   <item>Index has authz and caller specified an EQUALS value not in the authorized set — <c>403 Forbidden</c>.</item>
    ///   <item>Index has authz and caller specified nothing for that dimension — a <c>WhereIn(authorized)</c> is silently injected; an empty authorized set short-circuits to 0 results.</item>
    /// </list>
    /// Two response headers surface the narrowing transparently so the SPA can show the user what happened:
    /// <list type="bullet">
    ///   <item><c>X-CustomIndex-Version</c> — the active config hash.</item>
    ///   <item><c>X-AuthzNarrowed</c> — comma-separated list of dimensions where authz injected an IN-filter.</item>
    /// </list>
    /// Every decision (allow / narrow / deny) is recorded via <see cref="IAuthorizationAuditLog"/>.
    /// </remarks>
    [ApiController]
    [Route("api")]
    public sealed class GetErrorsByAttributesController(
        IErrorMessageDataStore store,
        CustomIndexConfig customIndexConfig,
        ICustomIndexAuthzResolver authzResolver,
        IServiceProvider serviceProvider) : ControllerBase
    {
        // IAuthorizationAuditLog is only registered when OIDC is enabled; resolve optionally
        // so the controller works in OIDC-off deployments (audit-log silently no-ops).
        IAuthorizationAuditLog AuditLog => serviceProvider.GetService(typeof(IAuthorizationAuditLog)) as IAuthorizationAuditLog;
        [Authorize(Policy = Permissions.MessagesView)]
        [Route("errors/by-attributes")]
        [HttpGet]
        public async Task<ActionResult<IList<FailedMessageView>>> ErrorsByAttributes(
            [FromQuery] PagingInfo pagingInfo,
            [FromQuery] SortInfo sortInfo)
        {
            var equalsFilters = new Dictionary<string, string>(StringComparer.Ordinal);
            var startsWithFilters = new Dictionary<string, string>(StringComparer.Ordinal);

            ParseQueryString(equalsFilters, startsWithFilters);

            // Authz narrowing: for each authz-eligible index, intersect requested filters
            // with the user's authorized values. Builds inFilters for dimensions the user
            // didn't filter on, denies dimensions where the user requested an out-of-scope value.
            var inFilters = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);
            var narrowedDimensions = new List<string>();
            var subjectId = User.FindFirst("sub")?.Value ?? User.Identity?.Name ?? "unknown";
            var subjectName = User.FindFirst("preferred_username")?.Value ?? subjectId;

            foreach (var index in customIndexConfig.Indexes)
            {
                var authorized = authzResolver.GetAuthorizedValues(User, index);
                if (authorized == null)
                {
                    continue; // no authz on this index
                }

                if (equalsFilters.TryGetValue(index.Key, out var requested) && !string.IsNullOrWhiteSpace(requested))
                {
                    // Caller asked for a specific value — must be in their authorized set.
                    var inSet = authorized.Any(v => string.Equals(v, requested, StringComparison.OrdinalIgnoreCase));
                    if (!inSet)
                    {
                        AuditLog?.Decision(
                            subjectId, subjectName,
                            permission: "messages:view",
                            resource: $"{index.Key}={requested}",
                            allowed: false,
                            reason: $"Custom-index authz: requested value '{requested}' for '{index.Key}' is not in the user's authorized set (source={index.Authz?.Source}, claim={index.Authz?.Claim})");
                        return Forbid();
                    }
                    AuditLog?.Decision(
                        subjectId, subjectName,
                        permission: "messages:view",
                        resource: $"{index.Key}={requested}",
                        allowed: true,
                        reason: $"Custom-index authz: requested value '{requested}' for '{index.Key}' is in the user's authorized set");
                    continue;
                }

                // No caller filter on this authz-eligible dimension — narrow to authorized set.
                if (authorized.Count == 0)
                {
                    AuditLog?.Decision(
                        subjectId, subjectName,
                        permission: "messages:view",
                        resource: index.Key,
                        allowed: false,
                        reason: $"Custom-index authz: user has zero authorized values for '{index.Key}' — short-circuit empty result");
                    Response.Headers["X-CustomIndex-Version"] = customIndexConfig.Version;
                    Response.Headers["X-AuthzNarrowed"] = index.Key + "=(empty)";
                    return Ok(new List<FailedMessageView>());
                }

                inFilters[index.Key] = authorized;
                narrowedDimensions.Add(index.Key);
                AuditLog?.Decision(
                    subjectId, subjectName,
                    permission: "messages:view",
                    resource: index.Key,
                    allowed: true,
                    reason: $"Custom-index authz: narrowed '{index.Key}' to user's authorized values [{string.Join(",", authorized)}]");
            }

            var results = await store.ErrorGetByAttributes(
                equalsFilters,
                startsWithFilters,
                inFilters,
                customIndexConfig.Version,
                pagingInfo,
                sortInfo);

            Response.WithQueryStatsAndPagingInfo(results.QueryStats, pagingInfo);
            Response.Headers["X-CustomIndex-Version"] = customIndexConfig.Version;
            if (narrowedDimensions.Count > 0)
            {
                Response.Headers["X-AuthzNarrowed"] = string.Join(",", narrowedDimensions);
            }
            return Ok(results.Results);
        }

        void ParseQueryString(
            Dictionary<string, string> equalsFilters,
            Dictionary<string, string> startsWithFilters)
        {
            const string prefix = "attr.";
            const string startsWithSuffix = ".starts-with";

            foreach (var (rawKey, rawValue) in Request.Query)
            {
                if (!rawKey.StartsWith(prefix))
                {
                    continue;
                }
                var rest = rawKey.Substring(prefix.Length);
                if (string.IsNullOrEmpty(rest) || rawValue.Count == 0)
                {
                    continue;
                }
                var value = rawValue.ToString();

                string header;
                bool isStartsWith;
                if (rest.EndsWith(startsWithSuffix))
                {
                    header = rest.Substring(0, rest.Length - startsWithSuffix.Length);
                    isStartsWith = true;
                }
                else
                {
                    header = rest;
                    isStartsWith = false;
                }

                if (string.IsNullOrEmpty(header) || !IsConfiguredKey(header))
                {
                    continue;
                }

                if (isStartsWith)
                {
                    startsWithFilters[header] = value;
                }
                else
                {
                    equalsFilters[header] = value;
                }
            }
        }

        bool IsConfiguredKey(string header) =>
            customIndexConfig.Indexes.Any(i => string.Equals(i.Key, header, StringComparison.Ordinal));
    }
}
