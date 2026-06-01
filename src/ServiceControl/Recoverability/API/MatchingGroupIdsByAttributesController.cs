namespace ServiceControl.Recoverability.API
{
    using System;
    using System.Collections.Generic;
    using System.Threading.Tasks;
    using Infrastructure.WebApi;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;
    using ServiceControl.Infrastructure.Auth.Rbac;
    using ServiceControl.Infrastructure.CustomIndexes;
    using ServiceControl.MessageFailures.Api;
    using ServiceControl.Persistence;

    /// <summary>
    /// Returns the set of failure-group IDs (filtered to the given classifier) whose
    /// underlying messages match the active custom-index attribute predicates.
    /// </summary>
    /// <remarks>
    /// Used by ServicePulse to narrow the Failed Message Groups view to only groups that
    /// contain messages matching the chip filters. Spike-stage implementation: queries
    /// the FailedMessage attributes index, loads up to 1000 matching docs, extracts their
    /// failure_groups and returns the distinct IDs for the requested classifier. Production
    /// would replace this with a server-side multi-map join index over groups + attributes.
    /// </remarks>
    [ApiController]
    [Route("api")]
    public sealed class MatchingGroupIdsByAttributesController(
        IErrorMessageDataStore store,
        CustomIndexConfig customIndexConfig) : ControllerBase
    {
        [Authorize(Policy = Permissions.RecoverabilityGroupsView)]
        [Route("recoverability/groups/{classifier}/by-attributes/group-ids")]
        [HttpGet]
        public async Task<ActionResult<IReadOnlyList<string>>> Get(string classifier)
        {
            var equalsFilters = new Dictionary<string, string>(StringComparer.Ordinal);
            var startsWithFilters = new Dictionary<string, string>(StringComparer.Ordinal);

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
                if (rest.EndsWith(startsWithSuffix))
                {
                    var header = rest.Substring(0, rest.Length - startsWithSuffix.Length);
                    if (!string.IsNullOrEmpty(header))
                    {
                        startsWithFilters[header] = value;
                    }
                }
                else
                {
                    equalsFilters[rest] = value;
                }
            }

            // No filters → empty list (caller will skip the narrowing).
            if (equalsFilters.Count == 0 && startsWithFilters.Count == 0)
            {
                return Ok(Array.Empty<string>());
            }

            var ids = await store.ErrorGetMatchingGroupIds(
                equalsFilters,
                startsWithFilters,
                new Dictionary<string, IReadOnlyList<string>>(),
                customIndexConfig.Version,
                classifier);

            Response.Headers["X-CustomIndex-Version"] = customIndexConfig.Version;
            return Ok(ids);
        }
    }
}
