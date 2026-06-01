namespace ServiceControl.MessageFailures.Api
{
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
    /// dynamic-field <c>FailedMessage/Attributes/v&lt;hash&gt;</c> RavenDB index.
    /// </summary>
    /// <remarks>
    /// Query convention:
    /// <list type="bullet">
    ///   <item><c>?attr.NServiceBus.Tenant=acme</c> — equality</item>
    ///   <item><c>?attr.NServiceBus.FailedQ.starts-with=Sales.</c> — starts-with</item>
    /// </list>
    /// The bare <c>attr.&lt;key&gt;=...</c> form is EQUALS; the <c>.starts-with</c>
    /// suffix is the alternate operator. Multiple predicates compose with AND.
    /// <para>
    /// Sibling of <see cref="GetAllErrorsController"/> — this is the spike-stage
    /// custom-index entry point. Authz narrowing (intersecting requested values
    /// with the user's authorized set per the loaded <see cref="CustomIndex"/>
    /// definitions) is task #5; for now any authenticated caller with
    /// <c>messages:view</c> can supply any predicate.
    /// </para>
    /// </remarks>
    [ApiController]
    [Route("api")]
    public sealed class GetErrorsByAttributesController(
        IErrorMessageDataStore store,
        CustomIndexConfig customIndexConfig) : ControllerBase
    {
        [Authorize(Policy = Permissions.MessagesView)]
        [Route("errors/by-attributes")]
        [HttpGet]
        public async Task<IList<FailedMessageView>> ErrorsByAttributes(
            [FromQuery] PagingInfo pagingInfo,
            [FromQuery] SortInfo sortInfo)
        {
            var equalsFilters = new Dictionary<string, string>();
            var startsWithFilters = new Dictionary<string, string>();

            foreach (var (rawKey, rawValue) in Request.Query)
            {
                if (!rawKey.StartsWith("attr."))
                {
                    continue;
                }

                var rest = rawKey.Substring("attr.".Length);
                if (string.IsNullOrEmpty(rest))
                {
                    continue;
                }
                if (rawValue.Count == 0)
                {
                    continue;
                }
                var value = rawValue.ToString();

                const string startsWithSuffix = ".starts-with";
                if (rest.EndsWith(startsWithSuffix))
                {
                    var header = rest.Substring(0, rest.Length - startsWithSuffix.Length);
                    if (!string.IsNullOrEmpty(header) && IsConfiguredKey(header))
                    {
                        startsWithFilters[header] = value;
                    }
                }
                else
                {
                    if (IsConfiguredKey(rest))
                    {
                        equalsFilters[rest] = value;
                    }
                }
            }

            var results = await store.ErrorGetByAttributes(
                equalsFilters,
                startsWithFilters,
                customIndexConfig.Version,
                pagingInfo,
                sortInfo);

            Response.WithQueryStatsAndPagingInfo(results.QueryStats, pagingInfo);
            Response.Headers["X-CustomIndex-Version"] = customIndexConfig.Version;
            return results.Results;
        }

        bool IsConfiguredKey(string header) =>
            customIndexConfig.Indexes.Any(i => string.Equals(i.Key, header, System.StringComparison.Ordinal));
    }
}
