#nullable enable
namespace ServiceControl.Infrastructure.WebApi;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using ServiceControl.Infrastructure.CustomIndexes;
using ServiceControl.Persistence;

/// <summary>
/// Exposes the currently loaded set of <see cref="CustomIndex"/> definitions
/// so ServicePulse can render filter chips and admin UI per defined index.
/// </summary>
/// <remarks>
/// The descriptor includes the index version (a hash of the configured keys) so
/// callers can detect a config change and refresh their chip catalog. POST / DELETE
/// are deferred to the admin-UI task (#6); for now the config is file-driven
/// (<c>extract-headers.yaml</c>, hot-reloadable by restarting the host).
/// </remarks>
[ApiController]
[Route("api")]
[AuthenticatedOnly]
public sealed class CustomIndexesController(
    CustomIndexConfig config,
    IErrorMessageDataStore store) : ControllerBase
{
    /// <summary>
    /// Returns the configured custom indexes.
    /// </summary>
    /// <response code="200">The current custom-index config (possibly empty).</response>
    /// <response code="401">No valid bearer token was provided.</response>
    [HttpGet]
    [Route("custom-indexes")]
    public ActionResult<CustomIndexesDescriptor> Get()
    {
        var entries = config.Indexes
            .Select(i => new CustomIndexEntry(
                Key: i.Key,
                Operator: i.Operator,
                Authz: i.Authz == null
                    ? null
                    : new CustomIndexAuthzEntry(
                        Source: i.Authz.Source,
                        Claim: i.Authz.Claim,
                        Key: i.Authz.Key)))
            .ToList();

        return Ok(new CustomIndexesDescriptor(
            Version: config.Version,
            Indexes: entries));
    }

    /// <summary>
    /// Returns distinct values observed for a configured custom-index attribute, with
    /// per-value document counts. Used by ServicePulse to populate dropdown filter chips
    /// instead of asking the user to type the exact value.
    /// </summary>
    /// <response code="200">The distinct values + counts (possibly empty).</response>
    /// <response code="401">No valid bearer token was provided.</response>
    /// <response code="404">The requested key is not a configured custom index.</response>
    [HttpGet]
    [Route("custom-indexes/{key}/values")]
    public async Task<ActionResult<AttributeValuesDescriptor>> GetValues(string key)
    {
        var configured = config.Indexes.FirstOrDefault(i => string.Equals(i.Key, key, StringComparison.Ordinal));
        if (configured is null)
        {
            return NotFound();
        }

        var facetCounts = await store.ErrorGetAttributeValues(key, config.Version);

        var values = facetCounts
            .Select(kvp => new AttributeValueCount(Value: kvp.Key, Count: kvp.Value))
            .OrderByDescending(v => v.Count)
            .ThenBy(v => v.Value, StringComparer.Ordinal)
            .ToList();

        return Ok(new AttributeValuesDescriptor(
            Key: key,
            IndexVersion: config.Version,
            Values: values));
    }
}

/// <summary>The JSON shape returned by <c>GET /api/custom-indexes</c>.</summary>
public sealed record CustomIndexesDescriptor(string Version, IReadOnlyList<CustomIndexEntry> Indexes);

/// <summary>A single configured custom index.</summary>
public sealed record CustomIndexEntry(string Key, string Operator, CustomIndexAuthzEntry? Authz);

/// <summary>The authz narrowing source for a custom index, or null for an unauthz'd filter chip.</summary>
public sealed record CustomIndexAuthzEntry(string Source, string? Claim, string? Key);

/// <summary>The JSON shape returned by <c>GET /api/custom-indexes/{key}/values</c>.</summary>
public sealed record AttributeValuesDescriptor(
    string Key,
    string IndexVersion,
    IReadOnlyList<AttributeValueCount> Values);

/// <summary>A single distinct value observed for an attribute, with its document count.</summary>
public sealed record AttributeValueCount(string Value, long Count);
