#nullable enable
namespace ServiceControl.Infrastructure.WebApi;

using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Mvc;
using ServiceControl.Infrastructure.CustomIndexes;

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
public sealed class CustomIndexesController(CustomIndexConfig config) : ControllerBase
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
}

/// <summary>The JSON shape returned by <c>GET /api/custom-indexes</c>.</summary>
public sealed record CustomIndexesDescriptor(string Version, IReadOnlyList<CustomIndexEntry> Indexes);

/// <summary>A single configured custom index.</summary>
public sealed record CustomIndexEntry(string Key, CustomIndexAuthzEntry? Authz);

/// <summary>The authz narrowing source for a custom index, or null for an unauthz'd filter chip.</summary>
public sealed record CustomIndexAuthzEntry(string Source, string? Claim, string? Key);
