#nullable enable
namespace ServiceControl.Infrastructure.CustomIndexes;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

/// <summary>
/// The loaded set of <see cref="CustomIndex"/> entries plus a content-derived
/// version hash. The hash is suffixed onto the RavenDB index name so a config
/// change produces a new index name and RavenDB builds the new index
/// side-by-side without blocking queries.
/// </summary>
public sealed class CustomIndexConfig
{
    public CustomIndexConfig(IReadOnlyList<CustomIndex> indexes)
    {
        Indexes = indexes ?? throw new ArgumentNullException(nameof(indexes));
        Version = ComputeVersion(indexes);
    }

    public IReadOnlyList<CustomIndex> Indexes { get; }

    /// <summary>
    /// Short stable hash of the configured key set; suffixed onto the index name.
    /// Same hash ⇒ same index. Different hash ⇒ RavenDB builds a new index.
    /// </summary>
    public string Version { get; }

    /// <summary>Just the configured header keys, sorted deterministically.</summary>
    public string[] Keys => Indexes
        .Select(i => i.Key)
        .OrderBy(k => k, StringComparer.Ordinal)
        .ToArray();

    public static readonly CustomIndexConfig Empty = new(Array.Empty<CustomIndex>());

    /// <summary>
    /// The active config, set once at host startup by the composition root. Read by
    /// <c>DatabaseSetup</c> when registering the dynamic-field index so the persistence
    /// layer doesn't need a new ctor parameter for a spike-stage feature.
    /// </summary>
    public static CustomIndexConfig Active { get; private set; } = Empty;

    public static void SetActive(CustomIndexConfig config) => Active = config ?? Empty;

    static string ComputeVersion(IReadOnlyList<CustomIndex> indexes)
    {
        var canonical = string.Join("\n", indexes
            .Select(i => i.Key)
            .OrderBy(k => k, StringComparer.Ordinal));

        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Convert.ToHexString(bytes).Substring(0, 8).ToLowerInvariant();
    }
}
