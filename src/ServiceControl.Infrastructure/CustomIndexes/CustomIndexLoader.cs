#nullable enable
namespace ServiceControl.Infrastructure.CustomIndexes;

using System;
using System.Collections.Generic;
using System.IO;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

/// <summary>
/// Loads <c>extract-headers.yaml</c> into a <see cref="CustomIndexConfig"/>.
/// Same loader shape as <see cref="ServiceControl.Infrastructure.Auth.Rbac.RbacPolicyLoader"/>.
/// </summary>
public static class CustomIndexLoader
{
    static readonly IDeserializer Deserializer = new DeserializerBuilder()
        .WithNamingConvention(CamelCaseNamingConvention.Instance)
        .IgnoreUnmatchedProperties()
        .Build();

    public static CustomIndexConfig LoadFromFile(string path)
    {
        if (!File.Exists(path))
        {
            return CustomIndexConfig.Empty;
        }

        var yaml = File.ReadAllText(path);
        return LoadFromString(yaml);
    }

    public static CustomIndexConfig LoadFromString(string yaml)
    {
        var doc = Deserializer.Deserialize<YamlRoot?>(yaml) ?? new YamlRoot();
        var raw = doc.ExtractHeaders ?? [];

        var indexes = new List<CustomIndex>(raw.Count);
        foreach (var entry in raw)
        {
            if (entry == null || string.IsNullOrWhiteSpace(entry.Key))
            {
                continue;
            }

            CustomIndexAuthz? authz = null;
            if (entry.Authz != null && !string.IsNullOrWhiteSpace(entry.Authz.Source))
            {
                authz = new CustomIndexAuthz(
                    Source: entry.Authz.Source!,
                    Claim: entry.Authz.Claim,
                    Key: entry.Authz.Key);
            }

            indexes.Add(new CustomIndex(entry.Key!, authz));
        }

        return new CustomIndexConfig(indexes);
    }

    sealed class YamlRoot
    {
        public List<YamlEntry>? ExtractHeaders { get; set; }
    }

    sealed class YamlEntry
    {
        public string? Key { get; set; }
        public YamlAuthz? Authz { get; set; }
    }

    sealed class YamlAuthz
    {
        public string? Source { get; set; }
        public string? Claim { get; set; }
        public string? Key { get; set; }
    }
}
