#nullable enable
namespace ServiceControl.Infrastructure.WebApi.Auth;

using Microsoft.AspNetCore.Authorization;

/// <summary>
/// An <see cref="IAuthorizationRequirement"/> that carries the permission string to be enforced.
/// Used by the S3 resource-based authorization mechanism.
/// <para>
/// Two distinct checks use this requirement:
/// <list type="bullet">
///   <item>Verb gate (pre-load): does the user hold <see cref="Permission"/> at all?</item>
///   <item>Resource scope (post-load): is the specific resource in scope for this user?</item>
/// </list>
/// </para>
/// </summary>
public sealed class PermissionRequirement(string permission) : IAuthorizationRequirement
{
    /// <summary>The permission being enforced (e.g. <c>messages:retry</c>).</summary>
    public string Permission { get; } = permission;
}
