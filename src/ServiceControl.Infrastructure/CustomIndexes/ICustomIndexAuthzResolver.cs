#nullable enable
namespace ServiceControl.Infrastructure.CustomIndexes;

using System.Collections.Generic;
using System.Security.Claims;

/// <summary>
/// Resolves the set of values a user is authorized to see for a given
/// authz-eligible <see cref="CustomIndex"/>. Returns <see langword="null"/> when the
/// index has no <see cref="CustomIndexAuthz"/> binding (no narrowing).
/// </summary>
/// <remarks>
/// In XACML terms this is a <strong>PIP (Policy Information Point)</strong> behind the
/// PDP-equivalent narrowing logic in the controller: for each authz-eligible attribute
/// dimension, the resolver answers "which values may this user see?" and the controller
/// intersects that with the user's requested filter.
/// </remarks>
public interface ICustomIndexAuthzResolver
{
    /// <returns>
    /// <see langword="null"/> ⇒ no authz binding on this index, so any value is allowed.
    /// Empty list ⇒ user is not authorized for any value in this dimension — controller
    /// short-circuits to 0 results.
    /// Non-empty list ⇒ the user's authorized values (case-insensitive set).
    /// </returns>
    IReadOnlyList<string>? GetAuthorizedValues(ClaimsPrincipal user, CustomIndex index);
}
