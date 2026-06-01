#nullable enable
namespace ServiceControl.Infrastructure.CustomIndexes;

/// <summary>
/// One configured message-attribute index. Declares a header to extract from each
/// failed message and (optionally) the authorization source that narrows the visible
/// values for the calling user.
/// </summary>
/// <param name="Key">The message header to extract (e.g. <c>NServiceBus.Tenant</c>).</param>
/// <param name="Operator">
/// UI / query-shape hint for this dimension. Currently <c>equals</c> (default) or
/// <c>starts-with</c>. Surfaced to ServicePulse so the filter chip knows whether to
/// generate <c>?attr.&lt;key&gt;=...</c> or <c>?attr.&lt;key&gt;.starts-with=...</c>.
/// </param>
/// <param name="Authz">
/// Optional. When present, the values the caller may see for this attribute are
/// intersected with the user's authorized set:
/// <list type="bullet">
///   <item><c>source: "idp-claim"</c> + <c>claim: &lt;name&gt;</c> — values come from a JWT claim.</item>
///   <item><c>source: "role"</c> + <c>key: &lt;property&gt;</c> — values come from the rbac.yaml role binding's named property.</item>
/// </list>
/// </param>
public sealed record CustomIndex(string Key, string Operator = "equals", CustomIndexAuthz? Authz = null);

public sealed record CustomIndexAuthz(string Source, string? Claim = null, string? Key = null);
