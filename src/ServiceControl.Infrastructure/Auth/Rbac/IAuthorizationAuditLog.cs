#nullable enable
namespace ServiceControl.Infrastructure.Auth.Rbac;

/// <summary>
/// Records every authorization allow/deny decision.
/// Implementations write structured log entries under the category
/// <c>ServiceControl.Audit</c> so they can be collected by any
/// <c>ILogger</c>-compatible sink (Seq, OTLP, in-memory test double, …).
/// </summary>
/// <remarks>
/// The sink for the decision the <strong>PDP</strong> (<see cref="IPermissionEvaluator"/>) returned.
/// PEPs call this immediately after every <c>AuthorizeAsync</c> to ensure both the permits and the
/// denies are captured — denies alone are not enough for compliance use cases. See
/// <c>research/platform-authorization/audit-logging-approaches.md</c> for the design rationale and
/// <c>research/platform-authorization/xacml-vocabulary.md</c> for the PEP/PDP/PAP/PIP vocabulary.
/// </remarks>
public interface IAuthorizationAuditLog
{
    /// <summary>
    /// Records a single authorization decision.
    /// </summary>
    /// <param name="subjectId">The stable identifier of the principal (e.g. the <c>sub</c> claim). Must not be null or empty.</param>
    /// <param name="subjectName">The human-readable display name of the principal (e.g. the <c>preferred_username</c> claim). Must not be null or empty.</param>
    /// <param name="permission">The permission that was evaluated (e.g. <c>messages:retry</c>).</param>
    /// <param name="resource">The specific resource checked, or <see langword="null"/> for verb-level checks.</param>
    /// <param name="allowed"><see langword="true"/> if the decision was allow; <see langword="false"/> for deny.</param>
    /// <param name="reason">A human-readable explanation (e.g. which policy rule matched, or why it didn't).</param>
    void Decision(string subjectId, string subjectName, string permission, string? resource, bool allowed, string reason);
}
