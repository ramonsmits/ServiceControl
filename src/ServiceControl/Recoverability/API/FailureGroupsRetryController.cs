namespace ServiceControl.Recoverability.API
{
    using System;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Mvc;
    using NServiceBus;
    using ServiceControl.Infrastructure.Auth.Rbac;
    using ServiceControl.Infrastructure.WebApi;
    using ServiceControl.Infrastructure.WebApi.Auth;
    using ServiceControl.Persistence;

    [ApiController]
    [Route("api")]
    public class FailureGroupsRetryController(
        IMessageSession bus,
        RetryingManager retryingManager,
        IErrorMessageDataStore store,
        IAuthorizationService authorizationService) : ControllerBase
    {
        [Authorize(Policy = Permissions.RecoverabilityGroupsRetry)]
        [Route("recoverability/groups/{groupId:required:minlength(1)}/errors/retry")]
        [HttpPost]
        public async Task<IActionResult> ArchiveGroupErrors(string groupId)
        {
            // Resource-scope check: load the group and verify this user may operate on it.
            // Groups span multiple queues and cannot be verified against a single queue address.
            // Scoped users (scope-restricted grants only) are denied fail-closed — see
            // FailureGroupAuthorizationHandler for the rationale.
            // NOTE: For bulk/group operations the group must exist for a scope check.
            // If the group cannot be loaded we still proceed (unknown group → operation is benign).
            var groupResult = await store.GetGroup(groupId, status: null, modified: null);
            var group = groupResult.Results.FirstOrDefault();
            if (group != null)
            {
                var scopeResult = await authorizationService.AuthorizeAsync(
                    User,
                    group,
                    new PermissionRequirement(Permissions.RecoverabilityGroupsRetry));

                if (!scopeResult.Succeeded)
                {
                    Response.ContentType = "application/json";
                    Response.StatusCode = StatusCodes.Status403Forbidden;
                    await Response.WriteAsJsonAsync(new
                    {
                        error = "forbidden",
                        permission = Permissions.RecoverabilityGroupsRetry,
                        resource = groupId,
                        reason = $"Group '{groupId}' cannot be scope-verified — access denied fail-closed for scoped users"
                    });
                    return Empty;
                }
            }

            var started = DateTime.UtcNow;

            if (!retryingManager.IsOperationInProgressFor(groupId, RetryType.FailureGroup))
            {
                await retryingManager.Wait(groupId, RetryType.FailureGroup, started);

                await bus.SendLocal(new RetryAllInGroup
                {
                    GroupId = groupId,
                    Started = started
                });
            }

            return Accepted();
        }
    }
}