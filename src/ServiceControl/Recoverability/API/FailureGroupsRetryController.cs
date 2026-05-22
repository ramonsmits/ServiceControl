namespace ServiceControl.Recoverability.API
{
    using System;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;
    using NServiceBus;
    using ServiceControl.Infrastructure.Auth.Rbac;
    using ServiceControl.Infrastructure.WebApi;
    using ServiceControl.Infrastructure.WebApi.Auth;
    using ServiceControl.Persistence;

    [ApiController]
    [Route("api")]
    public class FailureGroupsRetryController(IMessageSession bus, RetryingManager retryingManager) : ControllerBase
    {
        [RequirePermission(Permissions.RecoverabilityGroupsRetry)]
        [Authorize(Policy = Permissions.RecoverabilityGroupsRetry)]
        [Route("recoverability/groups/{groupId:required:minlength(1)}/errors/retry")]
        [HttpPost]
        public async Task<IActionResult> ArchiveGroupErrors(string groupId)
        {
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