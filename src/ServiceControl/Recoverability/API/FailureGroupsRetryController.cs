namespace ServiceControl.Recoverability.API
{
    using System;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;
    using NServiceBus;
    using ServiceControl.Infrastructure.Auth.Rbac;
    using ServiceControl.Infrastructure.WebApi.Auth;
    using ServiceControl.Persistence;

    [ApiController]
    [Route("api")]
    public class FailureGroupsRetryController(
        IMessageSession bus,
        RetryingManager retryingManager,
        IPermissionEvaluator permissionEvaluator) : ControllerBase
    {
        /// <summary>
        /// Retries all messages in the specified failure group.
        /// <para>
        /// <b>Fail-closed for scoped users:</b> failure groups span multiple queues and cannot be
        /// scope-checked against a single queue address. If the user holds only scope-restricted
        /// grants for <c>recoverabilitygroups:retry</c>, access is denied with 403.
        /// </para>
        /// </summary>
        [Authorize(Policy = Permissions.RecoverabilityGroupsRetry)]
        [Route("recoverability/groups/{groupId:required:minlength(1)}/errors/retry")]
        [HttpPost]
        public async Task<IActionResult> ArchiveGroupErrors(string groupId)
        {
            // Fail-closed for scoped users: groups span queues and cannot be scope-checked.
            if (!permissionEvaluator.HasUnrestrictedGrant(User, Permissions.RecoverabilityGroupsRetry))
            {
                await AuthorizationHelpers.WriteScopeDenied403(
                    Response,
                    Permissions.RecoverabilityGroupsRetry,
                    queueAddress: groupId);
                return new EmptyResult();
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